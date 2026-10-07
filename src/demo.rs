use anyhow::{Context, Result, anyhow, bail};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    time::Duration,
};
use url::Url;

use crate::{
    config::Policy,
    crypto::{self, Jwks},
    http_message::Request,
    report::{Profile, Report},
    signature,
};

pub fn serve(
    jwks_path: &Path,
    policy: &Policy,
    bind: SocketAddr,
    allow_non_loopback: bool,
    max_requests: Option<usize>,
) -> Result<()> {
    if !allow_non_loopback && !bind.ip().is_loopback() {
        bail!("demo verifier binds to loopback by default; use --allow-non-loopback explicitly");
    }
    let keys = crypto::read_jwks(jwks_path)?;
    let listener = TcpListener::bind(bind).with_context(|| format!("binding {bind}"))?;
    println!("Botgate demo verifier listening on http://{bind}");
    println!("It returns X-Botgate-Authenticated: true only after crypto and policy checks pass.");
    for (handled, connection) in listener.incoming().enumerate() {
        match connection {
            Ok(mut stream) => {
                if let Err(error) = handle(&mut stream, &keys, policy) {
                    let _ = respond(&mut stream, 400, false, &format!("{error:#}"));
                }
            }
            Err(error) => eprintln!("botgate demo: accepting connection: {error}"),
        }
        if max_requests.is_some_and(|limit| handled + 1 >= limit) {
            break;
        }
    }
    Ok(())
}

fn handle(stream: &mut TcpStream, keys: &Jwks, policy: &Policy) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let bytes = read_request(stream)?;
    let request = Request::parse(&bytes)?;
    let parsed = signature::parse(&request)?;
    let host = request
        .header("host")
        .ok_or_else(|| anyhow!("Host header is required"))?;
    let context = Url::parse(&format!("http://{host}/")).context("invalid Host header")?;
    let report = Report::analyze(
        &request,
        &parsed,
        policy,
        Profile::IetfDraft00,
        Some(keys),
        false,
        Some(&context),
        false,
    );
    let accepted = !report.has_errors();
    respond(
        stream,
        if accepted { 200 } else { 401 },
        accepted,
        &report.text(),
    )
}

fn read_request(stream: &mut TcpStream) -> Result<Vec<u8>> {
    const MAX_HEADERS: usize = 64 * 1024;
    const MAX_BODY: usize = 1024 * 1024;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let size = stream.read(&mut buffer).context("reading request")?;
        if size == 0 {
            bail!("connection closed before request headers completed");
        }
        bytes.extend_from_slice(&buffer[..size]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        if bytes.len() > MAX_HEADERS {
            bail!("request headers exceed 65536 bytes");
        }
    };
    let headers =
        std::str::from_utf8(&bytes[..header_end]).context("request headers are not UTF-8")?;
    let content_length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>())
        .transpose()
        .context("invalid Content-Length")?
        .unwrap_or(0);
    if content_length > MAX_BODY {
        bail!("request body exceeds 1048576 bytes");
    }
    let total = header_end + content_length;
    while bytes.len() < total {
        let remaining = total - bytes.len();
        let capacity = remaining.min(buffer.len());
        let size = stream
            .read(&mut buffer[..capacity])
            .context("reading request body")?;
        if size == 0 {
            bail!("connection closed before request body completed");
        }
        bytes.extend_from_slice(&buffer[..size]);
    }
    bytes.truncate(total);
    Ok(bytes)
}

fn respond(stream: &mut TcpStream, status: u16, accepted: bool, body: &str) -> Result<()> {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        _ => "Bad Request",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nX-Botgate-Authenticated: {accepted}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body.as_bytes())?;
    stream.flush()?;
    Ok(())
}
