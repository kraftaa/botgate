use anyhow::{Context, Result, bail};
use std::{
    fs,
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    path::Path,
    time::Duration,
};

use crate::crypto::{self, Jwks};

pub const WELL_KNOWN_PATH: &str = "/.well-known/http-message-signatures-directory";
pub const MEDIA_TYPE: &str = "application/http-message-signatures-directory+json";

pub fn serve(path: &Path, bind: SocketAddr, allow_non_loopback: bool, once: bool) -> Result<()> {
    if !allow_non_loopback && !bind.ip().is_loopback() {
        bail!("directory server binds to loopback by default; use --allow-non-loopback explicitly");
    }
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    validate_directory(&bytes)?;
    let listener = TcpListener::bind(bind).with_context(|| format!("binding {bind}"))?;
    println!(
        "Serving {} at http://{bind}{WELL_KNOWN_PATH}",
        path.display()
    );
    println!(
        "This built-in server is for local testing; conformant public discovery requires HTTPS."
    );
    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                if let Err(error) = handle(&mut stream, &bytes) {
                    eprintln!("botgate directory: {error:#}");
                }
            }
            Err(error) => eprintln!("botgate directory: accepting connection: {error}"),
        }
        if once {
            break;
        }
    }
    Ok(())
}

pub fn validate_directory(bytes: &[u8]) -> Result<Jwks> {
    validate_jwks(bytes, true)
}

pub fn validate_jwks(bytes: &[u8], enforce_thumbprint_kid: bool) -> Result<Jwks> {
    let keys: Jwks = serde_json::from_slice(bytes).context("parsing directory JWKS")?;
    if keys.keys.is_empty() {
        bail!("directory contains no keys");
    }
    if keys.keys.len() > 64 {
        bail!("directory contains more than 64 keys");
    }
    for key in &keys.keys {
        let thumbprint = crypto::thumbprint(key)?;
        if enforce_thumbprint_kid {
            if let Some(kid) = &key.kid {
                if kid != &thumbprint {
                    bail!("directory key kid does not match its JWK thumbprint");
                }
            }
        }
        if key.r#use.as_deref().is_some_and(|value| value != "sig") {
            bail!("directory key use must be sig when present");
        }
    }
    Ok(keys)
}

fn handle(stream: &mut TcpStream, directory: &[u8]) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut request = [0_u8; 16 * 1024];
    let size = stream.read(&mut request).context("reading request")?;
    if size == request.len() {
        return respond(
            stream,
            431,
            "Request Header Fields Too Large",
            "text/plain",
            b"",
            true,
        );
    }
    let head = std::str::from_utf8(&request[..size]).context("request headers are not UTF-8")?;
    let line = head
        .lines()
        .next()
        .unwrap_or_default()
        .trim_end_matches('\r');
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    if !matches!(method, "GET" | "HEAD") {
        return respond(stream, 405, "Method Not Allowed", "text/plain", b"", true);
    }
    if path != WELL_KNOWN_PATH {
        return respond(stream, 404, "Not Found", "text/plain", b"", true);
    }
    respond(stream, 200, "OK", MEDIA_TYPE, directory, method != "HEAD")
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
    include_body: bool,
) -> Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    if include_body {
        stream.write_all(body)?;
    }
    stream.flush()?;
    Ok(())
}

pub fn parse_bind(host: &str, port: u16) -> Result<SocketAddr> {
    let ip: IpAddr = host.parse().context("--bind must be an IP address")?;
    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_thumbprint_kid() {
        let bytes = br#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kid":"wrong"}]}"#;
        assert!(validate_directory(bytes).is_err());
    }
}
