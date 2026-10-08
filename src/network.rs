use anyhow::{Context, Result, anyhow, bail};
use reqwest::{Method, blocking::Client, header::HeaderMap, redirect::Policy};
use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    time::Duration,
};
use url::Url;

use crate::http_message::Request;

#[derive(Debug, Clone)]
pub struct NetworkPolicy {
    pub allow_private: bool,
    pub allow_http: bool,
    pub timeout: Duration,
    pub max_response_bytes: usize,
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

pub fn send_request(
    target: &Url,
    request: &Request,
    policy: &NetworkPolicy,
) -> Result<HttpResponse> {
    let client = client_for(target, policy)?;
    let method = Method::from_bytes(request.method.as_bytes()).context("invalid HTTP method")?;
    let mut builder = client.request(method, target.clone());
    for (name, value) in &request.headers {
        if matches!(
            name.as_str(),
            "content-length"
                | "connection"
                | "transfer-encoding"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "keep-alive"
                | "te"
                | "trailer"
                | "upgrade"
        ) {
            continue;
        }
        builder = builder.header(name, value);
    }
    let response = builder
        .body(request.body.clone())
        .send()
        .with_context(|| format!("sending request to {target}"))?;
    collect(response, policy.max_response_bytes)
}

pub fn get(target: &Url, accept: &str, policy: &NetworkPolicy) -> Result<HttpResponse> {
    let response = client_for(target, policy)?
        .get(target.clone())
        .header("accept", accept)
        .send()
        .with_context(|| format!("fetching {target}"))?;
    collect(response, policy.max_response_bytes)
}

fn collect(mut response: reqwest::blocking::Response, limit: usize) -> Result<HttpResponse> {
    if let Some(length) = response.content_length() {
        if length > limit as u64 {
            bail!("response Content-Length {length} exceeds byte limit {limit}");
        }
    }
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let mut body = Vec::new();
    response
        .by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut body)
        .context("reading HTTP response")?;
    if body.len() > limit {
        bail!("response exceeds byte limit {limit}");
    }
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn client_for(target: &Url, policy: &NetworkPolicy) -> Result<Client> {
    validate_url(target, policy.allow_http)?;
    let host = target
        .host_str()
        .ok_or_else(|| anyhow!("URL has no host"))?;
    let port = target
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL has no known port"))?;
    // IP literals are used as-is; `host_str()` would keep IPv6 brackets, which the resolver rejects.
    let domain = match target.host() {
        Some(url::Host::Domain(domain)) => Some(domain),
        _ => None,
    };
    let addresses: Vec<SocketAddr> = match target.host() {
        Some(url::Host::Ipv4(ip)) => vec![SocketAddr::new(ip.into(), port)],
        Some(url::Host::Ipv6(ip)) => vec![SocketAddr::new(ip.into(), port)],
        _ => (host, port)
            .to_socket_addrs()
            .with_context(|| format!("resolving {host}"))?
            .collect(),
    };
    if addresses.is_empty() {
        bail!("{host} resolved to no addresses");
    }
    for address in &addresses {
        if !policy.allow_private && !is_public(address.ip()) {
            bail!(
                "refusing non-public address {} for {host}; use the explicit private-network override only for an authorized test target",
                address.ip()
            );
        }
    }
    let mut builder = Client::builder()
        .timeout(policy.timeout)
        .redirect(Policy::none())
        .no_proxy();
    // Pin the validated resolution so a second lookup cannot redirect the connection.
    if let Some(domain) = domain {
        for address in addresses {
            builder = builder.resolve(domain, address);
        }
    }
    builder.build().context("building HTTP client")
}

fn validate_url(url: &Url, allow_http: bool) -> Result<()> {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        bail!("URL credentials and fragments are not allowed");
    }
    match url.scheme() {
        "https" => {}
        "http" if allow_http => {}
        "http" => {
            bail!("plain HTTP is disabled; use the explicit HTTP override only for local tests")
        }
        scheme => bail!("unsupported URL scheme {scheme}; only https is allowed"),
    }
    Ok(())
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => public_v6(ip),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || octets[0] == 0
        || octets[0] >= 240
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)))
}

fn public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    let segments = ip.segments();
    let embedded = |high: u16, low: u16| Ipv4Addr::from((u32::from(high) << 16) | u32::from(low));
    // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) reach the IPv4 address they embed.
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return public_v4(embedded(segments[6], segments[7]));
    }
    if segments[0] == 0x2002 {
        return public_v4(embedded(segments[1], segments[2]));
    }
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // Deprecated IPv4-compatible ::a.b.c.d.
        || segments[..6] == [0; 6]
        // NAT64 local-use prefix 64:ff9b:1::/48.
        || segments[..3] == [0x64, 0xff9b, 1]
        // Teredo 2001::/32 tunnels to an arbitrary IPv4 address.
        || segments[..2] == [0x2001, 0]
        // Benchmarking 2001:2::/48.
        || segments[..3] == [0x2001, 2, 0]
        // Discard-only 100::/64.
        || segments[..4] == [0x100, 0, 0, 0]
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        // Deprecated site-local fec0::/10.
        || (segments[0] & 0xffc0) == 0xfec0
        || segments[..2] == [0x2001, 0x0db8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_internal_and_special_addresses() {
        for value in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.2.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::1",
            "2002:7f00:1::",
            "2002:a00:1::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001:2::1",
            "100::1",
            "fec0::1",
        ] {
            assert!(!is_public(value.parse().unwrap()), "{value}");
        }
        assert!(is_public("8.8.8.8".parse().unwrap()));
        assert!(is_public("2606:4700:4700::1111".parse().unwrap()));
        // Embedded public IPv4 addresses stay reachable.
        assert!(is_public("64:ff9b::808:808".parse().unwrap()));
        assert!(is_public("2002:808:808::".parse().unwrap()));
    }
}
