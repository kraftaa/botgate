use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use std::{fs, path::Path};
use url::{Host, Url};

#[derive(Debug, Clone, Serialize)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    #[serde(skip_serializing)]
    pub body: Vec<u8>,
}

impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let split = find_header_end(bytes)
            .ok_or_else(|| anyhow!("request has no blank line after headers"))?;
        let head = std::str::from_utf8(&bytes[..split])
            .context("request line and headers must be UTF-8/ASCII")?;
        let body_start = if bytes.get(split..split + 4) == Some(b"\r\n\r\n") {
            split + 4
        } else {
            split + 2
        };
        let mut lines = head.lines();
        let line = lines
            .next()
            .ok_or_else(|| anyhow!("missing request line"))?;
        let mut parts = line.trim_end_matches('\r').split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| anyhow!("missing method"))?
            .to_string();
        let target = parts
            .next()
            .ok_or_else(|| anyhow!("missing request target"))?
            .to_string();
        let version = parts
            .next()
            .ok_or_else(|| anyhow!("missing HTTP version"))?
            .to_string();
        if parts.next().is_some() || !matches!(version.as_str(), "HTTP/1.0" | "HTTP/1.1") {
            bail!("malformed request line");
        }
        if method.is_empty() || !method.bytes().all(is_token_char) {
            bail!("invalid HTTP method");
        }
        if target.is_empty()
            || !target
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'#')
        {
            bail!("invalid HTTP request target");
        }
        if let Ok(url) = Url::parse(&target)
            && (!url.username().is_empty() || url.password().is_some() || url.fragment().is_some())
        {
            bail!("absolute request target contains forbidden URI components");
        }
        let mut headers = Vec::new();
        for raw in lines {
            let line = raw.trim_end_matches('\r');
            if line.starts_with(' ') || line.starts_with('\t') {
                bail!("obsolete folded headers are not accepted");
            }
            let (name, value) = line
                .split_once(':')
                // Debug formatting escapes control bytes so hostile input cannot drive the terminal.
                .ok_or_else(|| anyhow!("malformed header: {line:?}"))?;
            if name.is_empty() || !name.bytes().all(is_token_char) {
                bail!("invalid header name: {name:?}");
            }
            let value = trim_ows(value);
            if !value
                .bytes()
                .all(|byte| byte == b'\t' || (b' '..=b'~').contains(&byte))
            {
                bail!("invalid control or non-ASCII byte in header {name}");
            }
            headers.push((name.to_ascii_lowercase(), value.to_string()));
        }
        Ok(Self {
            method,
            target,
            version,
            headers,
            body: bytes[body_start..].to_vec(),
        })
    }

    pub fn header(&self, name: &str) -> Option<String> {
        let values: Vec<&str> = self
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect();
        (!values.is_empty()).then(|| values.join(", "))
    }

    pub fn remove_header(&mut self, name: &str) {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
    }

    pub fn set_header(&mut self, name: &str, value: String) {
        self.remove_header(name);
        self.headers.push((name.to_ascii_lowercase(), value));
    }

    pub fn authority(&self, context: Option<&Url>) -> Result<String> {
        if let Ok(url) = Url::parse(&self.target) {
            return authority_from_url(&url);
        }
        if let Some(host) = self.header("host") {
            if (host.ends_with(":80") || host.ends_with(":443")) && context.is_none() {
                bail!(
                    "cannot normalize a possibly default authority port without --context scheme"
                );
            }
            if let Some(context) = context {
                let parsed = Url::parse(&format!("{}://{host}/", context.scheme()))?;
                if !parsed.username().is_empty()
                    || parsed.password().is_some()
                    || parsed.path() != "/"
                    || parsed.query().is_some()
                    || parsed.fragment().is_some()
                {
                    bail!("Host is not a valid authority");
                }
                return authority_from_url(&parsed);
            }
            let parsed = Url::parse(&format!("botgate://{host}/"))?;
            if !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.path() != "/"
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                bail!("Host is not a valid authority");
            }
            return authority_from_url(&parsed);
        }
        if let Some(url) = context {
            return authority_from_url(url);
        }
        bail!("cannot derive @authority: provide Host or --context")
    }

    pub fn scheme(&self, context: Option<&Url>) -> Result<String> {
        if let Ok(url) = Url::parse(&self.target) {
            return Ok(url.scheme().to_ascii_lowercase());
        }
        context
            .map(|u| u.scheme().to_ascii_lowercase())
            .ok_or_else(|| anyhow!("cannot derive @scheme without an absolute target or --context"))
    }

    pub fn path(&self) -> Result<String> {
        if let Ok(url) = Url::parse(&self.target) {
            return Ok(if url.path().is_empty() {
                "/"
            } else {
                url.path()
            }
            .to_string());
        }
        let path = self
            .target
            .split_once('?')
            .map_or(self.target.as_str(), |(p, _)| p);
        if !path.starts_with('/') {
            bail!("unsupported request-target form: {}", self.target);
        }
        Ok(path.to_string())
    }

    pub fn query(&self) -> Result<String> {
        if let Ok(url) = Url::parse(&self.target) {
            return Ok(url
                .query()
                .map_or_else(|| "?".to_string(), |q| format!("?{q}")));
        }
        Ok(self
            .target
            .split_once('?')
            .map_or_else(|| "?".to_string(), |(_, q)| format!("?{q}")))
    }

    pub fn target_uri(&self, context: Option<&Url>) -> Result<String> {
        if let Ok(url) = Url::parse(&self.target) {
            return Ok(url.to_string());
        }
        let scheme = self.scheme(context)?;
        let authority = self.authority(context)?;
        Ok(format!("{scheme}://{authority}{}", self.target))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = format!("{} {} {}\r\n", self.method, self.target, self.version).into_bytes();
        for (name, value) in &self.headers {
            let pretty = name
                .split('-')
                .map(|s| {
                    let mut chars = s.chars();
                    chars
                        .next()
                        .map(|c| c.to_ascii_uppercase().to_string() + chars.as_str())
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>()
                .join("-");
            out.extend_from_slice(format!("{pretty}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .or_else(|| bytes.windows(2).position(|w| w == b"\n\n"))
}

fn trim_ows(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}
fn is_token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}
fn authority_from_url(url: &Url) -> Result<String> {
    let host = match url.host().ok_or_else(|| anyhow!("URL has no host"))? {
        Host::Domain(host) => host.to_ascii_lowercase(),
        Host::Ipv4(host) => host.to_string(),
        Host::Ipv6(host) => format!("[{host}]"),
    };
    Ok(match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_request_and_context() {
        let req =
            Request::parse(b"POST /a?x=1 HTTP/1.1\r\nHost: EXAMPLE.com\r\nX-A: b\r\n\r\nbody")
                .unwrap();
        assert_eq!(req.authority(None).unwrap(), "example.com");
        assert_eq!(req.path().unwrap(), "/a");
        assert_eq!(req.query().unwrap(), "?x=1");
        assert_eq!(req.body, b"body");
    }

    #[test]
    fn default_port_requires_scheme_context() {
        let req = Request::parse(b"GET / HTTP/1.1\r\nHost: EXAMPLE.com:443\r\n\r\n").unwrap();
        assert!(req.authority(None).is_err());
        let context = Url::parse("https://example.com/").unwrap();
        assert_eq!(req.authority(Some(&context)).unwrap(), "example.com");
    }

    #[test]
    fn preserves_ipv6_brackets_and_rejects_invalid_host_authorities() {
        let absolute = Request::parse(
            b"GET https://[2001:db8::1]:8443/a HTTP/1.1\r\nHost: ignored.test\r\n\r\n",
        )
        .unwrap();
        assert_eq!(absolute.authority(None).unwrap(), "[2001:db8::1]:8443");

        let invalid = Request::parse(b"GET / HTTP/1.1\r\nHost: user@example.test\r\n\r\n").unwrap();
        let context = Url::parse("https://example.test/").unwrap();
        assert!(invalid.authority(Some(&context)).is_err());
        assert!(invalid.authority(None).is_err());
    }

    #[test]
    fn rejects_malformed_http_control_data() {
        assert!(Request::parse(b"GET / HTTP/2\r\nHost: example.test\r\n\r\n").is_err());
        assert!(Request::parse(b"GE(T / HTTP/1.1\r\nHost: example.test\r\n\r\n").is_err());
        assert!(Request::parse(b"GET /#fragment HTTP/1.1\r\nHost: example.test\r\n\r\n").is_err());
        assert!(Request::parse(b"GET / HTTP/1.1\r\nX-Test: bad\0value\r\n\r\n").is_err());
    }
}
