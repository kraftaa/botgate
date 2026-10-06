use crate::http_message::Request;
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoveredComponent {
    pub name: String,
    pub params: Vec<(String, Value)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Value {
    String(String),
    Integer(i64),
    Decimal(String),
    Token(String),
    ByteSequence(Vec<u8>),
    Boolean(bool),
    InnerList(Vec<ParameterizedItem>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParameterizedItem {
    pub value: Value,
    pub params: Vec<(String, Value)>,
}

type DictionaryMember = (String, Value, Vec<(String, Value)>);

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) | Self::Token(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_string(&self) -> Option<&str> {
        if let Self::String(value) = self {
            Some(value)
        } else {
            None
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        if let Self::Integer(n) = self {
            Some(*n)
        } else {
            None
        }
    }
    fn serialize(&self) -> String {
        match self {
            Self::String(s) => quote(s),
            Self::Integer(n) => n.to_string(),
            Self::Decimal(n) => n.clone(),
            Self::Token(s) => s.clone(),
            Self::ByteSequence(bytes) => format!(":{}:", STANDARD.encode(bytes)),
            Self::Boolean(true) => "?1".into(),
            Self::Boolean(false) => "?0".into(),
            Self::InnerList(items) => format!(
                "({})",
                items
                    .iter()
                    .map(|item| {
                        let params = item
                            .params
                            .iter()
                            .map(|(name, value)| serialize_param(name, value))
                            .collect::<String>();
                        format!("{}{params}", item.value.serialize())
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SignatureInput {
    pub label: String,
    pub components: Vec<CoveredComponent>,
    pub params: Vec<(String, Value)>,
}

impl SignatureInput {
    pub fn param(&self, name: &str) -> Option<&Value> {
        self.params.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }
    /// True when `name` is covered as a whole, with no parameters that narrow or reinterpret it.
    pub fn covers(&self, name: &str) -> bool {
        self.components
            .iter()
            .any(|c| c.name.eq_ignore_ascii_case(name) && c.params.is_empty())
    }
    /// True when only the dictionary member `key` of field `name` is covered.
    pub fn covers_member(&self, name: &str, key: &str) -> bool {
        self.components.iter().any(|c| {
            c.name.eq_ignore_ascii_case(name)
                && matches!(c.params.as_slice(), [(param, value)] if param == "key" && value.as_string() == Some(key))
        })
    }
    /// True when `name` is covered in any form, including with parameters.
    pub fn mentions(&self, name: &str) -> bool {
        self.components
            .iter()
            .any(|c| c.name.eq_ignore_ascii_case(name))
    }
    pub fn canonical_value(&self) -> String {
        let items = self
            .components
            .iter()
            .map(component_identifier)
            .collect::<Vec<_>>()
            .join(" ");
        let params = self
            .params
            .iter()
            .map(|(name, value)| serialize_param(name, value))
            .collect::<String>();
        format!("({items}){params}")
    }
}

#[derive(Debug, Clone)]
pub struct ParsedSignatures {
    pub inputs: Vec<SignatureInput>,
    pub signatures: BTreeMap<String, Vec<u8>>,
}

pub fn parse(request: &Request) -> Result<ParsedSignatures> {
    let input_header = request.header("signature-input").unwrap_or_default();
    let signature_header = request.header("signature").unwrap_or_default();
    let mut inputs = Vec::new();
    let mut input_labels = BTreeSet::new();
    if !input_header.is_empty() {
        for member in split_top_level(&input_header, ',')? {
            let (label, value) = member
                .split_once('=')
                .ok_or_else(|| anyhow!("invalid Signature-Input dictionary member"))?;
            let label = label.trim();
            if !input_labels.insert(label.to_string()) {
                bail!("duplicate Signature-Input label {label}");
            }
            inputs.push(parse_input(label, value.trim())?);
        }
    }
    let mut signatures = BTreeMap::new();
    if !signature_header.is_empty() {
        for member in split_top_level(&signature_header, ',')? {
            let (label, value) = member
                .split_once('=')
                .ok_or_else(|| anyhow!("invalid Signature dictionary member"))?;
            let label = label.trim();
            validate_label(label)?;
            let encoded = value
                .trim()
                .strip_prefix(':')
                .and_then(|s| s.strip_suffix(':'))
                .ok_or_else(|| anyhow!("Signature value for {label} is not a byte sequence"))?;
            let bytes = STANDARD
                .decode(encoded)
                .context("invalid base64 signature")?;
            if signatures.insert(label.to_string(), bytes).is_some() {
                bail!("duplicate Signature label {label}");
            }
        }
    }
    Ok(ParsedSignatures { inputs, signatures })
}

fn parse_input(label: &str, value: &str) -> Result<SignatureInput> {
    validate_label(label)?;
    let close = matching_paren(value)?;
    let inner = &value[1..close];
    let mut components = Vec::new();
    let mut cursor = Cursor::new(inner);
    while cursor.skip_ows() {
        let name = cursor.string()?;
        let params = cursor.params()?;
        components.push(CoveredComponent {
            name: name.to_ascii_lowercase(),
            params,
        });
    }
    if components.is_empty() {
        bail!("Signature-Input {label} covers no components");
    }
    let mut tail = Cursor::new(&value[close + 1..]);
    let params = tail.params()?;
    tail.skip_ows();
    if !tail.done() {
        bail!("trailing data in Signature-Input {label}");
    }
    let mut identifiers = BTreeSet::new();
    for component in &components {
        let mut params = component.params.clone();
        params.sort_by(|a, b| a.0.cmp(&b.0));
        let normalized = format!(
            "{}|{}",
            component.name,
            params
                .iter()
                .map(|(name, value)| format!("{name}={}", value.serialize()))
                .collect::<Vec<_>>()
                .join(";")
        );
        if !identifiers.insert(normalized) {
            bail!(
                "duplicate covered component {}",
                component_identifier(component)
            );
        }
    }
    Ok(SignatureInput {
        label: label.to_string(),
        components,
        params,
    })
}

pub fn signature_base(
    request: &Request,
    input: &SignatureInput,
    context: Option<&Url>,
) -> Result<String> {
    let mut lines = Vec::new();
    for component in &input.components {
        let id = component_identifier(component);
        let value = component_value(request, component, context)
            .with_context(|| format!("resolving covered component {id}"))?;
        if value.contains(['\r', '\n']) {
            bail!("component value contains a newline");
        }
        lines.push(format!("{id}: {value}"));
    }
    lines.push(format!(
        "\"@signature-params\": {}",
        input.canonical_value()
    ));
    Ok(lines.join("\n"))
}

pub fn component_identifier(c: &CoveredComponent) -> String {
    let mut out = quote(&c.name);
    for (name, value) in &c.params {
        out.push_str(&serialize_param(name, value));
    }
    out
}

fn component_value(
    request: &Request,
    component: &CoveredComponent,
    context: Option<&Url>,
) -> Result<String> {
    if component.params.iter().any(|(name, _)| name == "req") {
        bail!("req components require a response signature context, but the input is a request");
    }
    if component.name.starts_with('@') {
        let allowed = if component.name == "@query-param" {
            &["name"][..]
        } else {
            &[][..]
        };
        reject_params(component, allowed)?;
    }
    match component.name.as_str() {
        "@method" => Ok(request.method.clone()),
        "@authority" => request.authority(context),
        "@scheme" => request.scheme(context),
        "@path" => request.path(),
        "@query" => request.query(),
        "@target-uri" => request.target_uri(context),
        "@request-target" => Ok(request.target.clone()),
        "@query-param" => query_param(request, component),
        name if name.starts_with('@') => bail!("unsupported derived component {name}"),
        name => {
            reject_params(component, &["key"])?;
            let raw = request
                .header(name)
                .ok_or_else(|| anyhow!("covered header {name} is absent"))?;
            if component.params.iter().any(|(name, _)| name == "key") {
                let key = param_string(component, "key")
                    .ok_or_else(|| anyhow!("key parameter must be a string"))?;
                dictionary_value(&raw, key)
            } else {
                Ok(raw)
            }
        }
    }
}

fn query_param(request: &Request, component: &CoveredComponent) -> Result<String> {
    let wanted =
        param_string(component, "name").ok_or_else(|| anyhow!("@query-param requires name"))?;
    let decoded_wanted = url::form_urlencoded::parse(format!("{wanted}=").as_bytes())
        .next()
        .map(|(key, _)| key.into_owned())
        .ok_or_else(|| anyhow!("invalid @query-param name"))?;
    let query = request.query()?;
    let values: Vec<String> = url::form_urlencoded::parse(query.trim_start_matches('?').as_bytes())
        .filter(|(key, _)| key.as_ref() == decoded_wanted)
        .map(|(_, v)| v.into_owned())
        .collect();
    if values.is_empty() {
        bail!("query parameter {wanted} is absent");
    }
    if values.len() > 1 {
        bail!("query parameter {wanted} occurs more than once and cannot be covered safely");
    }
    Ok(form_encode(&values[0]))
}

fn form_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"*-._".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[(byte >> 4) as usize]));
            out.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
    out
}

fn dictionary_value(raw: &str, key: &str) -> Result<String> {
    let mut seen = BTreeSet::new();
    let mut selected = None;
    for member in split_top_level(raw, ',')? {
        let (member_key, value, params) = parse_dictionary_member(member)?;
        if !seen.insert(member_key.clone()) {
            bail!("duplicate dictionary key {member_key}");
        }
        if member_key == key {
            let suffix = params
                .iter()
                .map(|(name, value)| serialize_param(name, value))
                .collect::<String>();
            selected = Some(format!("{}{suffix}", value.serialize()));
        }
    }
    selected.ok_or_else(|| anyhow!("dictionary key {key} is absent"))
}

pub fn dictionary_string_member(raw: &str, key: &str) -> Result<String> {
    let mut seen = BTreeSet::new();
    let mut selected = None;
    for member in split_top_level(raw, ',')? {
        let (member_key, value, _) = parse_dictionary_member(member)?;
        if !seen.insert(member_key.clone()) {
            bail!("duplicate dictionary key {member_key}");
        }
        if member_key == key {
            let result = match value {
                Value::String(value) => value,
                _ => bail!("dictionary member {key} is not a string"),
            };
            selected = Some(result);
        }
    }
    selected.ok_or_else(|| anyhow!("dictionary key {key} is absent"))
}

pub fn dictionary_byte_sequence_member(raw: &str, key: &str) -> Result<Vec<u8>> {
    let mut seen = BTreeSet::new();
    let mut selected = None;
    for member in split_top_level(raw, ',')? {
        let (member_key, value, _) = parse_dictionary_member(member)?;
        if !seen.insert(member_key.clone()) {
            bail!("duplicate dictionary key {member_key}");
        }
        if member_key == key {
            selected = Some(match value {
                Value::ByteSequence(bytes) => bytes,
                _ => bail!("dictionary member {key} is not a byte sequence"),
            });
        }
    }
    selected.ok_or_else(|| anyhow!("dictionary key {key} is absent"))
}

fn parse_dictionary_member(member: &str) -> Result<DictionaryMember> {
    let mut cursor = Cursor::new(member.trim());
    let key = cursor.key()?;
    let value = if cursor.s.as_bytes().get(cursor.pos) == Some(&b'=') {
        cursor.pos += 1;
        cursor.value()?
    } else {
        Value::Boolean(true)
    };
    let params = cursor.params()?;
    cursor.skip_ows();
    if !cursor.done() {
        bail!("trailing data in dictionary member {key}");
    }
    Ok((key, value, params))
}

pub fn parse_string_item(raw: &str) -> Result<String> {
    let mut cursor = Cursor::new(raw);
    let value = match cursor.value()? {
        Value::String(value) => value,
        _ => bail!("value is not a structured field string"),
    };
    cursor.params()?;
    cursor.skip_ows();
    if !cursor.done() {
        bail!("trailing data after structured field string");
    }
    Ok(value)
}

fn reject_params(component: &CoveredComponent, allowed: &[&str]) -> Result<()> {
    for (name, _) in &component.params {
        if !allowed.contains(&name.as_str()) {
            bail!("unsupported parameter {name} on {}", component.name);
        }
    }
    Ok(())
}

fn param_string<'a>(component: &'a CoveredComponent, name: &str) -> Option<&'a str> {
    component
        .params
        .iter()
        .find(|(n, _)| n == name)
        .and_then(|(_, v)| v.as_string())
}

pub fn split_top_level(s: &str, delimiter: char) -> Result<Vec<&str>> {
    let mut result = Vec::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut depth = 0i32;
    let mut start = 0;
    for (i, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            quoted = !quoted;
            continue;
        }
        if !quoted {
            if ch == '(' {
                depth += 1;
            }
            if ch == ')' {
                depth -= 1;
                if depth < 0 {
                    bail!("unbalanced parentheses");
                }
            }
            if ch == delimiter && depth == 0 {
                result.push(s[start..i].trim());
                start = i + ch.len_utf8();
            }
        }
    }
    if quoted || depth != 0 {
        bail!("unterminated structured field value");
    }
    result.push(s[start..].trim());
    Ok(result)
}

fn matching_paren(s: &str) -> Result<usize> {
    if !s.starts_with('(') {
        bail!("Signature-Input value must be an inner list");
    }
    let mut quoted = false;
    let mut escaped = false;
    for (i, ch) in s.char_indices().skip(1) {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            quoted = !quoted;
        } else if ch == ')' && !quoted {
            return Ok(i);
        }
    }
    bail!("unterminated Signature-Input inner list")
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
fn serialize_param(name: &str, value: &Value) -> String {
    if matches!(value, Value::Boolean(true)) {
        format!(";{name}")
    } else {
        format!(";{name}={}", value.serialize())
    }
}
pub fn validate_label(value: &str) -> Result<()> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        bail!("empty structured field dictionary key")
    };
    if !(first.is_ascii_lowercase() || first == b'*')
        || !bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.*-".contains(&b))
    {
        bail!("invalid structured field dictionary key: {value}")
    }
    Ok(())
}

struct Cursor<'a> {
    s: &'a str,
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn new(s: &'a str) -> Self {
        Self { s, pos: 0 }
    }
    fn done(&self) -> bool {
        self.pos >= self.s.len()
    }
    fn skip_ows(&mut self) -> bool {
        while self.pos < self.s.len() && matches!(self.s.as_bytes()[self.pos], b' ' | b'\t') {
            self.pos += 1;
        }
        !self.done()
    }
    fn string(&mut self) -> Result<String> {
        if self.s.as_bytes().get(self.pos) != Some(&b'"') {
            bail!("covered component must be a string");
        }
        self.pos += 1;
        let mut out = String::new();
        let mut escaped = false;
        while self.pos < self.s.len() {
            let ch = self.s[self.pos..].chars().next().unwrap();
            self.pos += ch.len_utf8();
            if escaped {
                if ch != '\\' && ch != '"' {
                    bail!("invalid escape in structured field string");
                }
                out.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                return Ok(out);
            } else {
                if !ch.is_ascii() || !((' '..='~').contains(&ch)) {
                    bail!("invalid character in structured field string");
                }
                out.push(ch);
            }
        }
        bail!("unterminated string")
    }
    fn params(&mut self) -> Result<Vec<(String, Value)>> {
        let mut out = Vec::new();
        loop {
            if self.s.as_bytes().get(self.pos) != Some(&b';') {
                break;
            }
            self.pos += 1;
            let name = self.token()?;
            validate_label(&name)?;
            if out.iter().any(|(existing, _)| existing == &name) {
                bail!("duplicate parameter {name}");
            }
            let value = if self.s.as_bytes().get(self.pos) == Some(&b'=') {
                self.pos += 1;
                self.value()?
            } else {
                Value::Boolean(true)
            };
            out.push((name, value));
        }
        Ok(out)
    }
    fn token(&mut self) -> Result<String> {
        let start = self.pos;
        let Some(first) = self.s.as_bytes().get(self.pos).copied() else {
            bail!("expected token");
        };
        if !(first.is_ascii_alphabetic() || first == b'*') {
            bail!("invalid token start");
        }
        self.pos += 1;
        while self.pos < self.s.len() {
            let b = self.s.as_bytes()[self.pos];
            if b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~:/".contains(&b) {
                self.pos += 1;
            } else {
                break;
            }
        }
        Ok(self.s[start..self.pos].to_string())
    }
    fn key(&mut self) -> Result<String> {
        let start = self.pos;
        while self.pos < self.s.len() {
            let b = self.s.as_bytes()[self.pos];
            if b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.*-".contains(&b) {
                self.pos += 1;
            } else {
                break;
            }
        }
        let key = &self.s[start..self.pos];
        validate_label(key)?;
        Ok(key.to_string())
    }
    fn value(&mut self) -> Result<Value> {
        match self.s.as_bytes().get(self.pos) {
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b':') => {
                self.pos += 1;
                let start = self.pos;
                while self.s.as_bytes().get(self.pos) != Some(&b':') {
                    if self.done() {
                        bail!("unterminated byte sequence");
                    }
                    self.pos += 1;
                }
                let encoded = &self.s[start..self.pos];
                self.pos += 1;
                Ok(Value::ByteSequence(
                    STANDARD
                        .decode(encoded)
                        .context("invalid base64 byte sequence")?,
                ))
            }
            Some(b'(') => self.inner_list(),
            Some(b'?') => {
                self.pos += 1;
                match self.s.as_bytes().get(self.pos) {
                    Some(b'1') => {
                        self.pos += 1;
                        Ok(Value::Boolean(true))
                    }
                    Some(b'0') => {
                        self.pos += 1;
                        Ok(Value::Boolean(false))
                    }
                    _ => bail!("invalid boolean"),
                }
            }
            Some(b'-' | b'0'..=b'9') => {
                let start = self.pos;
                self.pos += 1;
                while self
                    .s
                    .as_bytes()
                    .get(self.pos)
                    .is_some_and(u8::is_ascii_digit)
                {
                    self.pos += 1;
                }
                if self.s.as_bytes().get(self.pos) == Some(&b'.') {
                    self.pos += 1;
                    let fraction_start = self.pos;
                    while self
                        .s
                        .as_bytes()
                        .get(self.pos)
                        .is_some_and(u8::is_ascii_digit)
                    {
                        self.pos += 1;
                    }
                    let raw = &self.s[start..self.pos];
                    let integer = raw
                        .strip_prefix('-')
                        .unwrap_or(raw)
                        .split_once('.')
                        .unwrap()
                        .0;
                    let fraction = &self.s[fraction_start..self.pos];
                    if integer.is_empty()
                        || integer.len() > 12
                        || fraction.is_empty()
                        || fraction.len() > 3
                    {
                        bail!("structured field decimal is out of range");
                    }
                    let negative = raw.starts_with('-');
                    let unsigned = raw.strip_prefix('-').unwrap_or(raw);
                    let (integer, fraction) = unsigned.split_once('.').unwrap();
                    let integer: u64 = integer.parse()?;
                    let fraction = fraction.trim_end_matches('0');
                    let fraction = if fraction.is_empty() { "0" } else { fraction };
                    let negative =
                        negative && (integer != 0 || fraction.bytes().any(|byte| byte != b'0'));
                    let canonical =
                        format!("{}{integer}.{fraction}", if negative { "-" } else { "" });
                    return Ok(Value::Decimal(canonical));
                }
                let raw = &self.s[start..self.pos];
                let digits = raw.strip_prefix('-').unwrap_or(raw);
                if digits.is_empty() || digits.len() > 15 {
                    bail!("structured field integer exceeds the 15-digit limit");
                }
                let value: i64 = raw.parse()?;
                if !(-999_999_999_999_999..=999_999_999_999_999).contains(&value) {
                    bail!("structured field integer is out of range");
                }
                Ok(Value::Integer(value))
            }
            Some(_) => Ok(Value::Token(self.token()?)),
            None => bail!("missing parameter value"),
        }
    }

    fn inner_list(&mut self) -> Result<Value> {
        self.pos += 1;
        let mut items = Vec::new();
        loop {
            while self.s.as_bytes().get(self.pos) == Some(&b' ') {
                self.pos += 1;
            }
            if self.s.as_bytes().get(self.pos) == Some(&b')') {
                self.pos += 1;
                return Ok(Value::InnerList(items));
            }
            if self.done() {
                bail!("unterminated inner list");
            }
            let value = self.value()?;
            if matches!(value, Value::InnerList(_)) {
                bail!("nested inner lists are invalid");
            }
            let params = self.params()?;
            items.push(ParameterizedItem { value, params });
            match self.s.as_bytes().get(self.pos) {
                Some(b' ') | Some(b')') => {}
                _ => bail!("inner-list items must be separated by spaces"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_current_signature_input() {
        let i = parse_input("sig1", r#"("@authority" "signature-agent";key="sig1");created=1;expires=2;keyid="abc";tag="web-bot-auth""#).unwrap();
        assert_eq!(i.components.len(), 2);
        assert_eq!(
            i.canonical_value(),
            r#"("@authority" "signature-agent";key="sig1");created=1;expires=2;keyid="abc";tag="web-bot-auth""#
        );
    }

    #[test]
    fn query_param_is_decoded_then_canonically_encoded() {
        let request = Request::parse(
            b"GET /?bar=with+plus+whitespace HTTP/1.1\r\nHost: example.test\r\n\r\n",
        )
        .unwrap();
        let component = CoveredComponent {
            name: "@query-param".into(),
            params: vec![("name".into(), Value::String("bar".into()))],
        };
        assert_eq!(
            query_param(&request, &component).unwrap(),
            "with%20plus%20whitespace"
        );
    }

    #[test]
    fn matches_rfc_9421_encoded_query_parameter_examples() {
        let request = Request::parse(
            concat!(
                "GET /parameters?var=this%20is%20a%20big%0Amultiline%20value&",
                "bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something HTTP/1.1\r\n",
                "Host: example.test\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        for (name, expected) in [
            ("var", "this%20is%20a%20big%0Amultiline%20value"),
            ("bar", "with%20plus%20whitespace"),
            ("fa%C3%A7ade%22%3A%20", "something"),
        ] {
            let component = CoveredComponent {
                name: "@query-param".into(),
                params: vec![("name".into(), Value::String(name.into()))],
            };
            assert_eq!(query_param(&request, &component).unwrap(), expected);
        }
    }

    #[test]
    fn duplicate_query_param_is_rejected() {
        let request =
            Request::parse(b"GET /?x=one&x=two HTTP/1.1\r\nHost: example.test\r\n\r\n").unwrap();
        let component = CoveredComponent {
            name: "@query-param".into(),
            params: vec![("name".into(), Value::String("x".into()))],
        };
        assert!(query_param(&request, &component).is_err());
    }

    #[test]
    fn rejects_out_of_range_integer() {
        assert!(parse_input("sig1", r#"("@authority");created=-9223372036854775808"#,).is_err());
    }

    #[test]
    fn rejects_duplicate_components_and_parameters() {
        assert!(parse_input("sig1", r#"("@authority" "@authority");created=1"#,).is_err());
        assert!(parse_input("sig1", r#"("@authority");created=1;created=2"#,).is_err());
    }

    #[test]
    fn parses_dictionary_uri_containing_semicolon() {
        let raw = r#"agent2="https://agent.example/a;b";type=jwks_uri"#;
        assert_eq!(
            dictionary_string_member(raw, "agent2").unwrap(),
            "https://agent.example/a;b"
        );
        assert_eq!(
            dictionary_value(raw, "agent2").unwrap(),
            r#""https://agent.example/a;b";type=jwks_uri"#
        );
    }

    #[test]
    fn canonicalizes_all_rfc_8941_dictionary_member_shapes() {
        assert_eq!(dictionary_value("a", "a").unwrap(), "?1");
        assert_eq!(dictionary_value("a=:aGVsbG8=:", "a").unwrap(), ":aGVsbG8=:");
        assert_eq!(dictionary_value("a=1.230", "a").unwrap(), "1.23");
        assert_eq!(dictionary_value("a=-000.000", "a").unwrap(), "0.0");
        assert_eq!(
            dictionary_value("a=(one \"two\";x);p=1", "a").unwrap(),
            "(one \"two\";x);p=1"
        );
        assert_eq!(
            dictionary_byte_sequence_member("sha-512=:AA==:, sha-256=:aGk=:", "sha-256").unwrap(),
            b"hi"
        );
    }

    #[test]
    fn rejects_whitespace_before_parameters() {
        assert!(parse_input("sig1", r#"("@authority" ;req);created=1"#).is_err());
        assert!(dictionary_value("a=1 ;x", "a").is_err());
    }

    #[test]
    fn component_key_and_name_parameters_must_be_strings() {
        let request = Request::parse(
            b"GET /?view=full HTTP/1.1\r\nHost: example.test\r\nExample: a=1\r\n\r\n",
        )
        .unwrap();
        let keyed = parse_input("sig1", r#"("example";key=a);created=1"#).unwrap();
        let query = parse_input("sig1", r#"("@query-param";name=view);created=1"#).unwrap();
        assert!(signature_base(&request, &keyed, None).is_err());
        assert!(signature_base(&request, &query, None).is_err());
    }

    #[test]
    fn canonicalizes_forwarded_signature_dictionary_members() {
        let request = Request::parse(
            concat!(
                "GET / HTTP/1.1\r\n",
                "Host: example.test\r\n",
                "Signature-Input: agent=(\"@method\");created=1\r\n",
                "Signature: agent=:aGk=:\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        let input = parse_input(
            "browser",
            r#"("signature-input";key="agent" "signature";key="agent");created=2"#,
        )
        .unwrap();
        let base = signature_base(&request, &input, None).unwrap();
        assert!(base.contains(r#""signature-input";key="agent": ("@method");created=1"#));
        assert!(base.contains(r#""signature";key="agent": :aGk=:"#));
    }

    #[test]
    fn unsigned_request_parses_as_empty_set() {
        let request = Request::parse(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n").unwrap();
        let parsed = parse(&request).unwrap();
        assert!(parsed.inputs.is_empty());
        assert!(parsed.signatures.is_empty());
    }

    #[test]
    fn rejects_invalid_and_duplicate_labels() {
        assert!(validate_label("bad\r\nheader").is_err());
        assert!(validate_label("9starts-with-digit").is_err());
        let request = Request::parse(
            b"GET / HTTP/1.1\r\nHost: example.test\r\nSignature: sig1=:AA==:, sig1=:AA==:\r\n\r\n",
        )
        .unwrap();
        assert!(parse(&request).is_err());
    }
}
