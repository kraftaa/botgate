use crate::{
    http_message::Request,
    signature::{self, SignatureInput},
};
use anyhow::{Context, Result, anyhow, bail};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ring::{
    rand::SystemRandom,
    signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::Path};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

pub fn generate(private_path: &Path) -> Result<Jwk> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| anyhow!("Ed25519 key generation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(private_path)
            .with_context(|| format!("securely creating {}", private_path.display()))?;
        file.write_all(pkcs8.as_ref())?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(private_path)
            .with_context(|| format!("creating {}", private_path.display()))?;
        file.write_all(pkcs8.as_ref())?;
        file.sync_all()?;
    }
    jwk_from_pkcs8(pkcs8.as_ref())
}

pub fn jwk_from_private(private_path: &Path) -> Result<Jwk> {
    let bytes =
        fs::read(private_path).with_context(|| format!("reading {}", private_path.display()))?;
    jwk_from_pkcs8(&bytes)
}

fn jwk_from_pkcs8(bytes: &[u8]) -> Result<Jwk> {
    let pair = Ed25519KeyPair::from_pkcs8(bytes)
        .map_err(|_| anyhow!("invalid Ed25519 PKCS#8 private key"))?;
    let x = URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
    let kid = thumbprint_parts(&x);
    Ok(Jwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x,
        kid: Some(kid),
        r#use: Some("sig".into()),
    })
}

pub fn read_jwks(path: &Path) -> Result<Jwks> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    if let Ok(set) = serde_json::from_str::<Jwks>(&text) {
        return Ok(set);
    }
    let key: Jwk = serde_json::from_str(&text)
        .with_context(|| format!("parsing JWK/JWKS {}", path.display()))?;
    Ok(Jwks { keys: vec![key] })
}

pub fn thumbprint(jwk: &Jwk) -> Result<String> {
    if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
        bail!("only Ed25519 OKP keys are supported");
    }
    Ok(thumbprint_parts(&jwk.x))
}

fn thumbprint_parts(x: &str) -> String {
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

pub fn verify(
    request: &Request,
    input: &SignatureInput,
    signature_bytes: &[u8],
    jwks: &Jwks,
    context: Option<&Url>,
) -> Result<String> {
    if let Some(alg) = input.param("alg")
        && alg.as_str() != Some("ed25519")
    {
        bail!("unsupported alg parameter; Ed25519 verification requires alg=\"ed25519\"");
    }
    let keyid = input
        .param("keyid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing string keyid"))?;
    let jwk = jwks
        .keys
        .iter()
        .find(|k| thumbprint(k).ok().as_deref() == Some(keyid))
        .ok_or_else(|| anyhow!("no Ed25519 key matching keyid {keyid}"))?;
    let public = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .context("invalid base64url JWK x")?;
    let base = signature::signature_base(request, input, context)?;
    UnparsedPublicKey::new(&ED25519, public)
        .verify(base.as_bytes(), signature_bytes)
        .map_err(|_| anyhow!("Ed25519 signature verification failed"))?;
    Ok(base)
}

pub fn sign(
    request: &Request,
    input: &SignatureInput,
    private_path: &Path,
    context: Option<&Url>,
) -> Result<Vec<u8>> {
    let bytes =
        fs::read(private_path).with_context(|| format!("reading {}", private_path.display()))?;
    let pair = Ed25519KeyPair::from_pkcs8(&bytes)
        .map_err(|_| anyhow!("invalid Ed25519 PKCS#8 private key"))?;
    let base = signature::signature_base(request, input, context)?;
    Ok(pair.sign(base.as_bytes()).as_ref().to_vec())
}

pub fn signature_header(label: &str, bytes: &[u8]) -> String {
    format!("{label}=:{}:", STANDARD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{self, CoveredComponent, Value};

    #[test]
    fn ed25519_round_trip_and_bound_path_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("private.key");
        let jwk = generate(&private).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&private).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let keyid = thumbprint(&jwk).unwrap();
        let mut request =
            Request::parse(b"GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n").unwrap();
        request.set_header("signature-agent", "sig1=\"https://agent.example\"".into());
        let input = SignatureInput {
            label: "sig1".into(),
            components: vec![
                CoveredComponent {
                    name: "@authority".into(),
                    params: vec![],
                },
                CoveredComponent {
                    name: "@path".into(),
                    params: vec![],
                },
                CoveredComponent {
                    name: "signature-agent".into(),
                    params: vec![("key".into(), Value::String("sig1".into()))],
                },
            ],
            params: vec![
                ("created".into(), Value::Integer(1)),
                ("expires".into(), Value::Integer(4_000_000_000)),
                ("keyid".into(), Value::String(keyid)),
                ("tag".into(), Value::String("web-bot-auth".into())),
            ],
        };
        let sig = sign(&request, &input, &private, None).unwrap();
        let keys = Jwks { keys: vec![jwk] };
        verify(&request, &input, &sig, &keys, None).unwrap();
        let mut wrong_alg = input.clone();
        wrong_alg
            .params
            .push(("alg".into(), Value::String("rsa-pss-sha512".into())));
        assert!(verify(&request, &wrong_alg, &sig, &keys, None).is_err());

        let misleading_keyid = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let mut wrong_keyid = input.clone();
        wrong_keyid
            .params
            .iter_mut()
            .find(|(name, _)| name == "keyid")
            .unwrap()
            .1 = Value::String(misleading_keyid.into());
        let mut misleading_keys = keys.clone();
        misleading_keys.keys[0].kid = Some(misleading_keyid.into());
        assert!(verify(&request, &wrong_keyid, &sig, &misleading_keys, None).is_err());

        request.target = "/two".into();
        assert!(verify(&request, &input, &sig, &keys, None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn key_generation_does_not_follow_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        let private = dir.path().join("private.key");
        symlink(&victim, &private).unwrap();
        assert!(generate(&private).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
    }

    #[test]
    fn verifies_ietf_draft_00_ed25519_vector() {
        // Appendix E.2.1 of draft-ietf-webbotauth-httpsig-protocol-00.
        let raw = concat!(
            "GET / HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "Signature-Agent: agent2=\"https://signature-agent.test\"\r\n",
            "Signature-Input: sig2=(\"@authority\" \"signature-agent\";key=\"agent2\");created=1735689600;keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";alg=\"ed25519\";expires=4889289600;nonce=\"n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==\";tag=\"web-bot-auth\"\r\n",
            "Signature: sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:\r\n",
            "\r\n"
        );
        let request = Request::parse(raw.as_bytes()).unwrap();
        let parsed = signature::parse(&request).unwrap();
        let keys = Jwks {
            keys: vec![Jwk {
                kty: "OKP".into(),
                crv: "Ed25519".into(),
                x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs".into(),
                kid: Some("poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".into()),
                r#use: Some("sig".into()),
            }],
        };
        verify(
            &request,
            &parsed.inputs[0],
            parsed.signatures.get("sig2").unwrap(),
            &keys,
            None,
        )
        .unwrap();
    }
}
