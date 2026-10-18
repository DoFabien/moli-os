//! Cloudflare Access: who is behind a request that came through the tunnel.
//!
//! From the Internet, Moli is reached only through the Cloudflare tunnel, and
//! only after Cloudflare Access let a person in. Access signs that person's
//! identity in `Cf-Access-Jwt-Assertion` (RS256). Moli checks the signature
//! against the team's public keys, the audience (this very application), the
//! issuer and the expiry, and only then believes the e-mail. A header alone
//! proves nothing: anyone on the home network can send one.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde::Deserialize;

/// `[server.access]`: the Cloudflare Access application in front of Moli.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessConfig {
    /// Team name: keys come from `https://<team>.cloudflareaccess.com`.
    pub team: String,
    /// The application's audience tag (AUD). Not a secret.
    pub aud: String,
    /// Who may choose the dashboard's code from the dashboard (their e-mail,
    /// as Access proves it): the house's owners. Nobody when empty.
    #[serde(default)]
    pub owners: Vec<String>,
}

/// Keys rotate rarely (weeks) and overlap: refreshed hourly at most…
const KEYS_MAX_AGE: Duration = Duration::from_secs(3600);
/// …and never more than once a minute (an unknown key id is not a reason to
/// hammer Cloudflare).
const RETRY_AFTER: Duration = Duration::from_secs(60);
/// Clock skew tolerated on `nbf`/`exp`.
const LEEWAY_S: u64 = 60;
/// A real assertion is ~1 KB.
const MAX_TOKEN: usize = 8 * 1024;
const MAX_JWKS: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Key {
    n: Vec<u8>,
    e: Vec<u8>,
}

#[derive(Debug, Default)]
struct Keys {
    by_kid: HashMap<String, Key>,
    fetched: Option<Instant>,
    tried: Option<Instant>,
}

#[derive(Debug)]
pub(crate) struct Verifier {
    domain: String,
    issuer: String,
    aud: String,
    keys: RwLock<Keys>,
    fetching: tokio::sync::Mutex<()>,
    /// People already recognized (logged once each).
    seen: Mutex<HashSet<String>>,
}

impl Verifier {
    pub(crate) fn new(config: &AccessConfig) -> Self {
        let domain = format!("{}.cloudflareaccess.com", config.team.trim());
        Self {
            issuer: format!("https://{domain}"),
            domain,
            aud: config.aud.trim().to_owned(),
            keys: RwLock::new(Keys::default()),
            fetching: tokio::sync::Mutex::new(()),
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// The e-mail Access vouches for, or `None` (bad, expired, foreign or
    /// unverifiable token).
    pub(crate) async fn identity(&self, token: &str) -> Option<String> {
        let jwt = Jwt::parse(token)?;
        let (key, stale) = self.key(&jwt.kid);
        let key = match key {
            Some(key) if !stale => key,
            known => {
                // A fresh key set without this key: the key was withdrawn.
                // The one known before stands only when Cloudflare could not
                // be asked.
                let fresh = self.refresh().await;
                let now = self.key(&jwt.kid).0;
                if fresh { now? } else { now.or(known)? }
            }
        };
        match check(&jwt, &key, &self.issuer, &self.aud, now_s()) {
            Ok(email) => {
                let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
                if seen.len() < 64 && seen.insert(email.clone()) {
                    tracing::info!(%email, "Cloudflare Access: person recognized");
                }
                Some(email)
            }
            Err(why) => {
                tracing::warn!(why, "Cloudflare Access assertion refused");
                None
            }
        }
    }

    /// The key for `kid`, and whether the key set is due for a refresh.
    fn key(&self, kid: &str) -> (Option<Key>, bool) {
        let keys = self.keys.read().unwrap_or_else(PoisonError::into_inner);
        let stale = keys.fetched.is_none_or(|t| t.elapsed() > KEYS_MAX_AGE);
        (keys.by_kid.get(kid).cloned(), stale)
    }

    /// Fetches the key set again (at most once a minute); `true` when the
    /// set in hand is a fresh one.
    async fn refresh(&self) -> bool {
        let _one_at_a_time = self.fetching.lock().await;
        {
            let mut keys = self.keys.write().unwrap_or_else(PoisonError::into_inner);
            if keys.tried.is_some_and(|t| t.elapsed() < RETRY_AFTER) {
                return keys.fetched.is_some_and(|t| t.elapsed() < RETRY_AFTER);
            }
            keys.tried = Some(Instant::now());
        }
        match fetch(&self.domain).await {
            Ok(by_kid) => {
                let mut keys = self.keys.write().unwrap_or_else(PoisonError::into_inner);
                keys.by_kid = by_kid;
                keys.fetched = Some(Instant::now());
                true
            }
            // Keep the previous keys: Cloudflare unreachable must not lock
            // the family out while the keys they were signed with still hold.
            Err(e) => {
                tracing::warn!(error = %e, "Cloudflare Access keys not refreshed");
                false
            }
        }
    }
}

async fn fetch(domain: &str) -> anyhow::Result<HashMap<String, Key>> {
    #[derive(Deserialize)]
    struct Jwks {
        keys: Vec<Jwk>,
    }
    #[derive(Deserialize)]
    struct Jwk {
        kid: String,
        kty: String,
        #[serde(default)]
        n: Option<String>,
        #[serde(default)]
        e: Option<String>,
    }
    let request = moli_net::empty(
        http::Request::builder()
            .method(http::Method::GET)
            .uri("/cdn-cgi/access/certs"),
    )?;
    let (status, body) =
        moli_net::web(domain, 443, true, request, Duration::from_secs(8), MAX_JWKS).await?;
    anyhow::ensure!(status.is_success(), "certs: {status}");
    let jwks: Jwks = serde_json::from_slice(&body)?;
    let keys: HashMap<String, Key> = jwks
        .keys
        .into_iter()
        .filter(|k| k.kty == "RSA")
        .filter_map(|k| {
            Some((
                k.kid,
                Key {
                    n: b64url(k.n.as_deref()?)?,
                    e: b64url(k.e.as_deref()?)?,
                },
            ))
        })
        .collect();
    anyhow::ensure!(!keys.is_empty(), "no RSA key in the team's certs");
    Ok(keys)
}

/// A signed token, split but not yet trusted.
#[derive(Debug)]
pub(crate) struct Jwt {
    kid: String,
    signed: Vec<u8>,
    signature: Vec<u8>,
    claims: Vec<u8>,
}

impl Jwt {
    pub(crate) fn parse(token: &str) -> Option<Self> {
        #[derive(Deserialize)]
        struct Header {
            alg: String,
            kid: String,
        }
        if token.len() > MAX_TOKEN {
            return None;
        }
        let mut parts = token.split('.');
        let (header, claims, signature) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let parsed: Header = serde_json::from_slice(&b64url(header)?).ok()?;
        // RS256 only: never let the token choose a weaker (or no) algorithm.
        if parsed.alg != "RS256" {
            return None;
        }
        Some(Self {
            kid: parsed.kid,
            signed: format!("{header}.{claims}").into_bytes(),
            signature: b64url(signature)?,
            claims: b64url(claims)?,
        })
    }
}

/// Signature, audience, issuer, validity window, e-mail.
pub(crate) fn check(
    jwt: &Jwt,
    key: &Key,
    issuer: &str,
    aud: &str,
    now: u64,
) -> Result<String, &'static str> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audience {
        One(String),
        Many(Vec<String>),
    }
    #[derive(Deserialize)]
    struct Claims {
        aud: Audience,
        iss: String,
        exp: u64,
        #[serde(default)]
        nbf: Option<u64>,
        #[serde(default)]
        email: Option<String>,
    }
    RsaPublicKeyComponents {
        n: &key.n,
        e: &key.e,
    }
    .verify(&RSA_PKCS1_2048_8192_SHA256, &jwt.signed, &jwt.signature)
    .map_err(|_| "bad signature")?;
    let claims: Claims = serde_json::from_slice(&jwt.claims).map_err(|_| "unreadable claims")?;
    let audience_ok = match &claims.aud {
        Audience::One(a) => a == aud,
        Audience::Many(all) => all.iter().any(|a| a == aud),
    };
    if !audience_ok {
        return Err("another application's token");
    }
    if claims.iss != issuer {
        return Err("another team's token");
    }
    if claims.exp + LEEWAY_S < now {
        return Err("expired");
    }
    if claims.nbf.is_some_and(|nbf| nbf > now + LEEWAY_S) {
        return Err("not yet valid");
    }
    claims
        .email
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty() && e.len() <= 254 && !e.chars().any(char::is_control))
        .ok_or("no e-mail (service token?)")
}

fn now_s() -> u64 {
    moli_core::now_ms() / 1000
}

/// Base64url without padding (JWT, JWK).
pub(crate) fn b64url(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::caller::{Caller, Gate, Via};
    use crate::people::{Draft, People, Role};
    use axum::http::StatusCode;
    use moli_runtime::{Hub, HubOptions, MasterKey};
    use ring::rand::SystemRandom;
    use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const ISS: &str = "https://maison.cloudflareaccess.com";
    const AUD: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
    const NOW: u64 = 1_791_060_580;

    fn b64(bytes: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
            for i in 0..=chunk.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        out
    }

    /// A throwaway key, for tests only (tests/data).
    fn signer() -> (RsaKeyPair, Key) {
        let pair = RsaKeyPair::from_pkcs8(include_bytes!("../tests/data/access-test-key.pk8"))
            .expect("test key");
        let public: RsaPublicKeyComponents<Vec<u8>> = pair.public().into();
        let key = Key {
            n: public.n,
            e: public.e,
        };
        (pair, key)
    }

    fn token(pair: &RsaKeyPair, header: &str, claims: &str) -> String {
        let signed = format!("{}.{}", b64(header.as_bytes()), b64(claims.as_bytes()));
        let mut sig = vec![0; pair.public().modulus_len()];
        pair.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signed.as_bytes(),
            &mut sig,
        )
        .unwrap();
        format!("{signed}.{}", b64(&sig))
    }

    fn claims(aud: &str, iss: &str, exp: u64, email: &str) -> String {
        format!(
            r#"{{"aud":["{aud}"],"iss":"{iss}","exp":{exp},"iat":{NOW},"email":"{email}","type":"app"}}"#
        )
    }

    const HEADER: &str = r#"{"alg":"RS256","kid":"k1","typ":"JWT"}"#;

    /// A real signed assertion through the caller middleware, without fetching keys.
    async fn access_request(
        people: &Arc<People>,
        email: &str,
        path: &str,
        cookie: Option<&str>,
    ) -> (u16, String) {
        let (pair, key) = signer();
        let assertion = token(&pair, HEADER, &claims(AUD, ISS, now_s() + 3600, email));
        let verifier = Verifier::new(&AccessConfig {
            team: "maison".into(),
            aud: AUD.into(),
            owners: vec![],
        });
        *verifier.keys.write().unwrap() = Keys {
            by_kid: HashMap::from([("k1".into(), key)]),
            fetched: Some(Instant::now()),
            tried: Some(Instant::now()),
        };
        let app = axum::Router::new()
            .route("/api/journal", axum::routing::get(crate::rest::journal))
            .route(
                "/api/devices",
                axum::routing::get(|caller: Caller| async move {
                    axum::Json(serde_json::json!({
                        "via": caller.via_name(), "person": caller.person,
                    }))
                }),
            )
            .with_state(Hub::new(HubOptions::default()).unwrap())
            .layer(axum::middleware::from_fn_with_state(
                Gate {
                    access: Some(Arc::new(verifier)),
                    demo: false,
                    people: Arc::clone(people),
                },
                crate::caller::identify,
            ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let cookie = cookie.map_or_else(String::new, |c| format!("Cookie: {c}\r\n"));
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nCf-Ray: test\r\nCf-Access-Jwt-Assertion: {assertion}\r\n{cookie}\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        let result =
            tokio::time::timeout(Duration::from_secs(5), stream.read_to_string(&mut response))
                .await;
        server.abort();
        result.unwrap().unwrap();
        (response[9..12].parse().unwrap(), response)
    }

    fn person(name: &str, role: Role, email: &str) -> Draft {
        Draft {
            name: name.into(),
            role,
            emails: vec![email.into()],
            color: None,
            rooms: vec!["Salon".into()],
            expires: None,
            macs: vec![],
        }
    }

    #[tokio::test]
    async fn access_preserves_active_roles_and_unknown_household() {
        let hub = Hub::new(HubOptions::default()).unwrap();
        let people = Arc::new(People::open(hub, None, &["owner@example.com".into()]));
        let mut guest = person("Guest", Role::Guest, "guest@example.com");
        guest.expires = Some(moli_core::now_ms() + 3_600_000);
        people.create(guest).await.unwrap();
        people
            .create(person("Member", Role::Member, "member@example.com"))
            .await
            .unwrap();
        for (email, role) in [
            ("guest@example.com", "guest"),
            ("member@example.com", "member"),
            ("owner@example.com", "owner"),
        ] {
            let (status, body) = access_request(&people, email, "/api/devices", None).await;
            assert_eq!(status, 200, "{body}");
            assert!(body.contains(&format!("\"role\":\"{role}\"")), "{body}");
            if role == "guest" {
                assert!(body.contains("\"rooms\":[\"Salon\"]"), "{body}");
            }
            let (status, _) = access_request(&people, email, "/api/journal", None).await;
            assert_eq!(status, if role == "guest" { 403 } else { 200 });
        }
        let (status, body) =
            access_request(&people, "unknown@example.com", "/api/devices", None).await;
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("\"person\":null"), "{body}");
        assert!(body.contains("\"via\":\"access\""), "{body}");
    }

    #[tokio::test]
    async fn access_refuses_expired_people_before_cookie_fallback() {
        let dir = std::env::temp_dir().join(format!("moli-access-expired-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let hub = Hub::new(HubOptions {
            secrets: Some((dir.join("secrets.enc"), MasterKey::generate().unwrap())),
            ..HubOptions::default()
        })
        .unwrap();
        let sessions = crate::session::Sessions::new(hub.clone(), None, &[]);
        let people = Arc::new(People::open(hub, Some(&dir), &[]));
        let mut guest = person("Guest", Role::Guest, "guest@example.com");
        guest.expires = Some(1);
        people.create(guest).await.unwrap();
        people
            .create(person("Member", Role::Member, "member@example.com"))
            .await
            .unwrap();
        people
            .set_password("member", "a test password only")
            .await
            .unwrap();
        let caller = Caller {
            via: Via::Outside,
            key: "test".into(),
            person: None,
        };
        let (session, _) = people
            .login(&sessions, "member", "a test password only", &caller)
            .await
            .unwrap();
        let cookie = People::cookie(&session);
        for cookie in [None, Some(cookie.as_str())] {
            for path in [
                "/api/journal",
                "/api/devices",
                "/api/events",
                "/mcp",
                "/api/session",
            ] {
                let (status, body) =
                    access_request(&people, "guest@example.com", path, cookie).await;
                assert_eq!(status, StatusCode::FORBIDDEN.as_u16(), "{path}: {body}");
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn access_refuses_removed_addresses_until_explicitly_reassigned() {
        let people = Arc::new(People::open(
            Hub::new(HubOptions::default()).unwrap(),
            None,
            &[],
        ));
        people
            .create(person("Guest", Role::Guest, "old@example.com"))
            .await
            .unwrap();
        people
            .update("guest", person("Guest", Role::Guest, "new@example.com"))
            .await
            .unwrap();
        assert_eq!(
            access_request(&people, "old@example.com", "/api/devices", None)
                .await
                .0,
            403
        );
        assert_eq!(
            access_request(&people, "new@example.com", "/api/devices", None)
                .await
                .0,
            200
        );
        people.remove("guest").await.unwrap();
        assert_eq!(
            access_request(&people, "new@example.com", "/api/devices", None)
                .await
                .0,
            403
        );
        people
            .create(person("Guest", Role::Guest, "old@example.com"))
            .await
            .unwrap();
        assert_eq!(
            access_request(&people, "old@example.com", "/api/devices", None)
                .await
                .0,
            200
        );
        assert_eq!(
            access_request(&people, "old@example.com", "/api/journal", None)
                .await
                .0,
            403
        );
    }

    #[test]
    fn a_genuine_assertion_names_its_person() {
        let (pair, key) = signer();
        let t = token(
            &pair,
            HEADER,
            &claims(AUD, ISS, NOW + 3600, "Moi@Example.org"),
        );
        let jwt = Jwt::parse(&t).unwrap();
        assert_eq!(jwt.kid, "k1");
        assert_eq!(check(&jwt, &key, ISS, AUD, NOW).unwrap(), "moi@example.org");
    }

    #[test]
    fn forged_foreign_or_expired_assertions_are_refused() {
        let (pair, key) = signer();
        let good = claims(AUD, ISS, NOW + 3600, "moi@example.org");
        // Tampered claims, same signature.
        let t = token(&pair, HEADER, &good);
        let mut parts: Vec<&str> = t.split('.').collect();
        let evil = b64(claims(AUD, ISS, NOW + 3600, "intrus@example.com").as_bytes());
        parts[1] = &evil;
        let forged = parts.join(".");
        assert_eq!(
            check(&Jwt::parse(&forged).unwrap(), &key, ISS, AUD, NOW),
            Err("bad signature")
        );
        let other_app = token(
            &pair,
            HEADER,
            &claims("other", ISS, NOW + 3600, "moi@example.org"),
        );
        assert!(check(&Jwt::parse(&other_app).unwrap(), &key, ISS, AUD, NOW).is_err());
        let other_team = token(
            &pair,
            HEADER,
            &claims(
                AUD,
                "https://evil.cloudflareaccess.com",
                NOW + 3600,
                "moi@example.org",
            ),
        );
        assert!(check(&Jwt::parse(&other_team).unwrap(), &key, ISS, AUD, NOW).is_err());
        let expired = token(
            &pair,
            HEADER,
            &claims(AUD, ISS, NOW - 3600, "moi@example.org"),
        );
        assert_eq!(
            check(&Jwt::parse(&expired).unwrap(), &key, ISS, AUD, NOW),
            Err("expired")
        );
        // The token never chooses its algorithm.
        assert!(Jwt::parse(&token(&pair, r#"{"alg":"none","kid":"k1"}"#, &good)).is_none());
        assert!(Jwt::parse("a.b").is_none());
        assert!(Jwt::parse(&"a".repeat(MAX_TOKEN + 1)).is_none());
    }

    #[test]
    fn base64url_round_trips() {
        for sample in [&b""[..], b"f", b"fo", b"foo", b"foob", b"\xff\xfe\x00\x01"] {
            assert_eq!(b64url(&b64(sample)).unwrap(), sample);
        }
        assert!(b64url("a+b/").is_none(), "standard alphabet refused");
    }
}
