//! Client for the go-zkid-verifier challenge server.
//!
//! Fetches cryptographic challenges from the verifier server.

use std::error::Error;

const DEFAULT_SERVER_URL: &str = "http://localhost:8080";
const MAX_RETRIES: usize = 3;

/// `POST /challenge` response. `challenge` is the decimal field element the
/// prover folds into the device-sig proof and submits back at /link-verify.
#[derive(Debug, serde::Deserialize)]
pub struct ChallengeResponse {
    pub challenge: String,
    pub app_id: String,
    pub expires_at: String,
}

/// Fetch a fresh challenge from the verifier server via `POST /challenge`.
///
/// Retries up to 3 times on transient failures before returning an error.
pub fn create_challenge(server_url: &str) -> Result<ChallengeResponse, Box<dyn Error>> {
    let url = format!("{}/challenge", server_url.trim_end_matches('/'));

    let mut last_err = None;
    for attempt in 1..=MAX_RETRIES {
        match ureq::post(&url).send_bytes(&[]) {
            Ok(resp) => return Ok(resp.into_json()?),
            Err(e) => {
                eprintln!(
                    "Challenge server attempt {}/{} failed: {}",
                    attempt, MAX_RETRIES, e
                );
                last_err = Some(e);
                if attempt < MAX_RETRIES {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        }
    }
    Err(format!(
        "challenge server at {} unreachable after {} attempts: {}",
        server_url,
        MAX_RETRIES,
        last_err.unwrap()
    )
    .into())
}

/// Returns the default challenge server URL.
pub fn default_server_url() -> &'static str {
    DEFAULT_SERVER_URL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_response_deserialization() {
        let json = r#"{
            "app_id": "e775f2805fb993e05a208dbff15d1c1",
            "challenge": "215078321887317284868454961554019057364",
            "expires_at": "2026-01-01T00:00:00Z"
        }"#;
        let resp: ChallengeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.app_id, "e775f2805fb993e05a208dbff15d1c1");
        assert_eq!(resp.challenge, "215078321887317284868454961554019057364");
        assert_eq!(resp.expires_at, "2026-01-01T00:00:00Z");
    }

    #[test]
    #[ignore] // requires live challenge server on localhost:8080
    fn test_fetch_challenge_live() {
        let resp = create_challenge(DEFAULT_SERVER_URL).unwrap();
        assert!(!resp.challenge.is_empty());
        assert!(!resp.app_id.is_empty());
    }
}
