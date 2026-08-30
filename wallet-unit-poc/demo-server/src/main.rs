//! Demo server: relays an age-verification session between a wallet and a
//! browser, and natively verifies the two linked Spartan2 proofs the wallet
//! submits.

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use axum::{
    extract::{Path as AxumPath, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use clap::Parser;
use ecdsa_spartan2::{load_proof, load_verifying_key, prover::verify_linked, E, Scalar};
use ff::Field;
use serde::{Deserialize, Serialize};
use spartan2::{traits::snark::R1CSSNARKTrait, zk_spartan::R1CSSNARK};
use tower_http::services::ServeDir;
use tracing::info;
use tracing_subscriber::EnvFilter;

type VerifyingKey = <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey;

#[derive(Parser, Debug)]
#[command(about = "Relays an age-verification session and verifies the linked Spartan2 proofs")]
struct Cli {
    #[arg(long, default_value_t = 8080)]
    port: u16,
    #[arg(long, default_value = "../ecdsa-spartan2/keys/1k_mdoc_verifying.key")]
    mdoc_vk: PathBuf,
    #[arg(long, default_value = "../ecdsa-spartan2/keys/1k_show_verifying.key")]
    show_vk: PathBuf,
    #[arg(long, default_value = "../ecdsa-spartan2/keys/1k_mdoc_proof.bin")]
    ref_mdoc_proof: PathBuf,
    #[arg(long, default_value = "../ecdsa-spartan2/keys/1k_show_proof.bin")]
    ref_show_proof: PathBuf,
    #[arg(long, default_value = "./static")]
    static_dir: PathBuf,
    #[arg(long, default_value = "birth_date <= 20080829")]
    policy: String,
    #[arg(long, default_value = "Age 18 or older")]
    policy_display: String,
}

struct AppState {
    mdoc_vk: VerifyingKey,
    show_vk: VerifyingKey,
    // Because the demo policy, nonce, and credential are fixed, an honest
    // presentation's entire public-input vectors are deterministic. Equality
    // against these pins the issuer key, claim flags, nonce hash, predicate
    // list, RPN expression, and expressionResult==1 in one comparison.
    ref_mdoc_publics: Vec<Scalar>,
    ref_show_publics: Vec<Scalar>,
    policy: String,
    policy_display: String,
    sessions: Mutex<HashMap<u32, SessionState>>,
    next_id: AtomicU32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SessionStatus {
    Pending,
    Verified,
    Failed,
}

impl SessionStatus {
    fn as_str(self) -> &'static str {
        match self {
            SessionStatus::Pending => "pending",
            SessionStatus::Verified => "verified",
            SessionStatus::Failed => "failed",
        }
    }
}

// Per-check breakdown of a submission's verification outcome. All false
// until `verify_linked` has actually run against the submitted proofs.
#[derive(Clone, Copy, Default, Serialize)]
struct Checks {
    linked: bool,
    mdoc_publics: bool,
    show_publics: bool,
}

struct SessionState {
    status: SessionStatus,
    verify_ms: Option<u64>,
    mdoc_proof_bytes: Option<u64>,
    show_proof_bytes: Option<u64>,
    checks: Option<Checks>,
}

impl SessionState {
    fn pending() -> Self {
        SessionState {
            status: SessionStatus::Pending,
            verify_ms: None,
            mdoc_proof_bytes: None,
            show_proof_bytes: None,
            checks: None,
        }
    }
}

#[derive(Serialize)]
struct SessionCreateResponse {
    session_id: String,
    policy: String,
    policy_display: String,
    wallet_link: String,
}

#[derive(Serialize)]
struct SessionStatusResponse {
    status: &'static str,
    policy: String,
    policy_display: String,
    verify_ms: Option<u64>,
    mdoc_proof_bytes: Option<u64>,
    show_proof_bytes: Option<u64>,
    checks: Option<Checks>,
}

#[derive(Deserialize)]
struct ProofsRequest {
    mdoc_proof: String,
    show_proof: String,
}

#[derive(Serialize)]
struct ProofsResponse {
    status: &'static str,
}

fn build_state(cli: &Cli) -> AppState {
    let t0 = Instant::now();
    let mdoc_vk = load_verifying_key(&cli.mdoc_vk).expect("failed to load mdoc verifying key");
    let show_vk = load_verifying_key(&cli.show_vk).expect("failed to load show verifying key");
    info!(elapsed_ms = t0.elapsed().as_millis(), "loaded verifying keys");

    let ref_mdoc = load_proof(&cli.ref_mdoc_proof).expect("failed to load reference mdoc proof");
    let ref_show = load_proof(&cli.ref_show_proof).expect("failed to load reference show proof");

    let (ref_mdoc_publics, ref_show_publics) =
        verify_linked(&ref_mdoc, &mdoc_vk, &ref_show, &show_vk)
            .expect("reference proofs must verify and link — regenerate with `mdoc benchmark`");
    assert!(
        ref_show_publics.first() == Some(&Scalar::ONE),
        "reference expressionResult must be true"
    );

    AppState {
        mdoc_vk,
        show_vk,
        ref_mdoc_publics,
        ref_show_publics,
        policy: cli.policy.clone(),
        policy_display: cli.policy_display.clone(),
        sessions: Mutex::new(HashMap::new()),
        next_id: AtomicU32::new(1),
    }
}

/// Deserializes the two proofs (via a tempdir, reusing `load_proof` rather
/// than duplicating its bincode-over-mmap logic) and checks them against the
/// reference publics one predicate at a time. Never panics on bad input.
fn verify_submission(state: &AppState, mdoc_bytes: &[u8], show_bytes: &[u8]) -> (Checks, Option<u64>) {
    let Ok(dir) = tempfile::tempdir() else {
        return (Checks::default(), None);
    };
    let mdoc_path = dir.path().join("mdoc_proof.bin");
    let show_path = dir.path().join("show_proof.bin");
    if std::fs::write(&mdoc_path, mdoc_bytes).is_err()
        || std::fs::write(&show_path, show_bytes).is_err()
    {
        return (Checks::default(), None);
    }

    let Ok(mdoc_proof) = load_proof(&mdoc_path) else {
        return (Checks::default(), None);
    };
    let Ok(show_proof) = load_proof(&show_path) else {
        return (Checks::default(), None);
    };

    let t = Instant::now();
    let outcome = verify_linked(&mdoc_proof, &state.mdoc_vk, &show_proof, &state.show_vk);
    let verify_ms = t.elapsed().as_millis() as u64;
    let (linked, mdoc_publics, show_publics) = match outcome {
        Some((mp, sp)) => (true, mp == state.ref_mdoc_publics, sp == state.ref_show_publics),
        None => (false, false, false),
    };

    (
        Checks { linked, mdoc_publics, show_publics },
        Some(verify_ms),
    )
}

/// Base64-decodes both proofs, runs verification off the async runtime, and
/// records the outcome on the session. Shared by the HTTP handler and the
/// `#[ignore]`d integration test below.
async fn handle_proofs_submission(
    state: &Arc<AppState>,
    id: u32,
    mdoc_proof_b64: &str,
    show_proof_b64: &str,
) -> &'static str {
    let mdoc_bytes = BASE64_STANDARD.decode(mdoc_proof_b64);
    let show_bytes = BASE64_STANDARD.decode(show_proof_b64);

    let (checks, verify_ms, mdoc_len, show_len) = match (mdoc_bytes, show_bytes) {
        (Ok(mdoc_bytes), Ok(show_bytes)) => {
            let mdoc_len = mdoc_bytes.len() as u64;
            let show_len = show_bytes.len() as u64;
            let state = state.clone();
            let (checks, verify_ms) =
                tokio::task::spawn_blocking(move || verify_submission(&state, &mdoc_bytes, &show_bytes))
                    .await
                    .unwrap_or((Checks::default(), None));
            (checks, verify_ms, Some(mdoc_len), Some(show_len))
        }
        // Malformed base64 never reaches verification.
        _ => (Checks::default(), None, None, None),
    };

    let verified = checks.linked && checks.mdoc_publics && checks.show_publics;
    let status = if verified { SessionStatus::Verified } else { SessionStatus::Failed };
    if let Some(session) = state.sessions.lock().unwrap().get_mut(&id) {
        session.status = status;
        session.verify_ms = verify_ms;
        session.mdoc_proof_bytes = mdoc_len;
        session.show_proof_bytes = show_len;
        session.checks = Some(checks);
    }

    status.as_str()
}

async fn post_session(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    let id = state.next_id.fetch_add(1, Ordering::Relaxed);
    state.sessions.lock().unwrap().insert(id, SessionState::pending());

    // Echo back whatever host the phone's browser used to reach us, so the
    // wallet's callback lands on the same interface (LAN IP, tunnel, etc).
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let server = format!("http://{host}");
    let wallet_link = format!(
        "openacmdoc://verify?session={id}&server={}&policy={}&label={}",
        percent_encode(&server),
        percent_encode(&state.policy),
        percent_encode(&state.policy_display),
    );

    Json(SessionCreateResponse {
        session_id: id.to_string(),
        policy: state.policy.clone(),
        policy_display: state.policy_display.clone(),
        wallet_link,
    })
}

#[derive(Serialize)]
struct LatestSessionResponse {
    id: u32,
}

async fn get_latest_session(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let sessions = state.sessions.lock().unwrap();
    let Some(id) = sessions.keys().max().copied() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    Json(LatestSessionResponse { id }).into_response()
}

async fn get_session(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u32>,
) -> impl IntoResponse {
    let sessions = state.sessions.lock().unwrap();
    let Some(session) = sessions.get(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    Json(SessionStatusResponse {
        status: session.status.as_str(),
        policy: state.policy.clone(),
        policy_display: state.policy_display.clone(),
        verify_ms: session.verify_ms,
        mdoc_proof_bytes: session.mdoc_proof_bytes,
        show_proof_bytes: session.show_proof_bytes,
        checks: session.checks,
    })
    .into_response()
}

async fn post_proofs(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u32>,
    Json(body): Json<ProofsRequest>,
) -> impl IntoResponse {
    if !state.sessions.lock().unwrap().contains_key(&id) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let status = handle_proofs_submission(&state, id, &body.mdoc_proof, &body.show_proof).await;
    Json(ProofsResponse { status }).into_response()
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();
    let state = Arc::new(build_state(&cli));

    let serve_dir = ServeDir::new(&cli.static_dir).append_index_html_on_directories(true);
    let app = Router::new()
        .route("/api/session", post(post_session))
        .route("/api/session/latest", get(get_latest_session))
        .route("/api/session/:id", get(get_session))
        .route("/api/session/:id/proofs", post(post_proofs))
        .fallback_service(serve_dir)
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], cli.port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");
    info!("listening on {addr}");
    axum::serve(listener, app).await.expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_cli() -> Cli {
        Cli {
            port: 8080,
            mdoc_vk: PathBuf::from("../ecdsa-spartan2/keys/1k_mdoc_verifying.key"),
            show_vk: PathBuf::from("../ecdsa-spartan2/keys/1k_show_verifying.key"),
            ref_mdoc_proof: PathBuf::from("../ecdsa-spartan2/keys/1k_mdoc_proof.bin"),
            ref_show_proof: PathBuf::from("../ecdsa-spartan2/keys/1k_show_proof.bin"),
            static_dir: PathBuf::from("./static"),
            policy: "birth_date <= 20080829".to_string(),
            policy_display: "Age 18 or older".to_string(),
        }
    }

    // Real artifacts: a 471 MB verifying key. Run with:
    //   cargo test --release -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn verifies_reference_proofs_and_rejects_tampered_ones() {
        let cli = default_cli();
        let state = Arc::new(build_state(&cli));

        state.sessions.lock().unwrap().insert(1, SessionState::pending());

        let mdoc_bytes = std::fs::read(&cli.ref_mdoc_proof).expect("read reference mdoc proof");
        let show_bytes = std::fs::read(&cli.ref_show_proof).expect("read reference show proof");
        let mdoc_b64 = BASE64_STANDARD.encode(&mdoc_bytes);
        let show_b64 = BASE64_STANDARD.encode(&show_bytes);

        let status = handle_proofs_submission(&state, 1, &mdoc_b64, &show_b64).await;
        assert_eq!(status, "verified");

        let verify_ms = {
            let sessions = state.sessions.lock().unwrap();
            let session = sessions.get(&1).unwrap();
            assert_eq!(session.status, SessionStatus::Verified);
            let checks = session.checks.expect("checks should be recorded");
            assert!(checks.linked && checks.mdoc_publics && checks.show_publics);
            session.verify_ms.expect("verify_ms should be recorded")
        };
        assert!(verify_ms > 0, "verify_ms should be positive, got {verify_ms}");
        println!("verify_ms (reference proofs): {verify_ms}");

        let mut tampered = mdoc_bytes.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0xFF;
        let tampered_b64 = BASE64_STANDARD.encode(&tampered);

        let status = handle_proofs_submission(&state, 1, &tampered_b64, &show_b64).await;
        assert_eq!(status, "failed");
        let sessions = state.sessions.lock().unwrap();
        let session = sessions.get(&1).unwrap();
        assert_eq!(session.status, SessionStatus::Failed);
        assert!(!session.checks.expect("checks should be recorded").linked);
    }
}
