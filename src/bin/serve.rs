use anyhow::{Context as _, Result};
use http::{Request, Response};
use http_body_util::Full;
use hyper::{body::Bytes, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use landlock::{
    Access as _, AccessFs, AccessNet, NetPort, RestrictionStatus, Ruleset, RulesetAttr as _,
    RulesetCreatedAttr as _, path_beneath_rules,
};
use std::{convert::Infallible, env, fs};
use tokio::{
    net::TcpListener,
    signal::{self, unix::SignalKind},
};
use tokio_util::{future::FutureExt as _, sync::CancellationToken, task::TaskTracker};

const CONFIG_PATH: &str = "/config";
const JWKS_PATH: &str = "/config/jwks.json";
const OIDC_CONFIG_PATH: &str = "/config/openid-configuration";

const LISTENER_PORT: u16 = 31080;

#[tokio::main]
async fn main() -> Result<()> {
    // Linux current LTS 6.18
    let abi = landlock::ABI::V7;
    let ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .handle_access(AccessNet::from_all(abi))?;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cancelled = CancellationToken::new();

    let wait_cancel = tokio::spawn({
        let cancelled = cancelled.clone();
        async move {
            let mut sigterm =
                signal::unix::signal(SignalKind::terminate()).expect("handle SIGTERM");
            tokio::select! {
                _ = signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            };
            cancelled.cancel();
        }
    });

    match ruleset
        .create()?
        .add_rules(path_beneath_rules(&[CONFIG_PATH], AccessFs::from_read(abi)))?
        .add_rule(NetPort::new(LISTENER_PORT, AccessNet::BindTcp))?
        .restrict_self()?
    {
        RestrictionStatus {
            ruleset: landlock::RulesetStatus::FullyEnforced,
            no_new_privs: true,
            ..
        } => {}
        status => anyhow::bail!(
            "unacceptable landlock ruleset enforcement: ruleset={:?}, no_new_prives={}",
            status.ruleset,
            status.no_new_privs
        ),
    };

    let http_listener_host = env::var("JWKS_SYNC_HTTP_LISTENER_HOST")
        .map_err(anyhow::Error::new)
        .unwrap_or("localhost".to_owned());

    let _ = fs::read(JWKS_PATH).with_context(|| format!("failed to open {}", JWKS_PATH))?;
    let _ = fs::read(OIDC_CONFIG_PATH)
        .with_context(|| format!("failed to open {}", OIDC_CONFIG_PATH))?;

    let response = {
        move |req: Request<hyper::body::Incoming>| {
            let (body, status) = match req.uri().path() {
                "/openid/v1/jwks" | "/.well-known/jwks.json" => (
                    fs::read(JWKS_PATH).expect("checked for existence"),
                    http::StatusCode::OK,
                ),
                "/.well-known/openid-configuration" => (
                    fs::read(OIDC_CONFIG_PATH).expect("checked for existence"),
                    http::StatusCode::OK,
                ),
                _ => (Vec::new(), http::StatusCode::NOT_FOUND),
            };
            let mut resp = Response::new(Full::<Bytes>::from(body));
            *resp.status_mut() = status;
            async { Result::<_, Infallible>::Ok(resp) }
        }
    };

    let req_tracker = TaskTracker::new();

    let accept_cancelled = cancelled.clone();
    let accept_req_tracker = req_tracker.clone();

    async move {
        let listener = TcpListener::bind((http_listener_host, LISTENER_PORT))
            .await
            .expect("failed to listen");

        let req_tracker = accept_req_tracker.clone();
        loop {
            let stream = match listener.accept().await {
                Err(err) => {
                    eprintln!("Failed to accept connection: {:#}", err);
                    continue;
                }
                Ok((stream, _)) => TokioIo::new(stream),
            };

            let cancelled = cancelled.clone();
            req_tracker.spawn(
                async move {
                    let conn = http1::Builder::new().serve_connection(stream, service_fn(response));

                    if let Err(err) = conn.await {
                        eprintln!("Error serving connection: {:#}", err);
                    }
                }
                .with_cancellation_token_owned(cancelled),
            );
        }
    }
    .with_cancellation_token_owned(accept_cancelled)
    .await;

    println!("shutting down");

    wait_cancel.abort();
    let _ = wait_cancel.await;
    req_tracker.close();
    req_tracker.wait().await;

    Ok(())
}
