use anyhow::{Context as _, Result};
use http::{Request, Response};
use http_body_util::Full;
use hyper::{body::Bytes, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{convert::Infallible, env, fs};
use tokio::{
    net::TcpListener,
    signal::{self, unix::SignalKind},
};
use tokio_util::{future::FutureExt as _, sync::CancellationToken, task::TaskTracker};

const JWKS_PATH: &str = "/config/jwks.json";
const CONFIG_PATH: &str = "/config/openid-configuration";

#[tokio::main]
async fn main() -> Result<()> {
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

    let http_listener_host = env::var("JWKS_SYNC_HTTP_LISTENER_HOST")
        .map_err(anyhow::Error::new)
        .unwrap_or("localhost".to_owned());

    let _ = fs::read(JWKS_PATH).with_context(|| format!("failed to open {}", JWKS_PATH))?;
    let _ = fs::read(CONFIG_PATH).with_context(|| format!("failed to open {}", CONFIG_PATH))?;

    let response = {
        move |req: Request<hyper::body::Incoming>| {
            let (body, status) = match req.uri().path() {
                "/openid/v1/jwks" | "/.well-known/jwks.json" => (
                    fs::read(JWKS_PATH).expect("checked for existence"),
                    http::StatusCode::OK,
                ),
                "/.well-known/openid-configuration" => (
                    fs::read(CONFIG_PATH).expect("checked for existence"),
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
        let listener = TcpListener::bind((http_listener_host, 31080))
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
