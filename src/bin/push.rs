use std::fs;

use anyhow::{Context, Result};
use mainline::{Dht, MutableItem, SigningKey};
use oidc_issuer_config_sync::{SALT_JWKS, SALT_OPENID_CONFIG};
use tokio::signal::{self, unix::SignalKind};
use tokio_util::{future::FutureExt as _, sync::CancellationToken};

const PRIVATE_KEY_PATH: &str = "/var/run/secrets/oidc-issuer-config-sync/dht-private-key";

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

    push()
        .with_cancellation_token_owned(cancelled)
        .await
        .ok_or(anyhow::anyhow!("exited early"))
        .flatten()?;

    wait_cancel.abort();
    let _ = wait_cancel.await;

    Ok(())
}

async fn push() -> Result<()> {
    let private_key = fs::read_to_string(PRIVATE_KEY_PATH)
        .context(format!("couldn't read file {PRIVATE_KEY_PATH}"))?;
    let private_key_bytes: [u8; 32] = data_encoding::HEXLOWER
        .decode(private_key.trim().as_bytes())
        .context("private key is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key must be exactly 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&private_key_bytes);

    let kube = kube::Client::try_default()
        .await
        .context("building in-cluster kube client")?;
    let openid_config = kube
        .request_text(
            http::Request::get("/.well-known/openid-configuration")
                .body(Default::default())
                .context("building request")?,
        )
        .await
        .context("failed to get Kubernetes API JWKS")?;
    let jwks = kube
        .request_text(
            http::Request::get("/openid/v1/jwks")
                .body(Default::default())
                .context("building request")?,
        )
        .await
        .context("failed to get Kubernetes API JWKS")?;

    let pubkey = data_encoding::HEXLOWER.encode(signing_key.verifying_key().as_bytes());

    let seq = chrono::Utc::now().timestamp();
    let jwks_item = MutableItem::new(signing_key.clone(), jwks.as_bytes(), seq, Some(SALT_JWKS));
    let config_item = MutableItem::new(
        signing_key,
        openid_config.as_bytes(),
        seq,
        Some(SALT_OPENID_CONFIG),
    );

    let dht = Dht::client()?.as_async();

    dht.put_mutable(jwks_item, None)
        .await
        .context("put_mutable jwks failed")?;
    dht.put_mutable(config_item, None)
        .await
        .context("put_mutable config failed")?;

    println!(
        "published jwks len={}, config len={}, seq={seq}, pubkey={pubkey}",
        jwks.len(),
        openid_config.len()
    );

    Ok(())
}
