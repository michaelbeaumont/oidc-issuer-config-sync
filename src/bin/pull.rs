use anyhow::{Context, Result};
use k8s_openapi::{api::core::v1::ConfigMap, serde_json::json};
use kube::{
    Api,
    api::{Patch, PatchParams},
};
use mainline::{Dht, async_dht::AsyncDht};
use oidc_issuer_config_sync::{SALT_JWKS, SALT_OPENID_CONFIG};
use std::env;
use tokio::signal::{self, unix::SignalKind};
use tokio_util::{future::FutureExt as _, sync::CancellationToken};

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

    let configmap_name = env::var("JWKS_SYNC_CONFIGMAP_NAME")
        .map_err(anyhow::Error::new)
        .expect("JWKS_SYNC_CONFIGMAP_NAME must be set");
    let configmap_namespace = env::var("JWKS_SYNC_CONFIGMAP_NAMESPACE")
        .map_err(anyhow::Error::new)
        .expect("JWKS_SYNC_CONFIGMAP_NAMESPACE must be set");

    let pubkey = env::var("JWKS_SYNC_PUBKEY").expect("JWKS_SYNC_PUBKEY must be set");
    println!("polling for {pubkey}");

    let pubkey: [u8; 32] = data_encoding::HEXLOWER
        .decode(pubkey.as_bytes())
        .context("pubkey is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("pubkey must be exactly 32 bytes"))?;

    let dht = Dht::builder().port(37881).build()?.as_async();

    let kube = kube::Client::try_default()
        .with_cancellation_token(&cancelled)
        .await
        .ok_or(anyhow::anyhow!("exited early"))?
        .context("building in-cluster kube client")?;

    let configmaps: Api<ConfigMap> = Api::namespaced(kube, &configmap_namespace);

    let res = poll_once(&configmap_name, &dht, &pubkey, &configmaps)
        .with_cancellation_token_owned(cancelled)
        .await
        .ok_or(anyhow::anyhow!("exited early"))?
        .context("couldn't poll");

    wait_cancel.abort();
    let _ = wait_cancel.await;

    res
}

async fn poll_once(
    configmap_name: &str,
    dht: &AsyncDht,
    pubkey: &[u8; 32],
    configmaps: &Api<ConfigMap>,
) -> Result<()> {
    let jwks_item = dht
        .get_mutable_most_recent(pubkey, Some(SALT_JWKS))
        .await
        .context("couldn't find JWKS in DHT")?;

    let jwks_seq = jwks_item.seq();
    let jwks = jwks_item.value();

    let item = dht
        .get_mutable_most_recent(pubkey, Some(SALT_OPENID_CONFIG))
        .await
        .context("couldn't find openid-configuration in DHT")?;

    let config_seq = item.seq();
    let config = item.value();

    println!(
        "accepted jwks len={} seq={jwks_seq}, config len={} seq={config_seq}",
        jwks.len(),
        config.len()
    );

    let patch = json!({
        "data": {
            "jwks.json": str::from_utf8(jwks).context("jwks.json should be a string")?,
            "openid-configuration": str::from_utf8(config).context("openid-configuration should be a string")?,
        },
    });
    configmaps
        .patch(
            configmap_name,
            &PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await?;
    Ok(())
}
