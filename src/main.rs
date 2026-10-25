use anyhow::{Context, Result};
use clap::Parser;
use filtr::{AppState, Config, routers};
use std::net::SocketAddr;
use tokio::{net::TcpListener, sync::watch};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    // Environment mutation must finish before Tokio starts worker threads.
    match dotenvy::from_path(".env") {
        Ok(()) => {}
        Err(dotenvy::Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => anyhow::bail!("cannot load .env; check file permissions and syntax"),
    }
    run()
}

#[tokio::main]
async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("filtr=info")),
        )
        .json()
        .init();
    let config = Config::parse();
    config.validate()?;
    let listener = TcpListener::bind(config.listen)
        .await
        .context("cannot bind public listener")?;
    let admin_listener = TcpListener::bind(config.admin_listen)
        .await
        .context("cannot bind admin listener")?;
    let state = AppState::new(config).await?;
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("cannot register SIGTERM handler")?;
    let (public, admin) = routers(state);
    tracing::info!(public = %listener.local_addr()?, admin = %admin_listener.local_addr()?, "Filtr listening");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut admin_shutdown = shutdown_rx.clone();
    let mut public_shutdown = shutdown_rx;
    let mut public_server = tokio::spawn(async move {
        axum::serve(
            listener,
            public.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = public_shutdown.changed().await;
        })
        .await
    });
    let mut admin_server = tokio::spawn(async move {
        axum::serve(admin_listener, admin)
            .with_graceful_shutdown(async move {
                let _ = admin_shutdown.changed().await;
            })
            .await
    });
    tokio::select! {
        result = &mut public_server => { shutdown_tx.send_replace(true); result??; anyhow::bail!("public listener stopped unexpectedly"); }
        result = &mut admin_server => { shutdown_tx.send_replace(true); result??; anyhow::bail!("admin listener stopped unexpectedly"); }
        _ = async {
            #[cfg(unix)]
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            #[cfg(not(unix))]
            let _ = tokio::signal::ctrl_c().await;
        } => { shutdown_tx.send_replace(true); }
    }
    match tokio::time::timeout(std::time::Duration::from_secs(15), async {
        public_server.await??;
        admin_server.await??;
        Ok::<_, anyhow::Error>(())
    })
    .await
    {
        Ok(result) => result?,
        Err(_) => tracing::warn!("graceful shutdown deadline exceeded"),
    }
    Ok(())
}
