use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::Response,
    routing::get,
};
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::metrics::Metrics;

#[derive(serde::Serialize)]
struct MetricsResponse {
    active_connections: usize,
    total_connections: usize,
    bytes_uploaded: u64,
    bytes_downloaded: u64,
    dns_cache_hit: u64,
    dns_cache_miss: u64,
}

pub async fn run(listener: TcpListener, metrics: Arc<Metrics>) {
    let app = Router::new().route("/ws", get(upgrade)).with_state(metrics);

    if let Err(error) = axum::serve(listener, app).await {
        error!(
            service = "websocket",
            event = "server_error",
            error = %error
        );
    }
}

async fn upgrade(ws: WebSocketUpgrade, State(metrics): State<Arc<Metrics>>) -> Response {
    info!(service = "websocket", event = "upgrade_request");

    ws.on_upgrade(move |socket| handle_socket(socket, metrics))
}

async fn handle_socket(mut socket: WebSocket, metrics: Arc<Metrics>) {
    info!(service = "websocket", event = "client_connected");

    let mut timer = tokio::time::interval(Duration::from_secs(1));
    let mut streaming_metrics = false;

    loop {
        tokio::select! {
            result = socket.recv() => {
                match result {
                    Some(Ok(Message::Text(text))) => {
                        info!(
                            service = "websocket",
                            event = "message_received",
                            message = %text
                        );

                        if text.trim() == "metrics" {
                            streaming_metrics = true;

                            info!(
                                service = "websocket",
                                event = "metrics_streaming_started"
                            );
                        }
                    }

                    Some(Ok(Message::Close(reason))) => {
                        info!(
                            service = "websocket",
                            event = "client_closed",
                            reason = ?reason
                        );

                        break;
                    }

                    Some(Ok(Message::Binary(data))) => {
                        info!(
                            service = "websocket",
                            event = "binary_message_received",
                            bytes = data.len()
                        );
                    }

                    Some(Ok(Message::Ping(data))) => {
                        info!(
                            service = "websocket",
                            event = "ping_received",
                            bytes = data.len()
                        );
                    }

                    Some(Ok(Message::Pong(data))) => {
                        info!(
                            service = "websocket",
                            event = "pong_received",
                            bytes = data.len()
                        );
                    }

                    Some(Err(error)) => {
                        error!(
                            service = "websocket",
                            event = "receive_error",
                            error = %error
                        );

                        break;
                    }

                    None => {
                        info!(
                            service = "websocket",
                            event = "client_disconnected"
                        );

                        break;
                    }
                }
            }

            _ = timer.tick(), if streaming_metrics => {
                let response = MetricsResponse {
                    active_connections: metrics.active_connection(),
                    total_connections: metrics.total_connection(),
                    bytes_uploaded: metrics.uploaded(),
                    bytes_downloaded: metrics.downloaded(),
                    dns_cache_hit: metrics.total_dns_cache_hit(),
                    dns_cache_miss: metrics.total_dns_cache_miss(),
                };

                let json = match serde_json::to_string(&response) {
                    Ok(json) => json,

                    Err(error) => {
                        error!(
                            service = "websocket",
                            event = "metrics_serialization_error",
                            error = %error
                        );

                        continue;
                    }
                };

                info!(
                    service = "websocket",
                    event = "sending_metrics"
                );

                if let Err(error) = socket
                    .send(Message::Text(json.into()))
                    .await
                {
                    error!(
                        service = "websocket",
                        event = "send_error",
                        error = %error
                    );

                    break;
                }
            }
        }
    }

    info!(service = "websocket", event = "connection_finished");
}
