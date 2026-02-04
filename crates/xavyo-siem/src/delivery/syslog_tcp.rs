//! Syslog TCP/TLS delivery worker.
//!
//! Maintains a persistent TLS connection to the syslog receiver,
//! reconnecting on failure. This avoids creating a new TLS handshake
//! per message.

use super::{DeliveryError, DeliveryResult, DeliveryWorker};
use async_trait::async_trait;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_native_tls::TlsStream;

/// Syslog TCP/TLS delivery worker with persistent connection.
pub struct SyslogTcpWorker {
    host: String,
    port: u16,
    tls_verify_cert: bool,
    /// Persistent TLS connection (reconnects on failure).
    conn: Mutex<Option<TlsStream<TcpStream>>>,
}

impl SyslogTcpWorker {
    #[must_use] 
    pub fn new(host: String, port: u16, tls_verify_cert: bool) -> Self {
        Self {
            host,
            port,
            tls_verify_cert,
            conn: Mutex::new(None),
        }
    }

    /// Establish a new TLS connection to the syslog receiver.
    async fn connect(&self) -> Result<TlsStream<TcpStream>, DeliveryError> {
        let addr = format!("{}:{}", self.host, self.port);
        let stream = TcpStream::connect(&addr).await.map_err(|e| {
            DeliveryError::ConnectionFailed(format!("TCP connect to {addr} failed: {e}"))
        })?;

        let connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(!self.tls_verify_cert)
            .build()
            .map_err(|e| DeliveryError::TlsError(e.to_string()))?;

        let connector = tokio_native_tls::TlsConnector::from(connector);

        let tls_stream = connector.connect(&self.host, stream).await.map_err(|e| {
            DeliveryError::TlsError(format!("TLS handshake with {} failed: {}", self.host, e))
        })?;

        Ok(tls_stream)
    }
}

#[async_trait]
impl DeliveryWorker for SyslogTcpWorker {
    async fn deliver(&self, payload: &str) -> Result<DeliveryResult, DeliveryError> {
        let start = Instant::now();
        let message = format!("{payload}\n");

        let mut guard = self.conn.lock().await;

        // Try to reuse existing connection
        if let Some(ref mut tls_stream) = *guard {
            match tls_stream.write_all(message.as_bytes()).await {
                Ok(()) => {
                    if let Err(e) = tls_stream.flush().await {
                        tracing::warn!("Syslog TCP flush failed, reconnecting: {}", e);
                        // Fall through to reconnect
                    } else {
                        let latency = start.elapsed().as_millis() as u64;
                        return Ok(DeliveryResult::success(latency));
                    }
                }
                Err(e) => {
                    tracing::warn!("Syslog TCP write failed, reconnecting: {}", e);
                    // Fall through to reconnect
                }
            }
        }

        // Connect (or reconnect) and send
        let mut tls_stream = self.connect().await?;
        tls_stream
            .write_all(message.as_bytes())
            .await
            .map_err(|e| DeliveryError::SendFailed(e.to_string()))?;
        tls_stream
            .flush()
            .await
            .map_err(|e| DeliveryError::SendFailed(e.to_string()))?;

        let latency = start.elapsed().as_millis() as u64;

        // Store the connection for reuse
        *guard = Some(tls_stream);

        Ok(DeliveryResult::success(latency))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syslog_tcp_worker_creation() {
        let worker = SyslogTcpWorker::new("siem.example.com".to_string(), 6514, true);
        assert_eq!(worker.host, "siem.example.com");
        assert_eq!(worker.port, 6514);
        assert!(worker.tls_verify_cert);
    }

    #[tokio::test]
    async fn test_syslog_tcp_connection_failure() {
        let worker = SyslogTcpWorker::new("127.0.0.1".to_string(), 1, false);
        let result = worker.deliver("test message").await;
        assert!(result.is_err());
    }
}
