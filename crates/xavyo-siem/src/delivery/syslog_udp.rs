//! Syslog UDP delivery worker.

use super::{DeliveryError, DeliveryResult, DeliveryWorker};
use async_trait::async_trait;
use std::time::Instant;
use tokio::net::UdpSocket;

/// Maximum UDP message size (65507 bytes = 65535 - 20 IP header - 8 UDP header).
const MAX_UDP_MESSAGE_SIZE: usize = 65507;

/// Syslog UDP delivery worker.
pub struct SyslogUdpWorker {
    host: String,
    port: u16,
}

impl SyslogUdpWorker {
    #[must_use] 
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }
}

#[async_trait]
impl DeliveryWorker for SyslogUdpWorker {
    async fn deliver(&self, payload: &str) -> Result<DeliveryResult, DeliveryError> {
        let start = Instant::now();

        if payload.len() > MAX_UDP_MESSAGE_SIZE {
            return Err(DeliveryError::MessageTooLarge {
                size: payload.len(),
                max: MAX_UDP_MESSAGE_SIZE,
            });
        }

        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| DeliveryError::ConnectionFailed(format!("UDP bind failed: {e}")))?;

        let addr = format!("{}:{}", self.host, self.port);
        socket
            .send_to(payload.as_bytes(), &addr)
            .await
            .map_err(|e| {
                DeliveryError::SendFailed(format!("UDP send to {addr} failed: {e}"))
            })?;

        let latency = start.elapsed().as_millis() as u64;
        Ok(DeliveryResult::success(latency))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syslog_udp_worker_creation() {
        let worker = SyslogUdpWorker::new("siem.example.com".to_string(), 514);
        assert_eq!(worker.host, "siem.example.com");
        assert_eq!(worker.port, 514);
    }

    #[tokio::test]
    async fn test_udp_message_too_large() {
        let worker = SyslogUdpWorker::new("127.0.0.1".to_string(), 514);
        let oversized = "x".repeat(MAX_UDP_MESSAGE_SIZE + 1);
        let result = worker.deliver(&oversized).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            DeliveryError::MessageTooLarge { size, max } => {
                assert_eq!(size, MAX_UDP_MESSAGE_SIZE + 1);
                assert_eq!(max, MAX_UDP_MESSAGE_SIZE);
            }
            _ => panic!("Expected MessageTooLarge error"),
        }
    }

    #[tokio::test]
    async fn test_udp_send_to_localhost() {
        // Bind a receiver to verify the message is sent
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = receiver.local_addr().unwrap().port();

        let worker = SyslogUdpWorker::new("127.0.0.1".to_string(), port);
        let result = worker.deliver("test syslog message").await;
        assert!(result.is_ok());

        let delivery = result.unwrap();
        assert!(delivery.success);

        // Verify the message was received
        let mut buf = [0u8; 1024];
        let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
        let received = std::str::from_utf8(&buf[..len]).unwrap();
        assert_eq!(received, "test syslog message");
    }
}
