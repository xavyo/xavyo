//! Mock syslog servers for integration testing.
//!
//! Provides TCP, TLS, and UDP mock servers that capture received messages
//! for validation in tests.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// Mock TCP syslog server that captures received messages.
pub struct MockTcpSyslogServer {
    addr: SocketAddr,
    messages: Arc<Mutex<Vec<String>>>,
    shutdown: CancellationToken,
    _handle: tokio::task::JoinHandle<()>,
}

impl MockTcpSyslogServer {
    /// Start a mock TCP syslog server on the specified port.
    /// Use port 0 to let the OS assign an available port.
    pub async fn start(port: u16) -> Self {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .expect("Failed to bind TCP listener");
        let addr = listener.local_addr().expect("Failed to get local address");
        let messages: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let shutdown = CancellationToken::new();

        let messages_clone = Arc::clone(&messages);
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_clone.cancelled() => {
                        break;
                    }
                    result = listener.accept() => {
                        if let Ok((stream, _)) = result {
                            let messages_inner = Arc::clone(&messages_clone);
                            let shutdown_inner = shutdown_clone.clone();
                            tokio::spawn(async move {
                                Self::handle_connection(stream, messages_inner, shutdown_inner).await;
                            });
                        }
                    }
                }
            }
        });

        Self {
            addr,
            messages,
            shutdown,
            _handle: handle,
        }
    }

    async fn handle_connection(
        stream: TcpStream,
        messages: Arc<Mutex<Vec<String>>>,
        shutdown: CancellationToken,
    ) {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();

        loop {
            line.clear();
            tokio::select! {
                _ = shutdown.cancelled() => {
                    break;
                }
                result = reader.read_line(&mut line) => {
                    match result {
                        Ok(0) => break, // Connection closed
                        Ok(_) => {
                            let msg = line.trim_end().to_string();
                            if !msg.is_empty() {
                                messages.lock().await.push(msg);
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }

    /// Get the server's address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get all received messages.
    pub async fn received_messages(&self) -> Vec<String> {
        self.messages.lock().await.clone()
    }

    /// Clear received messages.
    pub async fn clear_messages(&self) {
        self.messages.lock().await.clear();
    }

    /// Shutdown the server.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

/// Mock TLS syslog server that captures received messages.
pub struct MockTlsSyslogServer {
    addr: SocketAddr,
    messages: Arc<Mutex<Vec<String>>>,
    shutdown: CancellationToken,
    _handle: tokio::task::JoinHandle<()>,
}

impl MockTlsSyslogServer {
    /// Start a mock TLS syslog server on the specified port.
    /// Use port 0 to let the OS assign an available port.
    pub async fn start(port: u16, cert_pem: &[u8], key_pem: &[u8]) -> Self {
        let identity = native_tls::Identity::from_pkcs8(cert_pem, key_pem)
            .expect("Failed to create TLS identity");
        let acceptor =
            native_tls::TlsAcceptor::new(identity).expect("Failed to create TLS acceptor");
        let acceptor = tokio_native_tls::TlsAcceptor::from(acceptor);

        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .expect("Failed to bind TCP listener");
        let addr = listener.local_addr().expect("Failed to get local address");
        let messages: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let shutdown = CancellationToken::new();

        let messages_clone = Arc::clone(&messages);
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_clone.cancelled() => {
                        break;
                    }
                    result = listener.accept() => {
                        if let Ok((stream, _)) = result {
                            let messages_inner = Arc::clone(&messages_clone);
                            let shutdown_inner = shutdown_clone.clone();
                            let acceptor_clone = acceptor.clone();
                            tokio::spawn(async move {
                                if let Ok(tls_stream) = acceptor_clone.accept(stream).await {
                                    Self::handle_tls_connection(tls_stream, messages_inner, shutdown_inner).await;
                                }
                            });
                        }
                    }
                }
            }
        });

        Self {
            addr,
            messages,
            shutdown,
            _handle: handle,
        }
    }

    async fn handle_tls_connection(
        stream: tokio_native_tls::TlsStream<TcpStream>,
        messages: Arc<Mutex<Vec<String>>>,
        shutdown: CancellationToken,
    ) {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();

        loop {
            line.clear();
            tokio::select! {
                _ = shutdown.cancelled() => {
                    break;
                }
                result = reader.read_line(&mut line) => {
                    match result {
                        Ok(0) => break, // Connection closed
                        Ok(_) => {
                            let msg = line.trim_end().to_string();
                            if !msg.is_empty() {
                                messages.lock().await.push(msg);
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }

    /// Get the server's address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get all received messages.
    pub async fn received_messages(&self) -> Vec<String> {
        self.messages.lock().await.clone()
    }

    /// Clear received messages.
    pub async fn clear_messages(&self) {
        self.messages.lock().await.clear();
    }

    /// Shutdown the server.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

/// Mock UDP syslog server that captures received messages.
pub struct MockUdpSyslogServer {
    addr: SocketAddr,
    messages: Arc<Mutex<Vec<String>>>,
    shutdown: CancellationToken,
    _handle: tokio::task::JoinHandle<()>,
}

impl MockUdpSyslogServer {
    /// Start a mock UDP syslog server on the specified port.
    /// Use port 0 to let the OS assign an available port.
    pub async fn start(port: u16) -> Self {
        let socket = UdpSocket::bind(format!("127.0.0.1:{}", port))
            .await
            .expect("Failed to bind UDP socket");
        let addr = socket.local_addr().expect("Failed to get local address");
        let messages: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let shutdown = CancellationToken::new();

        let messages_clone = Arc::clone(&messages);
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                tokio::select! {
                    _ = shutdown_clone.cancelled() => {
                        break;
                    }
                    result = socket.recv_from(&mut buf) => {
                        if let Ok((len, _)) = result {
                            if let Ok(msg) = std::str::from_utf8(&buf[..len]) {
                                messages_clone.lock().await.push(msg.to_string());
                            }
                        }
                    }
                }
            }
        });

        Self {
            addr,
            messages,
            shutdown,
            _handle: handle,
        }
    }

    /// Get the server's address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get all received messages.
    pub async fn received_messages(&self) -> Vec<String> {
        self.messages.lock().await.clone()
    }

    /// Clear received messages.
    pub async fn clear_messages(&self) {
        self.messages.lock().await.clear();
    }

    /// Shutdown the server.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

/// A mock server that can be configured to fail a certain number of times.
pub struct FailingMockServer {
    addr: SocketAddr,
    failures_remaining: Arc<std::sync::atomic::AtomicU32>,
    messages: Arc<Mutex<Vec<String>>>,
    shutdown: CancellationToken,
    _handle: tokio::task::JoinHandle<()>,
}

impl FailingMockServer {
    /// Start a mock TCP server that fails the first N requests.
    pub async fn start(port: u16, fail_first_n: u32) -> Self {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .expect("Failed to bind TCP listener");
        let addr = listener.local_addr().expect("Failed to get local address");
        let messages: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let failures_remaining = Arc::new(std::sync::atomic::AtomicU32::new(fail_first_n));
        let shutdown = CancellationToken::new();

        let messages_clone = Arc::clone(&messages);
        let failures_clone = Arc::clone(&failures_remaining);
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_clone.cancelled() => {
                        break;
                    }
                    result = listener.accept() => {
                        if let Ok((stream, _)) = result {
                            let remaining = failures_clone.load(std::sync::atomic::Ordering::SeqCst);
                            if remaining > 0 {
                                failures_clone.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                                // Close connection immediately to simulate failure
                                drop(stream);
                            } else {
                                // Accept and read message
                                let messages_inner = Arc::clone(&messages_clone);
                                tokio::spawn(async move {
                                    let mut reader = BufReader::new(stream);
                                    let mut line = String::new();
                                    if let Ok(_) = reader.read_line(&mut line).await {
                                        let msg = line.trim_end().to_string();
                                        if !msg.is_empty() {
                                            messages_inner.lock().await.push(msg);
                                        }
                                    }
                                });
                            }
                        }
                    }
                }
            }
        });

        Self {
            addr,
            failures_remaining,
            messages,
            shutdown,
            _handle: handle,
        }
    }

    /// Get the server's address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get remaining failure count.
    pub fn failures_remaining(&self) -> u32 {
        self.failures_remaining
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get all received messages.
    pub async fn received_messages(&self) -> Vec<String> {
        self.messages.lock().await.clone()
    }

    /// Shutdown the server.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_mock_tcp_server_receives_messages() {
        let server = MockTcpSyslogServer::start(0).await;
        let addr = server.addr();

        // Connect and send message
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"test message 1\n").await.unwrap();
        stream.write_all(b"test message 2\n").await.unwrap();
        stream.flush().await.unwrap();

        // Wait for messages to be processed
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let messages = server.received_messages().await;
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0], "test message 1");
        assert_eq!(messages[1], "test message 2");

        server.shutdown();
    }

    #[tokio::test]
    async fn test_mock_udp_server_receives_messages() {
        let server = MockUdpSyslogServer::start(0).await;
        let addr = server.addr();

        // Send UDP messages
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.send_to(b"udp message 1", addr).await.unwrap();
        socket.send_to(b"udp message 2", addr).await.unwrap();

        // Wait for messages to be processed
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let messages = server.received_messages().await;
        assert_eq!(messages.len(), 2);
        assert!(messages.contains(&"udp message 1".to_string()));
        assert!(messages.contains(&"udp message 2".to_string()));

        server.shutdown();
    }

    #[tokio::test]
    async fn test_failing_mock_server() {
        let server = FailingMockServer::start(0, 2).await;
        let addr = server.addr();

        // First two connections should fail
        let result1 = TcpStream::connect(addr).await;
        assert!(result1.is_ok()); // Connection succeeds but server closes it
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let result2 = TcpStream::connect(addr).await;
        assert!(result2.is_ok());
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        assert_eq!(server.failures_remaining(), 0);

        // Third connection should succeed
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"success message\n").await.unwrap();
        stream.flush().await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let messages = server.received_messages().await;
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0], "success message");

        server.shutdown();
    }
}
