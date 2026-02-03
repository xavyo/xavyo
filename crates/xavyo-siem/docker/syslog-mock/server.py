#!/usr/bin/env python3
"""
Syslog Mock Server

A mock server that accepts syslog messages over TCP and UDP (RFC 5424 format).
Provides an HTTP API for retrieving received messages during testing.
"""

import json
import os
import socket
import socketserver
import threading
import time
from datetime import datetime
from flask import Flask, request, jsonify

# Configuration from environment
TCP_PORT = int(os.environ.get("TCP_PORT", "514"))
UDP_PORT = int(os.environ.get("UDP_PORT", "514"))
API_PORT = int(os.environ.get("API_PORT", "8089"))
MAX_MESSAGES = int(os.environ.get("MAX_MESSAGES", "10000"))

# Thread-safe message storage
messages = []
messages_lock = threading.Lock()
start_time = time.time()

# Flask app for HTTP API
app = Flask(__name__)


class SyslogTCPHandler(socketserver.StreamRequestHandler):
    """Handler for TCP syslog connections."""

    def handle(self):
        """Process incoming TCP syslog messages."""
        client_ip = self.client_address[0]
        while True:
            try:
                # Read line-delimited messages
                line = self.rfile.readline()
                if not line:
                    break
                message = line.decode("utf-8", errors="replace").strip()
                if message:
                    store_message(message, "tcp", client_ip)
            except Exception as e:
                print(f"TCP handler error: {e}")
                break


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """Handler for UDP syslog datagrams."""

    def handle(self):
        """Process incoming UDP syslog messages."""
        data = self.request[0]
        client_ip = self.client_address[0]
        try:
            message = data.decode("utf-8", errors="replace").strip()
            if message:
                store_message(message, "udp", client_ip)
        except Exception as e:
            print(f"UDP handler error: {e}")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded TCP server for concurrent connections."""
    allow_reuse_address = True
    daemon_threads = True


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """Threaded UDP server for concurrent datagrams."""
    allow_reuse_address = True
    daemon_threads = True


def store_message(message: str, protocol: str, source_ip: str):
    """Store a received syslog message."""
    record = {
        "received_at": datetime.utcnow().isoformat() + "Z",
        "protocol": protocol,
        "source_ip": source_ip,
        "raw": message,
    }

    # Try to parse RFC 5424 format
    try:
        parsed = parse_rfc5424(message)
        if parsed:
            record["parsed"] = parsed
    except Exception:
        pass  # Store raw message even if parsing fails

    with messages_lock:
        # Enforce max messages limit
        if len(messages) >= MAX_MESSAGES:
            messages.pop(0)
        messages.append(record)


def parse_rfc5424(message: str) -> dict:
    """
    Parse RFC 5424 syslog message format.

    Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    Example: <134>1 2024-01-15T10:30:00Z xavyo idp - - - Test message
    """
    if not message.startswith("<"):
        return None

    # Extract priority
    pri_end = message.find(">")
    if pri_end == -1:
        return None

    try:
        pri = int(message[1:pri_end])
        facility = pri // 8
        severity = pri % 8
    except ValueError:
        return None

    rest = message[pri_end + 1:]
    parts = rest.split(" ", 7)

    if len(parts) < 7:
        return None

    result = {
        "priority": pri,
        "facility": facility,
        "severity": severity,
        "version": parts[0] if parts[0].isdigit() else None,
        "timestamp": parts[1] if len(parts) > 1 else None,
        "hostname": parts[2] if len(parts) > 2 else None,
        "app_name": parts[3] if len(parts) > 3 else None,
        "proc_id": parts[4] if len(parts) > 4 and parts[4] != "-" else None,
        "msg_id": parts[5] if len(parts) > 5 and parts[5] != "-" else None,
        "message": parts[7] if len(parts) > 7 else None,
    }

    return result


# Flask HTTP API routes

@app.route("/messages", methods=["GET"])
def get_messages():
    """
    Retrieve all received syslog messages.

    Query parameters:
        clear: If "true", clear messages after retrieval
        protocol: Filter by "tcp" or "udp"
    """
    clear = request.args.get("clear", "").lower() == "true"
    protocol = request.args.get("protocol", "").lower()

    with messages_lock:
        if protocol:
            result = [m for m in messages if m["protocol"] == protocol]
        else:
            result = list(messages)
        if clear:
            messages.clear()

    return jsonify(result), 200


@app.route("/messages/count", methods=["GET"])
def get_message_count():
    """Get the number of received messages."""
    with messages_lock:
        count = len(messages)
    return jsonify({"count": count}), 200


@app.route("/messages/clear", methods=["POST", "DELETE"])
def clear_messages():
    """Clear all stored messages."""
    with messages_lock:
        messages.clear()
    return jsonify({"text": "Messages cleared", "code": 0}), 200


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    uptime = time.time() - start_time
    return jsonify({
        "status": "healthy",
        "service": "syslog-mock",
        "version": "1.0.0",
        "uptime_seconds": round(uptime, 2),
        "messages_stored": len(messages),
        "tcp_port": TCP_PORT,
        "udp_port": UDP_PORT,
    }), 200


@app.route("/", methods=["GET"])
def root():
    """Root endpoint with service info."""
    return jsonify({
        "service": "syslog-mock",
        "description": "Mock syslog server (TCP/UDP) for testing",
        "endpoints": {
            f"TCP:{TCP_PORT}": "Syslog TCP receiver (RFC 5424)",
            f"UDP:{UDP_PORT}": "Syslog UDP receiver (RFC 5424)",
            "GET /messages": "Retrieve stored messages",
            "GET /messages/count": "Get message count",
            "POST /messages/clear": "Clear stored messages",
            "GET /health": "Health check",
        },
    }), 200


def start_tcp_server():
    """Start the TCP syslog server."""
    server = ThreadedTCPServer(("0.0.0.0", TCP_PORT), SyslogTCPHandler)
    print(f"TCP syslog server listening on port {TCP_PORT}")
    server.serve_forever()


def start_udp_server():
    """Start the UDP syslog server."""
    server = ThreadedUDPServer(("0.0.0.0", UDP_PORT), SyslogUDPHandler)
    print(f"UDP syslog server listening on port {UDP_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    print(f"Starting Syslog Mock Server")
    print(f"TCP Port: {TCP_PORT}, UDP Port: {UDP_PORT}, API Port: {API_PORT}")
    print(f"Max messages: {MAX_MESSAGES}")

    # Start syslog servers in background threads
    tcp_thread = threading.Thread(target=start_tcp_server, daemon=True)
    udp_thread = threading.Thread(target=start_udp_server, daemon=True)
    tcp_thread.start()
    udp_thread.start()

    # Run Flask API server in main thread
    app.run(host="0.0.0.0", port=API_PORT, threaded=True)
