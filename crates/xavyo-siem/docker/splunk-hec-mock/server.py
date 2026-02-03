#!/usr/bin/env python3
"""
Splunk HTTP Event Collector (HEC) Mock Server

A lightweight mock server that simulates the Splunk HEC API for testing purposes.
Accepts events via POST /services/collector/event and stores them in memory.
"""

import json
import os
import time
from datetime import datetime
from threading import Lock
from flask import Flask, request, jsonify

app = Flask(__name__)

# Configuration from environment
HEC_TOKEN = os.environ.get("HEC_TOKEN", "test-token-12345")
PORT = int(os.environ.get("PORT", "8088"))
MAX_EVENTS = int(os.environ.get("MAX_EVENTS", "10000"))

# Thread-safe event storage
events = []
events_lock = Lock()
start_time = time.time()


def validate_token(auth_header: str) -> bool:
    """Validate the Splunk authorization token."""
    if not auth_header:
        return False
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "splunk":
        return False
    return parts[1] == HEC_TOKEN


@app.route("/services/collector/event", methods=["POST"])
def collector_event():
    """
    Accept events via Splunk HEC protocol.

    Expected headers:
        Authorization: Splunk <token>
        Content-Type: application/json

    Expected body:
        {"time": <epoch>, "host": "<hostname>", "source": "<source>",
         "sourcetype": "<type>", "event": {...}}
    """
    # Validate authorization
    auth_header = request.headers.get("Authorization", "")
    if not validate_token(auth_header):
        return jsonify({"text": "Invalid token", "code": 4}), 401

    # Parse event data
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"text": "Invalid JSON format", "code": 6}), 400

    # Store event with metadata
    event_record = {
        "received_at": datetime.utcnow().isoformat() + "Z",
        "payload": data,
        "source_ip": request.remote_addr,
    }

    with events_lock:
        # Enforce max events limit to prevent memory exhaustion
        if len(events) >= MAX_EVENTS:
            events.pop(0)  # Remove oldest event
        events.append(event_record)

    return jsonify({"text": "Success", "code": 0}), 200


@app.route("/services/collector/event/1.0", methods=["POST"])
def collector_event_v1():
    """Alternative HEC endpoint (v1.0 format)."""
    return collector_event()


@app.route("/events", methods=["GET"])
def get_events():
    """
    Retrieve all received events.

    Query parameters:
        clear: If "true", clear events after retrieval
    """
    clear = request.args.get("clear", "").lower() == "true"

    with events_lock:
        result = list(events)
        if clear:
            events.clear()

    return jsonify(result), 200


@app.route("/events/count", methods=["GET"])
def get_event_count():
    """Get the number of received events."""
    with events_lock:
        count = len(events)
    return jsonify({"count": count}), 200


@app.route("/events/clear", methods=["POST", "DELETE"])
def clear_events():
    """Clear all stored events."""
    with events_lock:
        events.clear()
    return jsonify({"text": "Events cleared", "code": 0}), 200


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint for container orchestration."""
    uptime = time.time() - start_time
    return jsonify({
        "status": "healthy",
        "service": "splunk-hec-mock",
        "version": "1.0.0",
        "uptime_seconds": round(uptime, 2),
        "events_stored": len(events),
    }), 200


@app.route("/", methods=["GET"])
def root():
    """Root endpoint with service info."""
    return jsonify({
        "service": "splunk-hec-mock",
        "description": "Mock Splunk HTTP Event Collector for testing",
        "endpoints": {
            "POST /services/collector/event": "Submit events (requires Splunk auth header)",
            "GET /events": "Retrieve stored events",
            "GET /events/count": "Get event count",
            "POST /events/clear": "Clear stored events",
            "GET /health": "Health check",
        },
    }), 200


if __name__ == "__main__":
    print(f"Starting Splunk HEC Mock Server on port {PORT}")
    print(f"HEC Token: {HEC_TOKEN[:4]}...{HEC_TOKEN[-4:]}")
    print(f"Max events: {MAX_EVENTS}")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
