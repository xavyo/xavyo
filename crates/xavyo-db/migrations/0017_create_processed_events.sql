-- Migration: Create processed_events table for event idempotence
-- Feature: 016-kafka-event-bus

-- Create processed_events table
CREATE TABLE IF NOT EXISTS processed_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL,
    consumer_group VARCHAR(255) NOT NULL,
    topic VARCHAR(255) NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique constraint ensures same event is only processed once per consumer group
    CONSTRAINT unique_event_consumer UNIQUE (event_id, consumer_group)
);

-- Index for fast lookup by event_id
CREATE INDEX IF NOT EXISTS idx_processed_events_event_id ON processed_events(event_id);

-- Index for cleanup/retention queries by processed_at
CREATE INDEX IF NOT EXISTS idx_processed_events_processed_at ON processed_events(processed_at);

-- Comment for documentation
COMMENT ON TABLE processed_events IS 'Tracks processed Kafka events for idempotence - prevents duplicate processing';
COMMENT ON COLUMN processed_events.event_id IS 'UUID of the event from the Kafka message envelope';
COMMENT ON COLUMN processed_events.consumer_group IS 'Kafka consumer group that processed this event';
COMMENT ON COLUMN processed_events.topic IS 'Kafka topic the event was consumed from';
COMMENT ON COLUMN processed_events.processed_at IS 'Timestamp when the event was successfully processed';
