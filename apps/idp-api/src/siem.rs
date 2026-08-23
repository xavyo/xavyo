//! Honesty flags for SIEM live (Kafka) export.
//!
//! Batch export via `/governance/siem` is independent of these flags.
//! Real-time Kafka consumption of audit events is not started in this
//! process: `SiemEventConsumer` lives in `xavyo-siem` (no `xavyo-events`
//! dependency), and idp-api does not wire it.

/// Whether live Kafka-backed SIEM export *could* be compiled in.
///
/// Returns `kafka_configured` only when the Kafka consumer start path is
/// compiled (`kafka` feature). The default idp-api build has no Kafka
/// feature, so this is always `false`. This is not the same as a consumer
/// actually running — see [`siem_realtime_consumer_started`].
#[must_use]
pub fn siem_live_export_available(kafka_configured: bool) -> bool {
    cfg!(feature = "kafka") && kafka_configured
}

/// Whether a real-time SIEM Kafka consumer was started in this process.
///
/// Always `false` until `SiemEventConsumer` is wired (requires depending on
/// `xavyo-siem` and mapping Kafka events). Do not treat Kafka being
/// configured as live SIEM export.
#[must_use]
pub fn siem_realtime_consumer_started() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn siem_live_export_available_false_when_kafka_not_configured() {
        assert!(!siem_live_export_available(false));
    }

    #[test]
    fn siem_live_export_available_without_kafka_feature() {
        #[cfg(not(feature = "kafka"))]
        {
            assert!(
                !siem_live_export_available(true),
                "default build must not claim live SIEM export"
            );
        }
        #[cfg(feature = "kafka")]
        {
            assert!(
                siem_live_export_available(true),
                "kafka feature compiles the consumer start path"
            );
        }
    }

    #[test]
    fn siem_live_realtime_consumer_is_not_started() {
        assert!(
            !siem_realtime_consumer_started(),
            "SiemEventConsumer is not wired in idp-api"
        );
    }
}
