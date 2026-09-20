# CONNECT-IP diagnostics JSONL schema v2

Pipeline JSONL records carry `schema_version: 2`. Runtime data is represented by
typed QUIC, scheduler, GSO, queue, and TUN structures; the public record keeps
no connection identifier, client identity, address, packet number, or payload.

`downstream_gap` and `upstream_gap` are computed only between adjacent stages
in their own direction. The legacy `largest_pipeline_gap` JSON field remains
temporarily for compatibility and is deprecated; it combines the two
directional results and new consumers must use the directional fields.

Counter `total` values are process-lifetime cumulative values maintained across
connection generations. `delta` is the increase since the previous interval.
Active depth, congestion window, bytes in flight, RTT, and PMTU remain
instantaneous aggregates over currently active sessions.
