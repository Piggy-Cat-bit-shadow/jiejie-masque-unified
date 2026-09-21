# CONNECT-IP diagnostics

The former application-owned pipeline diagnostics JSONL format is removed from
the lean datapath. There is no `schema_version`, `largest_pipeline_gap`, queue
snapshot, or identity-bearing diagnostic record to consume. Transport-level
observability belongs to the maintained quic-go fork; use the service version
output and dependency provenance when identifying a deployment.
