# Snowflake

**Slug:** `snowflake`
**Category:** Data-lake target (not a detection vendor)
**Pricing posture:** Consumption-based (credits per compute second + storage). Free trial available (30-day, $400 in credits). Enterprise contracts for production use.
**Last verified:** 2026-05-04

---

## Product Overview

Snowflake is a cloud data platform, not a security product. In the equilibrium context, Snowflake is the **SQL-over-normalized-logs target**: the landing zone for security telemetry (Kubernetes audit logs, process events, image pull events, etc.) that security teams query using standard SQL for threat hunting, detection engineering, and compliance reporting.

Snowflake's relevance to equilibrium is as the **data lake tier** of a tiered detection architecture:
- **Streaming tier** (Falco, vendor SIEM): real-time alerting on individual events
- **Lake tier (Snowflake)**: hunt queries, statistical baselines, correlated multi-day investigations

Snowflake launched a dedicated **Cybersecurity workload** offering that packages ecosystem partner integrations (e.g., Hunters.AI, Anvilogic) for SOC use cases on top of the core data platform.

Sources: https://www.snowflake.com/en/resources/solution-brief/security-data-lake-with-advanced-threat-detection/ (fetched 2026-05-04), https://www.snowflake.com/resource/best-practices-for-security-log-ingestion-and-data-normalization-in-snowflake/ (search result), https://www.securityweek.com/snowflake-launches-cybersecurity-workload-find-threats-across-massive-data-sets/ (search result)

---

## Detection Model

**SQL:**
All detection logic in equilibrium's Snowflake vendor_detection blocks is expressed as standard SQL (ANSI SQL with Snowflake extensions). Snowflake SQL supports:
- CTEs (`WITH` clauses) for multi-step query decomposition
- Variant/semi-structured data queries (`request_object:spec:containers[0]:image::string`)
- JSON path traversal for Kubernetes audit log fields stored as VARIANT columns
- Window functions, `DATEADD`, `DATEDIFF` for time-windowed analytics
- Stored procedures and UDFs for encapsulating detection logic
- Streams and tasks for near-real-time incremental processing (append-only change tracking)
- Dynamic Data Masking for credential-safe sharing

**Detection authoring pattern (equilibrium model):**
```sql
-- Normalized landing table: K8S_AUDIT.PUBLIC.EVENTS
-- One row per audit event; VARIANT column holds request_object
SELECT ...
FROM K8S_AUDIT.PUBLIC.EVENTS
WHERE verb = 'create' AND object_resource = 'pods'
  AND event_time >= DATEADD(day, -7, CURRENT_TIMESTAMP())
```

**Detections are hunt queries or scheduled tasks**, not real-time streaming rules. This is the primary architectural difference from other vendors in this report.

**QUERY_LANGUAGES mapping:**
- `sql`: the canonical equilibrium enum value

---

## Telemetry Sources

Snowflake does not collect telemetry itself. It is a landing zone. Common ingestion patterns for Kubernetes security telemetry:

| Source | Ingestion Pattern | Snowflake Table Type |
|---|---|---|
| Kubernetes API server audit logs | Fluent Bit DaemonSet -> S3/GCS -> Snowpipe (auto-ingest) | K8S_AUDIT.PUBLIC.EVENTS (VARIANT) |
| Container runtime events (process, file, network) | Agent (Falco, Sysdig, Upwind) -> S3/Kafka -> Snowpipe | K8S_RUNTIME.PUBLIC.EVENTS |
| Image pull events | Admission controller logs -> S3 -> Snowpipe | K8S.PUBLIC.IMAGE_PULLS |
| CI/CD build attestations | Pipeline -> S3 -> Snowpipe | CI.PUBLIC.BUILD_ATTESTATIONS |
| Cloud provider logs (CloudTrail, GCP Audit) | CloudTrail -> S3 -> Snowpipe; or Snowflake Connector for CloudTrail | CLOUD_LOGS.* |

**MITRE Data Source mappings** are implicit: the data source is determined by what is loaded into each table, not by Snowflake itself.

---

## Container / Kubernetes Coverage Specifically

Snowflake has no native Kubernetes sensor or agent. Coverage depends entirely on what the operating team ingests.

**Recommended ingestion for equilibrium use cases:**

1. **Kubernetes audit logs** (for T1609, T1610, T1611 audit-plane detection): Fluent Bit DaemonSet or cloud-provider managed export (GKE Audit -> BigQuery -> Snowflake via data sharing, or GKE Audit -> Cloud Storage -> Snowpipe; EKS CloudWatch -> Firehose -> S3 -> Snowpipe).

2. **Runtime process events** (for T1609 process-side, T1611 syscall-side): A runtime sensor (Falco, Sysdig, Upwind) must ship events to S3 or Kafka; Snowpipe or Kafka connector lands them in Snowflake.

3. **Image pull events** (for T1525 provenance gap detection): Admission controller (Gatekeeper, Kyverno) logs or kubelet events.

4. **CI build attestations** (for T1525 digest provenance): Sigstore Rekor entries fetched from transparency log, or in-toto attestations from CI pipeline artifacts.

**Snowflake-native Kubernetes-specific features:**
- Snowpipe Streaming (low-latency, sub-second latency ingestion for streaming use cases)
- Streams + Tasks for incremental detection queries (runs on schedule or triggered by table changes)

---

## Public API Surface

Snowflake exposes a full REST API (SQL API v2) and JDBC/ODBC/Snowpark connectors:

- **SQL API:** `POST /api/v2/statements` -- submit a SQL statement for async execution; poll `GET /api/v2/statements/{statementHandle}` for results
- **Auth:** Key-pair authentication (RSA private key + public key registered in account) or OAuth 2.0
- **Python Snowpark / Snowflake Connector:** native programmatic query execution
- **Rate limits:** Not formally documented; governed by warehouse size and concurrency limits

**Relevance for equilibrium:** The SQL API allows equilibrium to execute hunt queries programmatically against a customer's Snowflake instance and retrieve results in JSON. The query itself is the detection content; Snowflake is the execution engine.

Sources: https://docs.snowflake.com/en/developer-guide/sql-api/overview (known from Snowflake documentation; not fetched in this session)

---

## Documentation References

- https://www.snowflake.com/en/resources/solution-brief/security-data-lake-with-advanced-threat-detection/ (security data lake brief)
- https://www.snowflake.com/resource/best-practices-for-security-log-ingestion-and-data-normalization-in-snowflake/ (ingestion best practices)
- https://www.securityweek.com/snowflake-launches-cybersecurity-workload-find-threats-across-massive-data-sets/ (cybersecurity workload announcement)
- https://www.anvilogic.com/snowflake (SOC on Snowflake pattern)
- https://osinger.medium.com/cloud-visibility-for-your-security-data-lake-bc510c390cfa (cloud visibility patterns)
- https://github.com/CrowdStrike/Kubernetes-FluentBit-Logging-Falcon-Logscale-Integration (example Fluent Bit K8s log pipeline, analogous to Snowflake pattern)

---

## Confidence and Gaps

**Confirmed:**
- Snowflake is a data platform, not a security detection vendor
- SQL is the query language; standard ANSI SQL plus Snowflake extensions
- Snowpipe supports automatic ingestion from S3/GCS/Azure Blob
- VARIANT columns support JSON/semi-structured data (required for K8s audit logs)
- Streams and Tasks enable incremental, scheduled detection queries
- Free 30-day trial with $400 in credits

**Likely:**
- The equilibrium SQL detection patterns for K8s audit logs are architecturally sound for Snowflake, assuming the landing table schema matches (`K8S_AUDIT.PUBLIC.EVENTS` with appropriate columns)
- Snowpipe Streaming provides sub-second latency ingestion suitable for near-real-time use

**Unknown / gaps:**
- The specific normalized schema for K8s audit logs in Snowflake is not standardized across customers; each organization defines their own table structure. The schemas in equilibrium's SQL queries are illustrative examples, not a standard.
- Whether Snowflake has a native K8s audit log connector (vs. requiring Fluent Bit / Firehose pipeline) is unconfirmed in fetched sources.
- Snowflake's Cybersecurity workload partner ecosystem (Hunters.AI, Anvilogic, etc.) may provide managed detection-as-data-lake schemas, but this is not confirmed from fetched sources.
