# Changelog

All notable changes to panw-api-ollama are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.17.2] - 2026-07-20

### Dependencies
- Refresh Cargo.lock to latest semver-compatible versions (no manifest range
  changes): tokio 1.52.3 -> 1.53.1, serde 1.0.228 -> 1.0.229, serde_json
  1.0.149 -> 1.0.151, thiserror 2.0.18 -> 2.0.19, uuid 1.23.1 -> 1.24.0, plus
  transitive updates.

## [0.17.1] - 2026-07-20

### Security
- Fix policy-override bypass on `/api/generate` (CWE-693). The handler scanned
  only `prompt`, forwarding `system` and `template` to Ollama unscanned. Per
  Ollama's spec, `system` overrides the Modelfile, so an attacker-supplied
  `system` message could override operator security policy without ever
  reaching the PANW scanner. `assess_generate_prompt` now scans `prompt`,
  `system`, and `template`, matching the all-messages scan already done on
  `/api/chat`. Reported by Yuval Fradkin <yuvalfradkin@gmail.com>.

### Tests
- Add `generate_malicious_system_blocked_or_masked` smoke regression covering a
  malicious `system` field with a benign prompt.

## [0.17.0] - 2026-05-19

### Security
- Wrap the PANW API key in `secrecy::SecretString` so it cannot leak via
  `Debug`, `Display`, default `serde::Serialize`, or `format!`. The secret
  is exposed only at the HTTP send site via `expose_secret()`.
- Sanitize client-facing error responses. Ollama upstream failures, generic
  PANW security service errors, and internal-server-error paths no longer
  reflect raw `Display` text (which can include reqwest URLs, internal
  hostnames, or arbitrary strings) to the client. Full details remain in
  server-side error logs. User-actionable cases (`Forbidden`, `Unauthenticated`,
  `TooManyRequests`, `BlockedContent`) are unchanged.
- Redact PANW response bodies in operational logs. Raw bodies move from
  `debug!` to `trace!(target: "panw::raw_body")`; error logs include only a
  256-byte UTF-8-bounded excerpt with explicit truncation marker.

### Reliability
- `OllamaClient::new` and `SecurityClient::new` now return
  `Result<Self, reqwest::Error>` instead of panicking via `.expect(...)` when
  the underlying `reqwest::Client` build fails. Errors propagate cleanly to
  `main()`.

### Performance
- `create_security_assessment_future` no longer clones the `code_buffer` when
  it is empty - the dominant case for benign chat traffic.
- `extract_code_blocks` preallocates result and per-block buffers with
  `String::with_capacity(content.len())`, eliminating geometric reallocations
  on code-heavy responses.
- Release profile now uses `lto = "thin"`, `codegen-units = 1`, `strip = true`
  for ~5-15% throughput improvement on the streaming hot path.

### Configuration
- Strict YAML config decoding: typos in `config.yaml` (e.g. `hsot:` instead
  of `host:`) now fail at startup with the offending field named, instead of
  silently using a default. Strict decoding is **only** applied to local
  config; PANW response payloads continue to decode leniently to absorb
  additive upstream schema changes.
  - **Operator-visible breaking change**: any existing config.yaml containing
    keys outside the documented schema will fail to load. Mitigation: error
    message names the offending field, fix is one line.

### Tests
- Add 5 unit tests for handler utilities (`format_security_violation_message`,
  `log_llm_metrics`, `build_json_response`).
- Add 5 property assertions on `ScanResponse` shape covering all 7 prompt
  flags and all 8 response flags.
- Add 3 tests for `body_excerpt` truncation (length, marker, UTF-8 boundary).
- Total unit tests: 24 -> 38 across the merged stack.

### Deferred to 0.18.0
- Migration to Rust edition 2024 (intentionally not bundled with security
  fixes per release-cut review).
- Full handler integration tests requiring a mock `AppState` harness.
- Stream-level total timeout (needs product decision on partial-content
  flush behavior).
- Strict response decoding (`deny_unknown_fields` on PANW response schemas)
  remains intentionally **disabled** to absorb upstream additive changes.

## [0.16.0] - 2026-05-19

### Streaming reliability
- Fix empty replies on `/api/generate` streams.
- Fix crash when `stream` field is omitted on `/api/chat` or `/api/generate`.

### Performance
- Streamed completions trigger 1-3 scans instead of 30+.
- Removed busy-loop that pinned a CPU core during scans.

### Security
- HTTP timeouts, TLS 1.2 minimum, and `https_only` enforced for the
  Prisma AIRS client.
- Stricter scan validation: malformed Prisma AIRS responses (missing
  category or action) are rejected instead of silently passing through.
- Code-block scanning fix: first line of fenced code with a language tag
  (e.g. ```rust) is no longer dropped before scanning.

### Schema
- Support for the latest Prisma AIRS scan-service fields (`session_id`,
  `tool_detected`, agent metadata, `profile_id`, scan summary, tool
  detection details).

### Quality
- First test suite added (23 unit tests) with scan-service response fixtures.
- Dependencies refreshed: axum, tokio, tower-http, uuid, chrono, thiserror 2.x.
- Replaced archived `serde_yml` with maintained `serde_yaml_ng`.
