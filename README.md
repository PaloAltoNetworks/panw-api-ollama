# panw-api-ollama

![file](https://github.com/user-attachments/assets/b54e6622-97e7-4ef8-8cd7-09dd2c5d89f3)

A proxy that sits in front of [Ollama](https://ollama.com/) and sends prompts and responses to the Palo Alto Networks Prisma AIRS AI Runtime API (API Intercept) for scanning before they reach the model or the user.

> **Community proof-of-value project.** panw-api-ollama is an open-source sample integration, not a supported Palo Alto Networks product. Use it to evaluate and demo AI Runtime scanning with Ollama. Report issues here on GitHub, not through Palo Alto Networks support.

## What it does

Point your client (for example [OpenWebUI](https://openwebui.com/)) at the proxy instead of Ollama. The proxy forwards everything to Ollama, and on the routes below it scans the content first. Depending on your AI Runtime security profile, a scan can block or mask:

- Prompt injection
- Data leakage (DLP, PII)
- Malicious code and URLs
- Harmful or toxic content

Blocked prompts never reach the model. Blocked or masked responses are replaced before they reach the client, including in streaming mode.

## What is scanned

Only these routes are scanned:

| Route | Scanned |
|---|---|
| `POST /api/chat` | prompt (all messages) and response |
| `POST /api/generate` | prompt, `system`, `template`, and response |
| `POST /api/embeddings`, `POST /api/embed` | input |

Every other path is forwarded to Ollama **without scanning**: model management (`/api/tags`, `/api/pull`, ...), and the OpenAI/Anthropic compatibility endpoints (`/v1/chat/completions`, `/v1/messages`, `/v1/embeddings`). If clients must not reach those, set `PASSTHROUGH_DISABLED=1` and every unhandled path returns `404`.

## Install

### Docker (recommended)

See the [Docker setup guide](docker/README.md).

### From source

1. Build:

   ```bash
   git clone https://github.com/PaloAltoNetworks/panw-api-ollama.git
   cd panw-api-ollama
   cargo build --release
   ```

2. Get an AI Runtime API Intercept key and a security profile name: follow [this tutorial](https://docs.paloaltonetworks.com/ai-runtime-security/activation-and-onboarding/ai-runtime-security-api-intercept-overview/onboard-api-runtime-security-api-intercept-in-scm) (step 13 gives the API key).

3. Configure:

   ```bash
   cp config.yaml.example config.yaml
   ```

   Then set at least:

   ```yaml
   ollama:
     base_url: "http://localhost:11434"

   security:
     api_key: "your-api-key"
     profile_name: "your-profile-name"
   ```

   Unknown keys in `config.yaml` are rejected at startup, so stick to the keys in `config.yaml.example`.

4. Run:

   ```bash
   ./target/release/panw-api-ollama
   ```

   The proxy listens on port `11435` by default.

   Slow hardware or reasoning models: the proxy gives up on Ollama after `STREAM_CHUNK_TIMEOUT_SECS` (default `300`) without receiving data. A non-streaming request sends nothing until the answer is complete, so raise it (or set `0` to disable) if long answers fail with `503`.

5. Point your client at `http://localhost:11435` instead of Ollama's `11434`. In OpenWebUI: Admin Settings > Connections, add an Ollama server with that URL (or set [`OLLAMA_BASE_URLS`](https://docs.openwebui.com/getting-started/env-configuration#ollama_base_urls)).

## Demo: with and without scanning

`config-examples/` contains an OpenWebUI setup that exposes the same model twice, once through the proxy and once directly against Ollama, for side-by-side demos:

- `config-1747909231428.json`: OpenWebUI connections, models prefixed `PANW` go through the proxy, `NOPAWN` go straight to Ollama.
- `PANW.llama2-uncensored_latest-1747909321539.json` and `NOPAWN.llama2-uncensored_latest-1747909327080.json`: the matching model configurations.

## Smoke tests

End-to-end tests live in `tests/smoke.rs` (benign and malicious payloads, streaming and non-streaming, chat, generate, embeddings). They are `#[ignore]`d so `cargo test` stays offline.

```bash
# proxy on localhost:11435, Ollama on :11434
cargo test --test smoke -- --ignored --nocapture

# different proxy / model
BASE_URL=http://my-proxy:11435 \
  MODEL=llama3.1:8b \
  EMBED_MODEL=nomic-embed-text \
  cargo test --test smoke -- --ignored --nocapture
```

## Resources

- [Prisma AIRS AI Runtime documentation](https://docs.paloaltonetworks.com/ai-runtime-security)
- [Scan API reference](https://pan.dev/prisma-airs/scan/api/)
- [CHANGELOG](CHANGELOG.md)
