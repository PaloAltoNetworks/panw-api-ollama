# panw-api-ollama

![file](https://github.com/user-attachments/assets/b54e6622-97e7-4ef8-8cd7-09dd2c5d89f3)

Enhance your Ollama deployment with enterprise-grade AI security using Palo Alto Networks Prisma AIRS AI Runtime API Intercept.

## What is this?

panw-api-ollama is a security proxy that sits between your [OpenWebUI](https://openwebui.com/) interface and [Ollama](https://ollama.com/) instance. It works by intercepting all prompts and responses, analyzing them with Palo Alto Networks' Prisma AIRS AI Runtime security technology, and protecting your system from:

- Prompt injection attacks
- Data exfiltration attempts
- Harmful or toxic content
- Personally identifiable information (PII) leakage
- Other AI-specific security threats

The best part? It's completely transparent to your existing setup - [Ollama](https://ollama.com/) will still work just as before, but with an added layer of security.

## Why use this?

- **Prevent Security Incidents**: Detect and block malicious prompts before they reach your LLM
- **Protect Sensitive Data**: Ensure responses don't contain unauthorized information
- **Maintain Compliance**: Implement guardrails for safe AI usage in enterprise environments
- **Visibility**: Gain insights into usage patterns and potential threats

## Use Cases

- **Secure AI models in production**: Validate prompt requests and responses to protect deployed AI models.
- **Detect data poisoning**: Identify contaminated training data before fine-tuning.
- **Protect adversarial input**: Safeguard AI agents from malicious inputs and outputs while maintaining workflow flexibility.
- **Prevent sensitive data leakage**: Use API-based threat detection to block sensitive data leaks during AI interactions.

## Upgrading to 0.17.0

> **Breaking change for operators with custom `config.yaml` files.**
>
> 0.17.0 enables strict YAML decoding (`#[serde(deny_unknown_fields)]`) on
> the `Config`, `ServerConfig`, `OllamaConfig`, and `SecurityConfig`
> structs. Any field present in `config.yaml` that is **not** documented
> in `config.yaml.example` will cause the proxy to fail at startup with
> an error naming the offending field.
>
> Why: this catches typos like `hsot:` instead of `host:` or stale keys
> from older versions, instead of silently using a default and producing
> puzzling runtime behavior.
>
> Mitigation: the error message names the offending field; remove it
> from `config.yaml` and restart. Strict decoding is **only** applied
> to local config files - PANW response payloads continue to decode
> leniently to absorb additive upstream schema changes.
>
> See `CHANGELOG.md` for the full 0.17.0 change set.

## Installation Options

There are two ways to install and run panw-api-ollama:

### Option 1: Docker Setup (Recommended)

Docker is the recommended installation method as it:
- Handles all permissions automatically
- Provides a pre-configured environment
- Eliminates system-level dependency issues
- Makes updates and maintenance easier

For Docker-based deployment, please refer to the instructions in the [Docker Setup README](docker/README.md).

### Option 2: Build from Source

If you prefer to build from source or can't use Docker, you can build the Rust application directly. Note that this method may require additional system configuration and could face permission issues depending on your setup.

#### Step 1: Build

```
git clone https://github.com/PaloAltoNetworks/panw-api-ollama.git
cd panw-api-ollama
cargo build --release
```

### Step 2: Get a Palo Alto Networks Prisma AIRS AI Runtime API Intercept Key

Follow [this tutorial](https://docs.paloaltonetworks.com/ai-runtime-security/activation-and-onboarding/ai-runtime-security-api-intercept-overview/onboard-api-runtime-security-api-intercept-in-scm), specifically step 13, to obtain your API key.

### Step 3: Configure

Rename `config.yaml.example` to `config.yaml` and update it with your API key:

```
cp config.yaml.example config.yaml
```

Then edit the file to add your Palo Alto Networks Prisma AIRS AI Runtime API Intercept key:

```yaml
pan_api:
  key: "your-pan-api-key-here"
```

### Step 4: Update OpenWebUI

For non-Docker installations, you need to change the Ollama port in OpenWebUI from 11434 to 11435:

1. Go to Settings > Server Management in the OpenWebUI interface
2. Add a new Ollama server with URL: `http://localhost:11435` 
3. Save your configuration

Alternatively, update your OpenWebUI environment settings:
[OpenWebUI Environment Configuration](https://docs.openwebui.com/getting-started/env-configuration#ollama_base_urls)

### Step 5: Download a model

Before using the service, make sure you have a model available:

```bash
ollama pull llama2-uncensored:latest
```

### Step 6: Run

```bash
./target/release/panw-api-ollama
```

You're all set! You can now use OpenWebUI as normal, but with enterprise security scanning all interactions.

## Configuration Examples

The project includes example configuration files in the `config-examples` directory that demonstrate different setup options:

### OpenWebUI Global Configuration

The `config-1747909231428.json` file shows how to set up OpenWebUI with both secured and unsecured Ollama connections:

```json
{
    "ollama": {
        "enable": true,
        "base_urls": [
            "http://panw-api-ollama:11435",  // Secure connection through panw-api-ollama
            "http://host.docker.internal:11434"  // Direct connection to Ollama
        ],
        "api_configs": {
            "0": {
                "enable": true,
                "tags": [],
                "prefix_id": "PANW",  // Models with this prefix use the security proxy
                "model_ids": [
                    "llama2-uncensored:latest"
                ],
                "key": ""
            },
            "1": {
                "enable": true,
                "tags": [],
                "prefix_id": "NOPAWN",  // Models with this prefix bypass the security proxy
                "model_ids": [
                    "nomic-embed-text:latest",
                    "llama2-uncensored:latest"
                ],
                "key": ""
            }
        }
    }
}
```

### Model Configurations

Two example model configurations are included to demonstrate before/after comparisons:

1. `PANW.llama2-uncensored_latest-1747909321539.json` - A model using the security proxy
2. `NOPAWN.llama2-uncensored_latest-1747909327080.json` - The same model bypassing the security proxy

These configurations allow you to perform side-by-side comparisons and demonstrations of how the Palo Alto Networks Prisma AIRS AI Runtime Security affects the model responses.

## Resources

- [Product Information](https://www.paloaltonetworks.com/prisma/prisma-ai-runtime-security)
- [Documentation](https://docs.paloaltonetworks.com/ai-runtime-security)
- [API Reference](https://pan.dev/prisma-airs/scan/api/)

## Support

For issues related to this integration, please file an issue on GitHub.
For questions about Palo Alto Networks Prisma AIRS AI Runtime API Intercept, please refer to official support channels.
