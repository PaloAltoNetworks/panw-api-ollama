# Docker Setup for panw-api-ollama

## Prerequisites

### Install Docker Desktop (Recommended)

We strongly recommend installing Docker Desktop as it provides:
- A user-friendly interface to manage containers
- Easy access to container logs through the UI
- Built-in container monitoring and management
- Simplified volume and network management

Download and install [Docker Desktop](https://www.docker.com/products/docker-desktop) for your platform (Windows, Mac, or Linux).

Alternative: If you prefer not to use Docker Desktop, you can install the Docker Engine directly, but you'll need to use command-line tools to manage containers and view logs.

## Components

This folder contains all Docker-related files for running the panw-api-ollama stack:
- Ollama: The AI model server
- panw-api-ollama: The security proxy 
- OpenWebUI: The web interface

## Docker Deployment Options Summary

| Configuration | Docker File | Description | Best For |
|---------------|------------|-------------|----------|
| Standard | `docker-compose.yaml` | All components (Ollama, panw-api-ollama, OpenWebUI) run in containers | Most platforms, simple setup |
| Windows with NVIDIA GPU | `docker-compose.win.yaml` | Same as standard but with NVIDIA GPU support for Ollama | Windows machines with NVIDIA GPU |
| Apple Silicon (Native) | `docker-compose.apple.yaml` | Ollama runs natively on macOS, other components in containers | Apple Silicon Macs (M1/M2/M3), best performance |

## Quick Start

### Step 1: Prepare configuration files

Copy the required configuration files within the docker folder:

```bash
# Copy environment variables file (required)
cp ../.env.example ./.env
```

### Step 2: Configure your environment variables

Edit the `.env` file in the root directory with your configuration:

```bash
# Required for security
SECURITY_API_KEY=your_panw_api_key_here
SECURITY_PROFILE_NAME=your_profile_name

# Optional configuration (defaults shown)
SERVER_HOST=0.0.0.0
SERVER_PORT=11435
SERVER_DEBUG_LEVEL=INFO
OLLAMA_BASE_URL=http://ollama:11434
SECURITY_BASE_URL=https://service.api.aisecurity.paloaltonetworks.com
SECURITY_APP_NAME=panw-api-ollama
SECURITY_APP_USER=docker
RUST_LOG=info

# OpenWebUI and Ollama settings
OPEN_WEBUI_PORT=3000
OLLAMA_DOCKER_TAG=latest
WEBUI_DOCKER_TAG=main
CUSTOM_CONFIG_PATH=./custom-config.json  # Path to your OpenWebUI config
```

### Step 3: Start the Docker stack

Choose one of the following deployment options based on your platform:

#### Standard Deployment (All Platforms)

```bash
cd docker
docker-compose up -d
```

This will start three containers:
- **ollama**: The Ollama service on port 11434 (internal only, not exposed to host)
  - Automatically downloads the llama2-uncensored:latest model on startup
- **panw-api-ollama**: The security broker service on port 11435 (internal only, not exposed to host)
- **open-webui**: The UI running on port 3000, connected to your security broker and exposed to the host system

#### Windows with NVIDIA GPU

For Windows users with NVIDIA GPUs, use the special Windows configuration file:

```bash
cd docker
docker-compose -f docker-compose.win.yaml up -d
```

This configuration includes NVIDIA GPU support for Ollama, enabling hardware acceleration.

#### Apple Silicon Native Installation (Recommended for M1/M2/M3 Macs)

For optimal performance on Apple Silicon Macs, a hybrid approach is recommended where:
- Ollama runs natively on macOS (not in Docker)
- panw-api-ollama and OpenWebUI run in containers

Follow these steps:

1. Install Ollama natively on your Mac:
   - Download and install from [ollama.com/download](https://ollama.com/download)

2. Start the native Ollama service and pull the model:
   ```bash
   # Start Ollama service in one terminal
   ollama serve

   # In a new terminal, pull the necessary model
   ollama pull llama2-uncensored:latest
   ```

3. Launch the Docker containers that will connect to your native Ollama:
   ```bash
   cd docker
   docker-compose -f docker-compose.apple.yaml up -d
   ```

This hybrid setup provides:
- Full hardware acceleration for Ollama on Apple Silicon
- The security and containerization benefits for the other components
- Better overall performance than running everything in containers

## Understanding Docker Compose Configurations

Each Docker Compose file is designed for specific use cases:

### docker-compose.yaml (Standard Configuration)

The default configuration suitable for most users, which:
- Runs all three components in containers: Ollama, panw-api-ollama, and OpenWebUI
- Connects OpenWebUI to panw-api-ollama using the internal Docker network
- panw-api-ollama connects to Ollama using the internal Docker network
- Automatically downloads the llama2-uncensored:latest model on startup

This setup is ideal for:
- First-time users
- Linux, macOS (Intel), and Windows without GPU
- Testing and development environments
- Production deployments on standard servers

### docker-compose.win.yaml (Windows with NVIDIA GPU)

Identical to the standard setup but adds NVIDIA GPU support for Ollama:
- Includes NVIDIA container runtime configurations
- Sets up GPU-related environment variables
- Makes the GPU available to the Ollama container
- All containers use the same networking as the standard setup

This configuration is essential for Windows users with NVIDIA GPUs who want hardware acceleration for their models.

### docker-compose.apple.yaml (Apple Silicon Hybrid)

A specialized configuration for Apple Silicon Macs that:
- **Does NOT include the Ollama container** - you run Ollama natively on macOS instead
- Configures panw-api-ollama to connect to your native Ollama via `host.docker.internal:11434`
- Runs panw-api-ollama and OpenWebUI in ARM64 containers for native performance
- Uses special host mapping to allow container-to-host communication

This hybrid approach provides significantly better performance than running Ollama in a container on Apple Silicon because:
1. Ollama can directly access Apple's Neural Engine and GPU
2. There's no virtualization overhead for the compute-intensive model inference
3. Native ARM64 execution is optimized for the hardware

**Important note:** When using this configuration, you must keep your native Ollama service running on your Mac as a prerequisite.

## Access OpenWebUI

Open your browser and navigate to:
```
http://localhost:3000
```

OpenWebUI will automatically connect to your panw-api-ollama broker, which then securely connects to Ollama.

Note: The Docker-specific hostnames like `panw-api-ollama` and `host.docker.internal` only work in Docker environments.

## Environment Variables

You can customize your Docker deployment using these environment variables:

### Required Environment Variables:
- `SECURITY_API_KEY`: Your Palo Alto Networks API key
- `SECURITY_PROFILE_NAME`: Your security profile name

### Optional Environment Variables:
- **Server Configuration**:
  - `SERVER_HOST`: Host to bind the server to (default: 0.0.0.0)
  - `SERVER_PORT`: Port to listen on (default: 11435)
  - `SERVER_DEBUG_LEVEL`: Logging level: INFO, DEBUG, ERROR (default: INFO)
  
- **Ollama Configuration**:
  - `OLLAMA_BASE_URL`: URL to connect to Ollama (default: http://ollama:11434)
  
- **Security Configuration**:
  - `SECURITY_BASE_URL`: Base URL for the security API (default: https://service.api.aisecurity.paloaltonetworks.com)
  - `SECURITY_APP_NAME`: Application name (default: panw-api-ollama)
  - `SECURITY_APP_USER`: Application user identifier (default: docker)
  
- **Docker Image Tags**:
  - `OLLAMA_DOCKER_TAG`: Specify the Ollama image version (default: latest)
  - `WEBUI_DOCKER_TAG`: Specify the OpenWebUI image version (default: main)
  
- **Port Mappings**:
  - `OPEN_WEBUI_PORT`: Change the port for OpenWebUI (default: 3000)
  - `PANW_API_PORT`: Change the port for panw-api-ollama (default: 11435)
  
- **Logging**:
  - `RUST_LOG`: Set the logging level for panw-api-ollama (default: info)

Example with custom settings:
```bash
OPEN_WEBUI_PORT=8080 RUST_LOG=debug SECURITY_APP_USER=custom-user docker-compose up -d
```

## GitHub Container Registry

This project publishes Docker images to the GitHub Container Registry (ghcr.io), making it easy to deploy without building the image yourself.

### Using the Pre-built Image

You can use the pre-built Docker image from GitHub Container Registry in your docker-compose.yaml:

```bash
# Pull and run using the latest image
docker-compose up -d
```

By default, docker-compose will use the latest image from `ghcr.io/paloaltonetworks/panw-api-ollama`. You can specify a different version tag using the `PANW_API_IMAGE` environment variable:

```bash
# Use a specific version
PANW_API_IMAGE=ghcr.io/paloaltonetworks/panw-api-ollama:v0.9.0 docker-compose up -d

# Or build from local source instead of using the registry
PANW_API_IMAGE='' docker-compose up -d
```

### Container Image Release Tags

The following tags are available for the Docker image:

- `latest`: Points to the most recent release
- `vX.Y.Z`: Specific version (e.g., `v0.9.0`)
- `vX.Y`: Minor version release (e.g., `v0.9`)
- `vX`: Major version release (e.g., `v0`)

## Additional Information

For more details about the panw-api-ollama project, including non-Docker installation methods, please refer to the [main README.md](../README.md) in the project root.
