# User Guide

This guide covers how to deploy and use pwsafe-service to access your Password Safe files through a web browser.

> ⚠️ **Security Notice**: This service has no built-in authentication beyond the master password required to open each safe. It is intended for **local or private network use only**. Do not expose it to the public internet.

## What is pwsafe-service?

pwsafe-service is a web service that provides browser-based access to [Password Safe](https://pwsafe.org/) (.psafe3) files. It allows you to view and copy passwords without installing a client application.

**Key Features:**
- Read-only access to your password safe files
- Sync safes from remote sources
- Browse entries organized by groups
- Copy passwords to clipboard with one click
- Runs in a Docker container

## Installation

### Prerequisites

- Docker

### Create Directories

The service uses two volume mounts:

| Path | Description |
|------|-------------|
| `/config` | Configuration files |
| `/data` | Safe files and other data |

You should have separate directories for both. For local only usage, there are no installation steps required for either directory.

To configure for remote safes usage, see [Providers](providers.md) for setup instructions.

### Docker Compose

Create a `docker-compose.yml` file:

```yaml
services:
  pwsafe:
    image: ghcr.io/rolledback/pwsafe-service:latest
    ports:
      - "8080:8080"
    volumes:
      - /opt/pwsafe/config:/config:ro
      - /opt/pwsafe/data:/data
    restart: unless-stopped
```

And then use Docker to start the service.

## Usage

### Accessing the Web Interface

Open your browser and navigate to the host machine's address and the configured port.

### Adding Password Safes

Use the **Add Safes** button to view options for adding/uploading safes.

- **Local Upload**: Use **Upload** option to upload .psafe3 files directly.
- **Remote Safes**: See [Providers](providers.md) for setup instructions.

### Viewing Passwords

1. Select a password safe file from the list on the homepage
2. Enter the master password to unlock the safe
3. Browse entries
