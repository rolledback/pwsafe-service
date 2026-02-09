# User Guide

This guide covers how to deploy and use pwsafe-service to access your Password Safe files through a web browser.

> ⚠️ **Security Notice**: This service has optional service-level authentication. If exposing this service to the internet, it is strongly recommended to enable authentication before doing so. Use of HTTPS is strongly recommended regardless if running in secured or unsecured mode.

## Security Modes

The first time you open the service in your browser, you'll be asked to choose a security mode.

### Unsecured Mode

No password is needed. Anyone on your network can access the service. This is best if you are only exposing the service on a trusted network.

### Secured Mode (alpha)

You set a password during setup. You must enter it each time you access the service. Your session expires after a few minutes of inactivity, and you'll need to re-enter the password.

### Changing Modes or Resetting Your Password

Remove the `auth` block from your `settings.json` and restart the service. You'll be prompted to choose a security mode again.

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
