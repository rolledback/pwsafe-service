# User Guide

This guide covers how to deploy and use pwsafe-service to access your Password Safe files through a web browser.

> ⚠️ **Security Notice**: This service has optional authentication. If exposing this service to the internet, it is strongly recommended to enable authentication before doing so. Use of HTTPS is strongly recommended.

## What is pwsafe-service?

pwsafe-service is a service that provides a web UI to access [Password Safe](https://pwsafe.org/) (.psafe3) files. It allows you to view and copy passwords without installing a client application.

### Key Features

- Read-only access to your password safe files
- Sync safes from remote sources
- Browse entries organized by groups
- Copy passwords to clipboard with one click
- Runs in a Docker container

## Prerequisites

- Docker

## Installation Steps

### Create Directories

The service uses two volume mounts:

| Path | Description |
|------|-------------|
| `/config` | Configuration files |
| `/data` | Safe files and other data |

It is recommended to have separate directories for both.

### Docker Compose

Create a `docker-compose.yml` file:

```yaml
services:
  pwsafe:
    image: ghcr.io/rolledback/pwsafe-service:latest
    ports:
      - "8080:8080"
    volumes:
      - /opt/pwsafe/config:/config
      - /opt/pwsafe/data:/data
    restart: unless-stopped
```

## First Start

Use Docker to start the service via your `docker-compose.yml` file.

> ⚠️ **Security Notice**: The first time you run the service, you should **not** expose it to the internet. Only expose the service to the internet if you have completed setting up authentication.

Once running, open your browser and navigate to the host machine's address and the configured port.

### Set Up Authentication

The first time you open the web UI in your browser, you'll be asked how you'd like to set up authentication. You can either:

- **Skip Authentication**: No password is needed to access the service. Anyone who can reach the service can access it. This should only be used if you are only exposing the service on a trusted network.
- **Set Up Password**: A password, of your choice, will be needed to access the service. This should be used if you are exposing the service to the internet, or if there are users on your network who shouldn't access your password safes or service settings.

Regardless of which choice you make, you'll always have to enter the password for any password safe you choose to access through the service.

### Changing Authentication or Resetting Your Password

Remove the `auth.mode` field from your [settings file](configuration.md) and restart the service. You will again be prompted to set up authentication the next time you open the web UI in your browser.

### Additional Authentication Settings

Refer to the [authentication configuration section](configuration.md#authentication-auth) for information on additional authentication settings.

## Usage

### Adding Password Safes

Use the **Add Safes** button to view options for adding/uploading safes.

- **Local Upload**: Use **Upload** option to upload .psafe3 files directly.
- **Remote Safes**: See [Providers](providers.md) for setup instructions.

### Viewing Passwords

1. Select a password safe file from the list on the homepage
2. Enter the master password to unlock the safe
3. Browse entries
