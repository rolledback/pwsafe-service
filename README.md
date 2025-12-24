# pwsafe-service

A web service for [Password Safe](https://pwsafe.org/) that provides browser-based access to your password safe files.

## Overview

This project allows you to access and view your Password Safe (.psafe3) files through a web portal without installing the desktop application. The service provides a read-only interface to browse your password entries organized by groups.


## Quick Start

### Docker Run

```bash
# Pull the latest image
docker pull ghcr.io/rolledback/pwsafe-service:latest

# Run the container
docker run -d \
  --name pwsafe \
  -p 8080:8080 \
  -v /path/to/your/safes:/safes:ro \
  ghcr.io/rolledback/pwsafe-service:latest

# Access at http://localhost:8080/web/
```

### Docker Compose

Create a `docker-compose.yml`:

```yaml
services:
  pwsafe:
    image: ghcr.io/rolledback/pwsafe-service:latest
    ports:
      - "8080:8080"
    volumes:
      - ./safes:/safes:ro
    environment:
      - PWSAFE_DIRECTORY=/safes
      - PWSAFE_PORT=8080
      - PWSAFE_HOST=0.0.0.0
    restart: unless-stopped
```

Then run:

```bash
docker-compose up -d
```

## Usage

1. Open `http://localhost:8080/web/` in your browser
2. Select a password safe file from the list
3. Enter the master password to unlock
4. Browse entries
5. Click "Copy" to copy passwords to clipboard

## License

MIT License - see [LICENSE](LICENSE) file for details.
