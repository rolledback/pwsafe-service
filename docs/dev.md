# Developer Guide

This guide covers development of pwsafe-service.

## Architecture

pwsafe-service consists of:

- **Backend** (`backend/`): Go REST API server that handles safe file operations
- **Frontend** (`frontend/`): React web application

## Development

### End-to-End Development

The easiest way to run the full stack locally is with the e2e dev scripts:

```bash
# Windows
.\e2e-dev.ps1

# Linux/macOS
./e2e-dev.sh
```

These scripts install dependencies, build the backend and frontend, and then start the backend, which serves the compiled frontend. Runtime configuration and data are stored under `runtime/`.

If `runtime/config/settings.json` does not exist, both scripts create it with the mock provider enabled.
They set `baseUrl` to `http://localhost:${PWSAFE_PORT}`. Existing settings files stay unchanged, including empty files.
Both scripts start the backend from `backend/` so the mock provider can read its test fixtures.
On first start, choose an authentication mode in the web UI.

### Component-Specific Development

For detailed instructions on developing each component:

- **Backend**: See [backend/README.md](../backend/README.md)
- **Frontend**: See [frontend/README.md](../frontend/README.md)

### Import Test Safes

Use [import-test-safes.sh](../import-test-safes.sh) or [import-test-safes.ps1](../import-test-safes.ps1) to upload all `.psafe3` files from `backend/testdata/` to a running service. Both scripts overwrite files with the same name. Use them only with a development instance.

The Bash script requires Bash, curl, and jq. The PowerShell script requires PowerShell 7 or later, without external dependencies. Complete the initial service setup before use.

```bash
# Default service URL: http://localhost:8080
./import-test-safes.sh

# Custom service URL
./import-test-safes.sh https://localhost:8443
```

```powershell
# Default service URL: http://localhost:8080
.\import-test-safes.ps1

# Custom service URL
.\import-test-safes.ps1 https://localhost:8443
```

If service authentication is enabled, both scripts prompt for the service password. Both obtain a CSRF token and stop at the first failed request. The Bash script removes its temporary session cookie file on exit. The PowerShell script keeps session cookies in memory.

### Working with Providers

To develop existing providers or add new ones, see [Providers](providers.md) as a primer. When changing or adding new providers, you must update that documentation.

If you are unable to set up any of the currently supported providers, you can enable a mock provider by updating the [providers block](configuration.md#providers-providers) in your settings file to include:

```json
{
  "providers": {
    "mock": {}
  }
}
```

The mock provider loads the safes from the `backend/testdata/` directory. Therefore the mock provider does not work for a deployed instance of the service.
