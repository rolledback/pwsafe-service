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

Copy the `.example` e2e dev scripts and configure as needed. These scripts build the backend and frontend, and then start the backend which serves the compiled frontend.

**Note:** The scripts do not install dependencies. Run `go mod download` in `backend/` and `npm install` in `frontend/` first. 

### Component-Specific Development

For detailed instructions on developing each component:

- **Backend**: See [backend/README.md](../backend/README.md)
- **Frontend**: See [frontend/README.md](../frontend/README.md)

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
