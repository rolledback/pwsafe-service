# pwsafe-service Frontend

React frontend for the pwsafe-service project, providing a web interface for accessing Password Safe (.psafe3) files.

## Development Prerequisites

- **Node.js**: Version 24 or later
- **npm**: Comes with Node.js

Verify Node.js installation:

```bash
node --version
npm --version
```

## Getting Started

### 1. Install Dependencies

```bash
cd frontend
npm install
```

### 2. Build

```bash
npm run build
```

### 3. Test Changes

The frontend is served from the backend. Use the e2e dev scripts to run the backend, serving your locally built frontend:

```bash
# Windows
.\e2e-dev.ps1

# Linux/macOS
./e2e-dev.sh
```

See [docs/dev.md](../docs/dev.md) for more details.

## Development Workflow

1. **Make changes** to code in `src/`
2. **Build**: `npm run build`
3. **Test changes** using e2e dev scripts
4. **Format code**: `npm run format`
5. **Commit** your changes
