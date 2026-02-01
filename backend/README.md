# pwsafe-service Backend

Go backend service for the pwsafe-service project, providing RESTful APIs for accessing Password Safe (.psafe3) files.

## Development Prerequisites

- **Go**: Version 1.25.5 or later
- **curl**: For API testing (optional)
- **jq**: For JSON formatting in tests (optional)

Verify Go installation:
```bash
go version
```

## Getting Started

### 1. Install Dependencies

```bash
cd backend
go mod download
```

### 2. Build the Application

```bash
go build -o bin/pwsafe-service cmd/pwsafe-service/main.go
```

### 3. Run the Service

```bash
# Run the built binary
./bin/pwsafe-service

# Or run directly without building
go run cmd/pwsafe-service/main.go
```

The service will start on `http://localhost:8080` by default.

## Configuration

Configure the service using environment variables:

| Variable | Description | Required |
|----------|-------------|----------|
| `PWSAFE_CONFIG_DIR` | Directory for configuration files (e.g., settings.json) | Yes |
| `PWSAFE_DATA_DIR` | Directory for safe files and synced data | Yes |
| `PWSAFE_STATIC_DIR` | Directory for frontend static files | Yes |
| `PWSAFE_PORT` | Server port (default: `8080`) | No |

## Testing

```bash
go test ./...
```

Test .psafe3 files are located in `testdata/` directory:
- `simple.psafe3` - Single entry, password: `password`
- `three.psafe3` - Multiple groups/entries, password: `three3#;`

See `testdata/README.md` for complete documentation.

## Development Workflow

1. **Make changes** to code in `internal/` or `cmd/`, add tests if applicable
3. **Build** the application: `go build -o bin/pwsafe-service cmd/pwsafe-service/main.go`
4. **Run tests** to verify changes: `go test ./...`
4. **Test with frontend** using e2e dev scripts
5. **Commit** your changes
