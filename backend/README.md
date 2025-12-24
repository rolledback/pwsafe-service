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
# Run with default configuration (uses testdata/ directory)
./bin/pwsafe-service

# Or run directly without building
go run cmd/pwsafe-service/main.go
```

The service will start on `http://localhost:8080` by default.

## Configuration

Configure the service using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `PWSAFE_DIRECTORY` | Directory containing .psafe3 files | `./testdata` |
| `PWSAFE_PORT` | Server port | `8080` |
| `PWSAFE_HOST` | Server host | `localhost` |

Example:
```bash
export PWSAFE_DIRECTORY=/path/to/safes
export PWSAFE_PORT=3000
./bin/pwsafe-service
```

## API Endpoints

### List Password Safe Files
```bash
GET /api/safes
```
Returns array of available .psafe3 files with metadata.

### Unlock Password Safe
```bash
POST /api/safes/{filename}/unlock
Content-Type: application/json

{
  "password": "your-master-password"
}
```
Returns tree structure of groups and entries with UUIDs.

### Get Entry Password
```bash
POST /api/safes/{filename}/entry
Content-Type: application/json

{
  "password": "your-master-password",
  "entryUuid": "c4dcfb52-b944-f141-af96-b746f184afe2"
}
```
Returns the password for the specified entry.

## Testing

### Run All Tests
```bash
go test ./...
```

### Run Tests with Verbose Output
```bash
go test ./... -v
```

### Run Tests with Coverage
```bash
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

### View Coverage in Browser
```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Test Files
Test .psafe3 files are located in `testdata/` directory:
- `simple.psafe3` - Single entry, password: `password`
- `three.psafe3` - Multiple groups/entries, password: `three3#;`

See `testdata/README.md` for complete documentation.

## Manual API Testing

### Example: List safes
```bash
curl http://localhost:8080/api/safes | jq .
```

### Example: Unlock safe
```bash
curl -X POST http://localhost:8080/api/safes/simple.psafe3/unlock \
  -H "Content-Type: application/json" \
  -d '{"password":"password"}' | jq .
```

### Example: Get entry password
```bash
curl -X POST http://localhost:8080/api/safes/simple.psafe3/entry \
  -H "Content-Type: application/json" \
  -d '{"password":"password","entryUuid":"c4dcfb52-b944-f141-af96-b746f184afe2"}' | jq .
```

## Development Workflow

1. **Make changes** to code in `internal/` or `cmd/`, add tests if applicable
2. **Run tests** to verify changes: `go test ./...`
3. **Build** the application: `go build -o bin/pwsafe-service cmd/pwsafe-service/main.go`
4. **Test manually** as needed
5. **Commit** your changes

## Architecture Notes

- **Stateless Design**: Password safe files are opened, read, and closed on every request (no in-memory caching)
- **Security**: Master passwords are required for each operation and are not stored
- **Entry Identification**: Entries are identified by UUID (not by path/title)
- **Group Structure**: Groups are parsed from the gopwsafe library's dot-separated group paths
