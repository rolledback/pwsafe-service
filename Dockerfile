# Stage 1: Build Frontend
FROM node:24-alpine AS frontend-builder

WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# Stage 2: Build Backend
FROM golang:1.25.5-alpine AS backend-builder

WORKDIR /backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -o pwsafe-service cmd/pwsafe-service/main.go

# Stage 3: Production Runtime
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy backend binary
COPY --from=backend-builder /backend/pwsafe-service .

# Copy frontend static files
COPY --from=frontend-builder /frontend/dist ./static

# Create directory for safes (can be mounted as volume)
RUN mkdir -p /safes

# Environment variables with defaults
ENV PWSAFE_DIRECTORY=/safes
ENV PWSAFE_PORT=8080
ENV PWSAFE_HOST=0.0.0.0
ENV PWSAFE_STATIC_DIR=/app/static

# Default port exposure
EXPOSE 8080

CMD ["/app/pwsafe-service"]
