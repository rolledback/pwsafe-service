package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rolledback/pwsafe-service/backend/internal/auth"
	"github.com/rolledback/pwsafe-service/backend/internal/config"
	"github.com/rolledback/pwsafe-service/backend/internal/handlers"
	"github.com/rolledback/pwsafe-service/backend/internal/middleware"
	"github.com/rolledback/pwsafe-service/backend/internal/provider"
	"github.com/rolledback/pwsafe-service/backend/internal/provider/mock"
	"github.com/rolledback/pwsafe-service/backend/internal/provider/onedrive"
	"github.com/rolledback/pwsafe-service/backend/internal/service"

	"golang.org/x/time/rate"
)

func main() {
	cfg := config.Load()

	log.Printf("pwsafe-service - Password Safe Web Service")
	log.Printf("Config Directory: %s", cfg.ConfigDirectory)
	log.Printf("Data Directory: %s", cfg.DataDirectory)
	log.Printf("Server: %s:%s", cfg.ServerHost, cfg.ServerPort)

	// Load settings from config directory
	settings, err := config.LoadSettings(cfg.ConfigDirectory)
	if err != nil {
		log.Fatalf("Failed to load settings: %v", err)
	}
	log.Printf("Base URL: %s", settings.BaseURL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	safeService := service.NewSafeService(cfg.DataDirectory)
	safeHandler := handlers.NewSafeHandler(safeService)

	// Prime the safe ID cache on startup
	if _, err := safeService.ListSafes(); err != nil {
		log.Printf("Warning: failed to prime safe ID cache: %v", err)
	}

	// Create provider registry and register factories
	registry := provider.NewRegistry()
	registry.Register("onedrive", onedrive.Factory)
	registry.Register("mock", mock.Factory)

	// Discover providers from settings
	providers, err := registry.Discover(settings, cfg.DataDirectory)
	if err != nil {
		log.Fatalf("Failed to discover providers: %v", err)
	}

	// Parse sync interval from settings
	var syncInterval time.Duration
	if settings.SyncInterval != "" {
		parsed, err := time.ParseDuration(settings.SyncInterval)
		if err != nil {
			log.Fatalf("Invalid syncInterval %q: %v", settings.SyncInterval, err)
		}
		syncInterval = parsed
		log.Printf("Sync interval: %s", syncInterval)
	}

	// Create SyncableSafesService for each discovered provider
	services := make(map[string]*service.SyncableSafesService)
	for id, p := range providers {
		svc := service.NewSyncableSafesService(ctx, cfg.DataDirectory, p, syncInterval)
		services[id] = svc
		defer svc.Stop()
	}

	log.Printf("Discovered %d provider(s)", len(services))

	// Create providers handler
	providersHandler := handlers.NewProvidersHandler(services, safeService)

	// Create static provider handler (for upload/delete of static safes)
	staticProviderHandler := handlers.NewStaticProviderHandler(cfg.DataDirectory, safeService)

	// Create auth service
	authService := auth.NewAuthService(cfg.DataDirectory, cfg.ConfigDirectory, settings)
	authHandler := handlers.NewAuthHandler(authService)

	// Log TLS warning for secured mode
	if authService.GetMode() == "secured" {
		log.Printf("WARNING: Secured mode active — ensure HTTPS is configured to protect passwords in transit")
	}

	// Start session cleanup goroutine
	go authService.CleanupExpiredSessions(ctx)

	// General rate limiter
	rateLimiter := middleware.NewRateLimiter(ctx, rate.Limit(5), 5)

	// Strict rate limiter for password-sensitive endpoints
	strictRateLimiter := middleware.NewRateLimiter(ctx, rate.Limit(0.2), 2)

	// Generate API nonce token
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		log.Fatalf("Failed to generate API token: %v", err)
	}
	apiToken := hex.EncodeToString(tokenBytes)
	log.Printf("API token generated (changes on each restart)")

	// Read index.html once at startup for token injection
	indexHTML, err := os.ReadFile(cfg.StaticDir + "/index.html")
	if err != nil {
		log.Fatalf("Failed to read index.html: %v", err)
	}
	// Inject token into index.html template (insert script before </head>)
	// Uses a placeholder for the CSP nonce which is replaced per-request
	tokenScript := fmt.Sprintf(`<script nonce="%%NONCE%%">window.__PWSAFE_TOKEN="%s";</script>`, apiToken)
	indexHTMLTemplate := strings.Replace(string(indexHTML), "</head>", tokenScript+"</head>", 1)

	// Auth routes (no RequireAuth)
	http.HandleFunc("/api/auth/status", middleware.CORS(authHandler.Status))
	http.HandleFunc("/api/auth/setup", middleware.CORS(middleware.RequireToken(apiToken, strictRateLimiter.Limit(authHandler.Setup))))
	http.HandleFunc("/api/auth/login", middleware.CORS(middleware.RequireToken(apiToken, strictRateLimiter.Limit(authHandler.Login))))
	http.HandleFunc("/api/auth/logout", middleware.CORS(middleware.RequireToken(apiToken, middleware.RequireAuth(authService, authHandler.Logout))))

	// Protected API routes (wrapped with RequireAuth)
	http.HandleFunc("/api/safes", middleware.CORS(middleware.RequireToken(apiToken, middleware.RequireAuth(authService, rateLimiter.Limit(safeHandler.ListSafes)))))
	http.HandleFunc("/api/safes/", middleware.CORS(middleware.RequireToken(apiToken, middleware.RequireAuth(authService, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path[len(r.URL.Path)-7:] == "/unlock" {
			strictRateLimiter.Limit(safeHandler.UnlockSafe)(w, r)
		} else if r.URL.Path[len(r.URL.Path)-6:] == "/entry" {
			strictRateLimiter.Limit(safeHandler.GetEntryPassword)(w, r)
		} else {
			http.NotFound(w, r)
		}
	}))))

	// Provider routes (new generic API)
	http.HandleFunc("/api/providers", middleware.CORS(middleware.RequireToken(apiToken, middleware.RequireAuth(authService, rateLimiter.Limit(providersHandler.ListProviders)))))
	http.HandleFunc("/api/providers/static/", middleware.CORS(middleware.RequireToken(apiToken, middleware.RequireAuth(authService, rateLimiter.Limit(staticProviderHandler.Route)))))
	http.HandleFunc("/api/providers/", middleware.CORS(middleware.RequireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
		// Don't rate limit or auth-check callbacks (they come from OAuth redirects)
		if middleware.IsOAuthCallback(r.URL.Path) {
			providersHandler.Route(w, r)
		} else {
			middleware.RequireAuth(authService, rateLimiter.Limit(providersHandler.Route))(w, r)
		}
	})))

	// Resolve absolute static dir once for containment checks
	absStaticDir, err := filepath.Abs(cfg.StaticDir)
	if err != nil {
		log.Fatalf("Failed to resolve static dir: %v", err)
	}

	http.HandleFunc("/web/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[4:] // Remove "/web" prefix

		// For index.html or root, serve injected version with CSP nonce
		if path == "/" || path == "/index.html" {
			serveInjectedHTML(w, indexHTMLTemplate)
			return
		}

		// Sanitize path and verify containment within static dir
		fullPath := filepath.Join(cfg.StaticDir, filepath.FromSlash(path))
		absPath, err := filepath.Abs(fullPath)
		if err != nil || !strings.HasPrefix(absPath, absStaticDir+string(filepath.Separator)) {
			serveInjectedHTML(w, indexHTMLTemplate)
			return
		}

		// Check if file exists
		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			// File doesn't exist, serve injected index.html for SPA routing
			serveInjectedHTML(w, indexHTMLTemplate)
			return
		}

		// File exists, serve it
		fs := http.FileServer(http.Dir(cfg.StaticDir))
		http.StripPrefix("/web", fs).ServeHTTP(w, r)
	})

	// Redirect all non-/api routes to /web
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
			http.NotFound(w, r)
			return
		}
		if len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/web" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/web"+r.URL.Path, http.StatusMovedPermanently)
	})

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", cfg.ServerHost, cfg.ServerPort),
		Handler: middleware.Logging(middleware.SecurityHeaders(http.DefaultServeMux)),
	}

	// Graceful shutdown on SIGTERM/SIGINT (needed for coverage data flush)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		<-sigCh
		log.Printf("Shutting down server...")
		server.Close()
	}()

	log.Printf("Starting server on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// serveInjectedHTML serves the index.html template with a per-request CSP nonce.
func serveInjectedHTML(w http.ResponseWriter, htmlTemplate string) {
	nonceBytes := make([]byte, 16)
	io.ReadFull(rand.Reader, nonceBytes)
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)

	html := strings.Replace(htmlTemplate, "%NONCE%", nonce, -1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s'; img-src 'self' data:", nonce))
	w.Write([]byte(html))
}
