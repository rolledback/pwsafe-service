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
	"github.com/rolledback/pwsafe-service/backend/internal/provider/oauthstate"
	"github.com/rolledback/pwsafe-service/backend/internal/provider/onedrive"
	"github.com/rolledback/pwsafe-service/backend/internal/service"
	"github.com/rolledback/pwsafe-service/backend/internal/webpath"
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

	safeService := service.NewSafeService(cfg.DataDirectory, settings.GetMaxSafeFileSize())
	safeHandler := handlers.NewSafeHandler(safeService)

	// Prime the safe ID cache on startup
	if _, err := safeService.ListSafes(); err != nil {
		log.Printf("Warning: failed to prime safe ID cache: %v", err)
	}

	// Create OAuth state store
	oauthStore := oauthstate.NewStore(10 * time.Minute)

	// Inject oauthStore into each provider's config
	for _, providerConfig := range settings.Providers {
		providerConfig["oauthStore"] = oauthStore
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
		svc := service.NewSyncableSafesService(ctx, cfg.DataDirectory, p, syncInterval, settings.GetMaxSafeFileSize())
		services[id] = svc
		defer svc.Stop()
	}

	log.Printf("Discovered %d provider(s)", len(services))

	// Create providers handler
	providersHandler := handlers.NewProvidersHandler(services, safeService)

	// Create static provider handler (for upload/delete of static safes)
	staticProviderHandler := handlers.NewStaticProviderHandler(cfg.DataDirectory, safeService, settings.GetMaxSafeFileSize())

	// Create auth service
	authService := auth.NewAuthService(cfg.DataDirectory, cfg.ConfigDirectory, settings)
	authHandler := handlers.NewAuthHandler(authService, settings.TrustedProxies)

	// Log TLS warning when auth mode is enabled
	if authService.GetMode() == "enabled" {
		log.Printf("WARNING: Auth mode enabled — ensure HTTPS is configured to protect passwords in transit")
	}

	// Start session cleanup goroutine
	go authService.CleanupExpiredSessions(ctx)

	// Rate limiters
	limiters := middleware.NewRateLimiters(ctx, settings.RateLimiter, settings.TrustedProxies)

	// Generate CSRF token
	csrfTokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, csrfTokenBytes); err != nil {
		log.Fatalf("Failed to generate CSRF token: %v", err)
	}
	csrfToken := hex.EncodeToString(csrfTokenBytes)
	log.Printf("CSRF token generated (changes on each restart)")

	// Read index.html once at startup for CSRF token injection
	indexHTML, err := os.ReadFile(cfg.StaticDir + "/index.html")
	if err != nil {
		log.Fatalf("Failed to read index.html: %v", err)
	}
	// Inject CSRF token into index.html template (insert script before </head>)
	// Uses a placeholder for the CSP nonce which is replaced per-request
	csrfScript := fmt.Sprintf(`<script nonce="%%CSP_NONCE%%">window.__PWSAFE_CSRF_TOKEN="%s";</script>`, csrfToken)
	indexHTMLTemplate := strings.Replace(string(indexHTML), "</head>", csrfScript+"</head>", 1)

	// API routes — declarative middleware via Route structs
	mux := http.NewServeMux()
	middleware.RegisterRoutes(mux, []middleware.Route{
		// Auth routes (no RequireAuth)
		{Pattern: "/api/auth/status", Handler: authHandler.Status, Method: http.MethodGet},
		{Pattern: "/api/auth/setup", Handler: authHandler.Setup, Csrf: true, Limiter: limiters.Strict, Method: http.MethodPost},
		{Pattern: "/api/auth/login", Handler: authHandler.Login, Csrf: true, Limiter: limiters.Strict, Method: http.MethodPost},
		{Pattern: "/api/auth/logout", Handler: authHandler.Logout, Csrf: true, Auth: true, Method: http.MethodPost},

		// Protected safe routes
		{Pattern: "/api/safes", Handler: safeHandler.ListSafes, Csrf: true, Auth: true, Limiter: limiters.Standard, Method: http.MethodGet},
		{Pattern: "/api/safes/", Handler: func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path[len(r.URL.Path)-7:] == "/unlock" {
				safeHandler.UnlockSafe(w, r)
			} else if r.URL.Path[len(r.URL.Path)-6:] == "/entry" {
				safeHandler.GetEntryPassword(w, r)
			} else {
				http.NotFound(w, r)
			}
		}, Csrf: true, Auth: true, Limiter: limiters.Strict, Method: http.MethodPost},

		// Provider routes
		{Pattern: "/api/providers", Handler: providersHandler.ListProviders, Csrf: true, Auth: true, Limiter: limiters.Standard, Method: http.MethodGet},
		{Pattern: "/api/providers/static/", Handler: staticProviderHandler.Route, Csrf: true, Auth: true, Limiter: limiters.Standard},
		{Pattern: "/api/providers/", Handler: func(w http.ResponseWriter, r *http.Request) {
			// OAuth callbacks skip auth and rate limiting
			if middleware.IsOAuthCallback(r.URL.Path) {
				providersHandler.Route(w, r)
			} else {
				middleware.RequireAuth(authService, settings.TrustedProxies, limiters.Standard.Limit(providersHandler.Route))(w, r)
			}
		}, Csrf: true},
	}, csrfToken, authService, settings.TrustedProxies)

	// Resolve absolute static dir once for containment checks
	absStaticDir, err := filepath.Abs(cfg.StaticDir)
	if err != nil {
		log.Fatalf("Failed to resolve static dir: %v", err)
	}

	mux.HandleFunc("/web/", limiters.Web.Limit(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[4:] // Remove "/web" prefix

		// Block control characters and Windows-reserved characters
		if !webpath.IsValid(path) {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}

		// Block source map files
		if strings.HasSuffix(path, ".map") {
			http.NotFound(w, r)
			return
		}

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
	}))

	// Redirect all non-/api routes to /web
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
		Addr:              fmt.Sprintf("%s:%s", cfg.ServerHost, cfg.ServerPort),
		Handler:           middleware.Logging(middleware.SecurityHeaders(settings.HSTS, settings.TrustedProxies, mux)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      300 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
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
	cspNonceBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, cspNonceBytes); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	cspNonce := base64.StdEncoding.EncodeToString(cspNonceBytes)

	html := strings.Replace(htmlTemplate, "%CSP_NONCE%", cspNonce, -1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'", cspNonce))
	w.Write([]byte(html))
}
