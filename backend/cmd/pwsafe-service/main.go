package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/rolledback/pwsafe-service/backend/internal/config"
	"github.com/rolledback/pwsafe-service/backend/internal/handlers"
	"github.com/rolledback/pwsafe-service/backend/internal/middleware"
	"github.com/rolledback/pwsafe-service/backend/internal/provider"
	"github.com/rolledback/pwsafe-service/backend/internal/provider/onedrive"
	"github.com/rolledback/pwsafe-service/backend/internal/service"
	"golang.org/x/time/rate"
)

func main() {
	cfg := config.Load()

	log.Printf("pwsafe-service - Password Safe Web Service")
	log.Printf("Safes Directory: %s", cfg.SafesDirectory)
	log.Printf("Server: %s:%s", cfg.ServerHost, cfg.ServerPort)

	staticDir := os.Getenv("PWSAFE_STATIC_DIR")
	if staticDir == "" {
		staticDir = "./static"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	safeService := service.NewSafeService(cfg.SafesDirectory)
	safeHandler := handlers.NewSafeHandler(safeService)

	// Create provider registry and register factories
	registry := provider.NewRegistry()
	registry.Register("onedrive", onedrive.Factory)

	// Discover providers from safes directory
	providers, err := registry.Discover(cfg.SafesDirectory)
	if err != nil {
		log.Fatalf("Failed to discover providers: %v", err)
	}

	// Create SyncableSafesService for each discovered provider
	services := make(map[string]*service.SyncableSafesService)
	for id, p := range providers {
		svc := service.NewSyncableSafesService(ctx, cfg.SafesDirectory, p)
		services[id] = svc
		defer svc.Stop()
	}

	log.Printf("Discovered %d provider(s)", len(services))

	// Create providers handler
	providersHandler := handlers.NewProvidersHandler(services)

	// Create static provider handler (for upload/delete of static safes)
	staticProviderHandler := handlers.NewStaticProviderHandler(cfg.SafesDirectory)

	rateLimiter := middleware.NewRateLimiter(rate.Limit(5), 5)

	http.HandleFunc("/api/safes", middleware.CORS(rateLimiter.Limit(safeHandler.ListSafes)))
	http.HandleFunc("/api/safes/", middleware.CORS(rateLimiter.Limit(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path[len(r.URL.Path)-7:] == "/unlock" {
			safeHandler.UnlockSafe(w, r)
		} else if r.URL.Path[len(r.URL.Path)-6:] == "/entry" {
			safeHandler.GetEntryPassword(w, r)
		} else {
			http.NotFound(w, r)
		}
	})))

	// Provider routes (new generic API)
	http.HandleFunc("/api/providers", middleware.CORS(rateLimiter.Limit(providersHandler.ListProviders)))
	http.HandleFunc("/api/providers/static/", middleware.CORS(rateLimiter.Limit(staticProviderHandler.Route)))
	http.HandleFunc("/api/providers/", middleware.CORS(func(w http.ResponseWriter, r *http.Request) {
		// Don't rate limit callbacks (they come from OAuth redirects)
		if strings.HasSuffix(r.URL.Path, "/auth/callback") {
			providersHandler.Route(w, r)
		} else {
			rateLimiter.Limit(providersHandler.Route)(w, r)
		}
	}))

	// Serve static files with SPA fallback
	http.HandleFunc("/web/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[4:] // Remove "/web" prefix
		fullPath := staticDir + path
		
		// Check if file exists
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			// File doesn't exist, serve index.html for SPA routing
			http.ServeFile(w, r, staticDir+"/index.html")
			return
		}
		
		// File exists, serve it
		fs := http.FileServer(http.Dir(staticDir))
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

	addr := fmt.Sprintf("%s:%s", cfg.ServerHost, cfg.ServerPort)
	log.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
