package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/rolledback/pwsafe-service/backend/internal/config"
	"github.com/rolledback/pwsafe-service/backend/internal/handlers"
	"github.com/rolledback/pwsafe-service/backend/internal/middleware"
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

	// Create OneDrive provider and sync service (new architecture)
	onedriveProvider := onedrive.NewOneDriveProvider(cfg.SafesDirectory, cfg.OneDriveClientID, cfg.OneDriveRedirectURI)
	onedriveSyncService := service.NewSyncableSafesService(ctx, cfg.SafesDirectory, onedriveProvider)
	defer onedriveSyncService.Stop()
	onedriveHandler := handlers.NewOneDriveHandler(onedriveSyncService)

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

	// OneDrive routes
	http.HandleFunc("/api/onedrive/status", middleware.CORS(rateLimiter.Limit(onedriveHandler.GetStatus)))
	http.HandleFunc("/api/onedrive/auth/url", middleware.CORS(rateLimiter.Limit(onedriveHandler.GetAuthURL)))
	http.HandleFunc("/api/onedrive/auth/callback", onedriveHandler.HandleCallback)
	http.HandleFunc("/api/onedrive/disconnect", middleware.CORS(rateLimiter.Limit(onedriveHandler.Disconnect)))
	http.HandleFunc("/api/onedrive/files", middleware.CORS(rateLimiter.Limit(onedriveHandler.HandleFiles)))
	http.HandleFunc("/api/onedrive/sync", middleware.CORS(rateLimiter.Limit(onedriveHandler.Sync)))

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
