package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/rolledback/pwsafe-service/backend/internal/config"
	"github.com/rolledback/pwsafe-service/backend/internal/handlers"
	"github.com/rolledback/pwsafe-service/backend/internal/middleware"
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

	safeService := service.NewSafeService(cfg.SafesDirectory)
	safeHandler := handlers.NewSafeHandler(safeService)

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

	addr := fmt.Sprintf("%s:%s", cfg.ServerHost, cfg.ServerPort)
	log.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
