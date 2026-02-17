package middleware

import (
	"net/http"
	"strings"
)

func SecurityHeaders(hstsEnabled bool, trustedProxies []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		if hstsEnabled {
			isHTTPS := r.TLS != nil
			if !isHTTPS {
				remoteIP := extractRemoteIP(r.RemoteAddr)
				if IsTrustedProxy(remoteIP, trustedProxies) {
					isHTTPS = r.Header.Get("X-Forwarded-Proto") == "https"
				}
			}
			if isHTTPS {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
		}
		next.ServeHTTP(w, r)
	})
}
