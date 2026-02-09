package middleware

import (
	"net"
	"net/http"
	"strings"
)

// GetClientIP extracts the client IP from a request.
// Checks X-Real-IP and X-Forwarded-For headers (set by reverse proxies like nginx)
// before falling back to RemoteAddr.
func GetClientIP(r *http.Request) string {
	// X-Real-IP is the most reliable when set by a trusted proxy
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}

	// X-Forwarded-For may contain a chain: "client, proxy1, proxy2"
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0]); ip != "" {
			return ip
		}
	}

	// Direct connection fallback
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
