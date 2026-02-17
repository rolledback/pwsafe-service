package middleware

import (
	"net"
	"net/http"
	"strings"
)

// extractRemoteIP extracts the IP address from r.RemoteAddr, stripping the port if present.
func extractRemoteIP(remoteAddr string) string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return ip
}

// IsTrustedProxy returns true if ip appears in the trustedProxies list.
func IsTrustedProxy(ip string, trustedProxies []string) bool {
	for _, trusted := range trustedProxies {
		if ip == trusted {
			return true
		}
	}
	return false
}

// GetClientIP extracts the client IP from a request.
// Proxy headers (X-Real-IP, X-Forwarded-For) are only honoured when the
// remote address is in the trustedProxies list. Otherwise the remote IP is
// returned directly, preventing header spoofing by untrusted clients.
func GetClientIP(r *http.Request, trustedProxies []string) string {
	remoteIP := extractRemoteIP(r.RemoteAddr)

	if !IsTrustedProxy(remoteIP, trustedProxies) {
		return remoteIP
	}

	// X-Real-IP is the most reliable when set by a trusted proxy
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}

	// X-Forwarded-For may contain a chain: "client, proxy1, proxy2"
	// Walk from right to find the rightmost non-trusted IP (the real client)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip != "" && !IsTrustedProxy(ip, trustedProxies) {
				return ip
			}
		}
	}

	return remoteIP
}
