# Configuration

This guide documents all settings available in `settings.json`. This file lives in your config directory. You do not need to create `settings.json` yourself.

## Minimal Contents

Your `settings.json` simply contains a JSON object which various settings can be added to. If you decide to create the file yourself, you should at least have it be an empty JSON object:

```json
{
}
```

Available settings are documented below.

## General Settings

| Field | Type | Default | Valid Range | Description |
|---|---|---|---|---|
| `baseUrl` | string | `""` | N/A | The full URL (protocol, hostname, optional port) you use to access pwsafe-service. This is used to construct OAuth callback URLs during provider authentication. |
| `syncInterval` | duration string | `"15m"` | Any positive Go duration | How often synced safes are re-fetched from providers. Uses Go duration format (e.g. `"30s"`, `"5m"`, `"1h"`). |
| `maxSafeFileSize` | integer (bytes) | `10485760` (10 MB) | > 0 | Maximum allowed size of a safe file. |

Example:

```json
{
  "baseUrl": "https://pwsafe.example.com",
  "syncInterval": "30m",
  "maxSafeFileSize": 5242880
}
```

## Authentication (`auth`)

The `auth` block is added for you on first run through the web UI. If you'd like to change the service's authentication or change your password, remove the `auth` block from `settings.json` and restart the service. See the [User Guide](user.md#set-up-authentication) for more information on authentication setup.

| Field | Type | Default | Valid Range | Description |
|---|---|---|---|---|
| `mode` | string | `""` (unset → setup prompt) | `"disabled"`, `"enabled"` | Auth mode. Set automatically during first-run setup. |
| `sessionTimeout` | duration string | `"3m"` | Any valid Go duration | Inactivity timeout before a session expires. Capped at `maxSessionLifetime`. |
| `bcryptCost` | integer | `10` | 4–14 | bcrypt hashing cost for password storage. Higher values are slower but more secure. |
| `maxSessions` | integer | `4` | 1–10,000 | Maximum concurrent sessions. When exceeded, the oldest session is evicted. |
| `maxSessionLifetime` | duration string | `"30m"` | ≥ `"1m"` | Absolute maximum lifetime of a session, regardless of activity. |

Example:

```json
{
  "auth": {
    "mode": "enabled",
    "sessionTimeout": "5m",
    "bcryptCost": 12,
    "maxSessions": 8,
    "maxSessionLifetime": "1h"
  }
}
```

## Rate Limiting (`rateLimiter`)

Rate limiting is per-IP and split into three tiers. Each tier has a `rate` (requests per second) and `burst` (burst capacity).

| Field | Type | Default | Valid Range | Description |
|---|---|---|---|---|
| `standard.rate` | float | `5` | > 0 | Requests per second for most API endpoints. |
| `standard.burst` | integer | `5` | ≥ 1 | Burst capacity for most API endpoints. |
| `strict.rate` | float | `0.2` | > 0 | Requests per second for auth, unlock, and entry retrieval endpoints. |
| `strict.burst` | integer | `2` | ≥ 1 | Burst capacity for auth, unlock, and entry retrieval endpoints. |
| `web.rate` | float | `50` | > 0 | Requests per second for static file serving. |
| `web.burst` | integer | `50` | ≥ 1 | Burst capacity for static file serving. |

Example:

```json
{
  "rateLimiter": {
    "standard": { "rate": 10, "burst": 20 },
    "strict": { "rate": 0.5, "burst": 3 },
    "web": { "rate": 100, "burst": 200 }
  }
}
```

## Network & Security

| Field | Type | Default | Valid Range | Description |
|---|---|---|---|---|
| `trustedProxies` | string array | `[]` | N/A | IP addresses of trusted reverse proxies. When a request comes from a listed IP, `X-Real-IP` and `X-Forwarded-For` headers are used for client IP extraction. This affects rate limiting, session IP binding, HSTS enforcement, and the `Secure` flag on session cookies. |
| `hsts` | boolean | `false` | N/A | When `true`, adds the `Strict-Transport-Security` header on HTTPS responses. Only takes effect when the connection is HTTPS (direct TLS or via a trusted proxy with `X-Forwarded-Proto: https`). |

Example:

```json
{
  "trustedProxies": ["172.17.0.1"],
  "hsts": true
}
```

## Providers (`providers`)

The `providers` field is a map of provider name to provider-specific configuration. See [Providers](providers.md) for detailed setup instructions for each supported provider.

For development, a mock provider is available. See the [Developer Guide](dev.md#working-with-providers) for details.

Example:

```json
{
  "providers": {
    "some-provider": {
      "provider-setting": "setting-value"
    }
  }
}
```
