# Providers

Providers allow pwsafe-service to sync password safes from remote sources (e.g. cloud storage). Synced password safes are resynced on a routine basis. Changes made to synced safes are overridden during resync. This guide covers how to configure supported providers.

## Getting Started

To use any provider, you will initially need to add `baseUrl` and `providers` to your [settings file](configuration.md):

```json
{
  "baseUrl": "http://localhost:8080",
  "providers": {}
}
```

- `baseUrl`: The full URL (protocol, hostname, optional port) you use to access pwsafe-service. This is used to construct OAuth callback URLs during authentication.
- `providers`: A map of provider configurations. Add entries here as you configure each provider.

## OneDrive

### Prerequisites

- Azure account

### Step 1: Register an Azure Application

1. Go to the [Azure Portal](https://portal.azure.com/)
2. Navigate to **Microsoft Entra ID**
3. Select **App registrations** → **New registration**
4. Configure the application:
   - **Name**: `pwsafe-service` (or any name you prefer)
   - **Supported account types**: Select "Personal Microsoft accounts only"
   - **Redirect URI**: Select "Public client/native (mobile & desktop)" and enter `<baseUrl>/api/providers/onedrive/auth/callback`
5. Click **Register**
6. Copy the **Application (client) ID** — you'll need this for configuration

You can add additional redirect URIs as needed. For example, for local development, you will need an additional entry for `http://localhost:8080`.

### Step 2: Configure API Permissions

1. In your app registration, go to **API permissions**
2. Click **Add a permission** → **Microsoft Graph** → **Delegated permissions**
3. Add these permissions:
   - `Files.Read`
   - `User.Read`
   - `offline_access`
4. Click **Add permissions**

### Step 3: Configure pwsafe-service

Update `"providers"` in your `settings.json` to include:

```json
{
  "onedrive": {
    "clientId": "your-client-id-here"
  }
}
```

- `clientId`: The Application (client) ID from Step 1.6

### Step 4: Connect Your Account

1. Start/restart pwsafe-service
2. Open the web interface
3. Navigate to the **Add Safes** → **OneDrive**
4. Click "Connect Account"
5. Sign in with your Microsoft account and authorize the application

Once connected, pwsafe-service will list all .psafe3 files in your OneDrive. You can choose which ones you would like synced to the host machine.