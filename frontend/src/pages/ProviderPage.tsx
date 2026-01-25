import { useEffect, useState, useRef } from "react";
import { useNavigate, useSearchParams, useParams } from "react-router-dom";
import { api, ProviderStatus, ProviderFile, Provider } from "../api/client";

function formatTimeAgo(isoString: string): string {
  const date = new Date(isoString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHour / 24);

  if (diffSec < 60) return "just now";
  if (diffMin < 60) return `${diffMin} minute${diffMin === 1 ? "" : "s"} ago`;
  if (diffHour < 24) return `${diffHour} hour${diffHour === 1 ? "" : "s"} ago`;
  return `${diffDay} day${diffDay === 1 ? "" : "s"} ago`;
}

function ProviderPage() {
  const navigate = useNavigate();
  const { providerId } = useParams<{ providerId: string }>();
  const [searchParams] = useSearchParams();
  const [provider, setProvider] = useState<Provider | null>(null);
  const [status, setStatus] = useState<ProviderStatus | null>(null);
  const [files, setFiles] = useState<ProviderFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [filesLoading, setFilesLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [, setTick] = useState(0); // Force re-render for time display
  const syncTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pendingFilesRef = useRef<ProviderFile[] | null>(null);
  const nextSyncTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Update time display every 20 seconds
  useEffect(() => {
    const interval = setInterval(() => setTick((t) => t + 1), 20000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const errorParam = searchParams.get("error");
    if (errorParam) {
      if (errorParam === "auth_failed") {
        setError("Authentication failed. Please try again.");
      } else if (errorParam === "token_exchange_failed") {
        setError("Failed to complete authentication. Please try again.");
      } else {
        setError("An error occurred. Please try again.");
      }
    }

    fetchProviderAndStatus();

    // Cleanup timers on unmount
    return () => {
      if (syncTimeoutRef.current) {
        clearTimeout(syncTimeoutRef.current);
      }
      if (nextSyncTimeoutRef.current) {
        clearTimeout(nextSyncTimeoutRef.current);
      }
    };
  }, [searchParams, providerId]);

  const scheduleNextFetch = (nextSyncAt: string) => {
    // Clear any existing scheduled fetch
    if (nextSyncTimeoutRef.current) {
      clearTimeout(nextSyncTimeoutRef.current);
    }

    const nextSyncTime = new Date(nextSyncAt).getTime();
    const now = Date.now();
    const delay = nextSyncTime - now + 1000; // Add 1s buffer

    // Only schedule if nextSyncAt is in the future (at least 5s away)
    if (delay < 5000) {
      return;
    }

    nextSyncTimeoutRef.current = setTimeout(() => {
      fetchStatus();
    }, delay);
  };

  const fetchProviderAndStatus = async () => {
    if (!providerId) return;

    try {
      // Fetch provider metadata
      const providersResult = await api.listProviders();
      const foundProvider = providersResult.providers?.find((p) => p.id === providerId);
      if (foundProvider) {
        setProvider(foundProvider);
      }

      // Fetch status
      const result = await api.getProviderStatus(providerId);
      setStatus(result);
      if (result.connected) {
        fetchFiles();
        // Schedule next fetch based on nextSyncAt
        if (result.nextSyncAt) {
          scheduleNextFetch(result.nextSyncAt);
        }
      }
    } catch (err) {
      console.error("Failed to fetch provider status:", err);
      setError("Failed to check provider connection status.");
    } finally {
      setLoading(false);
    }
  };

  const fetchStatus = async () => {
    if (!providerId) return;

    try {
      const result = await api.getProviderStatus(providerId);
      setStatus(result);
      if (result.connected) {
        fetchFiles();
        if (result.nextSyncAt) {
          scheduleNextFetch(result.nextSyncAt);
        }
      }
    } catch (err) {
      console.error("Failed to fetch provider status:", err);
      setError("Failed to check provider connection status.");
    }
  };

  const fetchFiles = async () => {
    if (!providerId) return;

    setFilesLoading(true);
    try {
      const result = await api.getProviderFiles(providerId);
      setFiles(result.files || []);
    } catch (err) {
      console.error("Failed to fetch provider files:", err);
    } finally {
      setFilesLoading(false);
    }
  };

  const handleToggleFile = async (fileId: string) => {
    if (syncing || !providerId) return; // Disable toggles while syncing

    const updatedFiles = files.map((f) => (f.id === fileId ? { ...f, selected: !f.selected } : f));
    setFiles(updatedFiles);
    pendingFilesRef.current = updatedFiles;

    // Clear any existing debounce timer
    if (syncTimeoutRef.current) {
      clearTimeout(syncTimeoutRef.current);
    }

    // Debounce: wait 500ms before saving and syncing
    syncTimeoutRef.current = setTimeout(async () => {
      const filesToSave = pendingFilesRef.current;
      if (!filesToSave) return;

      setSyncing(true);
      setError(null);
      try {
        await api.saveProviderFiles(providerId, filesToSave);
        await api.syncProvider(providerId);
        await fetchFiles();
        await fetchStatus();
      } catch (err) {
        console.error("Failed to save/sync file selection:", err);
        setError("Failed to sync files. Please try again.");
        // Revert on error
        setFiles(files);
      } finally {
        setSyncing(false);
        pendingFilesRef.current = null;
      }
    }, 500);
  };

  const handleRefresh = async () => {
    if (!providerId) return;

    setSyncing(true);
    setError(null);
    try {
      await api.syncProvider(providerId);
      await fetchFiles();
      await fetchStatus();
    } catch (err) {
      console.error("Failed to sync provider files:", err);
      setError("Failed to sync files. Please try again.");
    } finally {
      setSyncing(false);
    }
  };

  const handleConnect = async () => {
    if (!providerId) return;

    setConnecting(true);
    setError(null);

    try {
      const { url } = await api.getProviderAuthUrl(providerId);
      window.location.href = url;
    } catch (err) {
      console.error("Failed to get auth URL:", err);
      if (err instanceof Error && err.message.includes("not configured")) {
        setError("Provider integration is not configured.");
      } else {
        setError("Failed to start authentication. Please try again.");
      }
      setConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    if (!providerId) return;

    setDisconnecting(true);
    setError(null);

    try {
      await api.disconnectProvider(providerId);
      await fetchStatus();
    } catch (err) {
      console.error("Failed to disconnect:", err);
      setError("Failed to disconnect. Please try again.");
    } finally {
      setDisconnecting(false);
    }
  };

  const getInitials = (name?: string, email?: string): string => {
    if (name) {
      const parts = name.split(" ");
      if (parts.length >= 2) {
        return (parts[0][0] + parts[1][0]).toUpperCase();
      }
      return name.substring(0, 2).toUpperCase();
    }
    if (email) {
      return email.substring(0, 2).toUpperCase();
    }
    return "??";
  };

  const displayName = provider?.displayName || providerId || "Provider";
  const icon = provider?.icon ? <img src={provider.icon} alt="" className="provider-icon" /> : "☁️";

  if (loading) {
    return (
      <div className="container">
        <div className="page-header">
          <h1>
            <span className="icon">{icon}</span> {displayName}
          </h1>
          <button className="close-button" onClick={() => navigate("/add")}>
            ✕
          </button>
        </div>
        <div className="connect-card">
          <p>Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <div className="page-header">
        <h1>
          <span className="icon">{icon}</span> {displayName}
        </h1>
        <button className="close-button" onClick={() => navigate("/add")}>
          ✕
        </button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {status?.connected && !status?.needsReauth ? (
        <>
          <div className="account-card connected">
            <div className="account-info">
              <div className="account-avatar">{getInitials(status.accountName, status.accountEmail)}</div>
              <div className="account-details">
                <div className="account-name">{status.accountName || "Connected Account"}</div>
                {status.accountEmail && <div className="account-email">{status.accountEmail}</div>}
              </div>
            </div>
            <div className="account-actions">
              <button className="disconnect-btn" onClick={handleConnect} disabled={connecting}>
                {connecting ? "..." : "Reauth"}
              </button>
              <button className="disconnect-btn" onClick={handleDisconnect} disabled={disconnecting}>
                {disconnecting ? "..." : "Disconnect"}
              </button>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <span className="card-title">Available Safes</span>
              <span className="card-meta">
                {status.lastSyncTime && !syncing && (
                  <span style={{ marginRight: "8px" }}>Last synced {formatTimeAgo(status.lastSyncTime)}</span>
                )}
                <button className="card-action" onClick={handleRefresh} disabled={syncing || filesLoading}>
                  {syncing ? "Syncing..." : "Sync"}
                </button>
              </span>
            </div>

            {filesLoading && files.length === 0 ? (
              <div className="file-row">
                <div className="file-info">
                  <div className="file-name">Loading files...</div>
                </div>
              </div>
            ) : files.length === 0 ? (
              <div className="file-row">
                <div className="file-info">
                  <div className="file-name">No .psafe3 files found</div>
                  <div className="file-meta">Upload .psafe3 files to see them here</div>
                </div>
              </div>
            ) : (
              files.map((file) => (
                <div className="file-row" key={file.id}>
                  <div className="file-icon">🔒</div>
                  <div className="file-info">
                    <div className="file-name">{file.name}</div>
                    <div className="file-meta">{file.path}</div>
                  </div>
                  <div className={`toggle ${file.selected ? "active" : ""}`} onClick={() => handleToggleFile(file.id)}></div>
                </div>
              ))
            )}
          </div>
        </>
      ) : status?.connected && status?.needsReauth ? (
        <>
          <div className="account-card needs-reauth">
            <div className="account-info">
              <div className="account-avatar">{getInitials(status.accountName, status.accountEmail)}</div>
              <div className="account-details">
                <div className="account-name">{status.accountName || "Connected Account"}</div>
                {status.accountEmail && <div className="account-email">{status.accountEmail}</div>}
              </div>
            </div>
            <div className="account-actions">
              <button className="reconnect-btn" onClick={handleConnect} disabled={connecting}>
                {connecting ? "..." : "Reconnect"}
              </button>
              <button className="disconnect-btn" onClick={handleDisconnect} disabled={disconnecting}>
                {disconnecting ? "..." : "Disconnect"}
              </button>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <span className="card-title">Available Safes</span>
              <span className="card-meta">
                {status.lastSyncTime && (
                  <span style={{ marginRight: "8px" }}>Last synced {formatTimeAgo(status.lastSyncTime)}</span>
                )}
                <button className="card-action disabled" disabled>
                  Sync
                </button>
              </span>
            </div>
            {files.length === 0 ? (
              <div className="file-row disabled">
                <div className="file-info">
                  <div className="file-name">No synced files</div>
                  <div className="file-meta">Reconnect to refresh file list</div>
                </div>
              </div>
            ) : (
              files.map((file) => (
                <div className="file-row disabled" key={file.id}>
                  <div className="file-icon">🔒</div>
                  <div className="file-info">
                    <div className="file-name">{file.name}</div>
                    <div className="file-meta">{file.path}</div>
                  </div>
                  <div className={`toggle disabled ${file.selected ? "active" : ""}`}></div>
                </div>
              ))
            )}
          </div>
        </>
      ) : (
        <div className="connect-card">
          <div className="connect-title">Connect your account</div>
          <div className="connect-desc">Sign in to sync password safes from {displayName}</div>
          <button className="connect-btn" onClick={handleConnect} disabled={connecting}>
            {connecting ? "Connecting..." : "Connect Account"}
          </button>
        </div>
      )}
    </div>
  );
}

export default ProviderPage;
