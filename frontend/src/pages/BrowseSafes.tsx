import { useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { api, SafeFile } from "../api/client";

function BrowseSafes() {
  const navigate = useNavigate();
  const [safes, setSafes] = useState<SafeFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchSafes = async () => {
      try {
        const data = await api.listSafes();
        setSafes(data);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load safes");
      } finally {
        setLoading(false);
      }
    };

    fetchSafes();
  }, []);

  const handleSafeClick = (safeName: string) => {
    navigate(`/unlock/${safeName}`);
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  };

  if (loading) {
    return (
      <div className="browse-container">
        <h1>Select a Password Safe</h1>
        <div className="loading">Loading safes...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="browse-container">
        <h1>Select a Password Safe</h1>
        <div className="error">Error: {error}</div>
      </div>
    );
  }

  if (safes.length === 0) {
    return (
      <div className="browse-container">
        <h1>Select a Password Safe</h1>
        <div className="empty-state">
          <div className="empty-box"></div>
          <div className="empty-message">No safes found</div>
        </div>
      </div>
    );
  }

  return (
    <div className="browse-container">
      <h1>Select a Password Safe</h1>

      <div className="safe-grid">
        {safes.map((safe) => (
          <div key={safe.name} className="safe-row" onClick={() => handleSafeClick(safe.name)}>
            <div className="safe-summary">
              <div className="safe-icon">🔒</div>
              <div className="safe-details">
                <div className="safe-name">{safe.name}</div>
                <div className="safe-meta">Modified {formatDate(safe.lastModified)}</div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default BrowseSafes;
