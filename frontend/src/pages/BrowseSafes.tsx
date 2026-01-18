import { useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { api, SafeFile } from "../api/client";
import ItemRow from "../components/ItemRow";

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

  const handleSafeClick = (safePath: string) => {
    const encodedPath = encodeURIComponent(safePath);
    navigate(`/unlock/${encodedPath}`);
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

  return (
    <div className="browse-container">
      <h1>Select a Password Safe</h1>

      <div className="safe-grid">
        {safes.length === 0 ? (
          <div className="empty-state">
            <div className="empty-box"></div>
            <div className="empty-message">No safes found</div>
          </div>
        ) : (
          safes.map((safe) => (
            <ItemRow
              key={safe.path}
              icon="🔒"
              name={safe.name}
              metadata={`Modified ${formatDate(safe.lastModified)}`}
              sourceBadge={safe.source === "onedrive" ? "OneDrive" : undefined}
              onClick={() => handleSafeClick(safe.path)}
            />
          ))
        )}
      </div>

      <div className="add-banner" onClick={() => navigate("/add")}>
        <div className="add-banner-content">
          <span className="add-banner-icon">＋</span>
          <span className="add-banner-text">Add Safes</span>
        </div>
      </div>
    </div>
  );
}

export default BrowseSafes;
