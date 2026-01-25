import { useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { api, SafeFile, Provider } from "../api/client";
import ItemRow from "../components/ItemRow";

function BrowseSafes() {
  const navigate = useNavigate();
  const [safes, setSafes] = useState<SafeFile[]>([]);
  const [providers, setProviders] = useState<Map<string, Provider>>(new Map());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [safesData, providersData] = await Promise.all([api.listSafes(), api.listProviders()]);
        setSafes(safesData);

        const providerMap = new Map<string, Provider>();
        for (const p of providersData.providers || []) {
          providerMap.set(p.id, p);
        }
        setProviders(providerMap);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load safes");
      } finally {
        setLoading(false);
      }
    };

    fetchData();
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

  const getProviderBadge = (providerId: string): { name: string; color?: string } | null => {
    if (!providerId || providerId === "local" || providerId === "static") return null;
    const provider = providers.get(providerId);
    if (provider) {
      return { name: provider.displayName, color: provider.brandColor };
    }
    return { name: providerId };
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
          safes.map((safe) => {
            const badge = getProviderBadge(safe.provider);
            return (
              <ItemRow
                key={safe.path}
                icon="🔒"
                name={safe.name}
                metadata={`Modified ${formatDate(safe.lastModified)}`}
                sourceBadge={badge?.name}
                sourceBadgeColor={badge?.color}
                onClick={() => handleSafeClick(safe.path)}
              />
            );
          })
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
