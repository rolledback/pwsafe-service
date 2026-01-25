import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import ItemRow from "../components/ItemRow";
import { api, Provider } from "../api/client";

function AddSafes() {
  const navigate = useNavigate();
  const [providers, setProviders] = useState<Provider[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchProviders = async () => {
      try {
        const result = await api.listProviders();
        setProviders(result.providers || []);
      } catch (err) {
        console.error("Failed to fetch providers:", err);
        setError("Failed to load providers.");
      } finally {
        setLoading(false);
      }
    };

    fetchProviders();
  }, []);

  return (
    <div className="add-safes-container">
      <div className="page-header">
        <h1>Add Safes</h1>
        <button className="close-button" onClick={() => navigate("/")}>
          ✕
        </button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="source-list">
        {loading ? (
          <div className="loading-state">Loading providers...</div>
        ) : providers.length === 0 ? (
          <div className="empty-state">No providers configured</div>
        ) : (
          providers.map((provider) => (
            <ItemRow
              key={provider.id}
              icon={provider.icon ? <img src={provider.icon} alt="" className="provider-icon" /> : "☁️"}
              name={provider.displayName}
              onClick={() => navigate(`/add/${provider.id}`)}
            />
          ))
        )}

        {/* Static Upload option - always shown */}
        <ItemRow icon="📤" name="Upload" onClick={() => navigate("/add/static")} />
      </div>
    </div>
  );
}

export default AddSafes;
