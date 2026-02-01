import { useNavigate, useParams, useLocation } from "react-router-dom";
import { FormEvent, useState } from "react";
import { api } from "../api/client";

type LocationState = {
  safeName?: string;
};

function UnlockSafe() {
  const navigate = useNavigate();
  const location = useLocation();
  const { id } = useParams<{ id: string }>();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isUnlocking, setIsUnlocking] = useState(false);

  // Get display name from navigation state, or fall back to ID
  const state = location.state as LocationState | null;
  const displayName = state?.safeName || id || "Safe";

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();

    if (!id) {
      setError("No safe selected");
      return;
    }

    setIsUnlocking(true);
    setError(null);

    try {
      const structure = await api.unlockSafe(id, password);
      navigate(`/safe/${id}`, {
        state: {
          structure,
          password,
          id,
          safeName: displayName,
        },
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to unlock safe");
    } finally {
      setIsUnlocking(false);
    }
  };

  const handleCancel = () => {
    navigate("/");
  };

  return (
    <div className="unlock-container">
      <div className="unlock-card">
        <div className="safe-icon">🔒</div>
        <div className="safe-title">{displayName}</div>
        <div className="safe-subtitle">Enter your master password to unlock this safe</div>

        {error && <div className="error-message">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="password">Master Password</label>
            <input
              type="password"
              id="password"
              placeholder="Enter password"
              autoFocus
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={isUnlocking}
            />
          </div>

          <div className="button-group">
            <button type="button" className="secondary" onClick={handleCancel} disabled={isUnlocking}>
              Cancel
            </button>
            <button type="submit" className="primary" disabled={isUnlocking}>
              {isUnlocking ? "Unlocking..." : "Unlock"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default UnlockSafe;
