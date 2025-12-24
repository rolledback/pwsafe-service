import { useNavigate, useParams } from "react-router-dom";
import { FormEvent, useState } from "react";
import { api } from "../api/client";

function UnlockSafe() {
  const navigate = useNavigate();
  const { safeName } = useParams<{ safeName: string }>();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isUnlocking, setIsUnlocking] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();

    if (!safeName) {
      setError("No safe selected");
      return;
    }

    setIsUnlocking(true);
    setError(null);

    try {
      const structure = await api.unlockSafe(safeName, password);
      navigate(`/safe/${safeName}`, {
        state: {
          structure,
          password,
          safeName,
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
        <div className="safe-title">{safeName}</div>
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
