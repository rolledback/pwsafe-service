import { useNavigate, useParams } from "react-router-dom";
import { FormEvent, useState } from "react";
import { api } from "../api/client";

function UnlockSafe() {
  const navigate = useNavigate();
  const { safePath: encodedSafePath } = useParams<{ safePath: string }>();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isUnlocking, setIsUnlocking] = useState(false);

  // Decode the URL-encoded path
  const safePath = encodedSafePath ? decodeURIComponent(encodedSafePath) : "";
  // Extract display name from path (e.g., "/safes/work.psafe3" -> "work.psafe3")
  const displayName = safePath.split("/").pop() || safePath;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();

    if (!safePath) {
      setError("No safe selected");
      return;
    }

    setIsUnlocking(true);
    setError(null);

    try {
      const structure = await api.unlockSafe(safePath, password);
      navigate(`/safe/${encodeURIComponent(safePath)}`, {
        state: {
          structure,
          password,
          safePath,
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
