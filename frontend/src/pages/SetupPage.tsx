import { FormEvent, useState } from "react";
import { api } from "../api/client";

function SetupPage() {
  const [mode, setMode] = useState<"choose" | "password">("choose");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSkipAuth = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await api.authSetup("disabled");
      window.location.href = "/web/";
    } catch (err) {
      setError(err instanceof Error ? err.message : "Setup failed");
    } finally {
      setSubmitting(false);
    }
  };

  const handleEnableAuth = async (e: FormEvent) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }
    if (password.length === 0) {
      setError("Password cannot be empty");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await api.authSetup("enabled", password);
      window.location.href = "/web/";
    } catch (err) {
      setError(err instanceof Error ? err.message : "Setup failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="unlock-container">
      <div className="unlock-card">
        <div className="safe-icon">🔐</div>
        <div className="safe-title">Welcome to pwsafe-service</div>
        <div className="safe-subtitle">Choose how you'd like to set up authentication</div>

        {error && <div className="error-message">{error}</div>}

        {mode === "choose" ? (
          <div className="button-group" style={{ flexDirection: "column" }}>
            <button className="primary" onClick={() => setMode("password")} disabled={submitting}>
              Set Up Password
            </button>
            <button className="secondary" onClick={handleSkipAuth} disabled={submitting}>
              {submitting ? "Setting up..." : "Skip Authentication"}
            </button>
          </div>
        ) : (
          <form onSubmit={handleEnableAuth}>
            <div className="form-group">
              <label htmlFor="password">Password</label>
              <input
                type="password"
                id="password"
                placeholder="Enter password"
                autoFocus
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={submitting}
              />
            </div>
            <div className="form-group">
              <label htmlFor="confirmPassword">Confirm Password</label>
              <input
                type="password"
                id="confirmPassword"
                placeholder="Confirm password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                disabled={submitting}
              />
            </div>
            <div className="button-group">
              <button
                type="button"
                className="secondary"
                onClick={() => {
                  setMode("choose");
                  setError(null);
                }}
                disabled={submitting}
              >
                Back
              </button>
              <button type="submit" className="primary" disabled={submitting}>
                {submitting ? "Setting up..." : "Set Password"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

export default SetupPage;
