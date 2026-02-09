import { FormEvent, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api/client";

function LoginPage() {
  const [searchParams] = useSearchParams();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const expired = searchParams.get("expired") === "true";

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await api.login(password);
      window.location.href = "/web/";
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="unlock-container">
      <div className="unlock-card">
        <div className="safe-icon">🔒</div>
        <div className="safe-title">Login</div>
        <div className="safe-subtitle">Enter your password to continue</div>

        {expired && !error && <div className="error-message">Session expired. Please log in again.</div>}
        {error && <div className="error-message">{error}</div>}

        <form onSubmit={handleSubmit}>
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
          <div className="button-group">
            <button type="submit" className="primary" disabled={submitting}>
              {submitting ? "Logging in..." : "Login"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default LoginPage;
