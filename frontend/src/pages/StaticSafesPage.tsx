import { useEffect, useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { api, SafeFile } from "../api/client";

function StaticSafesPage() {
  const navigate = useNavigate();
  const [safes, setSafes] = useState<SafeFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetchSafes();
  }, []);

  const fetchSafes = async () => {
    try {
      const allSafes = await api.listSafes();
      // Filter to only static safes
      const staticSafes = allSafes.filter((safe) => safe.provider === "static");
      setSafes(staticSafes);
      setError(null);
    } catch (err) {
      console.error("Failed to fetch safes:", err);
      setError("Failed to load safes");
    } finally {
      setLoading(false);
    }
  };

  const handleFileSelect = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Reset the input so the same file can be selected again
    event.target.value = "";

    await uploadFile(file, false);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);

    const file = e.dataTransfer.files?.[0];
    if (!file) return;

    if (!file.name.toLowerCase().endsWith(".psafe3")) {
      setError("Only .psafe3 files are allowed");
      return;
    }

    await uploadFile(file, false);
  };

  const uploadFile = async (file: File, overwrite: boolean) => {
    setUploading(true);
    setError(null);

    try {
      const result = await api.uploadStaticSafe(file, overwrite);

      if (result.exists && !overwrite) {
        // File exists, ask for confirmation
        const confirmed = window.confirm(`A safe named "${result.name}" already exists. Do you want to overwrite it?`);
        if (confirmed) {
          await uploadFile(file, true);
        }
        return;
      }

      // Success - refresh the list
      await fetchSafes();
    } catch (err) {
      console.error("Failed to upload safe:", err);
      setError(err instanceof Error ? err.message : "Failed to upload safe");
    } finally {
      setUploading(false);
    }
  };

  const handleDelete = async (safe: SafeFile) => {
    const confirmed = window.confirm(`Are you sure you want to delete "${safe.name}"?`);
    if (!confirmed) return;

    setDeleting(safe.name);
    setError(null);

    try {
      await api.deleteStaticSafe(safe.name);
      await fetchSafes();
    } catch (err) {
      console.error("Failed to delete safe:", err);
      setError(err instanceof Error ? err.message : "Failed to delete safe");
    } finally {
      setDeleting(null);
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <div className="container">
      <div className="page-header">
        <h1>
          <span className="icon">📤</span> Upload
        </h1>
        <button className="close-button" onClick={() => navigate("/add")}>
          ✕
        </button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {/* Upload area */}
      <div
        className={`upload-card ${dragging ? "dragging" : ""}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <input type="file" ref={fileInputRef} onChange={handleFileSelect} accept=".psafe3" style={{ display: "none" }} />
        <button className="upload-btn" onClick={() => fileInputRef.current?.click()} disabled={uploading}>
          {uploading ? "Uploading..." : "Choose .psafe3 File"}
        </button>
      </div>

      {/* Static safes list */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Uploaded Safes</span>
        </div>

        {loading ? (
          <div className="file-row">
            <div className="file-info">
              <div className="file-name">Loading...</div>
            </div>
          </div>
        ) : safes.length === 0 ? (
          <div className="file-row">
            <div className="file-info">
              <div className="file-name">No uploaded safes yet</div>
              <div className="file-meta">Upload a .psafe3 file to get started</div>
            </div>
          </div>
        ) : (
          safes.map((safe) => (
            <div className="file-row" key={safe.path}>
              <div className="file-icon">🔒</div>
              <div className="file-info">
                <div className="file-name">{safe.name}</div>
                <div className="file-meta">Modified {formatDate(safe.lastModified)}</div>
              </div>
              <button className="delete-btn" onClick={() => handleDelete(safe)} disabled={deleting === safe.name}>
                {deleting === safe.name ? "..." : "Delete"}
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default StaticSafesPage;
