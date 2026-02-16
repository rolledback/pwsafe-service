import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { api } from "./api/client";
import BrowseSafes from "./pages/BrowseSafes";
import UnlockSafe from "./pages/UnlockSafe";
import TreeView from "./pages/TreeView";
import AddSafes from "./pages/AddSafes";
import ProviderPage from "./pages/ProviderPage";
import StaticSafesPage from "./pages/StaticSafesPage";
import SetupPage from "./pages/SetupPage";
import LoginPage from "./pages/LoginPage";
import Footer from "./components/Footer";
import { FaviconProvider } from "./context/FaviconContext";

type AuthState = {
  mode: string;
  authenticated: boolean;
  loading: boolean;
};

function AppContent() {
  const [auth, setAuth] = useState<AuthState>({ mode: "", authenticated: false, loading: true });

  useEffect(() => {
    api
      .getAuthStatus()
      .then((status) => setAuth({ mode: status.mode, authenticated: status.authenticated, loading: false }))
      .catch(() => setAuth({ mode: "", authenticated: false, loading: false }));
  }, []);

  if (auth.loading) {
    return (
      <div className="app-wrapper">
        <div className="app-content">
          <div className="loading">Loading...</div>
        </div>
      </div>
    );
  }

  if (auth.mode === "unset") {
    return (
      <div className="app-wrapper">
        <div className="app-content">
          <SetupPage />
        </div>
      </div>
    );
  }

  if (auth.mode === "enabled" && !auth.authenticated) {
    return (
      <div className="app-wrapper">
        <div className="app-content">
          <LoginPage />
        </div>
      </div>
    );
  }

  return (
    <div className="app-wrapper">
      <div className="app-content">
        <Routes>
          <Route path="/" element={<BrowseSafes />} />
          <Route path="/unlock/:id" element={<UnlockSafe />} />
          <Route path="/safe/:id" element={<TreeView />} />
          <Route path="/add" element={<AddSafes />} />
          <Route path="/add/static" element={<StaticSafesPage />} />
          <Route path="/add/:providerId" element={<ProviderPage />} />
          <Route path="/setup" element={<Navigate to="/" replace />} />
          <Route path="/login" element={<Navigate to="/" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
      <Footer />
    </div>
  );
}

function App() {
  return (
    <FaviconProvider>
      <BrowserRouter basename="/web">
        <AppContent />
      </BrowserRouter>
    </FaviconProvider>
  );
}

export default App;
