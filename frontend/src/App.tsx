import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import BrowseSafes from "./pages/BrowseSafes";
import UnlockSafe from "./pages/UnlockSafe";
import TreeView from "./pages/TreeView";
import Footer from "./components/Footer";

function App() {
  return (
    <BrowserRouter basename="/web">
      <div className="app-wrapper">
        <div className="app-content">
          <Routes>
            <Route path="/" element={<BrowseSafes />} />
            <Route path="/unlock/:safeName" element={<UnlockSafe />} />
            <Route path="/safe/:safeName" element={<TreeView />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
        <Footer />
      </div>
    </BrowserRouter>
  );
}

export default App;
