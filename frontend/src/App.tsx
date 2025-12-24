import { BrowserRouter, Routes, Route } from "react-router-dom";
import BrowseSafes from "./pages/BrowseSafes";
import UnlockSafe from "./pages/UnlockSafe";
import TreeView from "./pages/TreeView";

function App() {
  return (
    <BrowserRouter basename="/web">
      <Routes>
        <Route path="/" element={<BrowseSafes />} />
        <Route path="/unlock/:safeName" element={<UnlockSafe />} />
        <Route path="/safe/:safeName" element={<TreeView />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
