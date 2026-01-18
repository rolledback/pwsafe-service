import { useNavigate } from "react-router-dom";
import ItemRow from "../components/ItemRow";

function AddSafes() {
  const navigate = useNavigate();

  return (
    <div className="add-safes-container">
      <div className="page-header">
        <h1>Add Safes</h1>
        <button className="close-button" onClick={() => navigate("/")}>
          ✕
        </button>
      </div>

      <div className="source-list">
        <ItemRow icon="☁️" name="OneDrive" onClick={() => navigate("/add/onedrive")} />
      </div>
    </div>
  );
}

export default AddSafes;
