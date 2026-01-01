import { useParams, useNavigate, useLocation } from "react-router-dom";
import { useState, useEffect } from "react";
import { api, SafeStructure, Group, Entry } from "../api/client";

type LocationState = {
  structure: SafeStructure;
  password: string;
  safeName: string;
};

type TreeItemProps = {
  level: number;
  isGroup: boolean;
  isExpanded?: boolean;
  name: string;
  icon: string;
  entry?: Entry;
  onCopy?: (entry: Entry) => void;
  onToggle?: () => void;
};

function TreeItem({ level, isGroup, isExpanded, name, icon, entry, onCopy, onToggle }: TreeItemProps) {
  return (
    <div className={`tree-item ${isGroup ? "group" : ""}`} onClick={onToggle}>
      <span className="indent" style={{ width: `${level * 24}px` }}></span>
      <span className="expand-icon">{isGroup ? (isExpanded ? "▼" : "▶") : ""}</span>
      <span className="item-icon">{icon}</span>
      <span className="item-name">{name}</span>
      {!isGroup && entry && (
        <button
          className="copy-button"
          onClick={(e) => {
            e.stopPropagation();
            onCopy?.(entry);
          }}
        >
          Copy
        </button>
      )}
    </div>
  );
}

function TreeView() {
  const { safeName } = useParams<{ safeName: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const [structure, setStructure] = useState<SafeStructure | null>(null);
  const [password, setPassword] = useState<string | null>(null);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [copyMessage, setCopyMessage] = useState<string | null>(null);

  useEffect(() => {
    const state = location.state as LocationState | null;

    if (!state || !state.structure || !state.password || state.safeName !== safeName) {
      navigate("/");
      return;
    }

    setStructure(state.structure);
    setPassword(state.password);
  }, [safeName, navigate, location.state]);

  const getGroupPath = (groupName: string, parentPath: string = ""): string => {
    return parentPath ? `${parentPath}.${groupName}` : groupName;
  };

  const toggleGroup = (groupPath: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(groupPath)) {
        next.delete(groupPath);
      } else {
        next.add(groupPath);
      }
      return next;
    });
  };

  const handleCopyPassword = async (entry: Entry) => {
    if (!password || !safeName) {
      setCopyMessage("Error: Session expired");
      setTimeout(() => setCopyMessage(null), 3000);
      return;
    }

    try {
      const entryPassword = await api.getEntryPassword(safeName, password, entry.uuid);
      await navigator.clipboard.writeText(entryPassword);
      setCopyMessage(`Copied password for ${entry.title}`);
      setTimeout(() => setCopyMessage(null), 3000);
    } catch (err) {
      setCopyMessage(err instanceof Error ? err.message : "Failed to copy password");
      setTimeout(() => setCopyMessage(null), 3000);
    }
  };

  const renderGroup = (group: Group, level: number, parentPath: string = ""): React.ReactElement[] => {
    const groupPath = getGroupPath(group.name, parentPath);
    const isExpanded = expandedGroups.has(groupPath);
    const elements: React.ReactElement[] = [];

    elements.push(
      <TreeItem
        key={groupPath}
        level={level}
        isGroup={true}
        isExpanded={isExpanded}
        name={group.name}
        icon="📂"
        onToggle={() => toggleGroup(groupPath)}
      />,
    );

    if (isExpanded) {
      group.entries
        ?.slice()
        .sort((a, b) => a.title.localeCompare(b.title))
        .forEach((entry) => {
          elements.push(
            <TreeItem
              key={entry.uuid}
              level={level + 1}
              isGroup={false}
              name={`${entry.title} [${entry.username}]`}
              icon="🔑"
              entry={entry}
              onCopy={handleCopyPassword}
            />,
          );
        });

      group.groups
        ?.slice()
        .sort((a, b) => a.name.localeCompare(b.name))
        .forEach((subGroup) => {
          elements.push(...renderGroup(subGroup, level + 1, groupPath));
        });
    }

    return elements;
  };

  if (!structure) {
    return (
      <div className="tree-container-page">
        <div className="loading">Loading...</div>
      </div>
    );
  }

  return (
    <div className="tree-container-page">
      {copyMessage && <div className="toast-message">{copyMessage}</div>}

      <div className="tree-card">
        <div className="header">
          <div className="safe-name">{safeName}</div>
        </div>

        <div className="tree-container">
          {structure.groups
            .slice()
            .sort((a, b) => a.name.localeCompare(b.name))
            .map((group) => renderGroup(group, 0))}
        </div>
      </div>
    </div>
  );
}

export default TreeView;
