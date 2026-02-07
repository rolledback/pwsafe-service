import { useParams, useNavigate, useLocation } from "react-router-dom";
import { useState, useEffect, useRef } from "react";
import { api, SafeStructure, Group, Entry } from "../api/client";

type LocationState = {
  structure: SafeStructure;
  password: string;
  id: string;
  safeName: string;
};

type TreeItemProps = {
  level: number;
  isGroup: boolean;
  isExpanded?: boolean;
  name: string;
  icon: string;
  entry?: Entry;
  onCopyPassword?: (entry: Entry) => void;
  onCopyUsername?: (entry: Entry) => void;
  onToggle?: () => void;
};

function TreeItem({ level, isGroup, isExpanded, name, icon, entry, onCopyPassword, onCopyUsername, onToggle }: TreeItemProps) {
  return (
    <div className={`tree-item ${isGroup ? "group" : ""}`} onClick={onToggle}>
      <span className="indent" style={{ width: `${level * 24}px` }}></span>
      <span className="expand-icon">{isGroup ? (isExpanded ? "▼" : "▶") : ""}</span>
      <span className="item-icon">{icon}</span>
      <span className="item-name">{name}</span>
      {!isGroup && entry && (
        <>
          <button
            className="copy-button"
            onClick={(e) => {
              e.stopPropagation();
              onCopyUsername?.(entry);
            }}
          >
            Copy 👤
          </button>
          <button
            className="copy-button"
            onClick={(e) => {
              e.stopPropagation();
              onCopyPassword?.(entry);
            }}
          >
            Copy 🔑
          </button>
        </>
      )}
    </div>
  );
}

function TreeView() {
  const { id: urlId } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const [structure, setStructure] = useState<SafeStructure | null>(null);
  const [password, setPassword] = useState<string | null>(null);
  const [id, setId] = useState<string | null>(null);
  const [displayName, setDisplayName] = useState<string>("");
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [copyMessage, setCopyMessage] = useState<string | null>(null);
  const [filterText, setFilterText] = useState("");
  const [filterActive, setFilterActive] = useState(false);
  const filterInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const state = location.state as LocationState | null;

    if (!state || !state.structure || !state.password || state.id !== urlId) {
      navigate("/");
      return;
    }

    setStructure(state.structure);
    setPassword(state.password);
    setId(state.id);
    setDisplayName(state.safeName || urlId || "Safe");
  }, [urlId, navigate, location.state]);

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
    if (!password || !id) {
      setCopyMessage("Error: Session expired");
      setTimeout(() => setCopyMessage(null), 3000);
      return;
    }

    try {
      const entryPassword = await api.getEntryPassword(id, password, entry.uuid);
      await navigator.clipboard.writeText(entryPassword);
      setCopyMessage(`Copied password for ${entry.title}`);
      setTimeout(() => setCopyMessage(null), 3000);
    } catch (err) {
      setCopyMessage(err instanceof Error ? err.message : "Failed to copy password");
      setTimeout(() => setCopyMessage(null), 3000);
    }
  };

  const handleCopyUsername = async (entry: Entry) => {
    try {
      await navigator.clipboard.writeText(entry.username);
      setCopyMessage(`Copied username for ${entry.title}`);
      setTimeout(() => setCopyMessage(null), 3000);
    } catch (err) {
      setCopyMessage(err instanceof Error ? err.message : "Failed to copy username");
      setTimeout(() => setCopyMessage(null), 3000);
    }
  };

  type FilteredGroup = { group: Group; matchedEntries: Entry[]; matchedSubGroups: FilteredGroup[]; nameMatches: boolean };

  const filterTree = (
    groups: Group[],
    entries: Entry[],
    query: string,
  ): { filteredGroups: FilteredGroup[]; filteredEntries: Entry[] } => {
    const q = query.toLowerCase();

    const filterGroup = (group: Group): FilteredGroup | null => {
      const nameMatches = group.name.toLowerCase().includes(q);

      const matchedSubGroups = (group.groups || []).map(filterGroup).filter((g): g is FilteredGroup => g !== null);

      const matchedEntries = (group.entries || []).filter(
        (e) => e.title.toLowerCase().includes(q) || e.username.toLowerCase().includes(q),
      );

      if (nameMatches || matchedEntries.length > 0 || matchedSubGroups.length > 0) {
        return { group, matchedEntries, matchedSubGroups, nameMatches };
      }
      return null;
    };

    const filteredGroups = groups.map(filterGroup).filter((g): g is FilteredGroup => g !== null);
    const filteredEntries = entries.filter((e) => e.title.toLowerCase().includes(q) || e.username.toLowerCase().includes(q));
    return { filteredGroups, filteredEntries };
  };

  const renderFilteredGroup = (fg: FilteredGroup, level: number, parentPath: string = ""): React.ReactElement[] => {
    const groupPath = getGroupPath(fg.group.name, parentPath);
    const elements: React.ReactElement[] = [];

    elements.push(<TreeItem key={groupPath} level={level} isGroup={true} isExpanded={true} name={fg.group.name} icon="📂" />);

    fg.matchedSubGroups
      .slice()
      .sort((a, b) => a.group.name.localeCompare(b.group.name))
      .forEach((sub) => {
        elements.push(...renderFilteredGroup(sub, level + 1, groupPath));
      });

    fg.matchedEntries
      .slice()
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
            onCopyPassword={handleCopyPassword}
            onCopyUsername={handleCopyUsername}
          />,
        );
      });

    return elements;
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
      group.groups
        ?.slice()
        .sort((a, b) => a.name.localeCompare(b.name))
        .forEach((subGroup) => {
          elements.push(...renderGroup(subGroup, level + 1, groupPath));
        });

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
              onCopyPassword={handleCopyPassword}
              onCopyUsername={handleCopyUsername}
            />,
          );
        });
    }

    return elements;
  };

  const isFiltering = filterText.length > 0;
  const filtered = isFiltering && structure ? filterTree(structure.groups, structure.entries || [], filterText) : null;
  const hasResults = filtered ? filtered.filteredGroups.length > 0 || filtered.filteredEntries.length > 0 : true;

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
          <div className="safe-header-content">
            <div className="safe-icon">🔒</div>
            <div className="safe-name">{displayName}</div>
          </div>
          <button className="close-button" onClick={() => navigate("/")}>
            ✕
          </button>
        </div>

        <div className="filter-bar">
          {filterActive ? (
            <div className="filter-input-wrapper">
              <span className="filter-input-icon">🔍</span>
              <input
                ref={filterInputRef}
                className="filter-input"
                type="text"
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Escape") {
                    setFilterText("");
                    setFilterActive(false);
                  }
                }}
                onBlur={() => {
                  if (filterText === "") setFilterActive(false);
                }}
                placeholder="Filter entries..."
                autoFocus
              />
            </div>
          ) : (
            <div
              className="filter-pill"
              onClick={() => {
                setFilterActive(true);
                setTimeout(() => filterInputRef.current?.focus(), 0);
              }}
            >
              <span className="filter-pill-icon">🔍</span>
              <span className="filter-pill-text">Filter entries...</span>
            </div>
          )}
        </div>

        <div className="tree-container">
          {isFiltering && filtered ? (
            hasResults ? (
              <>
                {filtered.filteredGroups
                  .slice()
                  .sort((a, b) => a.group.name.localeCompare(b.group.name))
                  .map((fg) => renderFilteredGroup(fg, 0))}
                {filtered.filteredEntries
                  .slice()
                  .sort((a, b) => a.title.localeCompare(b.title))
                  .map((entry) => (
                    <TreeItem
                      key={entry.uuid}
                      level={0}
                      isGroup={false}
                      name={`${entry.title} [${entry.username}]`}
                      icon="🔑"
                      entry={entry}
                      onCopyPassword={handleCopyPassword}
                      onCopyUsername={handleCopyUsername}
                    />
                  ))}
              </>
            ) : (
              <div className="filter-empty">
                <div className="filter-empty-icon">🔍</div>
                <div>No matching entries found</div>
              </div>
            )
          ) : (
            <>
              {structure.groups
                .slice()
                .sort((a, b) => a.name.localeCompare(b.name))
                .map((group) => renderGroup(group, 0))}
              {structure.entries
                ?.slice()
                .sort((a, b) => a.title.localeCompare(b.title))
                .map((entry) => (
                  <TreeItem
                    key={entry.uuid}
                    level={0}
                    isGroup={false}
                    name={`${entry.title} [${entry.username}]`}
                    icon="🔑"
                    entry={entry}
                    onCopyPassword={handleCopyPassword}
                    onCopyUsername={handleCopyUsername}
                  />
                ))}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default TreeView;
