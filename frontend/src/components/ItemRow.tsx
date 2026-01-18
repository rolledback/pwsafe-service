export type ItemRowProps = {
  icon: string;
  name: string;
  metadata?: string;
  sourceBadge?: string;
  onClick?: () => void;
};

function ItemRow({ icon, name, metadata, sourceBadge, onClick }: ItemRowProps) {
  return (
    <div className="item-row" onClick={onClick}>
      <div className="item-summary">
        <div className="item-icon">{icon}</div>
        <div className="item-details">
          <div className="item-name">{name}</div>
          {(metadata || sourceBadge) && (
            <div className="item-meta">
              {metadata}
              {sourceBadge && <span className="safe-source"> ({sourceBadge})</span>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default ItemRow;
