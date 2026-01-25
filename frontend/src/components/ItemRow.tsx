import { ReactNode } from "react";

export type ItemRowProps = {
  icon: ReactNode;
  name: string;
  metadata?: string;
  sourceBadge?: string;
  sourceBadgeColor?: string;
  onClick?: () => void;
};

function ItemRow({ icon, name, metadata, sourceBadge, sourceBadgeColor, onClick }: ItemRowProps) {
  return (
    <div className="item-row" onClick={onClick}>
      <div className="item-summary">
        <div className="item-icon">{icon}</div>
        <div className="item-details">
          <div className="item-name">{name}</div>
          {(metadata || sourceBadge) && (
            <div className="item-meta">
              {metadata}
              {sourceBadge && (
                <span className="safe-source" style={sourceBadgeColor ? { color: sourceBadgeColor } : undefined}>
                  {" "}
                  ({sourceBadge})
                </span>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default ItemRow;
