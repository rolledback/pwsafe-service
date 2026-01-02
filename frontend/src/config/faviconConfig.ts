export type FaviconColorScheme = {
  name: string;
  primary: string;
  secondary: string;
  stroke: string;
};

export const FAVICON_COLOR_SCHEMES: FaviconColorScheme[] = [
  {
    name: "red",
    primary: "#dc2626",
    secondary: "#b91c1c",
    stroke: "#991b1b",
  },
  {
    name: "rose",
    primary: "#be123c",
    secondary: "#9f1239",
    stroke: "#881337",
  },
  {
    name: "orange",
    primary: "#ea580c",
    secondary: "#c2410c",
    stroke: "#9a3412",
  },
  {
    name: "bronze",
    primary: "#b45309",
    secondary: "#92400e",
    stroke: "#78350f",
  },
  {
    name: "green",
    primary: "#059669",
    secondary: "#047857",
    stroke: "#065f46",
  },
  {
    name: "cyan",
    primary: "#0891b2",
    secondary: "#0e7490",
    stroke: "#155e75",
  },
  {
    name: "blue",
    primary: "#4a90e2",
    secondary: "#357abd",
    stroke: "#2c5a8f",
  },
  {
    name: "dark-blue",
    primary: "#2c5282",
    secondary: "#1e3a5f",
    stroke: "#1a365d",
  },
  {
    name: "purple",
    primary: "#7c3aed",
    secondary: "#6d28d9",
    stroke: "#5b21b6",
  },
  {
    name: "black",
    primary: "#18181b",
    secondary: "#27272a",
    stroke: "#09090b",
  },
  {
    name: "slate-gray",
    primary: "#475569",
    secondary: "#334155",
    stroke: "#1e293b",
  },
];

export const DEFAULT_FAVICON_COLOR = "rose";
