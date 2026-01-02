import { createContext, useContext, ReactNode } from "react";
import { useFavicon } from "../hooks/useFavicon";
import { FaviconColorScheme } from "../config/faviconConfig";

type FaviconContext = {
  currentScheme: FaviconColorScheme;
  cycleFavicon: () => void;
  faviconDataUrl: string;
};

const FaviconContext = createContext<FaviconContext | undefined>(undefined);

export function FaviconProvider({ children }: { children: ReactNode }) {
  const faviconState = useFavicon();

  return <FaviconContext.Provider value={faviconState}>{children}</FaviconContext.Provider>;
}

export function useFaviconContext() {
  const context = useContext(FaviconContext);
  if (!context) {
    throw new Error("useFaviconContext must be used within FaviconProvider");
  }
  return context;
}
