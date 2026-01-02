import { useState, useEffect } from "react";
import { FAVICON_COLOR_SCHEMES, DEFAULT_FAVICON_COLOR, FaviconColorScheme } from "../config/faviconConfig";
import { generateFaviconSvg, setPageFavicon, getFaviconDataUrl } from "../utils/faviconUtils";

const STORAGE_KEY = "pwsafe-favicon-color";

export function useFavicon() {
  const [currentScheme, setCurrentScheme] = useState<FaviconColorScheme>(() => {
    const savedColor = localStorage.getItem(STORAGE_KEY);
    const scheme = FAVICON_COLOR_SCHEMES.find((s) => s.name === savedColor);
    return scheme || FAVICON_COLOR_SCHEMES.find((s) => s.name === DEFAULT_FAVICON_COLOR)!;
  });

  useEffect(() => {
    const svg = generateFaviconSvg(currentScheme.primary, currentScheme.secondary, currentScheme.stroke);
    setPageFavicon(svg);
  }, [currentScheme]);

  const cycleFavicon = () => {
    const currentIndex = FAVICON_COLOR_SCHEMES.findIndex((s) => s.name === currentScheme.name);
    const nextIndex = (currentIndex + 1) % FAVICON_COLOR_SCHEMES.length;
    const nextScheme = FAVICON_COLOR_SCHEMES[nextIndex];

    setCurrentScheme(nextScheme);
    localStorage.setItem(STORAGE_KEY, nextScheme.name);
  };

  const faviconDataUrl = getFaviconDataUrl(currentScheme.primary, currentScheme.secondary, currentScheme.stroke);

  return {
    currentScheme,
    cycleFavicon,
    faviconDataUrl,
  };
}
