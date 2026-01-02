export function generateFaviconSvg(primary: string, secondary: string, stroke: string): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect x="0.5" y="0.5" width="31" height="31" rx="2" fill="${primary}" stroke="${stroke}" stroke-width="1"/>
  <circle cx="16" cy="16" r="10.5" fill="${secondary}" stroke="${stroke}" stroke-width="1"/>
  <circle cx="16" cy="16" r="6.5" fill="none" stroke="#ffffff" stroke-width="1.2"/>
  <circle cx="16" cy="16" r="2.2" fill="#ffffff"/>
  <line x1="16" y1="16" x2="22" y2="10" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round"/>
  <rect x="28" y="14" width="4" height="4" fill="${secondary}" stroke="${stroke}" stroke-width="0.5"/>
</svg>`;
}

export function getFaviconDataUrl(primary: string, secondary: string, stroke: string): string {
  const svgString = generateFaviconSvg(primary, secondary, stroke);
  const encoded = encodeURIComponent(svgString);
  return `data:image/svg+xml,${encoded}`;
}

export function setPageFavicon(svgString: string): void {
  const dataUrl = `data:image/svg+xml,${encodeURIComponent(svgString)}`;

  let link = document.querySelector<HTMLLinkElement>("link[rel~='icon']");

  if (!link) {
    link = document.createElement("link");
    link.rel = "icon";
    document.head.appendChild(link);
  }

  link.href = dataUrl;
}
