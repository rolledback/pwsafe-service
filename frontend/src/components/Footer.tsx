import githubLogo from "../assets/github-mark.svg";
import { useFaviconContext } from "../context/FaviconContext";

function Footer() {
  const { faviconDataUrl, cycleFavicon } = useFaviconContext();

  return (
    <footer className="app-footer">
      <img src={faviconDataUrl} alt="Favicon" className="favicon-icon" onClick={cycleFavicon} />
      <span className="footer-separator"></span>
      <a href="https://github.com/rolledback/pwsafe-service" target="_blank" rel="noopener noreferrer" className="github-link">
        <img src={githubLogo} alt="GitHub" className="github-logo" />
      </a>
    </footer>
  );
}

export default Footer;
