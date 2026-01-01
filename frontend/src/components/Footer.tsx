import githubLogo from "../assets/github-mark.svg";

function Footer() {
  return (
    <footer className="app-footer">
      <a href="https://github.com/rolledback/pwsafe-service" target="_blank" rel="noopener noreferrer" className="github-link">
        <img src={githubLogo} alt="GitHub" className="github-logo" />
      </a>
    </footer>
  );
}

export default Footer;
