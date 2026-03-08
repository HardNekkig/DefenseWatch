"""
Vhost detection from Nginx and Apache configuration files.

Scans web server configs to discover all hosted domains, including
listen ports and SSL status.
"""

import logging
import re
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class VirtualHost:
    """Represents a discovered virtual host."""
    domain: str
    port: int
    ssl: bool
    config_file: str

    @property
    def url(self) -> str:
        """Generate the target URL for this vhost."""
        scheme = "https" if self.ssl else "http"
        # Omit standard ports (80/443) from URL
        if (self.port == 80 and not self.ssl) or (self.port == 443 and self.ssl):
            return f"{scheme}://{self.domain}"
        return f"{scheme}://{self.domain}:{self.port}"


def detect_nginx_vhosts(config_dirs: list[str] | None = None) -> list[VirtualHost]:
    """
    Detect virtual hosts from Nginx configuration files.

    Args:
        config_dirs: List of directories to search. Defaults to standard Nginx locations.

    Returns:
        List of discovered VirtualHost objects
    """
    if config_dirs is None:
        config_dirs = [
            "/etc/nginx/sites-enabled",
            "/etc/nginx/conf.d",
            "/usr/local/etc/nginx/sites-enabled",
        ]

    vhosts = []

    for config_dir in config_dirs:
        path = Path(config_dir)
        if not path.exists():
            continue

        for config_file in path.rglob("*"):
            if not config_file.is_file():
                continue
            # Skip backup files, dpkg files, etc.
            if config_file.name.startswith(".") or config_file.suffix in (".bak", ".dpkg-old", ".dpkg-dist"):
                continue

            try:
                vhosts.extend(_parse_nginx_config(config_file))
            except Exception as e:
                logger.debug(f"Failed to parse Nginx config {config_file}: {e}")

    return vhosts


def detect_apache_vhosts(config_dirs: list[str] | None = None) -> list[VirtualHost]:
    """
    Detect virtual hosts from Apache configuration files.

    Args:
        config_dirs: List of directories to search. Defaults to standard Apache locations.

    Returns:
        List of discovered VirtualHost objects
    """
    if config_dirs is None:
        config_dirs = [
            "/etc/apache2/sites-enabled",
            "/etc/httpd/conf.d",
            "/usr/local/etc/apache2/sites-enabled",
        ]

    vhosts = []

    for config_dir in config_dirs:
        path = Path(config_dir)
        if not path.exists():
            continue

        for config_file in path.rglob("*"):
            if not config_file.is_file():
                continue
            # Skip backup files
            if config_file.name.startswith(".") or config_file.suffix in (".bak", ".dpkg-old", ".dpkg-dist"):
                continue

            try:
                vhosts.extend(_parse_apache_config(config_file))
            except Exception as e:
                logger.debug(f"Failed to parse Apache config {config_file}: {e}")

    return vhosts


def _parse_nginx_config(config_file: Path) -> list[VirtualHost]:
    """Parse a single Nginx config file and extract server_name directives."""
    vhosts = []

    try:
        content = config_file.read_text(errors="ignore")
    except (IOError, PermissionError) as e:
        logger.debug(f"Cannot read {config_file}: {e}")
        return []

    # Remove comment blocks (lines starting with #)
    lines = []
    for line in content.splitlines():
        # Remove inline comments but preserve URLs with # fragments
        if "#" in line:
            # Only remove if # is at start or after whitespace (not in URLs)
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue  # Skip fully commented lines
        lines.append(line)
    content = "\n".join(lines)

    # Find all server blocks
    server_blocks = re.finditer(
        r'server\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}',
        content,
        re.MULTILINE | re.DOTALL
    )

    for match in server_blocks:
        block = match.group(1)

        # Extract server_name(s)
        server_names = []
        for name_match in re.finditer(r'server_name\s+([^;]+);', block):
            names = name_match.group(1).strip().split()
            # Filter out wildcard/default/placeholder server names
            excluded = ("_", "localhost", "127.0.0.1", "::1", "example.com", "example.net", "example.org")
            server_names.extend([
                n for n in names
                if n not in excluded
                and not n.startswith("*")
                and not n.endswith(".example")
                and not n.endswith(".test")
                and not n.endswith(".invalid")
                and not n.endswith(".localhost")
            ])

        if not server_names:
            continue

        # Detect port and SSL
        ssl = bool(re.search(r'listen\s+[^;]*\bssl\b', block))

        # Extract port from listen directive
        port = 443 if ssl else 80
        listen_match = re.search(r'listen\s+(?:\[::\]:)?(\d+)', block)
        if listen_match:
            port = int(listen_match.group(1))

        # Create VirtualHost for each server_name
        for domain in server_names:
            vhosts.append(VirtualHost(
                domain=domain,
                port=port,
                ssl=ssl,
                config_file=str(config_file)
            ))

    return vhosts


def _parse_apache_config(config_file: Path) -> list[VirtualHost]:
    """Parse a single Apache config file and extract ServerName/ServerAlias directives."""
    vhosts = []

    try:
        content = config_file.read_text(errors="ignore")
    except (IOError, PermissionError) as e:
        logger.debug(f"Cannot read {config_file}: {e}")
        return []

    # Find all VirtualHost blocks
    vhost_blocks = re.finditer(
        r'<VirtualHost\s+([^>]+)>(.+?)</VirtualHost>',
        content,
        re.MULTILINE | re.DOTALL | re.IGNORECASE
    )

    for match in vhost_blocks:
        addr_port = match.group(1).strip()
        block = match.group(2)

        # Extract port from VirtualHost directive (e.g., *:443, _default_:80)
        port = 80
        ssl = False
        port_match = re.search(r':(\d+)', addr_port)
        if port_match:
            port = int(port_match.group(1))
            ssl = (port == 443)

        # Check for SSLEngine directive
        if re.search(r'SSLEngine\s+on', block, re.IGNORECASE):
            ssl = True

        # Extract ServerName
        server_name = None
        name_match = re.search(r'ServerName\s+(\S+)', block, re.IGNORECASE)
        if name_match:
            server_name = name_match.group(1)

        # Extract ServerAlias(es)
        server_aliases = []
        for alias_match in re.finditer(r'ServerAlias\s+(.+)', block, re.IGNORECASE):
            aliases = alias_match.group(1).strip().split()
            server_aliases.extend(aliases)

        # Combine ServerName and ServerAlias
        excluded = ("localhost", "127.0.0.1", "::1", "example.com", "example.net", "example.org")
        domains = []
        if server_name and server_name not in excluded:
            domains.append(server_name)
        domains.extend([
            a for a in server_aliases
            if a not in excluded
            and not a.startswith("*")
            and not a.endswith(".example")
            and not a.endswith(".test")
            and not a.endswith(".invalid")
            and not a.endswith(".localhost")
        ])

        # Create VirtualHost for each domain
        for domain in domains:
            vhosts.append(VirtualHost(
                domain=domain,
                port=port,
                ssl=ssl,
                config_file=str(config_file)
            ))

    return vhosts


def detect_all_vhosts() -> list[VirtualHost]:
    """
    Detect all virtual hosts from both Nginx and Apache configurations.

    Returns:
        Deduplicated list of VirtualHost objects
    """
    all_vhosts = []

    # Detect Nginx vhosts
    nginx_vhosts = detect_nginx_vhosts()
    if nginx_vhosts:
        logger.info(f"Detected {len(nginx_vhosts)} Nginx virtual hosts")
        all_vhosts.extend(nginx_vhosts)

    # Detect Apache vhosts
    apache_vhosts = detect_apache_vhosts()
    if apache_vhosts:
        logger.info(f"Detected {len(apache_vhosts)} Apache virtual hosts")
        all_vhosts.extend(apache_vhosts)

    # Deduplicate by (domain, port, ssl) tuple
    seen = set()
    unique_vhosts = []
    for vhost in all_vhosts:
        key = (vhost.domain, vhost.port, vhost.ssl)
        if key not in seen:
            seen.add(key)
            unique_vhosts.append(vhost)

    return unique_vhosts
