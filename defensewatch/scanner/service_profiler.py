"""
Service and technology profiler for intelligent Nuclei template selection.

Detects running services and platforms (WordPress, MySQL, PHP, etc.) by
inspecting web server configs, config.yaml log entries, and filesystem
markers. Maps discoveries to Nuclei tags so scans focus on relevant templates.
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Nuclei tags grouped by technology
TECH_TAGS: dict[str, list[str]] = {
    "nginx": ["nginx"],
    "apache": ["apache"],
    "php": ["php"],
    "wordpress": ["wordpress", "wp-plugin", "wp-theme", "wp"],
    "mysql": ["mysql", "mariadb"],
    "postgresql": ["postgres"],
    "ssh": ["ssh"],
    "ftp": ["ftp"],
    "mail": ["smtp", "imap", "pop3", "mail"],
    "ssl": ["ssl", "tls"],
    "nodejs": ["nodejs"],
    "python": ["python", "django", "flask"],
    "java": ["java", "tomcat", "spring"],
    "docker": ["docker"],
    "phpmyadmin": ["phpmyadmin"],
    "grafana": ["grafana"],
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "joomla": ["joomla"],
    "drupal": ["drupal"],
    "laravel": ["laravel"],
    "nextcloud": ["nextcloud"],
    "redis": ["redis"],
    "mongodb": ["mongodb"],
    "elasticsearch": ["elasticsearch"],
    "rabbitmq": ["rabbitmq"],
    "prometheus": ["prometheus"],
}

# Always included — general security checks
BASE_TAGS = ["cve", "misconfig", "exposure", "default-login", "xss", "sqli", "lfi", "ssrf", "rce"]

# Filesystem markers: path pattern -> technology key
_FS_MARKERS: list[tuple[str, str]] = [
    ("/var/www/*/wp-config.php", "wordpress"),
    ("/var/www/*/wp-content", "wordpress"),
    ("/usr/share/wordpress", "wordpress"),
    ("/var/www/*/configuration.php", "joomla"),
    ("/var/www/*/sites/default/settings.php", "drupal"),
    ("/var/www/*/artisan", "laravel"),
    ("/var/www/*/config/config.php", "nextcloud"),
    ("/etc/mysql", "mysql"),
    ("/etc/mysql/mariadb.conf.d", "mysql"),
    ("/etc/postgresql", "postgresql"),
    ("/var/lib/redis", "redis"),
    ("/etc/redis", "redis"),
    ("/var/lib/mongodb", "mongodb"),
    ("/etc/mongod.conf", "mongodb"),
    ("/etc/elasticsearch", "elasticsearch"),
    ("/etc/grafana", "grafana"),
    ("/var/lib/jenkins", "jenkins"),
    ("/etc/gitlab", "gitlab"),
    ("/etc/phpmyadmin", "phpmyadmin"),
    ("/usr/share/phpmyadmin", "phpmyadmin"),
    ("/etc/rabbitmq", "rabbitmq"),
    ("/etc/prometheus", "prometheus"),
    ("/etc/docker", "docker"),
]

# Nginx config patterns: regex -> technology key
_NGINX_PATTERNS: list[tuple[str, str]] = [
    (r"fastcgi_pass\s+", "php"),
    (r"\.php\b", "php"),
    (r"/wp-content|/wp-admin|/wp-includes|wordpress", "wordpress"),
    (r"proxy_pass\s+http://.*:3000", "grafana"),
    (r"proxy_pass\s+http://.*:808[0-9]", "nodejs"),
    (r"proxy_pass\s+http://.*:9090", "prometheus"),
    (r"proxy_pass\s+http://.*:9200", "elasticsearch"),
    (r"proxy_pass\s+http://.*:15672", "rabbitmq"),
    (r"proxy_pass\s+http://.*:8080", "java"),
    (r"/phpmyadmin", "phpmyadmin"),
    (r"/jenkins", "jenkins"),
    (r"/gitlab", "gitlab"),
    (r"/nextcloud", "nextcloud"),
]


@dataclass
class ServiceProfile:
    """Result of service/technology detection."""
    detected_techs: dict[str, list[str]] = field(default_factory=dict)
    nuclei_tags: list[str] = field(default_factory=list)
    has_ssl: bool = False

    def summary(self) -> dict:
        return {
            "detected_technologies": {
                tech: reasons for tech, reasons in self.detected_techs.items()
            },
            "nuclei_tags": self.nuclei_tags,
            "tag_count": len(self.nuclei_tags),
        }


def profile_services(config) -> ServiceProfile:
    """
    Build a service profile by inspecting config, nginx configs, and filesystem.

    Args:
        config: AppConfig instance

    Returns:
        ServiceProfile with detected technologies and corresponding Nuclei tags
    """
    profile = ServiceProfile()

    _detect_from_config(config, profile)
    _detect_from_nginx_configs(profile)
    _detect_from_filesystem(profile)

    # Build the final tag list
    tags = set(BASE_TAGS)
    for tech in profile.detected_techs:
        if tech in TECH_TAGS:
            tags.update(TECH_TAGS[tech])

    if profile.has_ssl:
        tags.update(TECH_TAGS["ssl"])

    profile.nuclei_tags = sorted(tags)
    return profile


def _add_tech(profile: ServiceProfile, tech: str, reason: str):
    """Register a detected technology with its detection reason."""
    if tech not in profile.detected_techs:
        profile.detected_techs[tech] = []
    if reason not in profile.detected_techs[tech]:
        profile.detected_techs[tech].append(reason)


def _detect_from_config(config, profile: ServiceProfile):
    """Detect services from config.yaml log entries."""
    if config.logs.ssh_entries():
        _add_tech(profile, "ssh", "config: ssh log entries")

    if config.logs.http_entries():
        for entry in config.logs.http_entries():
            if entry.port == 443:
                profile.has_ssl = True
                break

    if config.logs.mysql_entries():
        _add_tech(profile, "mysql", "config: mysql log entries")

    if config.logs.postgresql_entries():
        _add_tech(profile, "postgresql", "config: postgresql log entries")

    if config.logs.mail_entries():
        _add_tech(profile, "mail", "config: mail log entries")

    if config.logs.ftp_entries():
        _add_tech(profile, "ftp", "config: ftp log entries")


def _detect_from_nginx_configs(profile: ServiceProfile):
    """Inspect Nginx site configs for technology hints."""
    search_dirs = [
        Path("/etc/nginx/sites-enabled"),
        Path("/etc/nginx/conf.d"),
    ]

    for config_dir in search_dirs:
        if not config_dir.exists():
            continue

        for config_file in config_dir.rglob("*"):
            if not config_file.is_file():
                continue
            if config_file.name.startswith(".") or config_file.suffix in (".bak", ".dpkg-old"):
                continue

            try:
                content = config_file.read_text(errors="ignore")
            except (IOError, PermissionError):
                continue

            _add_tech(profile, "nginx", f"config file: {config_file}")

            if re.search(r"listen\s+[^;]*\bssl\b", content):
                profile.has_ssl = True

            for pattern, tech in _NGINX_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    _add_tech(profile, tech, f"nginx config: {config_file.name}")


def _detect_from_filesystem(profile: ServiceProfile):
    """Check well-known filesystem paths for installed software."""
    for glob_pattern, tech in _FS_MARKERS:
        if "*" in glob_pattern:
            parent = Path(glob_pattern.split("*")[0])
            if not parent.exists():
                continue
            try:
                matches = list(parent.glob(glob_pattern[len(str(parent)) + 1:]))
            except (PermissionError, OSError):
                continue
            if matches:
                _add_tech(profile, tech, f"filesystem: {glob_pattern}")
        else:
            if Path(glob_pattern).exists():
                _add_tech(profile, tech, f"filesystem: {glob_pattern}")
