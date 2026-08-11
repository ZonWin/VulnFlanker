from __future__ import annotations

from app.matching.utils import normalize_name


PRODUCT_ALIAS_GROUPS: tuple[tuple[str, ...], ...] = (
    (
        "linux kernel",
        "linux-kernel",
        "linux",
        "kernel",
        "linux-image",
        "linux-image-generic",
        "linux-headers",
    ),
    ("ubuntu", "ubuntu linux"),
    ("debian", "debian linux"),
    ("red hat enterprise linux", "rhel", "redhat", "red hat"),
    ("centos", "centos linux"),
    ("rocky linux", "rocky"),
    ("almalinux", "alma linux"),
    ("amazon linux", "amzn", "amzn2"),
    ("nginx", "nginx-core", "nginx-common", "nginx-full"),
    ("openssh", "openssh-server", "openssh-client", "ssh", "sshd"),
    ("apache", "apache2", "httpd", "apache-http-server"),
    ("postgresql", "postgres", "postgresql-server"),
    ("mysql", "mysql-server", "mariadb", "mariadb-server"),
)


def product_aliases(product: str | None) -> list[str]:
    if not product:
        return []

    normalized = normalize_name(product)
    aliases = {product}
    for group in PRODUCT_ALIAS_GROUPS:
        normalized_group = {normalize_name(item) for item in group}
        if normalized in normalized_group:
            aliases.update(group)
            break
    return sorted(aliases)


def product_alias_groups() -> list[dict[str, object]]:
    groups = []
    for group in PRODUCT_ALIAS_GROUPS:
        canonical = group[0]
        groups.append(
            {
                "canonical": canonical,
                "aliases": list(group),
            }
        )
    return groups
