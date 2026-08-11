from __future__ import annotations

from collections.abc import Iterable

from app.connectors.base import CollectorMetadata, VulnerabilitySourceConnector


class CollectorRegistry:
    """Registry of independent collectors keyed by stable source name."""

    def __init__(self) -> None:
        self._collectors: dict[str, VulnerabilitySourceConnector] = {}

    def register(
        self,
        collector: VulnerabilitySourceConnector,
        *,
        replace: bool = False,
    ) -> VulnerabilitySourceConnector:
        source_name = collector.metadata.source_name
        if source_name != collector.source_name:
            raise ValueError("collector metadata source_name must match collector source_name")
        if source_name in self._collectors and not replace:
            raise ValueError(f"collector already registered: {source_name}")
        self._collectors[source_name] = collector
        return collector

    def get(self, source_name: str) -> VulnerabilitySourceConnector:
        try:
            return self._collectors[source_name]
        except KeyError as exc:
            raise KeyError(f"unknown vulnerability source collector: {source_name}") from exc

    def metadata(self) -> list[CollectorMetadata]:
        return [self._collectors[name].metadata for name in sorted(self._collectors)]

    def source_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._collectors))

    def register_many(
        self,
        collectors: Iterable[VulnerabilitySourceConnector],
        *,
        replace: bool = False,
    ) -> None:
        for collector in collectors:
            self.register(collector, replace=replace)


def build_builtin_registry() -> CollectorRegistry:
    # Imports stay local so source modules can import the registry contract
    # without creating a connector package import cycle.
    from app.connectors.aliyun_avd import AliyunAvdConnector
    from app.connectors.cisa_kev import CisaKevConnector
    from app.connectors.canonical_ubuntu import CanonicalUbuntuConnector
    from app.connectors.cve_list_v5 import CveListV5Connector
    from app.connectors.debian_security_tracker import DebianSecurityTrackerConnector
    from app.connectors.nvd import NvdCveConnector
    from app.connectors.redhat_csaf import RedHatCsafConnector

    registry = CollectorRegistry()
    registry.register_many(
        (
            CisaKevConnector(),
            AliyunAvdConnector(),
            CveListV5Connector(),
            NvdCveConnector(),
            CanonicalUbuntuConnector(),
            DebianSecurityTrackerConnector(),
            RedHatCsafConnector(),
        )
    )
    return registry
