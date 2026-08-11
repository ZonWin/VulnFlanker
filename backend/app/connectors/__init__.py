"""External connector extension points."""
from app.connectors.aliyun_avd import AliyunAvdConnector
from app.connectors.cisa_kev import CisaKevConnector
from app.connectors.base import (
    CollectorMetadata,
    CollectorPage,
    CollectorUpdateMode,
    RawIntelRecord,
    VulnerabilitySourceConnector,
)
from app.connectors.registry import CollectorRegistry, build_builtin_registry

__all__ = [
    "AliyunAvdConnector",
    "CisaKevConnector",
    "CollectorMetadata",
    "CollectorPage",
    "CollectorRegistry",
    "CollectorUpdateMode",
    "RawIntelRecord",
    "VulnerabilitySourceConnector",
    "build_builtin_registry",
]
