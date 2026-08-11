"""External connector extension points."""
from app.connectors.aliyun_avd import AliyunAvdConnector
from app.connectors.cisa_kev import CisaKevConnector
from app.connectors.cve_list_v5 import CveListV5Connector
from app.connectors.base import (
    CollectorMetadata,
    CollectorPage,
    CollectorUpdateMode,
    RawIntelRecord,
    VulnerabilitySourceConnector,
)
from app.connectors.registry import CollectorRegistry, build_builtin_registry
from app.connectors.nvd import NvdCveConnector

__all__ = [
    "AliyunAvdConnector",
    "CisaKevConnector",
    "CveListV5Connector",
    "CollectorMetadata",
    "CollectorPage",
    "CollectorRegistry",
    "CollectorUpdateMode",
    "RawIntelRecord",
    "NvdCveConnector",
    "VulnerabilitySourceConnector",
    "build_builtin_registry",
]
