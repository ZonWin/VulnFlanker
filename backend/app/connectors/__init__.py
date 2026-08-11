"""External connector extension points."""
from app.connectors.aliyun_avd import AliyunAvdConnector
from app.connectors.cisa_kev import CisaKevConnector
from app.connectors.canonical_ubuntu import CanonicalUbuntuConnector
from app.connectors.cve_list_v5 import CveListV5Connector
from app.connectors.debian_security_tracker import DebianSecurityTrackerConnector
from app.connectors.base import (
    CollectorMetadata,
    CollectorPage,
    CollectorUpdateMode,
    RawIntelRecord,
    VulnerabilitySourceConnector,
)
from app.connectors.registry import CollectorRegistry, build_builtin_registry
from app.connectors.nvd import NvdCveConnector
from app.connectors.redhat_csaf import RedHatCsafConnector

__all__ = [
    "AliyunAvdConnector",
    "CisaKevConnector",
    "CanonicalUbuntuConnector",
    "CveListV5Connector",
    "DebianSecurityTrackerConnector",
    "CollectorMetadata",
    "CollectorPage",
    "CollectorRegistry",
    "CollectorUpdateMode",
    "RawIntelRecord",
    "NvdCveConnector",
    "RedHatCsafConnector",
    "VulnerabilitySourceConnector",
    "build_builtin_registry",
]
