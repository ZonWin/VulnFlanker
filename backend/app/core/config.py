from functools import lru_cache
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "VulnFlanker"
    app_env: str = "development"
    api_prefix: str = "/api/v1"
    agent_api_prefix: str = "/agent/v1"
    agent_ingress_port: int = 8001
    legacy_agent_api_enabled: bool = False
    log_level: str = "INFO"
    system_timezone: str = "Asia/Shanghai"

    database_url: str = (
        "postgresql+psycopg://vulnflanker:vulnflanker@localhost:5432/vulnflanker"
    )
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"
    cisa_kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    cisa_kev_catalog_url: str = (
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    )
    cisa_kev_cve_record_url_template: str = (
        "https://cveawg.mitre.org/api/cve/{cve_id}"
    )
    cisa_kev_cve_record_fetch: bool = True
    cisa_kev_cve_record_workers: int = 8
    cisa_kev_monitor_enabled: bool = False
    cisa_kev_monitor_interval_seconds: int = 86_400
    cisa_kev_monitor_limit: int | None = None
    cisa_kev_monitor_tick_seconds: int = 300
    aliyun_avd_high_risk_url: str = "https://avd.aliyun.com/high-risk/list"
    watchvuln_collector_command: str | None = None
    watchvuln_collector_path: str | None = None
    watchvuln_collector_timeout_seconds: int = 300
    watchvuln_sources: str = "avd,chaitin,oscs,ti,threatbook,seebug,struts2,kev,venustech"
    watchvuln_page_limit: int = 1
    watchvuln_valuable_only: bool = True
    watchvuln_proxy: str | None = None
    watchvuln_skip_tls_verify: bool = False
    watchvuln_monitor_enabled: bool = False
    watchvuln_monitor_interval_seconds: int = 1800
    watchvuln_monitor_limit: int | None = None
    watchvuln_monitor_tick_seconds: int = 60
    intel_webhook_token: str | None = None
    intel_webhook_max_body_bytes: int = 1_000_000
    risk_weight_severity: float = 0.30
    risk_weight_exploitability: float = 0.18
    risk_weight_exposure: float = 0.15
    risk_weight_business_criticality: float = 0.17
    risk_weight_confidence: float = 0.08
    risk_weight_verification: float = 0.07
    risk_weight_asset_freshness: float = 0.05
    verification_queued_timeout_seconds: int = 86_400
    verification_in_progress_timeout_seconds: int = 3_600
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str | None = None
    bootstrap_admin_display_name: str = "系统管理员"
    session_cookie_name: str = "vulnflanker_session"
    session_ttl_seconds: int = 86_400
    session_cookie_secure: bool = False
    login_security_enabled: bool = True
    login_security_secret: str | None = None
    login_trusted_proxy_cidrs: str = "127.0.0.1/32,::1/128"
    login_ban_exempt_cidrs: str = ""
    login_ipv6_prefix_length: int = 64
    login_captcha_length: int = 5
    login_captcha_ttl_seconds: int = 120
    login_captcha_issue_limit: int = 20
    login_captcha_issue_window_seconds: int = 300
    login_captcha_failure_limit: int = 20
    login_captcha_failure_window_seconds: int = 300
    login_failure_threshold: int = 5
    login_failure_window_seconds: int = 600
    login_penalty_decay_seconds: int = 2_592_000
    ai_key_encryption_key: str | None = None
    secret_encryption_key: str | None = None

    @field_validator("cisa_kev_monitor_limit", "watchvuln_monitor_limit", mode="before")
    @classmethod
    def _empty_optional_int_to_none(cls, value: object) -> object:
        if value == "":
            return None
        return value

    @field_validator(
        "bootstrap_admin_password",
        "login_security_secret",
        "ai_key_encryption_key",
        "secret_encryption_key",
        mode="before",
    )
    @classmethod
    def _empty_optional_str_to_none(cls, value: object) -> object:
        if value == "":
            return None
        return value

    @field_validator("system_timezone")
    @classmethod
    def _valid_system_timezone(cls, value: str) -> str:
        normalized = value.strip()
        try:
            ZoneInfo(normalized)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("system_timezone must be a valid IANA timezone") from exc
        return normalized

    @field_validator("login_ipv6_prefix_length")
    @classmethod
    def _valid_login_ipv6_prefix_length(cls, value: int) -> int:
        if not 1 <= value <= 128:
            raise ValueError("login_ipv6_prefix_length must be between 1 and 128")
        return value

    @field_validator(
        "login_captcha_length",
        "login_captcha_ttl_seconds",
        "login_captcha_issue_limit",
        "login_captcha_issue_window_seconds",
        "login_captcha_failure_limit",
        "login_captcha_failure_window_seconds",
        "login_failure_threshold",
        "login_failure_window_seconds",
        "login_penalty_decay_seconds",
    )
    @classmethod
    def _positive_login_security_value(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("login security numeric settings must be positive")
        return value

    @field_validator("login_trusted_proxy_cidrs", "login_ban_exempt_cidrs")
    @classmethod
    def _valid_login_cidr_list(cls, value: str) -> str:
        from app.core.client_ip import validate_cidr_list

        return validate_cidr_list(value)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="VULNFLANKER_",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
