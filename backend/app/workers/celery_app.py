from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "vulnflanker",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks"],
)

celery_app.conf.task_default_queue = "vulnflanker.default"
celery_app.conf.task_serializer = "json"
celery_app.conf.result_serializer = "json"
celery_app.conf.accept_content = ["json"]

celery_app.conf.beat_schedule = {
    "vulnflanker-enrichment-source-dispatcher": {
        "task": "vulnflanker.dispatch_due_enrichment_sources",
        "schedule": settings.intel_enrichment_scheduler_tick_seconds,
    },
    "vulnflanker-enrichment-reevaluation-dispatcher": {
        "task": "vulnflanker.dispatch_pending_enrichment_reevaluations",
        "schedule": settings.intel_enrichment_scheduler_tick_seconds,
    },
    "vulnflanker-cisa-kev-monitor": {
        "task": "vulnflanker.collect_cisa_kev_monitor",
        "schedule": settings.cisa_kev_monitor_tick_seconds,
    },
    "vulnflanker-watchvuln-monitor": {
        "task": "vulnflanker.collect_watchvuln_monitor",
        "schedule": settings.watchvuln_monitor_tick_seconds,
    },
    "vulnflanker-email-delivery-dispatcher": {
        "task": "vulnflanker.dispatch_due_email_deliveries",
        "schedule": 60.0,
    },
    "vulnflanker-notification-cleanup": {
        "task": "vulnflanker.cleanup_expired_notifications",
        "schedule": 3600.0,
    },
}
