# apis/api_support/management/commands/cleanup_logs.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from apis.api_support.models import SystemMetrics, AppLog


class Command(BaseCommand):
    help = "Clean up old system metrics and logs."

    def add_arguments(self, parser):
        parser.add_argument(
            "--metrics-days",
            type=int,
            default=90,
            help="Retention period for system metrics (default: 90 days)."
        )
        parser.add_argument(
            "--logs-days",
            type=int,
            default=90,
            help="Retention period for application logs (default: 90 days)."
        )

    def handle(self, *args, **options):
        now = timezone.now()

        metrics_cutoff = now - timedelta(days=options["metrics_days"])
        logs_cutoff = now - timedelta(days=options["logs_days"])

        metrics_deleted, _ = SystemMetrics.objects.filter(timestamp__lt=metrics_cutoff).delete()
        logs_deleted, _ = AppLog.objects.filter(timestamp__lt=logs_cutoff).delete()

        self.stdout.write(
            self.style.SUCCESS(
                f"✅ Cleanup complete: {metrics_deleted} metrics and {logs_deleted} logs deleted."
            )
        )
