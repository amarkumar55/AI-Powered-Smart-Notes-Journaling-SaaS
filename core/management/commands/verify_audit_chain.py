import sys
from django.core.management.base import BaseCommand
from django.db import transaction
from apis.api_payment.models import PaymentAuditLog, AuditChainCheck


class Command(BaseCommand):
    help = "Verify integrity of the PaymentAuditLog tamper-evident chain and record result."

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=None,
            help="Number of most recent entries to check (default: all).",
        )
        parser.add_argument(
            "--checked-by",
            type=str,
            default="system",
            help="Identifier of who triggered the check (default: system).",
        )
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Print details of the chain verification process.",
        )

    def handle(self, *args, **options):
        limit = options["limit"]
        checked_by = options["checked_by"]
        verbose = options["verbose"]

        self.stdout.write(self.style.NOTICE("🔍 Verifying PaymentAuditLog integrity..."))

        try:
            is_valid = PaymentAuditLog.verify_chain(limit=limit)
            status = AuditChainCheck.STATUS_OK if is_valid else AuditChainCheck.STATUS_BROKEN
            details = "" if is_valid else "Audit chain integrity broken. Possible tampering."
        except Exception as e:
            status = AuditChainCheck.STATUS_ERROR
            details = str(e)

        with transaction.atomic():
            AuditChainCheck.objects.create(
                status=status,
                checked_by=checked_by,
                details=details,
                last_verified_log_id=(
                    PaymentAuditLog.objects.order_by("-id").first().id
                    if PaymentAuditLog.objects.exists() else None
                )
            )

        # Output
        if status == AuditChainCheck.STATUS_OK:
            self.stdout.write(self.style.SUCCESS("✅ Audit log chain is intact."))
            sys.exit(0)
        elif status == AuditChainCheck.STATUS_BROKEN:
            self.stderr.write(self.style.ERROR("❌ Audit log chain is BROKEN! Tampering detected."))
            if verbose:
                self.stderr.write("Hint: run with --limit to narrow down the suspect entries.")
            sys.exit(2)
        else:
            self.stderr.write(self.style.ERROR(f"❌ Error verifying audit log: {details}"))
            sys.exit(1)
