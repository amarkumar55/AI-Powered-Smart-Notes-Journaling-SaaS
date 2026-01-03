# payment/audit.py
from .models import PaymentAuditLog
from apis.api_auth.utlity import get_client_ip, get_request_id

def log_payment_event(
    request,
    *,
    action: str,
    outcome: str,
    message: str = "",
    payment_id: str = "",
    refund_id: str = "",
    amount=None,
    currency: str = "",
):
    try:
        PaymentAuditLog.objects.create(
            user=getattr(request, "user", None) if getattr(request, "user", None).is_authenticated else None,
            action=action,
            outcome=outcome,
            message=(message or "")[:4000],  # guard size
            ip_address=get_client_ip(request),
            user_agent=(request.META.get("HTTP_USER_AGENT") or "")[:1000],
            request_id=get_request_id(request),
            payment_id=str(payment_id or "")[:64],
            refund_id=str(refund_id or "")[:64],
            amount=amount,
            currency=(currency or "")[:8],
        )
    except Exception:
        # Never let audit failure break the API path
        pass
