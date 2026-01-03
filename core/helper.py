import datetime
from user_agents import parse
from django.utils import timezone

def sanitize_request_data(request_data: dict) -> dict:
    """
    Sanitize sensitive request data before logging.
    """
    sanitized_data = request_data.copy()
    if "password" in sanitized_data:
        sanitized_data["password"] = "********"
    return sanitized_data


def parse_user_agent(user_agent_string: str) -> dict:
    """
    Parse the User-Agent string into structured device/browser/os info.
    """
    ua = parse(user_agent_string or "")
    return {
        "browser": ua.browser.family or "Unknown",
        "browser_version": ua.browser.version_string or "Unknown",
        "os": ua.os.family or "Unknown",
        "os_version": ua.os.version_string or "Unknown",
        "device_type": (
            "Mobile" if ua.is_mobile else
            "Tablet" if ua.is_tablet else
            "PC" if ua.is_pc else
            "Bot" if ua.is_bot else
            "Other"
        ),
        "device_brand": ua.device.brand or ("Desktop" if ua.is_pc else "Unknown"),
        "device_model": ua.device.model or ("Desktop" if ua.is_pc else "Unknown"),
    }


def get_client_ip(request) -> str:
    """
    Extract client IP address from request headers.
    """
    ip = request.META.get("HTTP_X_FORWARDED_FOR")
    if ip:
        return ip.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "Unknown")


def store_activity(
    request,
    activity_type: str,
    user=None,
    data: dict = None,
    status_code: int = None,
    is_successful: bool = True,
    error_message: str = None
):
    """
    Store a user activity log with request, device, and context information.
    """

    # --- sanitize payload ---
    from apis.api_auth.models import UserActivity

    sanitized_data = sanitize_request_data(data) if data else {}
    for key, value in sanitized_data.items():
        if isinstance(value, (datetime.datetime, datetime.date)):
            sanitized_data[key] = value.isoformat()

    # --- request meta ---
    ip_address = get_client_ip(request)
    endpoint = request.path
    method = request.method
    user_agent_string = request.META.get("HTTP_USER_AGENT", "")

    # --- parse user agent ---
    ua_info = parse_user_agent(user_agent_string)

    # --- create activity record ---
    UserActivity.objects.create(
        user=user if user and user.is_authenticated else None,
        session_id=request.session.session_key if hasattr(request, "session") else None,
        activity_type=activity_type,
        endpoint=endpoint,
        method=method,
        status_code=status_code,
        data=sanitized_data,
        ip_address=ip_address,
        geo_country=None,   # ← hook into GeoIP later if needed
        geo_city=None,      # ← hook into GeoIP later if needed
        user_agent=user_agent_string,
        browser=ua_info["browser"],
        browser_version=ua_info["browser_version"],
        os=ua_info["os"],
        os_version=ua_info["os_version"],
        device_type=ua_info["device_type"],
        device_brand=ua_info["device_brand"],
        device_model=ua_info["device_model"],
        is_successful=is_successful,
        error_message=error_message,
        action_date_time=timezone.now(),
    )
