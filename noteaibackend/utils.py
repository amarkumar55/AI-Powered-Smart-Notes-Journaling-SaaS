from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import PermissionDenied
from django.http import Http404
from django_ratelimit.exceptions import Ratelimited
from django.middleware.csrf import CsrfViewMiddleware
from apis.api_auth.utlity import send_error_log  # your function for email logging

import logging
logger = logging.getLogger("django.request")


def custom_exception_handler(exc, context):
    """
    Centralized error handling:
    - Formats API errors consistently
    - Sends error reports for unhandled 500s
    """
    # Let DRF handle its built-in errors first
    response = exception_handler(exc, context)

    if response is not None:
        response.data = {
            "error": response.data,
            "status_code": response.status_code,
        }
        return response

    # Handle Django/3rd-party exceptions
    if isinstance(exc, PermissionDenied):
        return Response(
            {"error": "Permission denied", "status_code": status.HTTP_403_FORBIDDEN},
            status=status.HTTP_403_FORBIDDEN,
        )

    if isinstance(exc, Http404):
        return Response(
            {"error": "Resource not found", "status_code": status.HTTP_404_NOT_FOUND},
            status=status.HTTP_404_NOT_FOUND,
        )

    if isinstance(exc, Ratelimited):
        return Response(
            {"error": "Too many requests, please try again later.", "status_code": 429},
            status=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    if isinstance(exc, CsrfViewMiddleware):
        return Response(
            {"error": "CSRF verification failed.", "status_code": status.HTTP_403_FORBIDDEN},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    logger.error(
        f"Unhandled exception in {context.get('view')}: {exc}",
        exc_info=True
    )

    send_error_log(exc)

    return Response(
        {
            "error": "Internal server error. Our team has been notified.",
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
        },
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )
