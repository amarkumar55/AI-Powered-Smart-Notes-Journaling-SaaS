import pytest
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken
from django.middleware.csrf import get_token
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from rest_framework import status


@pytest.fixture
def user(django_user_model):
    return django_user_model.objects.create_user(
        email="test@example.com", password="OldPass123!"
    )


@pytest.fixture
def jwt_client(user):
    """API client authenticated with JWT (mobile app simulation)."""
    client = APIClient()
    refresh = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {str(refresh.access_token)}")
    return client


@pytest.fixture
def cookie_client(client, user):
    """API client authenticated with session cookie + CSRF (web simulation)."""
    client.force_login(user)
    csrf_token = get_token(client.request().wsgi_request)
    client.cookies[settings.CSRF_COOKIE_NAME] = csrf_token
    client.defaults["HTTP_X_CSRFTOKEN"] = csrf_token
    return client


@pytest.mark.django_db
class TestChangePasswordView:

    def test_change_password_jwt_success(self, jwt_client, user):
        url = reverse("change-password")
        response = jwt_client.post(url, {
            "old_password": "OldPass123!",
            "new_password": "NewPass123!",
            "confirm_password": "NewPass123!"
        })
        assert response.status_code == 200
        user.refresh_from_db()
        assert user.check_password("NewPass123!")

    def test_change_password_cookie_success(self, cookie_client, user):
        url = reverse("change-password")
        response = cookie_client.post(url, {
            "old_password": "OldPass123!",
            "new_password": "NewPass123!",
            "confirm_password": "NewPass123!"
        })
        assert response.status_code == 200
        user.refresh_from_db()
        assert user.check_password("NewPass123!")

    def test_change_password_cookie_missing_csrf(self, client, user):
        client.force_login(user)  # no csrf added
        url = reverse("change-password")
        response = client.post(url, {
            "old_password": "OldPass123!",
            "new_password": "NewPass123!",
            "confirm_password": "NewPass123!"
        })
        # Should fail due to CSRF check
        assert response.status_code == 403
        assert "CSRF" in response.data.get("detail", "")

    def test_change_password_invalid_old_password(self, jwt_client, user):
        url = reverse("change-password")
        response = jwt_client.post(url, {
            "old_password": "WrongPass123!",
            "new_password": "NewPass123!",
            "confirm_password": "NewPass123!"
        })
        assert response.status_code == 400
        assert "old_password" in response.data

    def test_change_password_password_mismatch(self, jwt_client, user):
        url = reverse("change-password")
        response = jwt_client.post(url, {
            "old_password": "OldPass123!",
            "new_password": "NewPass123!",
            "confirm_password": "Different123!"
        })
        assert response.status_code == 400
        assert "confirm_password" in response.data

    def test_rate_limiting(self, jwt_client, user):
        url = reverse("change-password")
        for _ in range(5):
            jwt_client.post(url, {
                "old_password": "OldPass123!",
                "new_password": "NewPass123!",
                "confirm_password": "NewPass123!"
            })
        response = jwt_client.post(url, {
            "old_password": "OldPass123!",
            "new_password": "AnotherPass123!",
            "confirm_password": "AnotherPass123!"
        })
        assert response.status_code == 429
