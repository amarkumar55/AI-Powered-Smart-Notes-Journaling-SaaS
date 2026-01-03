import pytest
from django.core import mail
from django.urls import reverse
from unittest.mock import patch
from django.core.cache import cache
from apis.api_auth.models import EmailOTP  # replace with actual app name
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken



@pytest.fixture
def user(django_user_model):
    return django_user_model.objects.create_user(
        email="user@example.com", password="TestPass123!"
    )


@pytest.fixture
def jwt_client(user):
    client = APIClient()
    refresh = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {str(refresh.access_token)}")
    return client


@pytest.mark.django_db
class TestPasswordVerificationView:
    def test_password_verification_success(self, jwt_client):
        url = reverse("password-verify")
        resp = jwt_client.post(url, {"password": "TestPass123!"})
        assert resp.status_code == 200
        assert "Password verified" in resp.data["message"]

    def test_password_verification_failure(self, jwt_client):
        url = reverse("password-verify")
        resp = jwt_client.post(url, {"password": "WrongPass"})
        assert resp.status_code == 400
        assert "password" in resp.data

    def test_rate_limiting(self, jwt_client):
        url = reverse("password-verify")
        for _ in range(10):
            jwt_client.post(url, {"password": "WrongPass"})
        resp = jwt_client.post(url, {"password": "WrongPass"})
        assert resp.status_code == 429


@pytest.mark.django_db
class TestUserProfileView:
    def test_get_profile(self, jwt_client, user):
        url = reverse("user-profile")
        resp = jwt_client.get(url)
        assert resp.status_code == 200
        assert resp.data["email"] == user.email

    def test_update_profile_success(self, jwt_client):
        url = reverse("user-profile")
        resp = jwt_client.put(url, {"first_name": "NewName"})
        assert resp.status_code == 200
        assert resp.data["user"]["first_name"] == "NewName"

    def test_update_profile_invalid(self, jwt_client):
        url = reverse("user-profile")
        resp = jwt_client.put(url, {"email": ""})
        assert resp.status_code == 400


@pytest.mark.django_db
class TestChangeEmailRequestOTPView:
    @patch("yourapp.views.send_otp_message")
    def test_request_email_change_success(self, mock_send, jwt_client, user):
        url = reverse("email-change-request")
        resp = jwt_client.post(url, {
            "old_email": user.email,
            "new_email": "new@example.com"
        })
        assert resp.status_code == 200
        assert "OTPs sent" in resp.data["message"]
        assert mock_send.call_count == 2

    def test_request_email_change_old_mismatch(self, jwt_client):
        url = reverse("email-change-request")
        resp = jwt_client.post(url, {
            "old_email": "wrong@example.com",
            "new_email": "new@example.com"
        })
        assert resp.status_code == 400

    def test_request_email_change_duplicate(self, jwt_client, django_user_model):
        other = django_user_model.objects.create_user(
            email="existing@example.com", password="x"
        )
        url = reverse("email-change-request")
        resp = jwt_client.post(url, {
            "old_email": other.email,
            "new_email": "existing@example.com"
        })
        assert resp.status_code == 400


@pytest.mark.django_db
class TestChangeEmailVerifyOTPView:
    def setup_otps(self, old_email, new_email, old_code="111111", new_code="222222"):
        EmailOTP.objects.create(email=old_email, otp=old_code)
        EmailOTP.objects.create(email=new_email, otp=new_code)

    def test_verify_success(self, jwt_client, user):
        cache.set(f"pending_new_email:{user.id}", "new@example.com", 600)
        self.setup_otps(user.email, "new@example.com")

        url = reverse("email-change-verify")
        resp = jwt_client.post(url, {
            "old_email": user.email,
            "new_email": "new@example.com",
            "old_email_otp": "111111",
            "new_email_otp": "222222",
        })
        assert resp.status_code == 200
        user.refresh_from_db()
        assert user.email == "new@example.com"

    def test_verify_wrong_otp(self, jwt_client, user):
        cache.set(f"pending_new_email:{user.id}", "new@example.com", 600)
        self.setup_otps(user.email, "new@example.com")

        url = reverse("email-change-verify")
        resp = jwt_client.post(url, {
            "old_email": user.email,
            "new_email": "new@example.com",
            "old_email_otp": "000000",
            "new_email_otp": "222222",
        })
        assert resp.status_code == 400
        assert "Invalid OTP" in resp.data["error"]


@pytest.mark.django_db
class TestAccountDeactivateRestore:
    def test_account_deactivate(self, jwt_client, user):
        url = reverse("account-deactivate")
        resp = jwt_client.post(url, {"password": "TestPass123!"})
        assert resp.status_code == 200
        user.refresh_from_db()
        assert not user.is_active
        assert any("Account Deactivated" in m.subject for m in mail.outbox)

    def test_account_restore(self, client, user):
        user.is_active = False
        user.save()
        url = reverse("account-restore")
        resp = client.post(url, {"email": user.email, "password": "TestPass123!"})
        assert resp.status_code == 200
        user.refresh_from_db()
        assert user.is_active
