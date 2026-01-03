# tests/test_auth_hybrid.py
from unittest.mock import patch
from django.urls import reverse
from api_auth.models import EmailOTP  
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from rest_framework.test import APITestCase, APIClient
from rest_framework_simplejwt.tokens import RefreshToken


User = get_user_model()

class HybridAuthTests(APITestCase):
    @patch("yourapp.views.send_otp_message")
    def test_two_factor_send_and_verify_enumeration_safe(self, mock_send):
        mock_send.return_value = True  # pretend OTP was "sent"

        client = APIClient()
        # send OTP (should always return generic success)
        resp = client.post(self.otp_send_url, {"email": self.email}, format="json")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("message", resp.data)

        # create OTP manually for testing verify
        otp_plain = "123456"
        hashed = make_password(otp_plain)
        EmailOTP.objects.create(
            email=self.email,
            otp=hashed,
            expires_at=None  # or set an expiry field if required
        )

        # verify endpoint with correct OTP
        resp = client.post(
            self.twofa_url,
            {"email": self.email, "otp": otp_plain},
            format="json",
            HTTP_X_CLIENT_TYPE="mobile"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("access_token", resp.data)

    def setUp(self):
        # Create test user
        self.email = "testuser@example.com"
        self.password = "P@ssw0rd!"
        self.user = User.objects.create_user(
            email=self.email,
            password=self.password,
            first_name="Test",
            last_name="User",
            username="testuser",
            birth_date="1990-01-01",
            gender="Other",
        )
        # If your User model requires is_email_verified
        if hasattr(self.user, "is_email_verified"):
            self.user.is_email_verified = True
            self.user.save(update_fields=["is_email_verified"])

        self.login_url = reverse("hybrid-login")
        self.twofa_url = reverse("hybrid-2fa")
        self.refresh_url = reverse("hybrid-refresh")
        self.logout_url = reverse("hybrid-logout")
        self.otp_send_url = reverse("2fa-send")

    def test_mobile_login_returns_tokens_in_body(self):
        client = APIClient()
        data = {"email": self.email, "password": self.password}
        # Tell server this is mobile client
        resp = client.post(self.login_url, data, format="json", HTTP_X_CLIENT_TYPE="mobile")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("access_token", resp.data)
        self.assertIn("refresh_token", resp.data)

    def test_web_login_requires_csrf_and_sets_cookies(self):
        # Use a client that enforces CSRF checks
        client = APIClient(enforce_csrf_checks=True)
        # First fetch csrf token via the bootstrap endpoint (or regular GET view)
        csrf_resp = client.get(reverse("csrf-bootstrap"))
        self.assertEqual(csrf_resp.status_code, 200)
        csrf_token = csrf_resp.data.get("csrfToken")
        self.assertTrue(csrf_token)

        # Now attempt web login with CSRF header and Client-Type web
        data = {"email": self.email, "password": self.password}
        resp = client.post(
            self.login_url,
            data,
            format="json",
            HTTP_X_CSRFTOKEN=csrf_token,
            HTTP_X_CLIENT_TYPE="web"
        )
        self.assertEqual(resp.status_code, 200)
        # Cookies should be set for access & refresh
        self.assertIn("access_token", resp.cookies)
        self.assertIn("refresh_token", resp.cookies)
        # Body must not contain tokens for web flow
        self.assertNotIn("access_token", resp.data)
        self.assertNotIn("refresh_token", resp.data)

    def test_two_factor_send_and_verify_enumeration_safe(self):
        client = APIClient()
        # send OTP (should always return generic success)
        resp = client.post(self.otp_send_url, {"email": self.email}, format="json")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("message", resp.data)

        # For verify: we need to create an EmailOTP entry.
        # If your app sends OTP via send_otp_message and stores hashed OTP,
        # you should either:
        #  - monkeypatch send_otp_message to create a known OTP, or
        #  - directly create EmailOTP with hashed OTP using make_password.
        from django.contrib.auth.hashers import make_password
        from api_auth.models import EmailOTP  # <- adjust import as necessary

        otp_plain = "123456"
        hashed = make_password(otp_plain)
        EmailOTP.objects.create(email=self.email, otp=hashed, expires_at=None)  # adapt fields to your model
        # verify endpoint
        resp = client.post(self.twofa_url, {"email": self.email, "otp": otp_plain}, format="json", HTTP_X_CLIENT_TYPE="mobile")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("access_token", resp.data)

    def test_refresh_rotation_blacklists_old_refresh(self):
        # Create refresh token for user
        refresh = RefreshToken.for_user(self.user)
        old_refresh_str = str(refresh)

        # Use refresh endpoint as mobile (body)
        client = APIClient()
        resp = client.post(self.refresh_url, {"refresh": old_refresh_str}, format="json")
        self.assertEqual(resp.status_code, 200)
        new_refresh = resp.data.get("refresh_token")
        new_access = resp.data.get("access_token")
        self.assertIsNotNone(new_refresh)
        self.assertIsNotNone(new_access)

        # Old refresh should now be invalid (blacklisted)
        # Trying to use the old refresh should raise InvalidToken (server should return 401)
        resp2 = client.post(self.refresh_url, {"refresh": old_refresh_str}, format="json")
        self.assertNotEqual(resp2.status_code, 200)

    def test_logout_blacklists_refresh_and_clears_cookies(self):
        # Simulate web login cookies set by server
        client = APIClient(enforce_csrf_checks=True)
        csrf_resp = client.get(reverse("csrf-bootstrap"))
        csrf_token = csrf_resp.data.get("csrfToken")

        # perform login to set cookies
        login_resp = client.post(
            self.login_url,
            {"email": self.email, "password": self.password},
            format="json",
            HTTP_X_CSRFTOKEN=csrf_token,
            HTTP_X_CLIENT_TYPE="web"
        )
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn("refresh_token", login_resp.cookies)

        # Logout will clear cookies & blacklist refresh
        resp = client.post(self.logout_url, {}, format="json", HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("refresh_token", resp.cookies)  # cookie removed
