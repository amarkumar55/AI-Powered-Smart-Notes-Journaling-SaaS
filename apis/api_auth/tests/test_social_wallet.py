import pytest
from datetime import datetime, timedelta
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status

from yourapp.models import User, Follow, Wallet, WalletTransaction, UserActivity


@pytest.mark.django_db
class TestFollowUnfollow:
    def setup_method(self):
        self.client = APIClient()
        self.user1 = User.objects.create_user(username="alice", password="pass123")
        self.user2 = User.objects.create_user(username="bob", password="pass123")
        self.client.force_authenticate(self.user1)

    def test_follow_user(self):
        url = reverse("follow-user", args=[self.user2.id])
        res = self.client.post(url)
        assert res.status_code == status.HTTP_201_CREATED
        assert Follow.objects.filter(follower=self.user1, following=self.user2).exists()

    def test_follow_self_disallowed(self):
        url = reverse("follow-user", args=[self.user1.id])
        res = self.client.post(url)
        assert res.status_code == 400

    def test_follow_duplicate_returns_200(self):
        Follow.objects.create(follower=self.user1, following=self.user2)
        url = reverse("follow-user", args=[self.user2.id])
        res = self.client.post(url)
        assert res.status_code == 200
        assert res.data["message"] == "Already following this user."

    def test_unfollow_user(self):
        Follow.objects.create(follower=self.user1, following=self.user2)
        url = reverse("unfollow-user", args=[self.user2.id])
        res = self.client.delete(url)
        assert res.status_code == 200
        assert not Follow.objects.filter(follower=self.user1, following=self.user2).exists()

    def test_unfollow_not_following(self):
        url = reverse("unfollow-user", args=[self.user2.id])
        res = self.client.delete(url)
        assert res.status_code == 400


@pytest.mark.django_db
class TestFollowersFollowingList:
    def setup_method(self):
        self.client = APIClient()
        self.user1 = User.objects.create_user(username="alice", password="pass123")
        self.user2 = User.objects.create_user(username="bob", password="pass123")
        self.user3 = User.objects.create_user(username="charlie", password="pass123")
        self.client.force_authenticate(self.user1)

        Follow.objects.create(follower=self.user2, following=self.user1)  # bob → alice
        Follow.objects.create(follower=self.user1, following=self.user3)  # alice → charlie

    def test_list_followers(self):
        url = reverse("followers-list", args=[self.user1.id])
        res = self.client.get(url)
        assert res.status_code == 200
        assert any(u["username"] == "bob" for u in res.data)

    def test_list_following(self):
        url = reverse("following-list", args=[self.user1.id])
        res = self.client.get(url)
        assert res.status_code == 200
        assert any(u["username"] == "charlie" for u in res.data)

    def test_search_followers(self):
        url = reverse("followers-list", args=[self.user1.id]) + "?search=bob"
        res = self.client.get(url)
        assert res.status_code == 200
        assert len(res.data) == 1
        assert res.data[0]["username"] == "bob"


@pytest.mark.django_db
class TestWallet:
    def setup_method(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username="dave", password="pass123")
        self.client.force_authenticate(self.user)

    def test_wallet_balance_created(self):
        url = reverse("wallet-balance")
        res = self.client.get(url)
        assert res.status_code == 200
        assert "balance" in res.data

    def test_wallet_transactions_filtering(self):
        wallet, _ = Wallet.objects.get_or_create(user=self.user)
        now = datetime.utcnow()

        WalletTransaction.objects.create(wallet=wallet, amount=100, description="Deposit")
        WalletTransaction.objects.create(wallet=wallet, amount=-20, description="Withdrawal")

        url = reverse("wallet-transactions") + "?search=Deposit"
        res = self.client.get(url)
        assert res.status_code == 200
        assert any("Deposit" in tx["description"] for tx in res.data)

        start = (now - timedelta(days=1)).date().isoformat()
        end = (now + timedelta(days=1)).date().isoformat()
        url = reverse("wallet-transactions") + f"?start_date={start}&end_date={end}"
        res = self.client.get(url)
        assert res.status_code == 200
        assert len(res.data) >= 2


@pytest.mark.django_db
class TestUserActivity:
    def setup_method(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username="eve", password="pass123")
        self.client.force_authenticate(self.user)

        now = datetime.utcnow()
        UserActivity.objects.create(user=self.user, activity_type="login", action_date_time=now)
        UserActivity.objects.create(user=self.user, activity_type="logout", action_date_time=now - timedelta(days=2))

    def test_activity_list(self):
        url = reverse("user-activity")
        res = self.client.get(url)
        assert res.status_code == 200
        assert any(a["activity_type"] == "login" for a in res.data)

    def test_activity_search(self):
        url = reverse("user-activity") + "?search=login"
        res = self.client.get(url)
        assert res.status_code == 200
        assert all("login" in a["activity_type"] for a in res.data)

    def test_activity_date_filter(self):
        start = (datetime.utcnow() - timedelta(days=1)).date().isoformat()
        url = reverse("user-activity") + f"?start_date={start}"
        res = self.client.get(url)
        assert res.status_code == 200
        assert all(
            datetime.fromisoformat(a["action_date_time"].replace("Z", "+00:00")).date() >= datetime.fromisoformat(start).date()
            for a in res.data
        )
