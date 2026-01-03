from django.urls import path

from .views import (
    RegisterView,
    EmailVerificationView, 
    ResendEmailVerificationView,
    WalletBalanceView, 
    WalletTransactionsView,
    UserActivityView,
    PasswordResetRequestView, 
    PasswordResetConfirmView, 
    ChangePasswordView, 
    PasswordVerificationView,
    AccountDeactivateView,
    AccountRestoreView,
    UserProfileView, 
    TwoFactorLoginOtpSend, 
    ChangeEmailRequestOTPView, 
    ChangeEmailVerifyOTPView,
    HybridLoginView,
    CsrfBootstrapView,
    FollowUserView,
    UnfollowUserView, 
    FollowersListView, 
    FollowingListView, 
    HybridTokenRefreshView, 
    HybridLogoutView,
    HybridTwoFactorLoginView,
    PublicProfileView,
    BlockUserFromFollow
)


urlpatterns = [

    path("csrf-bootstrap/", CsrfBootstrapView.as_view(), name="csrf-bootstrap"),
    
    path("register/", RegisterView.as_view(), name="api_register"),
    path("login/", HybridLoginView.as_view(), name="api_login"),
    path("login/2fa/", HybridTwoFactorLoginView.as_view(), name="api_2fa_login"),
    path("resend/otp/", TwoFactorLoginOtpSend.as_view(), name="api_2fa_login_otp_send"),
    path("token/refresh/", HybridTokenRefreshView.as_view(), name="api_logout"),
    path("logout/", HybridLogoutView.as_view(), name="api_logout"),
    
    # Email Verification
    path("verify-email/<uidb64>/<token>/", EmailVerificationView.as_view(), name="api_verify_email"),
    path("resend-verification/", ResendEmailVerificationView.as_view(), name="api_resend_verification"),
    
    # Password Management
    path("password-reset-request/", PasswordResetRequestView.as_view(), name="api_password_reset_request"),
    path("password-reset-confirm/<uidb64>/<token>/", PasswordResetConfirmView.as_view(), name="api_password_reset_confirm"),
  
    path("change-password/", ChangePasswordView.as_view(), name="api_change_password"),
    path("verify-password/", PasswordVerificationView.as_view(), name="api_verify_password"),

    path("profile/", UserProfileView.as_view(), name="api_profile"),
    

    path("change-email/request-otp/", ChangeEmailRequestOTPView.as_view(), name="api_change_email_otp_request"),
    path("change-email/verify/", ChangeEmailVerifyOTPView.as_view(), name="api_change_email_otp_verify"),
    path('account/deactivate/', AccountDeactivateView.as_view(), name='account-deactivate'),
    path('account/restore/', AccountRestoreView.as_view(), name='account-restore'),

    path('follow/<uuid:user_id>/', FollowUserView.as_view(), name='follow-user'),
    path('unfollow/<uuid:user_id>/', UnfollowUserView.as_view(), name='unfollow-user'),
    path('followers/', FollowersListView.as_view(), name='followers-list'),
    path('following/', FollowingListView.as_view(), name='following-list'),
    path('wallet/balance/', WalletBalanceView.as_view(), name='wallet_balance'),
    path('wallet/transactions/', WalletTransactionsView.as_view(), name='wallet_transaction'),
    path('activity/', UserActivityView.as_view(), name='api_user_activity'),
    path("profile/<str:username>/", PublicProfileView.as_view(), name="public-profile"),
    path("block/profile/<uuid:user_id>/", BlockUserFromFollow.as_view(), name="block-profile"),
]