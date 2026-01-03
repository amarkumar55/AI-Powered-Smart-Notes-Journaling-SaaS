import os
import environ
from pathlib import Path
from datetime import timedelta

BASE_DIR = Path(__file__).resolve().parent.parent
env = environ.Env()
environ.Env.read_env()

SECRET_KEY=env("SECRET_KEY", default="super-secret-key")
DEBUG = env.bool("DEBUG", default=False)
ALLOWED_HOSTS = ["*"]
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")


INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",
    "channels",
    "django_crontab",
    "django_ratelimit",
    "apis.api_auth",
    "apis.api_public",
    "apis.api_support",
    "apis.api_notes",
    "apis.api_notification",
    "apis.api_payment",
    "apis.api_subscription",
    "apis.api_planner",
    "core",
    "apis.api_journal",
]


MIDDLEWARE = [
    "noteaibackend.middleware.RatelimitMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",   
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apis.api_auth.middleware.ConditionalCSRFMiddleware",
    "apis.api_auth.middleware.APIRateLimitMiddleware",
    "apis.api_auth.middleware.APIRequestLoggingMiddleware",
    "apis.api_auth.middleware.APISecurityHeadersMiddleware",
]


REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "apis.api_auth.middleware.CookieOrHeaderJWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 20,
    "EXCEPTION_HANDLER": "noteaibackend.utils.custom_exception_handler",
}


SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),    
}


FIELD_ENCRYPTION_KEY = "X3t6Z2aGz8JvT2kH6qU0t1mG5pL1N6fY2oQ1R5dH2sI="



DATABASES = {
    "default": {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'smartnotes',
        'USER': 'amarkumar',
        'PASSWORD': '@amar9691',
        'HOST': 'localhost',
        'PORT': '5432',
        "OPTIONS": {
            "options": "-c search_path=public"  
        },
    },
}



CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1",
        "OPTIONS": {"CLIENT_CLASS": "django_redis.client.DefaultClient"},
    }
}


ASGI_APPLICATION = "noteaibackend.asgi.application"

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [("127.0.0.1", 6379)],
        },
    },
}

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, "templates")], 
        "APP_DIRS": True, 
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]


CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_HEADERS = ["*"]
CORS_ALLOW_METHODS = ["*"]



 
SECURE_SSL_REDIRECT= not DEBUG
SECURE_HSTS_SECONDS= 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD=True
SECURE_BROWSER_XSS_FILTER=True
SECURE_CONTENT_TYPE_NOSNIFF=True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"


SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE="Strict"
SESSION_EXPIRE_AT_BROWSER_CLOSE=True
SESSION_COOKIE_NAME='session_id'
SESSION_SAVE_EVERY_REQUEST=True
SESSION_COOKIE_AGE=1800
CSRF_COOKIE_NAME='csrftoken'
CSRF_COOKIE_SECURE=True
CSRF_COOKIE_HTTPONLY=True
CSRF_COOKIE_SAMESITE="Strict"

CSRF_TRUSTED_ORIGINS=[
    "https://yourdomain.com",
    "https://www.yourdomain.com",
]

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",  
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]


AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",  # default
]


STATIC_URL = "/static/"
MEDIA_URL = "/media/"
MEDIA_ROOT = os.path.join(BASE_DIR, "media")

LOG_DIR = BASE_DIR / 'logs'
LOG_DIR.mkdir(exist_ok=True)  
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,

    'formatters': {
        'verbose': {
            'format': '[{asctime}] {levelname} {name} [{pathname}:{lineno}]: {message}',
            'style': '{',
        },
    },

    'handlers': {
        'file': {
            'level': 'DEBUG',  # capture all levels including traceback
            'class': 'logging.FileHandler',
            'filename': LOG_DIR / 'django_errors.log',
            'formatter': 'verbose',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'payment_file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': LOG_DIR / 'payment.log',
            'maxBytes': 5 * 1024 * 1024,  # 5 MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
        'mail_admins': {
            'level': 'ERROR',
            'class': 'django.utils.log.AdminEmailHandler',
            'formatter': 'verbose',
        },
    },

    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': True,
        },
        'django.request': {
            'handlers': ['file', 'console', 'mail_admins'],
            'level': 'DEBUG',       # ⬅️ log everything including tracebacks
            'propagate': True,      # ⬅️ allow bubbling up so full errors show
        },
        'django.security': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'payment': {
            'handlers': ['payment_file', 'console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'custom': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    }
}

AUTH_USER_MODEL = "api_auth.CustomUser"

ROOT_URLCONF = 'noteaibackend.urls'

EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST=env("EMAIL_HOST", default="smtp.gmail.com")
EMAIL_PORT=env.int("EMAIL_PORT", default=587)
EMAIL_USE_TLS=False
EMAIL_HOST_USER=env("EMAIL_HOST_USER", default="your-email@example.com")
EMAIL_HOST_PASSWORD=env("EMAIL_HOST_PASSWORD", default="your-password")
DEFAULT_FROM_EMAIL=env("DEFAULT_FROM_EMAIL", default="noreply@noteai.com")

SUPPORT_EMAIL=''
DEFAULT_FREE_CREDIT=10000

ADMIN_ERROR_REPORT_MANAGER=""
FRONTEND_URL="https://localhost:8000"
MOBILE_APP_DEEP_LINK_SCHEME=""

RAZOR_KEY_ID=''
RAZOR_KEY_SECRET=''
APP_NAME='NoteAI'
ADMINS= [
    ("Amar Kumar", ""),
]