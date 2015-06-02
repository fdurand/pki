from django.conf import settings
from django.core.exceptions import ImproperlyConfigured



class Configuration(object):
    def __init__(self, **kwargs):
        self.defaults = kwargs


    def __getattr__(self, k):
        try:
            return getattr(settings, k)
        except AttributeError:
            if k in self.defaults:
                return self.defaults[k]
            raise ImproperlyConfigured("django-secure requires %s setting." % k)


conf = Configuration(
    SECURE_HSTS_SECONDS=0,
    SECURE_HSTS_INCLUDE_SUBDOMAINS=False,
    SECURE_FRAME_DENY=False,
    SECURE_CONTENT_TYPE_NOSNIFF=False,
    SECURE_BROWSER_XSS_FILTER=False,
    SECURE_SSL_REDIRECT=False,
    SECURE_SSL_HOST=None,
    SECURE_SSL_PORT=None,
    SECURE_REDIRECT_EXEMPT=[],
    SECURE_PROXY_SSL_HEADER=None,
    SECURE_CHECKS=[
        "djangosecure.check.csrf.check_csrf_middleware",
        "djangosecure.check.sessions.check_session_cookie_secure",
        "djangosecure.check.sessions.check_session_cookie_httponly",
        "djangosecure.check.djangosecure.check_security_middleware",
        "djangosecure.check.djangosecure.check_sts",
        "djangosecure.check.djangosecure.check_sts_include_subdomains",
        "djangosecure.check.djangosecure.check_frame_deny",
        "djangosecure.check.djangosecure.check_content_type_nosniff",
        "djangosecure.check.djangosecure.check_xss_filter",
        "djangosecure.check.djangosecure.check_ssl_redirect",
        "djangosecure.check.djangosecure.check_secret_key",
        ]
    )

