import re

from django.http import HttpResponsePermanentRedirect

from .conf import conf
from django.conf import settings


class SecurityMiddleware(object):
    def __init__(self):
        self.sts_seconds = conf.SECURE_HSTS_SECONDS
        self.sts_include_subdomains = conf.SECURE_HSTS_INCLUDE_SUBDOMAINS
        self.frame_deny = conf.SECURE_FRAME_DENY
        self.content_type_nosniff = conf.SECURE_CONTENT_TYPE_NOSNIFF
        self.xss_filter = conf.SECURE_BROWSER_XSS_FILTER
        self.redirect = conf.SECURE_SSL_REDIRECT
        self.redirect_host = conf.SECURE_SSL_HOST
        self.proxy_ssl_header = conf.SECURE_PROXY_SSL_HEADER
        self.redirect_port = conf.SECURE_SSL_PORT
        self.redirect_exempt = [
            re.compile(r) for r in conf.SECURE_REDIRECT_EXEMPT]


    def process_request(self, request):
        if self.proxy_ssl_header and not request.is_secure():
            header, value = self.proxy_ssl_header
            if request.META.get(header, None) == value:
                # We're only patching the current request; its secure status
                # is not going to change.
                request.is_secure = lambda: True

        path = request.path.lstrip("/")
        if (self.redirect and
                not request.is_secure() and
                not any(pattern.search(path)
                        for pattern in self.redirect_exempt)):
            host = self.redirect_host or request.get_host()
            port = ":" + self.redirect_port or ""
            myhost = host.split(":")
            return HttpResponsePermanentRedirect(
                "https://%s%s%s" % (myhost[0], port, request.get_full_path()))


    def process_response(self, request, response):
        if (self.frame_deny and
                not getattr(response, "_frame_deny_exempt", False) and
                not 'x-frame-options' in response):
            response["x-frame-options"] = "DENY"

        if (self.sts_seconds and
                request.is_secure() and
                not 'strict-transport-security' in response):
            sts_header = ("max-age=%s" % self.sts_seconds)

            if self.sts_include_subdomains:
                sts_header = sts_header + "; includeSubDomains"

            response["strict-transport-security"] = sts_header

        if (self.content_type_nosniff and
                not 'x-content-type-options' in response):
            response["x-content-type-options"] = "nosniff"

        if self.xss_filter and not 'x-xss-protection' in response:
            response["x-xss-protection"] = "1; mode=block"

        return response
