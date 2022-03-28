from werkzeug.wrappers import Request, Response


class advancedauthMiddleware:
    def __init__(self, app):
        self.app = app
        self.overrides = [
            "/",
            "/user/login",
            "/user/register",
            "/user/logged_in",
            "/user/reset",
            "/user/_logout",
            "/user/logged_out",
            "/user/logged_out_redirect",
        ]

    def __call__(self, environ, start_response):
        request = Request(environ)
        if (
            request.environ.get("PATH_INFO", "") not in self.overrides
            and "webassets" not in request.environ.get("PATH_INFO", "")
            and "/api/i18n" not in request.environ.get("PATH_INFO", "")
        ):
            if not request.environ.get("repoze.who.identity", False):
                res = Response(
                    "Authorization Required", mimetype="text/plain", status=403
                )
                return res(environ, start_response)
        return self.app(environ, start_response)
