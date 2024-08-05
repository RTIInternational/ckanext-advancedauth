import logging
import sqlalchemy as sa
from dateutil import parser
from werkzeug.wrappers import Request
from werkzeug.utils import redirect
from werkzeug.exceptions import HTTPException
import base64
import re


class AdvancedauthMiddleware:
    def __init__(self, app, config):
        self.app = app
        self.engine = sa.create_engine(config.get("sqlalchemy.url"))
        self.overrides = [
            "/",
            "/user/login",
            "/user/register",
            "/user/reset",
            "/user/_logout",
            "/user/logged_out",
            "/user/logged_out_redirect",
            "/dataset",
            "/about",
        ]
        self.session_cookie_name = config.get("beaker.session.key")

    def __call__(self, environ, start_response):
        request = Request(environ)
        path_info = request.path

        # ignore static paths
        static_paths = ["/base", "/webassets", "/images"]
        if any(path_info.startswith(p) for p in static_paths):
            return self.app(environ, start_response)

        session = request.cookies.get(self.session_cookie_name)

        userid = None
        if session:
            session = str(base64.b64decode(session))

            # pickled session data so we need to extract the user_id
            # get the substring between 'user_idq' and the next 'q'
            pattern = r"user_idq(.*?)q"
            match = re.search(pattern, session)
            if match:
                userid = match[0]

        if userid:
            # extract the 36-character user_id from the matched substring
            pattern = r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
            match = re.search(pattern, userid)[0]
            if match:
                userid = match

        if (
            userid
            and path_info not in self.overrides
            and not path_info.startswith("/user/reset")
        ):

            sql = """
                    SELECT 
                        advancedauth_extras.key, 
                        advancedauth_extras.value,
                        advancedauth_extras.user_id
                    FROM 
                        "advancedauth_extras"
                    WHERE 
                        advancedauth_extras.user_id = %s
                        AND advancedauth_extras.key IN ('password_last_reset_date', 'password_reset_required_date')
                  """
            res = self.engine.execute(sql, userid)
            rows = [row for row in res]

            if self.is_password_reset_required(rows):
                response = redirect(f"/user/reset?redirect=True")
                return response(environ, start_response)

        # continue with the original application flow if not logged in or no reset required
        return self.app(environ, start_response)

    def is_password_reset_required(self, res):
        password_last_reset_date = None
        password_reset_required_date = None

        for row in res:
            key = row[0]
            value = row[1]
            if key == "password_last_reset_date":
                password_last_reset_date = parser.parse(value)
            elif key == "password_reset_required_date":
                password_reset_required_date = parser.parse(value)

        if password_reset_required_date:
            if (
                not password_last_reset_date
                or password_last_reset_date < password_reset_required_date
            ):
                return True
        return False


class AdvancedauthErrorLogMiddleware:
    def __init__(self, app):
        self.app = app
        self.logger = logging.getLogger(__name__)

    def __call__(self, environ, start_response):
        try:
            return self.app(environ, start_response)
        except HTTPException as e:
            self.logger.error(f"HTTPException: {e.description}")
            raise
        except Exception as e:
            self.logger.error(f"Exception: {e}", exc_info=True)
            raise
