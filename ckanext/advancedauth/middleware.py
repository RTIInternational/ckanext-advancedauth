import logging
import sqlalchemy as sa
from dateutil import parser
from werkzeug.wrappers import Request
from werkzeug.utils import redirect
from werkzeug.exceptions import HTTPException

class advancedauthMiddleware:
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
            "/about"
        ]

    def __call__(self, environ, start_response):
        request = Request(environ)
        path_info = request.path

        # ignore static paths
        static_paths = ['/base', '/webassets', '/images']
        if any(path_info.startswith(p) for p in static_paths):
            return self.app(environ, start_response)
        
        # check if the user is logged in before executing sql query
        identity = request.environ.get("repoze.who.identity", {})
        userid = identity.get("repoze.who.userid", None)
        if userid and path_info not in self.overrides and not path_info.startswith("/user/required_reset"):
            # username is not stored in advancedauth table and id is not available in identity
            sql = """
                    SELECT 
                        advancedauth_extras.key, 
                        advancedauth_extras.value,
                        advancedauth_extras.user_id
                    FROM 
                        "user"
                    INNER JOIN 
                        advancedauth_extras ON "user".id = advancedauth_extras.user_id
                    WHERE 
                        "user".name = %s
                        AND advancedauth_extras.key IN ('password_last_reset_date', 'password_reset_required_date')
                  """
            res = self.engine.execute(sql, userid)
            rows = [row for row in res]

            if self.is_password_reset_required(rows):
                first_row = rows[0]
                user_id = first_row[2] # each row from sql query has shape (key, value, user_id)
                response = redirect(f"/user/required_reset/{user_id}")
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
            if not password_last_reset_date or password_last_reset_date < password_reset_required_date:
                return True
        return False

class advancedauthErrorLogMiddleware:
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
