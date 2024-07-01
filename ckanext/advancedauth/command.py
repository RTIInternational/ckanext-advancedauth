import logging
import ckan.model as model
import ckan.plugins.toolkit as toolkit
from .model import advancedauthExtras

log = logging.getLogger(__name__)


def sysadmin_context():
    user = toolkit.get_action("get_site_user")(
        {"model": model, "ignore_auth": True}, {}
    )
    return {"ignore_auth": True, "user": user["name"], "auth_user_obj": None}


def reset_all_users_passwords():
    context = sysadmin_context()
    users = toolkit.get_action("user_list")(context, {})
    user_ids = [user.get("id") for user in users if not user.get("sysadmin", False)]
    for userid in user_ids:
        advancedauthExtras.update_password_date(
            userid=userid, key="password_reset_required_date"
        )
    return "Password reset flag set for all users"


def reset_user_password(username):
    context = sysadmin_context()
    user = toolkit.get_action("user_show")(context, {"id": username})
    advancedauthExtras.update_password_date(
        userid=user["id"], key="password_reset_required_date"
    )
    return "Password reset flag set for user: {}".format(username)
