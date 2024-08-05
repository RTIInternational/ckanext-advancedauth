import ckan.lib.base as base
import ckan.lib.helpers as h
import ckan.lib.mailer as mailer
import ckan.lib.navl.dictization_functions as dictization_functions
import ckan.logic as logic
import ckan.model as model
import ckan.lib.authenticator as authenticator

from ckan.common import _, g, request
from ckan.views.user import PerformResetView, RequestResetView
from .model import advancedauthExtras as ae
from six import text_type
from flask import Blueprint, request

import logging

log = logging.getLogger(__name__)

advancedauth_user = Blueprint("advancedauth_user", __name__, url_prefix="/user")


class ExtendedRequestResetView(RequestResetView):
    pass


class ExtendedPerformResetView(PerformResetView):
    # This is a copy of the PerformResetView post method from ckan/views/user.py
    # Adds update_password_date and changes validation error dict to error_summary
    def post(self, id):
        context, user_dict = self._prepare(id)
        context["reset_password"] = True
        user_state = user_dict["state"]
        error_summary = None
        try:
            new_password = self._get_form_password()
            user_dict["password"] = new_password
            username = request.form.get("name")
            if username is not None and username != "":
                user_dict["name"] = username
            user_dict["reset_key"] = g.reset_key
            user_dict["state"] = model.State.ACTIVE
            logic.get_action("user_update")(context, user_dict)
            mailer.create_reset_key(context["user_obj"])
            ae.update_password_date(user_dict["id"], "password_last_reset_date")
            h.flash_success(_("Your password has been reset."))
            return h.redirect_to("home.index")
        except logic.NotAuthorized:
            h.flash_error(_("Unauthorized to edit user %s") % id)
        except logic.NotFound:
            h.flash_error(_("User not found"))
        except dictization_functions.DataError:
            h.flash_error(_("Integrity Error"))
        except logic.ValidationError as e:
            error_summary = e.error_summary
        except ValueError as e:
            error_summary = text_type(e)
        user_dict["state"] = user_state
        extra_vars = {"user_dict": user_dict, "error_summary": error_summary}
        return base.render("user/perform_reset.html", extra_vars)


advancedauth_user.add_url_rule(
    "/reset", view_func=ExtendedRequestResetView.as_view(str("perform_reset"))
)
advancedauth_user.add_url_rule(
    "/reset/<id>", view_func=ExtendedPerformResetView.as_view(str("perform_reset"))
)
