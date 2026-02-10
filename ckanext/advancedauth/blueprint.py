import os
import ckan.lib.base as base
import ckan.lib.helpers as h
import ckan.lib.navl.dictization_functions as dictization_functions
import ckan.logic as logic

from ckan.common import _, g, request
from ckan.views.user import EditView
from .logic import complete_user_registration
from flask import Blueprint, request, redirect

import logging

log = logging.getLogger(__name__)

advancedauth_user = Blueprint("advancedauth_user", __name__, url_prefix="/user")


class ExtendedEditView(EditView):
    # This is a copy of the EditView post method from ckan/views/user.py reused for new user register/profile page
    # Adds update registration_complete update
    def post(self, id=None):
        context, id = self._prepare(id)
        if not context["save"]:
            return self.get(id)

        try:
            data_dict = logic.clean_dict(
                dictization_functions.unflatten(
                    logic.tuplize_dict(logic.parse_params(request.form))
                )
            )
            data_dict.update(
                logic.clean_dict(
                    dictization_functions.unflatten(
                        logic.tuplize_dict(logic.parse_params(request.files))
                    )
                )
            )

        except dictization_functions.DataError:
            base.abort(400, _("Integrity Error"))
        data_dict.setdefault("activity_streams_email_notifications", False)

        data_dict["id"] = id

        try:
            user = logic.get_action("user_update")(context, data_dict)
        except logic.NotAuthorized:
            base.abort(403, _("Unauthorized to edit user %s") % id)
        except logic.NotFound:
            base.abort(404, _("User not found"))
        except logic.ValidationError as e:
            errors = e.error_dict
            error_summary = e.error_summary
            return self.get(id, data_dict, errors, error_summary)

        h.flash_success(_("Profile updated"))
        complete_user_registration(user, data_dict)
        resp = h.redirect_to("user.read", id=user["name"])

        return resp

    def get(self, id=None, data=None, errors=None, error_summary=None):
        context, id = self._prepare(id)
        data_dict = {"id": id}

        current_user = context.get("auth_user_obj").id
        if current_user != id:
            base.abort(403, _("Unauthorized to edit user %s") % "")

        try:
            old_data = logic.get_action("user_show")(context, data_dict)

            g.display_name = old_data.get("display_name")
            g.user_name = old_data.get("name")

            data = data or old_data

        except logic.NotAuthorized:
            base.abort(403, _("Unauthorized to edit user %s") % "")
        except logic.NotFound:
            base.abort(404, _("User not found"))

        errors = errors or {}
        extra_vars = {"data": data, "errors": errors, "error_summary": error_summary}

        return base.render("user/register.html", extra_vars)


def ras_enabled():
    return os.getenv("RAS_ENABLED", "false").lower() == "true"


def logged_out_redirect():
    return redirect("https://auth.nih.gov/siteminderagent/smlogout.asp")


if ras_enabled():
    advancedauth_user.add_url_rule(
        "/register", view_func=ExtendedEditView.as_view(str("register"))
    )
    advancedauth_user.add_url_rule(
        "/logged_out_redirect", view_func=logged_out_redirect, methods=["GET"]
    )
