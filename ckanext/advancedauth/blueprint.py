import ckan.lib.base as base
import ckan.lib.helpers as h
import ckan.lib.mailer as mailer
import ckan.lib.navl.dictization_functions as dictization_functions
import ckan.logic as logic
import ckan.model as model
import ckan.lib.authenticator as authenticator

from ckan.common import _, g, request
from ckan.views.user import PerformResetView, EditView, RegisterView
from .model import advancedauthExtras as ae
from six import text_type
from flask import Blueprint, request
from .captcha import check_captcha
from ckan.lib import captcha

import logging

log = logging.getLogger(__name__)

advancedauth_user = Blueprint("advancedauth_user", __name__, url_prefix="/user")


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


class ExtendedEditView(EditView):
    # This is a copy of the EditView post method from ckan/views/user.py reused for required_reset page
    # Adds update_password_date
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

        context["message"] = data_dict.get("log_message", "")
        data_dict["id"] = id

        if data_dict["password1"] and data_dict["password2"]:
            identity = {"login": g.user, "password": data_dict["old_password"]}
            auth = authenticator.UsernamePasswordAuthenticator()

            if auth.authenticate(request.environ, identity) != g.user:
                errors = {"oldpassword": [_("Password entered was incorrect")]}
                error_summary = (
                    {_("Old Password"): _("incorrect password")}
                    if not g.userobj.sysadmin
                    else {_("Sysadmin Password"): _("incorrect password")}
                )
                return self.get(id, data_dict, errors, error_summary)

        try:
            user = logic.get_action("ckan_user_update")(context, data_dict)
        except logic.NotAuthorized:
            base.abort(403, _("Unauthorized to edit user %s") % id)
        except logic.NotFound:
            base.abort(404, _("User not found"))
        except logic.ValidationError as e:
            errors = e.error_dict
            error_summary = e.error_summary
            return self.get(id, data_dict, errors, error_summary)

        h.flash_success(_("Password updated"))
        ae.update_password_date(data_dict["id"], "password_last_reset_date")
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

        return base.render("user/required_reset.html", extra_vars)


class ExtendedRegisterView(RegisterView):
    # Override original check_recaptcha (google recaptcha) with turnstile check_captcha
    def post(self):
        captcha.check_recaptcha = check_captcha
        return super().post()


advancedauth_user.add_url_rule(
    "/reset/<id>", view_func=ExtendedPerformResetView.as_view(str("perform_reset"))
)
advancedauth_user.add_url_rule(
    "/required_reset/<id>", view_func=ExtendedEditView.as_view(str("required_reset"))
)
advancedauth_user.add_url_rule(
    "/register", view_func=ExtendedRegisterView.as_view(str("register"))
)
