import datetime

import ckan.plugins.toolkit as toolkit
import ckan.lib.mailer as mailer
import ckan.model as model
from ckan.plugins.toolkit import chained_action
from ckan.logic import ValidationError
from ckan.logic.action.create import user_create
from ckan.logic.action.get import user_show
from ckan.logic.action.update import user_update
from ckan.logic.action.delete import user_delete
from ckan.logic import check_access, get_or_bust, NotFound
from ckan.model import core

from .helpers import helpers
from .model import advancedauthExtras
from .validators import get_validators


# injects validators from json schema into existing schema
def _modify_user_schema(context, mode):
    advancedauth_schema = helpers["advancedauth_schema"]()
    advancedauth_schema_keys = helpers["advancedauth_schema_keys"]()
    schema = context["schema"]

    # require fullname if specified
    if toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.require_fullname", False)
    ):
        schema["fullname"] = [toolkit.get_validator("not_empty")]

    # add required schema fields with not_empty validator
    for field in advancedauth_schema_keys["required"]:
        schema[field] = [
            get_validators()["not_empty_string"],
            toolkit.get_validator("not_empty"),
        ]

    # add optionals schema fields with ignore_missing validator
    for field in advancedauth_schema_keys["optional"]:
        schema[field] = [toolkit.get_validator("ignore_missing")]

    # add any additional validators from the schema
    for field in advancedauth_schema:
        addl_validators = field[1].get("additional_validators", [])
        if len(addl_validators):
            for validator in addl_validators:
                schema[field[0]].append(toolkit.get_validator(validator))

    # Add the terms of service field if it exists
    if helpers["advancedauth_terms_of_service"]() and mode == "create":
        schema["advancedauth_terms_of_service"] = [toolkit.get_validator("not_empty")]

    context["schema"] = schema
    return context


# intercepts user creation and gathers new data
def custom_user_create(context, data_dict):
    if context.get("ignore_auth"):
        # Allow CKAN CLI to create sysadmin
        return user_create(context, data_dict)

    schema = context["schema"]
    schema["email"] += [
        get_validators()["not_empty_string"],
        toolkit.get_validator("email_validator"),
    ]

    context = _modify_user_schema(context, "create")
    data_dict["email"] = data_dict["email"].lower()
    # run ckan's user_create function
    user_dict = user_create(context, data_dict)
    # it will exit here if validation fails

    # Save all the data collected to the db
    extras = advancedauthExtras()
    advancedauth_schema_keys = helpers["advancedauth_schema_keys"]()
    for field in advancedauth_schema_keys["all"]:
        extras = advancedauthExtras(
            user_id=user_dict.get("id"), key=field, value=data_dict.get(field, "")
        )
        extras.save()

    # add the terms of service agreement
    if helpers["advancedauth_terms_of_service"]():
        extras = advancedauthExtras(
            user_id=user_dict.get("id"),
            key="advancedauth_terms_of_service",
            value=data_dict.get("advancedauth_terms_of_service", ""),
        )
        extras.save()

    # Send email notification to administrator if configured to do so
    if toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.user_create_email", False)
    ):
        if toolkit.config.get(
            "ckanext.advancedauth.user_create_email_recipient_email", False
        ):
            recipient_name = toolkit.config.get(
                "ckanext.advancedauth.user_create_email_recipient_name", "Admin"
            )
            recipient_email = toolkit.config.get(
                "ckanext.advancedauth.user_create_email_recipient_email"
            )
            recipient_url = (
                toolkit.config.get("ckan.site_url") + "/user/" + user_dict.get("name")
            )
            subject = "New User Registered: " + user_dict.get("name")
            body = (
                "User "
                + user_dict.get("name")
                + " registered with email "
                + user_dict.get("email")
                + ".\n"
            )
            deny_list = [
                "name",
                "email",
                "email_hash",
                "sysadmin",
                "apikey",
                "state",
                "number_created_packages",
                "activity_streams_email_notifications",
                "about",
                "number_of_edits",
            ]
            for key, value in user_dict.items():
                value = "" if value is None else value
                if key not in deny_list:
                    body += key + ": " + value + "\n"
            advancedauth_schema = helpers["advancedauth_schema"]()
            for item in advancedauth_schema:
                body += item[1].get("label") + ": " + data_dict.get(item[0], "") + "\n"
            body += "\nLink to profile: " + recipient_url
            mailer.mail_recipient(recipient_name, recipient_email, subject, body)

    # send welcome email if configured to do so
    if toolkit.asbool(toolkit.config.get("ckanext.advancedauth.welcome_email", False)):
        recipient_name = user_dict.get("fullname", False) or user_dict.get("name", "")
        recipient_email = user_dict.get("email")
        default_subject = (
            toolkit.config.get("ckan.site_title", "") + ": New User Registration"
        )
        subject = toolkit.config.get(
            "ckanext.advancedauth.welcome_email_subject", default_subject
        )
        body = "Thank you for registering for " + toolkit.config.get(
            "ckan.site_title", ""
        )
        body += "\n"
        # TODO: Add better tooling for sites. This is very fragile and fails on many special characters.
        # We should specify a location for an email template
        if toolkit.config.get("ckanext.advancedauth.welcome_email_text", False):
            body += toolkit.config.get("ckanext.advancedauth.welcome_email_text")
            body += "\n"
        body += toolkit.config.get("ckan.site_title", "") + " Team"
        mailer.mail_recipient(recipient_name, recipient_email, subject, body)

    return user_dict


# adds custom metadata to user show
def custom_user_show(context, data_dict):
    # get user using ckan method
    user_dict = user_show(context, data_dict)
    # get extra fields
    extras = advancedauthExtras().get_all_extras(user_dict.get("id"))

    # add each public field to the object
    advancedauth_schema_keys = helpers["advancedauth_schema_keys"]()
    for field in advancedauth_schema_keys["public"]:
        user_dict[field] = ""

    # add each private field if the logged in user is the user being shown or the logged in user is sysadmin
    auth_user = context["auth_user_obj"]
    if auth_user is not None:
        username = user_dict["id"]
        if username == auth_user.id or auth_user.sysadmin:
            for field in advancedauth_schema_keys["private"]:
                user_dict[field] = ""

    # fill in fields from extras, respecting privacy
    for extra in extras:
        if extra.key in user_dict.keys():
            user_dict[extra.key] = extra.value

    return user_dict


# edits custom metadata in update function
def custom_user_update(context, data_dict):
    schema = context.get("schema")
    if schema is not None:
        schema["email"] += [
            get_validators()["not_empty_string"],
            toolkit.get_validator("email_validator"),
        ]

    # ignore this onpassword reset workflow
    if context["auth_user_obj"] is not None:
        context = _modify_user_schema(context, "update")
    # update user using ckan method
    data_dict["email"] = data_dict["email"].lower()
    user_dict = user_update(context, data_dict)
    user_id = user_dict.get("id")
    # add each field to the object
    advancedauth_schema_keys = helpers["advancedauth_schema_keys"]()
    extras = advancedauthExtras().get_all_extras(user_id)
    for field in advancedauth_schema_keys["all"]:
        extra_for_field = [extra for extra in extras if extra.key == field]
        new_val_for_field = data_dict.get(field, "")

        # Verify the value is not blank
        if new_val_for_field != "":
            if len(extra_for_field):
                # If an entry for the field exists in the advancedauth table, update it
                extra_for_field = extra_for_field[0]
                if new_val_for_field != extra_for_field.value:
                    extra_for_field.value = new_val_for_field
                    extra_for_field.updated = datetime.datetime.utcnow()
                    extra_for_field.save()
                user_dict[field] = extra_for_field.value
            else:
                # If an entry for the field does not exist, create it
                extra = advancedauthExtras(
                    user_id=user_id, key=field, value=new_val_for_field
                )
                extra.save()
                user_dict[field] = new_val_for_field
        user_dict[field] = ""
    return user_dict


# To enable the user's right to erasure (GDPR), we override the user_delete action
# To scrub personal details from the account rather than simply mark "deleted"
def custom_user_delete(context, data_dict):
    """Delete a user.

    Only sysadmins can delete users.

    :param id: the id or usernamename of the user to delete
    :type id: string
    """

    check_access("user_delete", context, data_dict)

    model = context["model"]
    user_id = get_or_bust(data_dict, "id")
    user = model.User.get(user_id)

    if user is None:
        raise NotFound('User "{id}" was not found.'.format(id=user_id))

    # Keep the user's ID
    model.Session.query(model.User).filter(model.User.id == user_id).update(
        {
            "name": user_id,
            "fullname": "[deleted]",
            "email": None,
            "about": None,
            "apikey": None,
            "image_url": None,
            "state": core.State.DELETED,
        }
    )
    # Delete user's info from advancedauth table too
    model.Session.query(advancedauthExtras).filter(
        advancedauthExtras.user_id == user_id
    ).delete()

    user_memberships = (
        model.Session.query(model.Member).filter(model.Member.table_id == user.id).all()
    )

    for membership in user_memberships:
        membership.delete()

    datasets_where_user_is_collaborator = (
        model.Session.query(model.PackageMember)
        .filter(model.PackageMember.user_id == user.id)
        .all()
    )
    for collaborator in datasets_where_user_is_collaborator:
        collaborator.delete()

    model.repo.commit()


# Sysadmins have access to the original package functions
# Non-admin users have restrictions on dataset visibility
def enforce_visibility_check(func_name):
    # CKAN chained_action decorator requires function to be named the same as original
    # https://docs.ckan.org/en/2.9/extensions/plugin-interfaces.html#ckan.plugins.interfaces.IActions
    @chained_action
    def func(original_action, context, data_dict):
        try:
            toolkit.check_access("sysadmin", context, {})
        except toolkit.NotAuthorized:
            try:
                # only sysadmins can change visibility on existing datasets
                pkg = toolkit.get_action("package_show")(
                    {"ignore_auth": True}, {"id": data_dict.get("name")}
                )
                data_dict["private"] = pkg["private"]
            except ValidationError:
                # only sysadmins can make public datasets
                data_dict["private"] = True
        return original_action(context, data_dict)

    func.__name__ = func_name
    return func


# returns our new custom actions overriding the basic action names, and returns the framework actions as ckan_<action> for compatibility if needed
actions = {
    "user_create": custom_user_create,
    "user_show": custom_user_show,
    "user_update": custom_user_update,
    "user_delete": custom_user_delete,
    "ckan_user_update": user_update,
    "ckan_user_show": user_show,
    "ckan_user_create": user_create,
    "ckan_user_delete": user_delete,
    "package_create": enforce_visibility_check("package_create"),
    "package_update": enforce_visibility_check("package_update"),
    "package_revise": enforce_visibility_check("package_revise"),
}
