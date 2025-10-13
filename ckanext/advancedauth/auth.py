import logging
import ckan.plugins.toolkit as toolkit
from ckan.plugins.toolkit import auth_sysadmins_check
import ckan.authz as authz
import ckan.model as model
from .model import advancedauthAudit

log = logging.getLogger(__name__)


# writes an audit object to the audit table
def advancedauth_auditor(next_func, context, data_dict=None):
    func_name = next_func.__name__
    if any(action in func_name for action in ["resource", "package", "datastore"]):
        package_id = context["package"].id if context.get("package", False) else ""
        resource_id = context["resource"].id if context.get("resource", False) else ""
        user_id = ""
        if context["auth_user_obj"] and hasattr(context["auth_user_obj"], "id"):
            user_id = context["auth_user_obj"].id
        elif context["user"]:
            user = model.User.get(context["user"])
            if user and hasattr(user, "id"):
                user_id = user.id
        if not user_id:
            log.debug(
                "Could not locate user ID; user: {}, auth_user_obj: {}".format(
                    context["user"], context.get("auth_user_obj", False)
                )
            )
            return
        audit = advancedauthAudit(
            user_id=user_id,
            action=func_name,
            package_id=package_id,
            resource_id=resource_id,
        )
        audit.save()


# this permission, added to the package_update action, only allows the original creator of the
# dataset OR an organizational admin to update the package. This is so that "editor" members
# of organization can't edit each others datasets
def check_package_update(context, data_dict=None, func_name=None):
    only_authors_can_edit = toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.only_authors_can_edit") or False
    )
    if not func_name == "package_update" or not only_authors_can_edit:
        return False
    if not data_dict:
        data_dict = {"id": context.get("package").id}
    package = toolkit.get_action("package_show")(context, data_dict)

    user_id = context.get("auth_user_obj").id
    success_conditions = 0
    # if the current user created the dataset
    if user_id == package.get("creator_user_id", ""):
        success_conditions += 1

    # if the current user is an admin of the org for the dataset
    organization = toolkit.get_action("organization_show")(
        context, {"id": package.get("owner_org")}
    )

    def is_user_in_org(usr):
        return usr.get("id", "") == user_id and usr.get("capacity", "") == "admin"

    users_in_org = list(filter(is_user_in_org, organization.get("users", [{}])))
    if len(users_in_org) > 0:
        success_conditions += 1

    if success_conditions > 0:
        return True
    else:
        raise toolkit.NotAuthorized("You do not have permission to edit this dataset")


# this permission function denies access to users with no organizations, which is self-registered
# users who have not yet been approved by mapMECFS admins
def check_only_approved_users(context, data_dict=None, func_name=None):
    only_approved_users_var = toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.only_approved_users") or False
    )
    only_approved_users_actions = [
        "package_show",
        "user_list",  # integration tool checks user_list access
        "user_show",
        "organization_list",
        "group_list",
    ]

    if not only_approved_users_var or func_name not in only_approved_users_actions:
        return False

    func = toolkit.get_action("organization_list_for_user")
    user_id = ""
    # If auth_user_obj exists in context, use it. Otherwise, use user_obj
    if context.get("auth_user_obj", False) and hasattr(
        context.get("auth_user_obj"), "id"
    ):
        user_id = context.get("auth_user_obj").id
    elif context.get("user_obj", False) and hasattr(context.get("user_obj"), "id"):
        user_id = context.get("user_obj").id

    if user_id:
        orgs = func({}, {"id": user_id})
        if len(orgs):
            return True
        # allow new user to edit their own profile for "registration"
        if func_name == "user_show":
            requested_user_id = data_dict.get("id", "")
            user_obj = context.get("auth_user_obj", {})
            if requested_user_id == user_obj.id or requested_user_id == user_obj.name:
                return True
        approval_message = toolkit.config.get(
            "ckanext.advancedauth.only_approved_users_message",
            "Your account is pending approval",
        )
        toolkit.abort(403, approval_message)
    else:
        raise toolkit.NotAuthorized("You must be logged in to access this feature")


@toolkit.auth_allow_anonymous_access
@toolkit.chained_auth_function
@auth_sysadmins_check
def advancedauth_wrapper_function(next_func, context, data_dict=None):
    # run auditor
    advancedauth_auditor(next_func, context, data_dict)

    # get function name
    func_name = next_func.__name__

    if check_anonymous_access(func_name, context):
        return {"success": True}

    if check_sysadmin_access(context):
        return {"success": True}

    if check_only_approved_users(context, data_dict, func_name):
        return {"success": True}

    if check_package_update(context, data_dict, func_name):
        return {"success": True}

    if check_create_organization(context, func_name):
        return {"success": True}

    return next_func(context, data_dict)


# gets all authentication actions from authz
# append our auth wrapper function to all actions
def get_actions_list():
    actions_list = {}
    actions = list(authz.auth_functions_list())
    for action in actions:
        actions_list[action] = advancedauth_wrapper_function
    return actions_list


def check_anonymous_access(func_name, context):
    disallow_anonymous_access = toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.disallow_anonymous_access") or False
    )

    action_allowlist = toolkit.aslist(
        toolkit.config.get("ckanext.advancedauth.action_allowlist", "")
    )

    # if anonymous access is allowed, skip the auth check
    if not disallow_anonymous_access:
        return True

    # if anonymous access is disallowed, and the action is not in the exception list, check if user is logged in
    if disallow_anonymous_access and func_name not in action_allowlist:
        if not context.get("auth_user_obj", False) and not context.get("user", False):
            err_msg = "Authentication is required to access this feature ({0})".format(
                func_name
            )
            raise toolkit.NotAuthorized(err_msg)
    return False


def check_sysadmin_access(context):
    user = context.get("auth_user_obj", "")
    if user and hasattr(user, "sysadmin") and user.sysadmin:
        if not user.state == "active":
            raise toolkit.NotAuthorized()
        return True
    return False


def check_create_organization(context, func_name=None):
    if func_name != "organization_create" and func_name != "group_create":
        return False
    if check_sysadmin_access(context):
        return True
    raise toolkit.NotAuthorized("You do not have permission to create an organization")
