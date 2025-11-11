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
    # custom auth not applicable for actions other than package_update. continue sequence of checks
    if not func_name == "package_update":
        return False
    only_authors_can_edit = toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.only_authors_can_edit") or False
    )
    # skip custom auth if setting is not enabled
    if not only_authors_can_edit:
        return False
    if not data_dict:
        data_dict = {"id": context.get("package").id}
    package = toolkit.get_action("package_show")(context, data_dict)

    user_id = ""
    # If auth_user_obj exists in context, use it. Otherwise, use user_obj
    if context.get("auth_user_obj", False) and hasattr(
        context.get("auth_user_obj"), "id"
    ):
        user_id = context.get("auth_user_obj").id
    elif context.get("user_obj", False) and hasattr(context.get("user_obj"), "id"):
        user_id = context.get("user_obj").id
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

    if success_conditions == 0:
        raise toolkit.NotAuthorized("You do not have permission to edit this dataset")

    return False


def check_only_approved_users(context, data_dict=None, func_name=None):
    """
    Approved users are those who belong to an org. The following actions are restricted to approved users only:
        package_show • user_list • user_show • organization_list • group_list
    """
    only_approved_users_var = toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.only_approved_users") or False
    )
    # continue sequence of checks if only_approved_users_var is False
    if not only_approved_users_var:
        return False

    only_approved_users_actions = [
        "package_show",
        "user_list",  # integration tool checks user_list access
        "user_show",
        "organization_list",
        "group_list",
    ]

    # continue sequence of checks if action is not in the only_approved_users_actions list
    if func_name not in only_approved_users_actions:
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
        # continue sequence of checks if user belongs to at least one organization
        if len(orgs):
            return False
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
        raise toolkit.NotAuthorized(approval_message)
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

    check_anonymous_access(func_name, context)

    if check_sysadmin_access(context, func_name):
        return {"success": True}

    check_only_approved_users(context, data_dict, func_name)
    check_package_update(context, data_dict, func_name)

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
    """
    Anonymous users are those not logged in. mapMECFS currently disallows anonymous access except for the following actions:
        request_reset • user_reset • site_read • user_create • package_search • datastore_search • organization_list_for_user • package_create • sysadmin
    The setting for allowing anonymous access is untested and should not be enabled.
    The authorization function has no explicit approvals hence the reason for including package_create.
    """
    disallow_anonymous_access = toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.disallow_anonymous_access") or False
    )
    allow_anonymous_access = not disallow_anonymous_access

    action_allowlist = toolkit.aslist(
        toolkit.config.get("ckanext.advancedauth.action_allowlist", "")
    )

    # if anonymous access is allowed, continue sequence of checks
    if allow_anonymous_access:
        return False

    # if anonymous access is disallowed, and the action is not in the exception list, explicitly deny for anonymous users
    if disallow_anonymous_access and func_name not in action_allowlist:
        user_id = ""
        if context.get("auth_user_obj", False) and hasattr(
            context.get("auth_user_obj"), "id"
        ):
            user_id = context.get("auth_user_obj").id
        elif context.get("user_obj", False) and hasattr(context.get("user_obj"), "id"):
            user_id = context.get("user_obj").id
        if not user_id:
            err_msg = "Authentication is required to access this feature ({0})".format(
                func_name
            )
            raise toolkit.NotAuthorized(err_msg)
    return False


def check_sysadmin_access(context, func_name):
    user = context.get("auth_user_obj", "")
    if user and hasattr(user, "sysadmin") and user.sysadmin:
        # explict deny for deleted users
        if not user.state == "active":
            raise toolkit.NotAuthorized("sysadmin was deleted")
        # explicit approve action if user is sysadmin
        return True

    # user is not sysadmin - explicit deny for these actions
    sysadmin_only_actions = ["organization_create", "group_create"]
    if func_name in sysadmin_only_actions:
        raise toolkit.NotAuthorized(f"only sysadmins may perform {func_name}")

    # continue sequence of checks
    return False
