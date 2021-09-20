import ckan.plugins.toolkit as toolkit
import ckan.authz as authz
from .model import advancedauthAudit

# checks to see if the user is logged in and aborts with a 403 if not
@toolkit.auth_allow_anonymous_access
@toolkit.chained_auth_function
def advancedauth_check_access(next_func, context, data_dict=None):
    func_name = next_func.__name__
    if not context.get("auth_user_obj", False) and not context.get("user", False):
        err_msg = "Authentication is required to access this feature ({0})".format(
            func_name
        )
        raise toolkit.NotAuthorized(err_msg)
    else:
        if any(action in func_name for action in ["resource", "package", "datastore"]):
            package_id = context["package"].id if context.get("package", False) else ""
            resource_id = (
                context["resource"].id if context.get("resource", False) else ""
            )
            user_id = context["auth_user_obj"].id
            audit = advancedauthAudit(
                user_id=user_id,
                action=func_name,
                package_id=package_id,
                resource_id=resource_id,
            )
            audit.save()
        return next_func(context, data_dict)


# this permission, added to the package_update action, only allows the original creator of the
# dataset OR an organizational admin to update the package. This is so that "editor" members
# of organization can't edit each others datasets
def my_package_update(context, data_dict=None):
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
        return {"success": True}
    else:
        return {"success": False}


# this permission function denies access to users with no organizations, which is self-registered
# users who have not yet been approved by mapMECFS admins
def only_approved_users(context, data_dict=None):
    func = toolkit.get_action("organization_list_for_user")
    user_id = ""
    try:
        user_id = context.get("auth_user_obj").id
    except AttributeError:
        user_id = context.get("user_obj").id

    orgs = func({}, {"id": user_id})
    if len(orgs):
        return {"success": True}

    approval_message = toolkit.config.get(
        "ckanext.advancedauth.only_approved_users_message",
        "Your account is pending approval",
    )
    toolkit.abort(403, approval_message)


# this is published to the plugin
def get_auth_functions():
    ret = {}
    if toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.only_authors_can_edit", False)
    ):
        ret["package_update"] = my_package_update

    if toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.only_approved_users", False)
    ):
        ret["package_show"] = only_approved_users
        ret["user_list"] = only_approved_users
        ret["user_show"] = only_approved_users
        ret["ckanext_mecfs_explorer"] = only_approved_users
        ret["organization_list"] = only_approved_users

    return ret


# gets all authentication actions from authz, and appends the above permission to any not allowed by the production.ini file
def get_actions_list():
    actions_list = {}
    if toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.disallow_anonymous_access", False)
    ):
        # get all possible actions
        actions = list(authz.auth_functions_list())
        # remove allowlisted action
        allowlist = toolkit.aslist(
            toolkit.config.get("ckanext.advancedauth.action_allowlist", "")
        )
        for action in allowlist:
            actions.remove(action)
        # create dict with all remaining actions mapped to our function
        action_func = advancedauth_check_access
        for action in actions:
            actions_list[action] = action_func
    return actions_list
