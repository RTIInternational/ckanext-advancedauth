import ckan.plugins.toolkit as toolkit
import ckan.authz as authz
from .model import advancedauthAudit

# writes an audit object to the audit table
def advancedauth_auditor(next_func, context, data_dict=None):
    func_name = next_func.__name__
    if any(action in func_name for action in ["resource", "package", "datastore"]):
        package_id = context["package"].id if context.get("package", False) else ""
        resource_id = context["resource"].id if context.get("resource", False) else ""
        if context["user"] or context["auth_user_obj"]:
            user_id = context["auth_user_obj"].id
            audit = advancedauthAudit(
                user_id=user_id,
                action=func_name,
                package_id=package_id,
                resource_id=resource_id,
            )
            audit.save()


# checks to see if the user is logged in and aborts with a 403 if not
def advancedauth_check_access(next_func, context, data_dict=None):
    func_name = next_func.__name__
    if not context.get("auth_user_obj", False) and not context.get("user", False):
        err_msg = "Authentication is required to access this feature ({0})".format(
            func_name
        )
        raise toolkit.NotAuthorized(err_msg)


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
    print(orgs)
    approval_message = toolkit.config.get(
        "ckanext.advancedauth.only_approved_users_message",
        "Your account is pending approval",
    )
    toolkit.abort(403, approval_message)


@toolkit.auth_allow_anonymous_access
@toolkit.chained_auth_function
def advancedauth_wrapper_function(next_func, context, data_dict=None):
    # run auditor
    advancedauth_auditor(next_func, context, data_dict)

    # get function name
    func_name = next_func.__name__

    # set up variables for only_approved_users
    only_approved_users_var = toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.only_approved_users", False)
    )
    only_approved_users_actions = [
        "package_show",
        "user_list",
        "user_show",
        "organization_list",
    ]

    # run only_approved_users
    # this aborts with 403 if failed
    if only_approved_users_var and func_name in only_approved_users_actions:

        only_approved_users(context, data_dict)

    ## setup variables for disallow_anonymous_access
    disallow_anonymous_access = toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.disallow_anonymous_access", False)
    )

    action_allowlist = toolkit.aslist(
        toolkit.config.get("ckanext.advancedauth.action_allowlist", "")
    )

    ## run advancedauth_check_access
    if disallow_anonymous_access and func_name not in action_allowlist:
        advancedauth_check_access(next_func, context, data_dict)

    ## setup only_authors_can_edit
    only_authors_can_edit = toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.only_authors_can_edit", False)
    )

    if func_name == "package_update" and only_authors_can_edit:
        package_update = my_package_update(context, data_dict)
        if package_update.get("success") == False:
            return package_update

    return next_func(context, data_dict)


# gets all authentication actions from authz
# append our auth wrapper function to all actions
def get_actions_list():
    actions_list = {}
    actions = list(authz.auth_functions_list())
    for action in actions:
        actions_list[action] = advancedauth_wrapper_function
    return actions_list
