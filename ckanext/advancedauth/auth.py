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
