from ckan.common import request
import ckan.plugins.toolkit as toolkit
from ckan.logic.action.get import (
    user_show,
    user_list,
    current_package_list_with_resources,
    resource_show,
    package_show,
)
import ckan.model as model
from ckan.logic import NotFound, ValidationError
from flask import Blueprint

from .model import advancedauthAudit


audit_table = Blueprint("audit_table", __name__)


@audit_table.route("/audituser")
def user_audit():
    if toolkit.g.userobj and toolkit.g.userobj.sysadmin:
        user_id = request.params.get("userid", None)
        rows = advancedauthAudit().get_all_actions_by_user(user_id)
        actions = map(map_row_data, rows)
        return {
            action["id"]: {k: v for k, v in action.items() if k != "id"}
            for action in actions
        }
    return {
        "error": "User must be logged in as a sysadmin in order to access this API endpoint."
    }


@audit_table.route("/auditfile")
def file_audit():
    if toolkit.g.userobj and toolkit.g.userobj.sysadmin:
        resource_id = request.params.get("resourceid", None)
        rows = advancedauthAudit().get_all_actions_by_file(resource_id)
        actions = map(map_row_data, rows)
        return {
            action["id"]: {k: v for k, v in action.items() if k != "id"}
            for action in actions
        }
    return {
        "error": "User must be logged in as a sysadmin in order to access this API endpoint."
    }


@audit_table.route("/auditdates")
def date_audit():
    if toolkit.g.userobj and toolkit.g.userobj.sysadmin:
        start_date = request.params.get("startdate", "2000-01-01")
        end_date = request.params.get("enddate", "3000-12-12")
        rows = advancedauthAudit().get_all_actions_by_date(start_date, end_date)
        actions = map(map_row_data, rows)
        return {
            action["id"]: {k: v for k, v in action.items() if k != "id"}
            for action in actions
        }
    return {
        "error": "User must be logged in as a sysadmin in order to access this API endpoint."
    }


@audit_table.route("/getusers")
def list_users():
    if toolkit.g.userobj and toolkit.g.userobj.sysadmin:
        users = user_list({"model": model}, {})
        return {user["id"]: {k: v for k, v in user.items()} for user in users}
    return {
        "error": "User must be logged in as a sysadmin in order to access this API endpoint."
    }


@audit_table.route("/getresources")
def list_resources():
    if toolkit.g.userobj and toolkit.g.userobj.sysadmin:
        packages = current_package_list_with_resources(
            {"user": toolkit.g.userobj.name, "model": model}, {}
        )
        resource_lst = []
        for package in packages:
            for resource in package.get("resources", []):
                resource["package_name"] = package["title"]
                resource_lst.append(resource)
        return {
            resource["id"]: {k: v for k, v in resource.items()}
            for resource in resource_lst
        }
    return {
        "error": "User must be logged in as a sysadmin in order to access this API endpoint."
    }


def map_row_data(row):
    resource_name = ""
    package_name = ""
    try:
        resource_name = resource_show({"model": model}, {"id": row.resource_id})["name"]
    except (NotFound, ValidationError):
        resource_name = ""
    try:
        package_name = package_show({"model": model}, {"id": row.package_id})["name"]
    except (NotFound, ValidationError):
        package_name = ""
    return {
        "id": row.id,
        "user_id": row.user_id,
        "username": user_show({"model": model}, {"id": row.user_id})["name"],
        "action": row.action,
        "package_id": row.package_id,
        "package_name": package_name,
        "resource_id": row.resource_id,
        "resource_name": resource_name,
        "timestamp": row.timestamp
    }
