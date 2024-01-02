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
from flask_cors import CORS, cross_origin

from .model import advancedauthAudit
from ckan.model import meta, Package, Resource
from sqlalchemy.orm import joinedload

audit_table = Blueprint("audit_table", __name__)
cors = CORS(audit_table)


@cross_origin()
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


@cross_origin()
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


@cross_origin()
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


@cross_origin()
@audit_table.route("/getusers")
def list_users():
    if toolkit.g.userobj and toolkit.g.userobj.sysadmin:
        users = user_list({"model": model}, {})
        return {user["id"]: {k: v for k, v in user.items()} for user in users}
    return {
        "error": "User must be logged in as a sysadmin in order to access this API endpoint."
    }


@cross_origin()
@audit_table.route("/getpackages")
def list_packages():
    if toolkit.g.userobj and toolkit.g.userobj.sysadmin:
        session = meta.Session
        packages = (
            session.query(Package).options(joinedload(Package.resources_all)).all()
        )
        return {
            package.id: {
                "id": package.id,
                "name": package.name,
                "resources": [
                    {"id": resource.id, "name": resource.name}
                    for resource in package.resources_all
                ],
            }
            for package in packages
        }
    return {
        "error": "User must be logged in as a sysadmin in order to access this API endpoint."
    }


def map_row_data(row):
    return {
        "id": row.id,
        "user_id": row.user_id,
        "action": row.action,
        "package_id": row.package_id,
        "resource_id": row.resource_id,
        "timestamp": row.timestamp,
    }
