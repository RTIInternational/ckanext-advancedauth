from ckan.common import request
import ckan.plugins.toolkit as toolkit
from ckan.logic.action.get import user_show
import ckan.model as model
from flask import Blueprint

from .model import advancedauthAudit


audit_table = Blueprint("audit_table", __name__)


@audit_table.route("/audituser")
def user_audit():
  if toolkit.g.userobj and toolkit.g.userobj.sysadmin:
    user_id = request.params.get("userid", None)
    rows = advancedauthAudit().get_all_actions_by_user(user_id)
    actions = map(map_row_data, rows)
    return {action["id"]: {k:v for k,v in action.items() if k != "id"} for action in actions}
  return { "error": "User must be logged in as a sysadmin in order to access this API endpoint." }
  

@audit_table.route("/auditfile")
def file_audit():
  if toolkit.g.userobj and toolkit.g.userobj.sysadmin:
    resource_id = request.params.get("resourceid", None)
    rows = advancedauthAudit().get_all_actions_by_file(resource_id)
    actions = map(map_row_data, rows)
    return {action["id"]: {k:v for k,v in action.items() if k != "id"} for action in actions}
  return { "error": "User must be logged in as a sysadmin in order to access this API endpoint." }


@audit_table.route("/auditdates")
def date_audit():
  if toolkit.g.userobj and toolkit.g.userobj.sysadmin:
    start_date = request.params.get("startdate", "2000-01-01")
    end_date = request.params.get("enddate", "3000-12-12")
    rows = advancedauthAudit().get_all_actions_by_date(start_date, end_date)
    actions = map(map_row_data, rows)
    return {action["id"]: {k:v for k,v in action.items() if k != "id"} for action in actions}
  return { "error": "User must be logged in as a sysadmin in order to access this API endpoint." }



def map_row_data(row):
  return {
    "id": row.id,
    "user_id": row.user_id,
    "username": user_show({"model": model}, {"id": row.user_id})["name"],
    "action": row.action,
    "package_id": row.package_id,
    "resource_id": row.resource_id
  }
