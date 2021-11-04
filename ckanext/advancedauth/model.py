from sqlalchemy import Table, Column, ForeignKey, types
from sqlalchemy.exc import ArgumentError

from ckan.model.meta import metadata, mapper, Session
from ckan.model.domain_object import DomainObject
from ckan.model.types import make_uuid

import datetime


advancedauth_extras_table = Table(
    "advancedauth_extras",
    metadata,
    Column("id", types.UnicodeText, primary_key=True, default=make_uuid),
    Column("user_id", types.UnicodeText, ForeignKey("user.id")),
    Column("key", types.UnicodeText),
    Column("value", types.UnicodeText),
    Column("created", types.DateTime, default=datetime.datetime.utcnow),
    Column("updated", types.DateTime),
)


advancedauth_audit_table = Table(
    "advancedauth_audit",
    metadata,
    Column("id", types.UnicodeText, primary_key=True, default=make_uuid),
    Column("user_id", types.UnicodeText, ForeignKey("user.id")),
    Column("action", types.UnicodeText),
    Column("package_id", types.UnicodeText),
    Column("resource_id", types.UnicodeText),
    Column("timestamp", types.DateTime, default=datetime.datetime.utcnow),
)


def initdb():
    if not advancedauth_extras_table.exists():
        advancedauth_extras_table.create()
    if not advancedauth_audit_table.exists():
        advancedauth_audit_table.create()
    try:
        mapper(advancedauthExtras, advancedauth_extras_table)
    except ArgumentError:
        # this means the class is already mapped
        pass
    try:
        mapper(advancedauthAudit, advancedauth_audit_table)
    except ArgumentError:
        # this means the class is already mapped
        pass


class advancedauthExtras(DomainObject):
    def __repr__(self):
        return "<advancedauthExtras id=%s user_id=%s key=%s value=%s>" % (
            self.id,
            self.user_id,
            self.key,
            self.value,
        )

    def __str__(self):
        return self.__repr__().encode("ascii", "ignore")

    @classmethod
    def get_all_extras(self, userid=None):
        query = Session.query(advancedauthExtras).filter(
            advancedauthExtras.user_id == userid
        )
        return query.all()

    def update(self, user, request):
        pass


class advancedauthAudit(DomainObject):
    def __repr__(self):
        return "<advancedauthAudit id=%s user_id=%s action=%s package_id=%s resource_id=%s timestamp=%s>" % (
            self.id,
            self.user_id,
            self.action,
            self.package_id,
            self.resource_id,
            self.timestamp,
        )

    def __str__(self):
        return self.__repr__().encode("ascii", "ignore")

    @classmethod
    def get_all_actions_by_user(self, userid=None):
        query = Session.query(advancedauthAudit).filter(
            advancedauthAudit.user_id == userid
        )
        return query.all()

    @classmethod
    def get_all_actions_by_file(self, resourceid=None):
        query = Session.query(advancedauthAudit).filter(
            advancedauthAudit.resource_id == resourceid
        )
        return query.all()

    @classmethod
    def get_all_actions_by_date(self, start_date="2000-01-01", end_date="3000-12-12"):
        converted_start_date = datetime.datetime.strptime(start_date, "%Y-%m-%d")
        converted_end_date = datetime.datetime.strptime(end_date, "%Y-%m-%d")
        query = Session.query(advancedauthAudit).filter(
            (advancedauthAudit.timestamp >= converted_start_date)
            & (advancedauthAudit.timestamp <= converted_end_date)
        )
        return query.all()

    def update(self, user, request):
        pass
