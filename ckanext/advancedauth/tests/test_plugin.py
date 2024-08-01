"""Tests for plugin.py."""

import pytest
import ckan.plugins.toolkit as toolkit
import ckan.logic as logic
import ckan.tests.factories as factories
import ckan.tests.helpers as helpers

from ckanext.advancedauth.model import advancedauthAudit
from ckanext.advancedauth.helpers import (
    advancedauth_must_view_privacy_policy,
    advancedauth_must_view_terms_of_service,
)


@pytest.mark.ckan_config("ckanext.advancedauth.must_view_privacy_policy", "true")
def test_must_view_privacy_policy_getter():
    assert advancedauth_must_view_privacy_policy() == True


@pytest.mark.ckan_config("ckanext.advancedauth.must_view_privacy_policy", "")
def test_must_view_privacy_policy_empty_string():
    assert advancedauth_must_view_privacy_policy() == False


@pytest.mark.ckan_config("ckanext.advancedauth.must_view_terms_of_service", "true")
def test_must_view_terms_of_service_getter():
    assert advancedauth_must_view_terms_of_service() == True


@pytest.mark.ckan_config("ckanext.advancedauth.must_view_terms_of_service", "")
def test_must_view_terms_of_service_empty_string():
    assert advancedauth_must_view_terms_of_service() == False


# These plugins are included to suppress warnings: recline_view image_view
@pytest.mark.ckan_config("ckan.plugins", "recline_view image_view advancedauth")
@pytest.mark.usefixtures("clean_db", "with_plugins", "with_request_context")
class TestPlugin(object):
    def test_member_delete_organization(self):
        user = factories.User()
        owner_org = factories.Organization(
            users=[{"name": user["id"], "capacity": "member"}]
        )
        with pytest.raises(logic.NotAuthorized) as e:
            logic.check_access(
                "organization_delete", {"user": user["name"]}, {"id": owner_org["id"]}
            )

        assert (
            e.value.message
            == f'User {user["name"]} not authorized to delete organization {owner_org["id"]}'
        )

    def test_resource_view(self):
        user = factories.User()
        owner_org = factories.Organization(
            users=[{"name": user["id"], "capacity": "member"}]
        )
        dataset = factories.Dataset(owner_org=owner_org["id"], private=True)
        resource = factories.Resource(package_id=dataset["id"])
        assert logic.check_access(
            "resource_show", {"user": user["name"]}, {"id": resource["id"]}
        )
        with pytest.raises(logic.NotAuthorized):
            logic.check_access("resource_show", {"user": ""}, {"id": resource["id"]})

    def test_audit_table(self):
        user = factories.User()
        owner_org = factories.Organization(
            users=[{"name": user["id"], "capacity": "member"}]
        )
        dataset = factories.Dataset(owner_org=owner_org["id"])
        resource = factories.Resource(package_id=dataset["id"])
        audit = advancedauthAudit(
            user_id=user["id"],
            action="package_show",
            package_id=dataset["id"],
            resource_id=resource["id"],
        )
        audit.save()
        assert (
            len(advancedauthAudit.get_all_actions_by_file(resourceid=resource["id"]))
            > 0
        )
        assert len(advancedauthAudit.get_all_actions_by_user(userid=user["id"])) > 0
