"""Tests for plugin.py."""

import pytest
import ckan.logic as logic
import ckan.tests.factories as factories
import ckan.tests.helpers as helpers

from ckanext.advancedauth.model import advancedauthAudit
import random
import string
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
@pytest.mark.ckan_config("ckanext.advancedauth.disallow_anonymous_access", "true")
@pytest.mark.ckan_config(
    "ckanext.advancedauth.action_allowlist",
    "request_reset user_reset site_read user_create package_search datastore_search organization_list_for_user package_create sysadmin",
)
@pytest.mark.ckan_config("ckanext.advancedauth.only_authors_can_edit", "true")
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

    def test_only_sysadmin_users(self):
        """
        Our custom authorization function explicitly denies the following actions for all users except sysadmin:
            organization_create • group_create
        Other auth checks including default CKAN are still in place.
        """
        sysadmin_user = factories.Sysadmin()
        non_sysadmin_user = factories.User()
        org_name = "".join(random.choices(string.ascii_lowercase, k=8))

        assert logic.check_access(
            "organization_create", {"user": sysadmin_user["id"]}, {"name": org_name}
        )

        with pytest.raises(logic.NotAuthorized):
            logic.check_access(
                "organization_create",
                {"user": non_sysadmin_user["id"]},
                {"name": org_name},
            )

    def test_anonymous_users(self):
        """
        Anonymous users are those not logged in. mapMECFS currently disallows anonymous access except for the following actions:
            request_reset • user_reset • site_read • user_create • package_search • datastore_search • organization_list_for_user • package_create • sysadmin
        The setting for allowing anonymous access is untested and should not be enabled.
        """
        # Authorization function will allow actions listed above to proceed in sequence of checks. Here we test for user_create
        assert logic.check_access("user_create", {"user": ""})

        # Authorization function should always deny any actions not explicitly listed for anonymous users. Current_package_list_with_resources is an example
        # that is not explicitly checked, so we test for this.
        with pytest.raises(logic.NotAuthorized):
            logic.check_access("current_package_list_with_resources", {"user": ""})

    def test_only_approved_users(self):
        """
        Approved users are those who belong to an org. The following actions are restricted to approved users only:
            package_show • user_list • user_show • organization_list • group_list
        """
        owner_user = factories.User()
        owner_org = factories.Organization(
            users=[{"name": owner_user["id"], "capacity": "member"}]
        )
        owner_dataset = factories.Dataset(owner_org=owner_org["id"], private=True)
        no_org_user = factories.User()

        # Authorization function will allow actions listed above to proceed in sequence of checks. Here package_show is tested
        assert logic.check_access(
            "package_show", {"user": owner_user["id"]}, {"id": owner_dataset["name"]}
        )

        # User with no orgs should not be able to invoke approved-users-only actions. Here package_show is tested
        with pytest.raises(logic.NotAuthorized):
            logic.check_access(
                "package_show",
                {"user": no_org_user["id"]},
                {"id": owner_dataset["name"]},
            )

    def test_package_update(self):
        """
        For a given dataset, only an organizational admin or creator+editor may update it.
        """
        org_user_dataset_creator = factories.User()
        org_user_editor = factories.User()
        org_user_member = factories.User()
        org_user_admin = factories.User()
        owner_org = factories.Organization(
            users=[
                {"name": org_user_dataset_creator["id"], "capacity": "editor"},
                {"name": org_user_editor["id"], "capacity": "editor"},
                {"name": org_user_member["id"], "capacity": "member"},
                {"name": org_user_admin["id"], "capacity": "admin"},
            ]
        )
        dataset = factories.Dataset(
            owner_org=owner_org["id"], private=True, user=org_user_dataset_creator
        )

        # check creator can update their own dataset
        assert logic.check_access(
            "package_update",
            {"user": org_user_dataset_creator["id"]},
            {"id": dataset["name"]},
        )

        # check another editor in the same org cannot update a dataset they did not author
        with pytest.raises(logic.NotAuthorized):
            logic.check_access(
                "package_update",
                {"user": org_user_editor["id"]},
                {"id": dataset["name"]},
            )

        # check org admin of same org can update dataset
        assert logic.check_access(
            "package_update",
            {"user": org_user_admin["id"]},
            {"id": dataset["name"]},
        )

        # check org admin of different org cannot edit dataset
        different_org_admin = factories.User()
        _ = factories.Organization(
            users=[{"name": different_org_admin["id"], "capacity": "admin"}]
        )
        with pytest.raises(logic.NotAuthorized):
            logic.check_access(
                "package_update",
                {"user": different_org_admin["id"]},
                {"id": dataset["name"]},
            )

    def test_package_update_creator_removed_from_org(self):
        """
        When a dataset creator is removed from the organization that owns the dataset,
        they should no longer be able to update the dataset.
        """
        sysadmin_user = factories.Sysadmin()
        dataset_creator = factories.User()
        owner_org = factories.Organization(
            users=[{"name": dataset_creator["id"], "capacity": "admin"}]
        )
        dataset = factories.Dataset(
            owner_org=owner_org["id"], private=False, user=dataset_creator
        )

        # remove creator's membership so core CKAN will now reject package_update
        helpers.call_action(
            "member_delete",
            {"user": sysadmin_user["name"]},
            id=owner_org["id"],
            object=dataset_creator["id"],
            object_type="user",
        )

        with pytest.raises(logic.NotAuthorized):
            logic.check_access(
                "package_update",
                {"user": dataset_creator["id"]},
                {"id": dataset["name"]},
            )

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
