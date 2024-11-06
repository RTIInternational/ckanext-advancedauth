import json
import os
import inspect

import ckan.plugins.toolkit as toolkit


# returns the JSON schema file located adjacent to this file
def advancedauth_schema():
    """
    Import schema for advancedauth plugin given 2 config params in production.ini (see example)
    Ex:
        ckanext.advancedauth.modify_user_schema = true
        ckanext.advancedauth.user_schema_location = ckanext.mecfs.schema:user_schema.json
    """
    if toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.modify_user_schema", False)
    ):
        plugin_location = toolkit.config.get(
            "ckanext.advancedauth.user_schema_location"
        )
        module, file_name = plugin_location.split(":", 1)
        try:
            # __import__ has an odd signature
            m = __import__(module, fromlist=[""])
        except ImportError:
            return
        schema_location = os.path.join(os.path.dirname(inspect.getfile(m)), file_name)
        if os.path.exists(schema_location):
            try:
                from paste.reloader import watch_file

                watch_file(schema_location)
            except ImportError:
                pass
            with open(schema_location) as f:
                data = json.load(f)
                sorted_data = sorted(data.items(), key=lambda x: x[1].get("order", 999))
            return sorted_data
    return {}


# gets a dict with required keys and optional keys, plus a combined list of all keys
def advancedauth_schema_keys():
    schema = advancedauth_schema()
    keys = {"required": [], "optional": [], "private": [], "public": [], "all": []}
    for item in schema:
        # get required/optional
        if item[1].get("required", False):
            keys["required"].append(item[0])
        else:
            keys["optional"].append(item[0])

        # get private/public
        if item[1].get("private", False):
            keys["private"].append(item[0])
        else:
            keys["public"].append(item[0])

        # also add to all
        keys["all"].append(item[0])

    return keys


# returns either false, or the location of a terms of service file
def advancedauth_terms_of_service():
    return toolkit.config.get("ckanext.advancedauth.terms_of_service_filename", False)


def advancedauth_terms_of_service_label():
    return toolkit.config.get(
        "ckanext.advancedauth.terms_of_service_label", "Terms Of Service"
    )


def advancedauth_must_view_terms_of_service():
    return toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.must_view_terms_of_service") or False
    )


def advancedauth_require_fullname():
    return toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.require_fullname", False)
    )


def advancedauth_inline_dua():
    return toolkit.config.get(
        "ckanext.advancedauth.inline_dua", "user/snippets/inline_dua.html"
    )


def advancedauth_privacy_policy():
    return toolkit.config.get("ckanext.advancedauth.privacy_policy_filename", False)


def advancedauth_privacy_policy_label():
    return toolkit.config.get(
        "ckanext.advancedauth.privacy_policy_label", "Privacy Policy"
    )


def advancedauth_must_view_privacy_policy():
    return toolkit.asbool(
        toolkit.config.get("ckanext.advancedauth.must_view_privacy_policy") or False
    )


def advancedauth_inline_privacy_policy():
    return toolkit.config.get(
        "ckanext.advancedauth.inline_privacy_policy",
        "user/snippets/inline_privacy_policy.html",
    )


def advancedauth_turnstile_sitekey():
    return toolkit.config.get("ckanext.advancedauth.turnstile_sitekey", "")


# publishes the helpers for use elsewhere and for adding to templates
helpers = {
    "advancedauth_schema": advancedauth_schema,
    "advancedauth_schema_keys": advancedauth_schema_keys,
    "advancedauth_terms_of_service": advancedauth_terms_of_service,
    "advancedauth_terms_of_service_label": advancedauth_terms_of_service_label,
    "advancedauth_must_view_terms_of_service": advancedauth_must_view_terms_of_service,
    "advancedauth_inline_dua": advancedauth_inline_dua,
    "advancedauth_privacy_policy": advancedauth_privacy_policy,
    "advancedauth_privacy_policy_label": advancedauth_privacy_policy_label,
    "advancedauth_must_view_privacy_policy": advancedauth_must_view_privacy_policy,
    "advancedauth_inline_privacy_policy": advancedauth_inline_privacy_policy,
    "advancedauth_require_fullname": advancedauth_require_fullname,
    "advancedauth_turnstile_sitekey": advancedauth_turnstile_sitekey,
}
