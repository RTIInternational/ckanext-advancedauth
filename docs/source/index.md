[ckanext-advancedauth documentation master file]: <> (This is a comment, it will not be included)

# ckanext-advancedauth


```{toctree}
---
maxdepth: 2
---

```

[GitHub](https://github.com/RTIInternational/ckanext-advancedauth)


This CKAN extension provides a number of enhancements on top of CKAN's existing authentication system.

## Requirements

This plugin is compatible with CKAN 2.9 or later.

## Installation

```
pip install -e "git+https://github.com/RTIInternational/ckanext-advancedauth.git#egg=ckanext-advancedauth"
```

## Features

Enable the features you want to use with configuration options.

- [Only allow authenticated users](#only-allow-authenticated-users)
- [Additional user metadata](#additional-user-metadata)
- [New user email](#new-user-email)
- [Terms of Service / Privacy Policy](#terms-of-service-privacy-policy)


### Only allow authenticated users

By default, unauthenticated users are allowed to use most CKAN actions. This feature only allows specific actions (`action_allowlist`) and blocks all others.

```
ckanext.advancedauth.disallow_anonymous_access = true
ckanext.advancedauth.action_allowlist = request_reset user_reset site_read user_create package_search organization_list_for_user package_create sysadmin
ckanext.advancedauth.disallow_public_datasets = true
```
### Only allow approved users
By enabling this feature, users who do not belong to organizations will not be allowed access to basic site functionality and will instead receive an error message of your choosing. This feature allows administrators to enable self-registration, but only allow access once "approved" by adding users to an organization.

```
ckanext.advancedauth.only_approved_users = true
"ckanext.advancedauth.only_approved_users_message = <your message here>
```

### Disallow edits except for author
By default, CKAN allows all users with the "editor" role in an organization to edit datasets. By enabling this feature, only administrators and the original author of a given dataset will be able to edit.

```
ckanext.advancedauth.only_authors_can_edit = true
```
### Additional user metadata

Define a schema of additional fields to add to the user.

```
ckanext.advancedauth.modify_user_schema = true
ckanext.advancedauth.user_schema_location = ckanext.mypackage.schema:user_schema.json
```

The schema json file will add the new user metadata to user registration, update, and view. Each field should be defined as such:

```
"key": {
    "label": String, human-readable label,
    "input": String, Which input to render on forms, choose from text, textarea, checkbox,
    "placeholder": String, optional, placeholder for form inputs,
    "required": Boolean, defaults to false if undefined. Whether to validate and require this field,
    "private": Boolean, defaults to false if undefined. If true, will only be visible to that user and sysadmins on read,
    "additional_validators": Array of strings, optional, additional validators to add to this field via `toolkit.get_validator()`,
    "order": int, optional, for ordering these fields in forms/display because Python dictionaries and json are inherently unordered
}
```

### New user email

This feature leverages the `mailer` functionality in CKAN, so it will not function without [email settings](https://docs.ckan.org/en/2.9/maintaining/configuration.html#email-settings) configured.

Email new users

```
ckanext.advancedauth.welcome_email = True
ckanext.advancedauth.welcome_email_subject = Welcome to my CKAN site
ckanext.advancedauth.welcome_email_text = Thanks for joining my CKAN site.
```

Email admin when new user joins the site

```
ckanext.advancedauth.user_create_email = True
ckanext.advancedauth.user_create_email_recipient_email = admin@email.com
ckanext.advancedauth.user_create_email_recipient_name = Admin
```

### Validation
The current iteration of CKAN (`2.9.3`) does not provide validation in the event of a user's email consisting of only whitespace (" "). This feature intercepts the CKAN action when a user registers or resets their password and adds the custom `not_empty_string` validator in addition to the CKAN `email_validator`. This plugin also adds the `not_empty_string` validator to any custom schema fields that have `required` set to `true`.

### Terms of Service / Privacy Policy

Add a terms of service/data use agreement to your registration page. By enabling this option and providing a terms of service, users will be required to agree to a terms of service on the registration form.

Providing a filename for a terms of service file will force a user to check a box agreeing to terms of service, and will provide a link to downloading that file (which you can publish in a different plugin). Additionally, this adds a `advancedauth_terms_of_service` template block as well as a `advancedauth_disclaimer` block for you to add inline readable views/disclaimers in a separate plugin.

Additionally, providing a `terms_of_service_label` will use that term instead of `Terms Of Service`. For example, you may want to call this "Data Use Agreement" or "User Agreement".

Specifying `advancedauth_must_view_terms_of_service` as `true` will force the user to view/download the Terms of Service file before being allowed to click the submit button.

```
ckanext.advancedauth.terms_of_service_filename = files/TermsOfUse_26jan2021.pdf
ckanext.advancedauth.must_view_terms_of_service = True
ckanext.advancedauth.terms_of_service_label = Terms of Use
ckanext.advancedauth.inline_dua = user/snippets/inline_terms_of_use.html

ckanext.advancedauth.privacy_policy_filename = files/Privacy_Policy_09aug2021.pdf
ckanext.advancedauth.must_view_privacy_policy = True
ckanext.advancedauth.privacy_policy_label = Privacy Policy
ckanext.advancedauth.inline_privacy_policy = user/snippets/inline_privacy_policy.html
```
