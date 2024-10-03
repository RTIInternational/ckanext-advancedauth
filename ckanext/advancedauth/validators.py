from ckan.plugins.toolkit import Invalid


# Raise error if uploaded file does not include an extension, or the extension is not allowed.
def not_empty_string(key, flattened_data, errors, context):
    value = flattened_data.get(key, "")
    if not value or value.strip() == "":
        raise Invalid("Field cannot be blank or consist of only spaces.")


def confirm_email(key, flattened_data, errors, context):
    email = flattened_data.get(key, "")
    extras = flattened_data.get(("__extras",), {})
    confirm_email = extras.get("email-confirm", "")

    if email != confirm_email:
        raise Invalid("Emails do not match.")


# published to the plugin
def get_validators():
    return {
        "not_empty_string": not_empty_string,
        "confirm_email": confirm_email,
    }
