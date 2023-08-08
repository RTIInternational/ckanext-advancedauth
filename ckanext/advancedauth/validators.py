from ckan.plugins.toolkit import Invalid


# Raise error if uploaded file does not include an extension, or the extension is not allowed.
def not_empty_string(key, flattened_data, errors, context):
    value = flattened_data.get(key, "")
    if not value or value.strip() == "":
        raise Invalid("Field cannot be blank or consist of only spaces.")


# published to the plugin
def get_validators():
    return {
        "not_empty_string": not_empty_string,
    }
