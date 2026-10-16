from pathlib import Path


def test_edit_user_form_includes_password_fields_for_ckan_edit_post():
    template_path = (
        Path(__file__).resolve().parent.parent
        / "templates"
        / "user"
        / "edit_user_form.html"
    )
    template = template_path.read_text(encoding="utf-8")

    assert 'name="password1"' in template
    assert 'name="password2"' in template
