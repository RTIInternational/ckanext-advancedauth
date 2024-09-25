# encoding: utf-8

import requests

from ckan.common import config
from ckan.types import Request


def check_captcha(request: Request) -> None:
    """Check a user\'s recaptcha submission is valid, and raise CaptchaError
    on failure."""
    turnstile_secret_key = config.get("ckanext.advancedauth.turnstile_secretkey")
    if not turnstile_secret_key:
        return

    client_ip_address = request.environ.get("REMOTE_ADDR", "Unknown IP Address")
    client_token = request.form.get("cf-turnstile-response", "")
    siteverify_endpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

    params = dict(
        secret=turnstile_secret_key,
        response=client_token,
        remoteip=client_ip_address,
    )

    timeout = config.get("ckan.requests.timeout")
    response = requests.post(siteverify_endpoint, params, timeout=timeout)

    data = response.json()

    try:
        if not data["success"]:
            raise CaptchaError()
    except IndexError:
        # Something weird with recaptcha response
        raise CaptchaError()


class CaptchaError(ValueError):
    pass
