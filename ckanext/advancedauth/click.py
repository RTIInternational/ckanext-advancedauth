# -*- coding: utf-8 -*-
import click
from ckanext.advancedauth.command import reset_all_users_passwords, reset_user_password


@click.group()
def advancedauth():
    """advancedauth commands
    Usage:
            advancedauth reset_password --username=<username> to set flag for a specific user
            advancedauth reset_password to reset passwords for all non-admin users.
    """
    pass


@advancedauth.command()
@click.option("--username", default=None, help="Username of user to reset password")
def reset_password(username):
    """
    advancedauth reset_password <username>
    """
    if username is None:
        print("Setting all non-admin users to reset their password upon next login")
        reset_all_users_passwords()
    else:
        print(
            "Setting user {} to reset their password upon next login".format(username)
        )
        reset_user_password(username)


def get_commands():
    return [advancedauth]
