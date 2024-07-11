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
@click.option(
    "--all", is_flag=True, help="Include sysadmins in password reset requirement"
)
def reset_password(username, all=False):
    """
    advancedauth reset_password <username>
    """
    if username is None:
        if all:
            print("Setting all users to reset their password upon next login")
        else:
            print("Setting all non-admin users to reset their password upon next login")
        reset_all_users_passwords(all)
    else:
        print(
            "Setting user {} to reset their password upon next login".format(username)
        )
        reset_user_password(username)


def get_commands():
    return [advancedauth]
