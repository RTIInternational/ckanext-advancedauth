# -*- coding: utf-8 -*-
import click
from ckanext.advancedauth.command import reset_all_users_passwords, reset_user_password


@click.group()
def advancedauth():
    """advancedauth commands
    Usage:
            advancedauth reset-password <username>

                    Sets flag for user to reset password upon their next login
                    'all' can optionally be used in place of username to set flag for all users
    """
    pass


@advancedauth.command()
@click.argument("username")
def reset_password(username):
    """
    advancedauth reset_password <username>
    """
    if not username:
        print('Setting all non-admin users to reset their password upon next login')
        reset_all_users_passwords()
    else:
        print("Setting user {} to reset their password upon next login".format(username))
        reset_user_password(username)


def get_commands():
    return [advancedauth]
