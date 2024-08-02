import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

from .auth import get_actions_list
from .helpers import helpers
from .logic import actions
from .model import initdb
from .auditdata import audit_table
from .middleware import AdvancedauthMiddleware, AdvancedauthErrorLogMiddleware
from .click import get_commands
from .blueprint import advancedauth_user


class AdvancedauthPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IConfigurable)
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.IAuthFunctions, inherit=True)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IMiddleware)
    plugins.implements(plugins.IClick)

    #######################################################################
    # IBlueprint                                                          #
    # Return a Flask Blueprint object to be registered by the app         #
    #######################################################################
    def get_blueprint(self):
        return [audit_table, advancedauth_user]

    # IConfigurer
    # Adds templates to CKAN
    def update_config(self, config_):
        toolkit.add_template_directory(config_, "templates")
        toolkit.add_public_directory(config_, "public")
        toolkit.add_resource("fanstatic", "advancedauth")

    # IConfigurable
    # runs at startup
    def configure(self, config):
        initdb()

    # IActions
    # defines/redefines actions
    def get_actions(self):
        return actions

    # IAuthFunctions
    # Adds additional authentication functions to actions
    def get_auth_functions(self):
        return get_actions_list()

    # ITemplateHelpers
    # makes functions available in templates
    def get_helpers(self):
        return helpers

    # IMiddleware
    def make_middleware(self, app, config):
        app = AdvancedauthMiddleware(app, config)
        return app

    def make_error_log_middleware(self, app, config):
        app = AdvancedauthErrorLogMiddleware(app)
        return app

    # IClick
    def get_commands(self):
        return get_commands()
