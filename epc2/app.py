"""
This script is a component of the Enumpi Project's back-end controller.
It is the app-defining component of the Flask-based API/UI service.

Author: Zac Adam-MacEwen (zadammac@kenshosec.com)
A Kensho Security Labs utility.

Produced under license.
Full license and documentation to be found at:
https://github.com/ZAdamMac/Enumpi-C2
"""

from flask import Blueprint
from flask_restful import Api
from resources.actionmanage import ManageAction
from resources.clientmanage import ManageClient
from resources.userauth import AuthenticateUser
from resources.usermanage import ManageUser
from resources.clientauth import AuthenticateClient
from resources.commandmanage import ManageCommand
from resources.controller import Controller

__version__ = "prototype"


api_bp = Blueprint('api', __name__)
api = Api(api_bp)

# New Routes below this line
api.add_resource(AuthenticateUser, '/user/auth')
api.add_resource(ManageUser, '/user/manage')
api.add_resource(ManageAction, "/action/manage")
api.add_resource(ManageClient, "/client/manage")
api.add_resource(AuthenticateClient, "/client/auth")
api.add_resource(ManageCommand, "/command/manage")
api.add_resource(Controller, "/client/control")
