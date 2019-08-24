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
from resources.userauth import AuthenticateUser

__version__ = "prototype"


api_bp = Blueprint('api', __name__)
api = Api(api_bp)

# New Routes below this line
api.add_resource(AuthenticateUser, '/user/auth')