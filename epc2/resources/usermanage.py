"""
This script is a component of the Enumpi Project's back-end controller.
This resource handles various user-management tasks, such as returning
a list of users, adding or updating a user, and removing user access.

Author: Zac Adam-MacEwen (zadammac@kenshosec.com)
A Kensho Security Labs utility.

Produced under license.
Full license and documentation to be found at:
https://github.com/ZAdamMac/Enumpi-C2
"""

import bcrypt
from datetime import datetime
from flask_restful import Resource
from flask import current_app, request, make_response, redirect, render_template
import json
from os import urandom
import pymysql
from .utilties import build_auth_token, json_validate


class AuthenticateUser(Resource):
    def get(self):
        # Return the list of users, if authenticated.
        pass

    def post(self):
        # Add a new user, if authenticated.
        pass

    def patch(self):
        # edit an existing user, if authenticated.
        pass

    def delete(self):
        # deactivate (set permissions 0) a user if authenticated.
        pass
