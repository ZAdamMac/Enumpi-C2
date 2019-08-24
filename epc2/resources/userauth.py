"""
This script is a component of the Enumpi Project's back-end controller.
This resource handles authentication of users against the controller front-end,
providing a session token that can be used to authenticate other requests.

Author: Zac Adam-MacEwen (zadammac@kenshosec.com)
A Kensho Security Labs utility.

Produced under license.
Full license and documentation to be found at:
https://github.com/ZAdamMac/Enumpi-C2
"""

from datetime import datetime
from flask_restful import Resource
from flask import current_app, request, jsonify
import json
import pymysql


class AuthenticateUser(Resource):
    def get(self):
        #  Render a Login Page
        pass

    def post(self):
        #   Authenticate the provided credentials, respond with cookie and redirect to home.
        json_data = request.get_json(force=True)
        if not json_data:
            return {'message': 'No data provided'}, 400
        # validate JSON arguments that are expected are present
        # validate the user
        # generate and store the bearer key, token, and expiry.
        # set bearer token as header.
        # redirect to home.

        pass
