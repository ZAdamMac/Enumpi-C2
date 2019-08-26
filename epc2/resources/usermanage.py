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
from .utilties import build_auth_token, json_validate, token_validate, UserModel


class ManageUser(Resource):
    def get(self):
        cookie = request.cookies["auth"]
        ttl = int(current_app.config["USER_TTL"])*60
        iss = current_app.config["NETWORK_LABEL"]
        try:
            connection = pymysql.connect(host=current_app.config["DBHOST"],
                                         user=current_app.config["USERNAME"],
                                         password=current_app.config["PASSPHRASE"],
                                         db='enumpi',
                                         charset='utf8mb4',
                                         cursorclass=pymysql.cursors.DictCursor)
            connection.ping(reconnect=True)
        except KeyError:
            return {'message': 'Internal Server Error'}, 500
        except pymysql.Error:
            return {'message': 'Internal Server Error'}, 500
        token_user, new_token = token_validate(cookie, ttl, connection,
                                               urandom(64), iss, "user",
                                               "bearer")
        if token_user:
            # First we need to know who's asking.
            cur = connection.cursor()
            requestor = UserModel()
            cmd = "SELECT * FROM users WHERE user_id=%s"
            cur.execute(cmd, token_user)
            d_user = cur.fetchone()
            requestor.from_dict(d_user)

            # And of course, if they're allowed to do that.
            if requestor.can_report:
                array_response = {}
                cmd = "SELECT * FROM users"
                cur.execute(cmd)
                l_results = cur.fetchall()
                row_number = 0

                for each in l_results:
                    row_number += 1
                    user = UserModel()
                    user.from_dict(each)
                    array_response.update({row_number: user.dump_json(False)})

                resp = make_response(array_response)
                resp.set_cookie("auth", new_token)
                resp.status_code = 200
                resp.content_type = "application/json"
                return resp
            else:
                return {'message': 'Insufficient Permissions.'}, 403

        else:
            return {'message': 'unauthorized'}, 403

    def post(self):
        # Add a new user, if authenticated.
        pass

    def patch(self):
        # edit an existing user, if authenticated.
        pass

    def delete(self):
        # deactivate (set permissions 0) a user if authenticated.
        pass
