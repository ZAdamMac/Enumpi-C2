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
import uuid
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
                connection.close()
                return resp
            else:
                return {'message': 'Insufficient Permissions.'}, 403

        else:
            return {'message': 'unauthorized'}, 403

    def post(self):
        # Add a new user, if authenticated.
        cookie = request.cookies["auth"]
        ttl = int(current_app.config["USER_TTL"]) * 60
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
            if requestor.can_users:
                # Let's validate the request body
                dict_schema = {
                               "username": "",
                               "firstName": "",
                                "lastName": "",
                                "email": "",
                                "newPwd": "",
                                "forceResetPwd": True,
                                "permissions": {"active": True,
                                                "useReportingApi": True,
                                                "canIssueCommands": True,
                                                "canModifyClients": True,
                                                "isUserAdmin": True
                                                }
                              }
                d_json = request.get_json()
                json_valid, errors = json_validate(d_json, dict_schema)
                if json_valid:
                    cur = connection.cursor()
                    cur.execute("SELECT username FROM users WHERE username=%s", d_json["username"])
                    result = cur.fetchall()
                    if len(result) >0:
                        is_unique_user = False
                    else:
                        is_unique_user = True
                else:
                    is_unique_user = False

                if json_valid and is_unique_user:
                    # Let's add this user to the DB!
                    new_user = UserModel()
                    d_json = request.get_json()
                    d_json.update({"userId": str(uuid.uuid4())})  # We know this to be a new user.
                    new_user.from_json(d_json)
                    d_user = new_user.dump_dict()
                    cmd = """INSERT INTO users 
                            (user_id, username, fname, lname, 
                            email, passwd, pw_reset, access)
                            VALUES (%(user_id)s, %(username)s, %(fname)s, %(lname)s,
                            %(email)s, %(passwd)s, %(pw_reset)s, %(access)s)"""
                    cur.execute(cmd, d_user)
                    connection.commit()
                    connection.close()
                    resp = make_response({'created user': d_user["username"]})
                    resp.set_cookie("auth", new_token)
                    resp.status_code = 200
                    resp.content_type = "application/json"
                elif is_unique_user:
                    resp = make_response({'message': "errors in request body"}.update({"errors": errors}))
                    resp.status_code = 400
                    resp.set_cookie("auth", new_token)
                else:
                    resp = make_response({'message': "user is not unique."})
                    resp.status_code = 400
                    resp.set_cookie("auth", new_token)
            else:
                resp = make_response({'message': 'Insufficient Permissions'})
                resp.status_code = 403
                resp.set_cookie("auth", new_token)
            return resp
        else:
            return {'message': 'unauthorized'}, 403

    def patch(self):
        # edit an existing user, if authenticated.
        pass

    def delete(self):
        # deactivate (set permissions 0) a user if authenticated.
        pass
