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

import bcrypt
from datetime import datetime
from flask_restful import Resource
from flask import current_app, request, make_response, redirect
import json
from os import urandom
import pymysql
from .utilties import build_auth_token, json_validate


class AuthenticateUser(Resource):
    def get(self):
        #  Render a Login Page
        pass

    def post(self):
        #   Authenticate the provided credentials, respond with cookie and redirect to home.
        json_data = request.get_json(force=True)
        dict_schema = {
            "uid": "",
            "password": ""
        }
        if not json_data:  # Obviously we need some kind of data in the post.
            return {'message': 'No data provided'}, 400
        json_valid, json_errors = json_validate(json_data, dict_schema)
        if not json_valid:  # Has to be the right kind of data as well.
            return {'message': "errors in request body"}.update({"errors": json_errors}), 400
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
        cur = connection.cursor()
        username = json_data["uid"]
        cur.execute("SELECT * FROM users WHERE username=%s", username)
        dict_user = cur.fetchone()

        pwd = json_data["password"].encode('utf9')
        if not bcrypt.checkpw(pwd, dict_user["passwd"]):
            return {'error': "Unauthorized"}, 403

        ttl = int(current_app.config["USER_TTL"])*60
        key = urandom(64)  # HMAC SHA256 uses 64-byte keys
        issuer = current_app.config["NETWORK_LABEL"]
        uid = dict_user["user_id"]
        aud = "user"
        token, expiry = build_auth_token(ttl, key, uid, issuer, aud)
        cmd = "UPDATE users SET bearer_token_key=%s, bearer_token_expiry=%s WHERE user_id=%s"
        cur.execute(cmd, (key, expiry, uid))
        connection.commit()
        connection.close()
        resp = make_response(redirect('/home'))  # Kick these kids back out to home.
        resp.set_cookie('auth', token)  # Give them their token though.
        return resp
