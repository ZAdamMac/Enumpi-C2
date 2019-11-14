"""
This script is a component of the Enumpi Project's back-end controller.
This resource handles the retrieval of fresh client Device Codes, using those
to prepare bearer and refresh tokens, and using refresh tokens to renew expired
bearer tokens.

Author: Zac Adam-MacEwen (zadammac@kenshosec.com)
A Kensho Security Labs utility.

Produced under license.
Full license and documentation to be found at:
https://github.com/ZAdamMac/Enumpi-C2
"""

import bcrypt
import datetime
from flask_restful import Resource
from flask import current_app, request, make_response
from os import urandom
import pymysql
import uuid
from .utilties import authenticated_exec, build_auth_token, json_validate, token_validate

__version__ = "prototype"


class AuthenticateClient(Resource):
    def get(self):
        """An authenticated user with client-grant permissions may retrieve a
        fresh device code for a client, with a configurable TTL. If this action
        is taken for a device where the device code already exists, this
        creates a new device code. If the client ID cannot be found in the
        grants table, it fails overall.

        :return: In the valid case, a json dictionary of (row, action) pairs
        """
        # FUTURE add query scoping.
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
            body = request.get_json()
            dict_return = authenticated_exec(token_user, "can_grant", connection,
                                             client_auth_get, body)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

    def post(self):
        """The post method accepts a JSON object as shown below and responds
        with a bearer token (following the global TTL) and refresh token
        following the client-specific TTL, in a JSON body response.

        {
            "clientId":"string",
            "deviceCode": "string
        }

        :return:
        """
        # Add a new user, if authenticated.
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

        # authenticate a device code/client ID pair (much like user auth)
        proceed, client_id, b_ttl = authenticate_device_code(request.get_json(), connection)

        if proceed:
            iss = current_app.config["NETWORK_LABEL"]
            aud = "client"
            a_ttl = int(current_app.config["CLIENT_TTL"])
            a_key = urandom(64)
            b_key = urandom(64)
            bearer, bearer_expiry = build_auth_token(a_ttl, a_key, client_id, iss, aud)
            refresh, refresh_expiry = build_auth_token(b_ttl, b_key, client_id, iss, aud)
            response = {"bearer": bearer, "bearerExpiry": bearer_expiry,
                        "refresh": refresh, "refreshExpiry": refresh_expiry}
            cur = connection.cursor()
            cmd = "UPDATE client_grants " \
                  "SET bearer_token_key=%(bearer)s, bearer_token_expiry=FROM_UNIXTIME(%(bearerExpiry)s), " \
                  "refresh_token_key=%(refresh)s, refresh_token_expiry=FROM_UNIXTIME(%(refreshExpiry)s) " \
                  "WHERE client_id=%(client_id)s"
            args = {"bearer": a_key, "bearerExpiry": bearer_expiry,
                    "refresh": b_key, "refreshExpiry": refresh_expiry,
                    "client_id": client_id}
            cur.execute(cmd, args)
            connection.commit()
            connection.close()
        else:
            response = {"error": 403, "message": "Unauthorized"}

        return response

    def patch(self):
        """The patch method expects a refresh token in the authorization header
        and sends back a corresponding bearer token.

        :return:
        """
        # edit an existing user, if authenticated.
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

        client_id, new_token = token_validate(cookie, ttl, connection, urandom(64), iss, "client", "refresh")
        if client_id:
            resp = make_response({"message": "Ok"})
            resp.set_cookie("auth", new_token)
            resp.status_code = 200
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

    def delete(self):
        """Allows an authenticated user to invalidate the refresh token for a
        given client, disabling it until the next time it's handshaked off.

        :return:
        """
        # deactivate (set permissions 0) a user if authenticated.
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
            body = request.get_json()
            dict_return = authenticated_exec(token_user, "can_grant", connection,
                                             client_management_delete, body)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

# Here follow the actual actions!


def client_auth_get(body, connection):
    """Uses a three-way join to get clients expressed in the dictionaries we
    would expect to see them in in the JSON output, then quickly turns that
    response into a keyed dictionary of its own for transport.

    :param body:
    :param connection:
    :return:
    """
    cur = connection.cursor()
    client_id = body["clientId"]
    device_id = str(uuid.uuid4())
    print(device_id)
    device_code = bcrypt.hashpw(device_id.encode('utf-8'), bcrypt.gensalt())
    ttl = int(current_app.config["CLIENT_TTL"]) * 60
    expiry = (datetime.datetime.now() + datetime.timedelta(minutes=ttl)).timestamp()
    cmd = "UPDATE client_grants " \
          "SET device_code=%(device_code)s, " \
          "device_code_expiry=FROM_UNIXTIME(%(device_code_expiry)s) " \
          "WHERE client_id=%(client_id)s"
    args = {"device_code": device_code, "device_code_expiry": expiry, "client_id": client_id}
    cur.execute(cmd, args)
    response = {"clientId": client_id, "deviceCode": device_id}
    response.update({"error": 200})

    return response


def authenticate_device_code(body, conn):
    """Accepts a Client ID and Device Code in JSON format and authenticates
    them against the database. If valid, returns a tuple (true, client_id,
    refresh_ttl). If invalid, returns the tuple (False, None, None).

    :param body: The body of the client response - expects a JSON object
    :param conn: A pymsql DB connection
    :return:
    """

    dict_schema = {"clientId": "string", "deviceCode": "string"}
    proceed, errors = json_validate(body, dict_schema)

    if proceed:
        client_id = body["clientId"]
        cur = conn.cursor()
        cmd = "SELECT client_id, device_code, device_code_expiry, refresh_token_expiry " \
              "FROM client_grants " \
              "WHERE client_id LIKE %s"
        cur.execute(cmd, client_id)
        # There should only ever be one response
        dict_client = cur.fetchone()
        if dict_client:
            expiry = dict_client["device_code_expiry"]
            if datetime.datetime.now() < expiry:  # Token is not expired
                device_code = body["deviceCode"].encode("utf8")  # Because bcrypt is fussy
                device_code_hash = dict_client["device_code"]
                if bcrypt.checkpw(device_code, device_code_hash):
                    # All checks out and we can create a token. Just need to get the refresh token expiry ttl
                    print(dict_client["refresh_token_expiry"])
                    refresh_ttl = ((datetime.datetime.strptime(str(dict_client["refresh_token_expiry"]), '%Y-%m-%d %H:%M:%S') -
                                   datetime.datetime.now()).total_seconds()/60)
                    return True, client_id, refresh_ttl
                else:
                    return False, None, None
            else:
                return False, None, None

        else:
            return False, None, None


def client_management_delete(body, connection):
    """expects a json object with "clientId" as its only key.

    :param body: A dict created from a json object, nominally the body of the request.
    :param connection: The DB connection to be used.
    :return:
    """
    cur = connection.cursor()
    client_id = body["clientId"]
    cmd = "SELECT client_id FROM client_grants WHERE client_id=%s"
    cur.execute(cmd, client_id)
    ret = cur.fetchmany()
    if len(ret) != 0:
        cmd = "UPDATE client_grants SET refresh_token_key=0, bearer_token_key=0 WHERE client_id=%s"
        cur.execute(cmd, client_id)
        return {"error": 200}
    else:
        return {"error": 400, "msg": "Client ID not found on the grants table"}
