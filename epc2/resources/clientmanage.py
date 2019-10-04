"""
This script is a component of the Enumpi Project's back-end controller.
This resource handles the registration of new clients, modification of their
credentials, and remote retirement of clients.

Author: Zac Adam-MacEwen (zadammac@kenshosec.com)
A Kensho Security Labs utility.

Produced under license.
Full license and documentation to be found at:
https://github.com/ZAdamMac/Enumpi-C2
"""

import dateutil.parser as dateparser
from flask_restful import Resource
from flask import current_app, request, make_response
from os import urandom
import pymysql
import uuid
from .utilties import authenticated_exec, json_validate, token_validate

__version__ = "prototype"


class ManageClient(Resource):
    def get(self):
        """An authenticated user with reporting permissions may retrieve a
        full listing of all actions set up on the server. Only requires
        User.can_command as a user issuing commands would need this listing.

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
            dict_return = authenticated_exec(token_user, "can_report", connection,
                                             client_management_get, None)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

    def post(self):
        """The post method allows the creation of a new action using the
        following model json object. All fields required. Requires the user
        have the "can_grant" permission.

        {
            "clientName": "string",
            "description": "string",
            "location": "strint",
            "expiry": "ISO 8601 Timestamp"
        }

        :return:
        """
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
            body = request.get_json()
            body.update({"userId": token_user})
            dict_return = authenticated_exec(token_user, "can_grant", connection,
                                             client_management_post, body)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

    def patch(self):
        """The post method allows the modification of an existing client, using
         a provided JSON data set. Only clientId is required. This requires
         User.can_grant permissions as it can modify the overall TTL of the
         client.

        {
        "clientId": "string",
        "location": "string",
        "description": "string",
        "clientName": "string",
        "refreshExpy": "ISO 8601 Timestamp"
        }
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
        token_user, new_token = token_validate(cookie, ttl, connection,
                                               urandom(64), iss, "user",
                                               "bearer")
        if token_user:
            body = request.get_json()
            dict_return = authenticated_exec(token_user, "can_grant", connection,
                                             client_management_patch, body)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

    def delete(self):
        """accepts a json object containing an client ID to be retired, and
        deletes it from the grants table. The client will continue to appear
        as a listing from this class's GET method, but cannot authenticate
        to the C2 - it is simply retained for Hysterical Reasons.

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


def client_management_get(body, connection):
    """Uses a three-way join to get clients expressed in the dictionaries we
    would expect to see them in in the JSON output, then quickly turns that
    response into a keyed dictionary of its own for transport.

    :param body:
    :param connection:
    :return:
    """
    cur = connection.cursor()
    del body  # Body is not used
    cmd = "SELECT c.client_id AS cid, c.common_name as name, c.description as description, " \
          "c.placement as location, g.device_code_expiry as dcExpire, g.bearer_token_expiry " \
          "as bearerExpire, g.refresh_token_expiry as refreshExpire, u.username as username " \
          "FROM clients c LEFT JOIN client_grants g on c.client_id = g.client_id JOIN users u ON " \
          "c.user_id = u.user_id;"
    cur.execute(cmd)
    clients = cur.fetchall()
    response = {}
    counter = -1
    for client in clients:
        counter += 1
        response.update({counter: client})
    response.update({"error": 200})

    return response


def client_management_post(body, connection):
    """A very simplistic function that adds a fresh client to the client table,
    as well as the corresponding grants for the client_grants table. The function
    depends on the calling method above adding the token_user value to the dictionary
    passed in as body with the key "userId".
    """
    cur = connection.cursor()
    dict_schema = {"clientName": "", "description": "", "location": "", "expiry": "",
                   "userId": ""}  # this requires adding the user UUID before calling.
    json_valid, errors = json_validate(body, dict_schema)

    if json_valid:
        client_id = str(uuid.uuid4())
        expiry = dateparser.parse(body["expiry"])
        d_action = {"client_id": client_id, "expiry": expiry, "location": body["location"],
                    "description": body["description"], "client_name": body["clientName"],
                    "user_id": body["userId"]}
        cmd = "INSERT INTO clients (client_id, common_name, description, placement, user_id)" \
              " VALUES (%(client_id)s, %(client_name)s, %(description)s, %(location)s," \
              " %(user_id)s)"
        cur.execute(cmd, d_action)
        cmd = "INSERT INTO client_grants (client_id, device_code_expiry, refresh_token_expiry) " \
              "VALUES (%(client_id)s, %(expiry)s, %(expiry)s)"
        cur.execute(cmd, d_action)
        response = {"client_id": client_id, "error": 200}
    else:
        response = {"all_errors": errors, "error": 400}

    return response


def client_management_patch(body, connection):
    """A very simplistic function that modifies an existing client on either table."""
    cur = connection.cursor()
    possible_keys = ["refreshExpy", "name", "description", "placement"]
    if "clientId" not in body.keys():
        json_valid = False
    else:
        json_valid = True
        errors = "Unrecognized Client ID"

    if json_valid:
        for check_key in possible_keys:  # This serves as a key whitelist
            if check_key in body.keys():
                if check_key != "refreshExpy":
                    value = body[check_key]
                    cmd = "UPDATE clients " \
                          "SET {0}=%(value)s " \
                          "WHERE client_id=%(client_id)s".format(check_key)
                    # This cmd variable and its format operation are why we need a
                    # command whitelist. Using format in this way allows us to insert
                    # check_key as the column name - doing it the simpler way (as part
                    # of the args dictionary) escapes the column name and breaks the
                    # statement.
                    args = {"value": value, "client_id": body["clientId"]}
                else:
                    value = dateparser.parse(body[check_key])
                    cmd = "UPDATE client_grants " \
                          "SET refresh_token_expiry=%(value)s " \
                          "WHERE client_id=%(client_id)s"
                    print(cmd)
                    args = {"value": value, "client_id": body["clientId"]}
                cur.execute(cmd, args)
        client_id = body["clientId"]
        response = {"client_id": client_id, "error": 200}
    else:
        response = {"all_errors": errors, "error": 400}

    return response


def client_management_delete(body, connection):
    """A simplistic function that removes the relevant grants for a client,
    rendering it inoperable while causing it to remain in the overall client listing."""
    cur = connection.cursor()
    dict_schema = {"clientId": ""}
    json_valid, errors = json_validate(body, dict_schema)

    if json_valid:
        action_id = body["clientId"]
        cmd = """DELETE FROM client_grants WHERE client_id=%s"""
        cur.execute(cmd, action_id)
        response = {"deleted_client_id": action_id, "error": 200}
    else:
        response = {"all_errors": errors, "error": 400}

    return response
