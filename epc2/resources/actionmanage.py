"""
This script is a component of the Enumpi Project's back-end controller.
This resource handles the registration of new actions, listing of available
actions, deletion of actions, and their modification.

Author: Zac Adam-MacEwen (zadammac@kenshosec.com)
A Kensho Security Labs utility.

Produced under license.
Full license and documentation to be found at:
https://github.com/ZAdamMac/Enumpi-C2
"""

from flask_restful import Resource
from flask import current_app, request, make_response
import json
from os import urandom
import pymysql
import uuid
from .utilties import authenticated_exec, json_validate, token_validate

__version__ = "prototype"


class ManageAction(Resource):
    def get(self):
        """An authenticated user with reporting permissions may retrieve a
        full listing of all actions set up on the server.

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
                                             action_management_get, None)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

    def post(self):
        """The post method allows the creation of a new action using the
        following model json object. All fields required.

        {
        "action": "string",
        "description": "string",
        "dummyCommand": {}
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
            dict_return = authenticated_exec(token_user, "can_command", connection,
                                             action_management_post, body)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

    def patch(self):
        """The post method allows the modification of an existing user, using
         a provided JSON data set. Only userId is required.

        {
        "actionId": "string",
        "action": "string",
        "description": "string",
        "dummyCommand": {}
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
            dict_return = authenticated_exec(token_user, "can_command", connection,
                                             action_management_patch, body)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

    def delete(self):
        """accepts a json object containing an action ID to be retired, and
        deletes it from the DB.

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
            dict_return = authenticated_exec(token_user, "can_command", connection,
                                             action_management_delete, body)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

# Here follow the actual actions!


def action_management_get(body, connection):
    """A very simplistic function that gets all of the actions in the action
    table, then dumps them into a json object suitable for modification/display"""
    cur = connection.cursor()
    del body
    cmd = "SELECT * FROM actions"
    cur.execute(cmd)
    actions = cur.fetchall()
    response = {}
    counter = -1
    for action in actions:
        counter += 1
        this_action = {"actionId": action["action_id"],  # need to switch between naming
                       "description": action["description"],  # conventions :/
                       "action": action["action"],
                       "dummyCommand": action["dummy_command"]}
        response.update({counter: this_action})
    response.update({"error": 200})

    return response


def action_management_post(body, connection):
    """A very simplistic function that adds a fresh action to the actions table."""
    cur = connection.cursor()
    dict_schema = {"action": "", "description": "", "dummyCommand": {}}
    json_valid, errors = json_validate(body, dict_schema)

    if json_valid:
        action_id = str(uuid.uuid4())
        dummy_command = json.dumps(body["dummyCommand"])
        d_action = {"action_id": action_id, "dummy_command": dummy_command,
                    "description": body["description"], "action": body["action"]}
        cmd = """INSERT INTO actions
                 (action_id, action, description, dummy_command)
                 VALUES (%(action_id)s, %(action)s, %(description)s, %(dummy_command)s)"""
        cur.execute(cmd, d_action)
        response = {"action_id": action_id, "error": 200}
    else:
        response = {"all_errors": errors, "error": 400}

    return response


def action_management_patch(body, connection):
    """A very simplistic function that modifies an existing action."""
    cur = connection.cursor()
    dict_schema = {"actionId": "", "action": "", "description": "", "dummyCommand": {}}
    json_valid, errors = json_validate(body, dict_schema)

    if json_valid:
        dummy_command = json.dumps(body["dummyCommand"])
        d_action = {"action_id": body["actionId"], "dummy_command": dummy_command,
                    "description": body["description"], "action": body["action"]}
        cmd = """UPDATE actions 
        SET action=%(action)s, description=%(description)s, dummy_command=%(dummy_command)s 
        WHERE action_id=%(action_id)s"""
        cur.execute(cmd, d_action)
        response = {"edited_action_id": body["actionId"], "error": 200}
    else:
        response = {"all_errors": errors, "error": 400}

    return response


def action_management_delete(body, connection):
    """A very simplistic function that drops a single action from the table."""
    cur = connection.cursor()
    dict_schema = {"actionId": ""}
    json_valid, errors = json_validate(body, dict_schema)

    if json_valid:
        action_id = body["actionId"]
        cmd = """DELETE FROM actions WHERE action_id=%s"""
        cur.execute(cmd, action_id)
        response = {"deleted_action_id": action_id, "error": 200}
    else:
        response = {"all_errors": errors, "error": 400}

    return response
