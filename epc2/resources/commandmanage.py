"""
This script is a component of the Enumpi Project's back-end controller.
This resource handles the registration of registration, display, and
management of commands by appropriately-authenticated users.

Author: Zac Adam-MacEwen (zadammac@kenshosec.com)
A Kensho Security Labs utility.

Produced under license.
Full license and documentation to be found at:
https://github.com/ZAdamMac/Enumpi-C2
"""

import datetime
from flask_restful import Resource
from flask import current_app, request, make_response
import json
from os import urandom
import pymysql
import uuid
from .utilties import authenticated_exec, json_validate, token_validate

__version__ = "prototype"


class ManageCommand(Resource):
    def get(self):
        """An authenticated user with reporting permissions may retrieve a
        full listing of all commands logged by the server set up on the server.

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
                                             command_management_get, None)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

    def post(self):
        """The post method allows the registration of a new command using the
        following model json object. All fields required.

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
            body.update({"userId": token_user})  # We need to insert this value into the argument.
            dict_return = authenticated_exec(token_user, "can_command", connection,
                                             command_management_post, body)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

    def delete(self):
        """This will mark a specified command as though it were acknowledged,
        preveventing it from being executed. A message is also registered,
        indicating that the job was never executed.

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
            body.update({"userId": token_user})  # We need to insert this value into the argument.
            dict_return = authenticated_exec(token_user, "can_command", connection,
                                             command_management_delete, body)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

# Here follow the actual actions!


def command_management_get(body, connection):
    """A stored join function that gets all the currently registered commands,
    their relevant metadata, the name of the client they are associated with
    and the message, if any. This is returned to the requestor in a JSON
    format for further processing."""
    cur = connection.cursor()
    del body

    # Unwieldy command handles most of the data processing in SQL which is faster than doing this in python.

    cmd = "SELECT c.command_id, c.command as command_type, p.common_name as target_device, " \
          "u.username as issued_by, c.json_cmd as command_body, c.period, c.time_next, c.time_logged, " \
          "c.time_sent, c.time_acknowledged, m.body as msg_body " \
          "FROM commands c " \
          "LEFT JOIN clients p ON c.client_id = p.client_id " \
          "LEFT JOIN users u ON c.user_id = u.user_id " \
          "LEFT JOIN messages m ON c.msg_id = m.msg_id "
    cur.execute(cmd)
    commands = cur.fetchall()
    response = {}
    counter = -1
    for command in commands:
        output_keys = {"command_id": "commandId", "target_device": "targetDevice", "command_type": "commandType",
                       "issued_by": "issuedBy", "command_body": "commandBody", "period": "interval",
                       "time_next": "timeNext", "time_logged": "timeLogged", "time_sent": "timeSent",
                       "time_acknowledged": "timeAck", "msg_body": "message"}
        counter += 1
        this_action = {}
        for key in output_keys.keys():
            this_action.update({output_keys[key]: command[key]})
        response.update({str(counter): this_action})
    response.update({"error": 200})

    return response


def command_management_post(body, connection):
    """A very simplistic function that adds a fresh command to the commands table."""
    cur = connection.cursor()
    dict_schema = {"command": "", "interval": "", "arguments": {}, "firstRun": "",
                   "clientId": "", "userId": ""}
    json_valid, errors = json_validate(body, dict_schema)

    if json_valid:
        d_action = {}
        d_action.update({"command_id": str(uuid.uuid4())})
        json_cmd = json.dumps(body["arguments"])
        d_action.update({"json_cmd": json_cmd})
        d_action.update({"time_next": datetime.datetime.strptime(body["firstRun"], "%Y-%m-%dT%H:%M:%SZ").timestamp()})
        d_action.update(body)
        cmd = "INSERT INTO commands (command_id, client_id, user_id, command, json_cmd, period, time_next) " \
              "VALUES (%(command_id)s, %(clientId)s, %(userId)s, %(command)s, " \
              "%(json_cmd)s, %(interval)s, FROM_UNIXTIME(%(time_next)s))"
        cur.execute(cmd, d_action)
        response = {"error": 200}
    else:
        response = {"all_errors": errors, "error": 400}

    return response


def command_management_delete(body, connection):
    """This function removes a command from execution by marking it as
    acknowledged, setting a message to the appropriate effect as well."""
    cur = connection.cursor()
    dict_schema = {"commandId": "", "userId": ""}
    json_valid, errors = json_validate(body, dict_schema)

    if json_valid:
        d_args = {}
        d_args.update({"command_id": body["commandId"]})
        d_args.update({"now": datetime.datetime.now().timestamp()})
        d_args.update({"msg_id": str(uuid.uuid4())})
        d_args.update({"body": ("Command deleted before execution by userID: %s" % body["userId"])})
        # First, make sure this hasn't already been executed.
        cmd = "SELECT time_acknowledged " \
              "FROM commands " \
              "WHERE command_id=%s"
        cur.execute(cmd, d_args["command_id"])
        response = cur.fetchone()
        # Gotta be a better way to do the following line, but...
        if response["time_acknowledged"] != datetime.datetime.fromtimestamp(0):
            cmd = "INSERT INTO messages " \
                  "(msg_id, body, time)" \
                  "VALUES (%(msg_id)s, %(body)s, FROM_UNIXTIME(%(now)s))"
            cur.execute(cmd, d_args)
            cmd = "UPDATE commands " \
                  "SET time_acknowledged=FROM_UNIXTIME(%(now)s), time_next=time_next " \
                  "WHERE command_id=%(command_id)s"
            cur.execute(cmd, d_args)
            response = {"error": 200}
        else:
            response = {"error": 400, "message": "Could not delete command - already acknowledged."}
    else:
        response = {"all_errors": errors, "error": 400}

    return response
