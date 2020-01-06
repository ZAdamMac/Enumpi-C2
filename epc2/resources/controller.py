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


class Controller(Resource):
    def get(self):
        """Performs validation of the incoming client authorization token, then
        uses the client_id value extracted from that token as the principal
        argument to command_get(). Also handles a refresh of the bearer token
        and assignment thereof to the response.

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
        token_client, new_token = token_validate(cookie, ttl, connection, urandom(64), iss, "client", "bearer")
        if token_client:
            dict_return = control_get(token_client, connection)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

    def post(self):
        """The post method allows an authenticated client to post a message,
        which is correlated to a specific command in the commands table.
        Message length is limited to a string of 255 or fewer characters -
        larger data transfers should be handled as file transfer operations.

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
        token_client, new_token = token_validate(cookie, ttl, connection,  urandom(64), iss, "client", "bearer")
        if token_client:
            dict_return = control_post(request.get_json(), connection)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

    def patch(self):
        """ A highly simplistic method built out to allow authenticated clients
        to write arbitrary messages to the message table, which are not
        correlated to IDs. Owing to the short message length restriction (255
        characters), this will likely most be used for general error messaging
        or heartbeat implementation.

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
        token_client, new_token = token_validate(cookie, ttl, connection, urandom(64), iss, "client", "bearer")
        if token_client:
            dict_return = control_patch(request.get_json(), connection)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

    def delete(self):
        """Expects a json object with one attribute, "clientIds", which should be
        a list/array of client_id values to acknowledge. This can be used to
        immediately acknowledge long-running commands.
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
        token_client, new_token = token_validate(cookie, ttl, connection, urandom(64), iss, "client", "bearer")
        if token_client:
            dict_return = control_delete(request.get_json(), connection)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403


# Here follow the actual actions!

def control_get(client_id, conn):
    """ A highly simplistic function that runs a single SQL query in order to
    fetch all commands where two conditions are met:
        - The command is targeted for this client's client_id, and;
        - The command has not been correctly acknowledged.

    :param client_id: a client_id value, max 36 characters (usually, a uuid.uuid4() string)
    :param conn: a database connection object that supports the .cursor method.
    :return:
    """
    cur = conn.cursor()
    cmd = "SELECT command_id as commandId, command, json_cmd as args, time_next as runAt " \
          "FROM commands " \
          "WHERE client_id=%s " \
          "AND time_acknowledged NOT LIKE FROM_UNIXTIME(0)"
    cur.execute(cmd, client_id)  # This yields all non-acknowledged commands
    array_all_commands = cur.fetchall()

    if len(array_all_commands) == 0:
        return {"error": 200}
    else:
        dict_all_commands = {}
        counter = -1
        for each in array_all_commands:
            counter += 1
            dict_all_commands.update({str(counter): each})
        dict_all_commands.update({"error": 200})

    return dict_all_commands


def control_post(body, connection):
    """This command executes a few SQL commands to insert a received message
    from the client into the messages table, then correlate that message to
    the relevant command. All times are fetched from the local system for consistency.

    Expects the response body to contain the following:
    {
        "commandId":    A serial identifier for the command, which must match the command found in the commands table.
        "message":      A string of 255 or fewer characters constituting the body of the message.
                        Larger responses should be file-transferred instead.
    }

    :param body: The body of the request, deserialized using request.get_json() from Flask.
    :param connection: A DB connection.
    :return:
    """
    dict_schema = {"commandId": "string", "message": "string"}
    proceed, errors = json_validate(body, dict_schema)

    if proceed:
        cur = connection.cursor()
        body.update({"now": datetime.datetime.now().timestamp()})
        body.update({"msg_id": str(uuid.uuid4())})
        cmd = "INSERT INTO messages " \
              "(msg_id, body, time)" \
              "VALUES (%(msg_id)s, %(message)s, FROM_UNIXTIME(%(now)s))"
        cur.execute(cmd, body)
        cmd = "UPDATE commands " \
              "SET time_acknowledged=time_acknowledged, time_next=time_next, msg_id=%(msg_id)s, time_logged=%(now)s " \
              "WHERE command_id=%(commandId)s"
        cur.execute(cmd, body)
        connection.commit()
        response = {"error":200}
    else:
        response = {"all_errors": errors, "error": 400}

    return response


def control_patch(body, connection):
    """A very simplistic function, expecting a body with the "message"
    attribute, which will be written into the messages table as is.

    :param body: The body of the original request, as returned by flask's request.get_json()
    :param connection: A connection object from pymysql as used throughout this system.
    :return:
    """
    dict_schema = {"message": "string"}
    proceed, errors = json_validate(body, dict_schema)

    if proceed:
        cur = connection.cursor()
        body.update({"now": datetime.datetime.now().timestamp()})
        body.update({"msg_id": str(uuid.uuid4())})
        cmd = "INSERT INTO messages " \
              "(msg_id, body, time)" \
              "VALUES (%(msg_id)s, %(message)s, FROM_UNIXTIME(%(now)s))"
        cur.execute(cmd, body)
        connection.commit()
        response = {"error":200}
    else:
        response = {"all_errors": errors, "error": 400}

    return response


def control_delete(body, connection):
    """Expects a json object with one attribute, "commandIds", which should be
    a list/array of client_id values to acknowledge. This can be used to
    immediately acknowledge long-running commands.

    :param body:
    :param connection:
    :return:
    """
    dict_schema = {"commandIds": []}
    proceed, errors = json_validate(body, dict_schema)
    cur = connection.cursor()

    if proceed:
        for command_id in body["commandIds"]:
            now = datetime.datetime.now().timestamp()
            cmd = "UPDATE commands " \
                  "SET time_acknowledged=FROM_UNIXTIME(%s), time_next=time_next " \
                  "WHERE command_id=%s"
            cur.execute(cmd, (now, command_id))
        connection.commit()
        response = {"error": 200}
    else:
        response = {"all_errors": errors, "error": 400}

    return response
