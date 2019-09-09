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

from flask_restful import Resource
from flask import current_app, request, make_response
from os import urandom
import pymysql
import uuid
from .utilties import authenticated_exec, json_validate, token_validate, UserModel

__version__ = "prototype"


class ManageUser(Resource):
    def get(self):
        """An authenticated user with reporting permissions may retrieve a
        full listing of all users active and inactive on the server.

        :return: In the valid case, a json dictionary of (row, user) pairs
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
                                             user_management_get, None)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

    def post(self):
        """The post method allows the creation of a new user using the
        following model json object. All fields required.

        {
        "username": "string",
        "firstName": "string",
        "lastName": "string",
        "email": "string",
        "newPwd": "string, max 72 characters (bcrypt limitation)",
        "forceResetPwd": Boolean,
        "permissions": {"active": Boolean,
                        "useReportingApi": Boolean,
                        "canIssueCommands": Boolean,
                        "canModifyClients": Boolean,
                        "isUserAdmin": Boolean
                        }
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
            dict_return = authenticated_exec(token_user, "can_users", connection,
                                             user_management_post, body)
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
                "userId": "string"
                "username": "string",
                "firstName": "string",
                "lastName": "string",
                "email": "string",
                "newPwd": "string, max 72 characters (bcrypt limitation)",
                "forceResetPwd": Boolean,
                "permissions": {"active": Boolean,
                                "useReportingApi": Boolean,
                                "canIssueCommands": Boolean,
                                "canModifyClients": Boolean,
                                "isUserAdmin": Boolean
                                }
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
            dict_return = authenticated_exec(token_user, "can_users", connection,
                                             user_management_patch, body)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403

    def delete(self):
        """accepts a json object containing either user_id or useername, and
        sets that user's can_login bit to 0.

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
            dict_return = authenticated_exec(token_user, "can_users", connection,
                                             user_management_delete, body)
            resp = make_response(dict_return)
            resp.set_cookie("auth", new_token)
            resp.status_code = dict_return["error"]
            resp.content_type = "application/json"
            return resp
        else:
            return {'message': 'unauthorized'}, 403


def user_management_get(body, connection):
    """
    Lists all the users in the database in a json object
    :param body: not used, so can be dropped.
    :param connection: a db connection object
    :return: the preformatted response body
    """

    del body
    cur = connection.cursor()
    array_response = {}
    cmd = "SELECT * FROM users"
    cur.execute(cmd)
    l_results = cur.fetchall()
    row_number = -1

    for each in l_results:
        row_number += 1
        user = UserModel()
        user.from_dict(each)
        array_response.update({row_number: user.dump_json(False)})
    array_response.update({"error": 200})

    return array_response


def user_management_post(body, connection):
    """
    Adds the user described in the body to the database.

    :param body: JSON body of the request
    :param connection: A connection object
    :return:
    """

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
    json_valid, errors = json_validate(body, dict_schema)
    if json_valid:
        cur = connection.cursor()
        cur.execute("SELECT username FROM users WHERE username=%s", body["username"])
        result = cur.fetchall()
        if len(result) > 0:
            is_unique_user = False
        else:
            is_unique_user = True
    else:
        is_unique_user = False

    if json_valid and is_unique_user:
        # Let's add this user to the DB!
        new_user = UserModel()
        body.update({"userId": str(uuid.uuid4())})  # We know this to be a new user.
        new_user.from_json(body)
        d_user = new_user.dump_dict()
        cmd = """INSERT INTO users 
                               (user_id, username, fname, lname, 
                               email, passwd, pw_reset, access)
                               VALUES (%(user_id)s, %(username)s, %(fname)s, %(lname)s,
                               %(email)s, %(passwd)s, %(pw_reset)s, %(access)s)"""
        cur.execute(cmd, d_user)
        response ={'created user': d_user["username"], "error": 200}
    elif is_unique_user:
        response = {'message': "errors in request body", "error": 400}.update({"errors": errors})
    else:
        response = {'message': 'user is not unique', "error": 400}

    return response


def user_management_patch(body, connection):
    # We can't just validate the damn thing because patch.
    # The only required field is UUID. We need to validate that exists.
    # After that, we need a way to programmatically add keys.
    d_json = body
    cur = connection.cursor()
    if d_json:
        if "userId" not in d_json.keys():
            subject_user = False
        else:
            dict_mapping = {
                "userId": "uid", "username": "name", "firstName": "fname",
                "lastName": "lname", "email": "email", "newPwd": "new_password",
                "forceResetPwd": "force_reset"
            }
            cmd = "SELECT * FROM users WHERE user_id=%s"
            cur.execute(cmd, d_json["userId"])
            subject_user = False
            d_subject = cur.fetchone()
            if len(d_subject) > 0:  # We found a user with that ID
                subject_user = UserModel()
                subject_user.from_dict(d_subject)
                # We can update the user model programmatically with __setattr__
                for field in d_json.keys():  # Easier than nesting Try.
                    if field in dict_mapping.keys():  # Only care about those.
                        # We can change these attributes programmatically!
                        # In retrospect this would have been a better way to handle
                        # UserModel's "from" methods in the first place.
                        # Possible point for the future.
                        subject_user.__setattr__(dict_mapping[field], d_json[field])
                if "permissions" in d_json.keys():
                    # Permissions are a dictionary, we can assign them the same
                    # way as above.
                    dict_mapping = {
                        'active': "can_login",
                        "useReportingApi": "can_report",
                        "canIssueCommands": "can_command",
                        "canModifyClients": "can_grant",
                        "isUserAdmin": "can_users"
                    }
                    permissions = d_json["permissions"]
                    for each in permissions.keys():
                        subject_user.__setattr__(dict_mapping[each],
                                                 permissions[each])
    else:
        subject_user = False

    if subject_user:  # This will only be set if a user was found.
        # Let's add this user to the DB!
        d_user = subject_user.dump_dict()
        if d_user["passwd"]:  # May not be changing the password.
            cmd = """UPDATE users 
                              SET username=%(username)s, fname=%(fname)s, lname=%(lname)s,
                              email=%(email)s, passwd=%(passwd)s, pw_reset=%(pw_reset)s,
                              access=%(access)s
                              WHERE user_id=%(user_id)s"""
        else:  # In which case, just remove the password.
            cmd = """UPDATE users 
                              SET username=%(username)s, fname=%(fname)s, lname=%(lname)s,
                              email=%(email)s, pw_reset=%(pw_reset)s, access=%(access)s
                              WHERE user_id=%(user_id)s"""
        cur.execute(cmd, d_user)
        d_user.pop("passwd", None)
        response = {'updated user': d_user, "error": 200}
    else:
        response = {'message': "user doesn't exist. Try POSTing it!", "error": 400}

    return response


def user_management_delete(body, connection):
    d_json = body
    cur = connection.cursor()
    if d_json:
        if "userId" in d_json.keys():
            cmd = "SELECT * FROM users WHERE user_id=%s"
            key = d_json["userId"]
        elif "username" in d_json.keys():
            cmd = "SELECT * FROM users WHERE username=%s"
            key = d_json["username"]
        else:  # Makes the linter happy. :/
            cmd = False
            key = False
        if cmd and key:
            cur.execute(cmd, key)
            d_user = cur.fetchone()
            subject_user = UserModel()
            if d_user:
                subject_user.from_dict(d_user)
                # Finally, deactivate!
                subject_user.can_login = False
                # This method of deactivation is being preferred so that
                # user records can be maintained in the DB for historical
                # reasons.
        else:
            subject_user = False
    else:
        subject_user = False

    if subject_user:  # This will only be set if a user was found.
        # Let's update this user in the DB!
        d_user = subject_user.dump_dict()
        cmd = "UPDATE users SET access=%s WHERE user_id=%s"
        cur.execute(cmd, (d_user["access"], d_user["user_id"]))
        resp = {'deactivated user': d_user, "error": 200}
    else:
        resp = {'message': "user doesn't exist. Try POSTing it!", "error": 400}

    return resp
