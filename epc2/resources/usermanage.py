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
from .utilties import json_validate, token_validate, UserModel

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
            # First we need to know who's asking.
            cur = connection.cursor()
            requestor = UserModel()
            cmd = "SELECT * FROM users WHERE user_id=%s"
            cur.execute(cmd, token_user)
            d_user = cur.fetchone()
            requestor.from_dict(d_user)

            # And of course, if they're allowed to do that.
            if requestor.can_report and requestor.can_login:
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
            # First we need to know who's asking.
            cur = connection.cursor()
            requestor = UserModel()
            cmd = "SELECT * FROM users WHERE user_id=%s"
            cur.execute(cmd, token_user)
            d_user = cur.fetchone()
            requestor.from_dict(d_user)

            # And of course, if they're allowed to do that.
            if requestor.can_users and requestor.can_login:
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
                    if len(result) > 0:
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
            # First we need to know who's asking.
            cur = connection.cursor()
            requestor = UserModel()
            cmd = "SELECT * FROM users WHERE user_id=%s"
            cur.execute(cmd, token_user)
            d_user = cur.fetchone()
            requestor.from_dict(d_user)

            # And of course, if they're allowed to do that.
            if requestor.can_users and requestor.can_login:
                # We can't just validate the damn thing because patch.
                # The only required field is UUID. We need to validate that exists.
                # After that, we need a way to programmatically add keys.
                d_json = request.get_json()
                if d_json:
                    if "userId" not in d_json.keys():
                        subject_user = False
                    else:
                        dict_mapping = {
                            "userId": "uid", "username": "name", "firstName": "fname",
                            "lastName": "lname", "email": "email", "newPwd": "new_password",
                            "forceResetPwd": "force_reset"
                        }
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
                    connection.commit()
                    connection.close()
                    d_user.pop("passwd", None)
                    resp = make_response({'updated user': d_user})
                    resp.set_cookie("auth", new_token)
                    resp.status_code = 200
                    resp.content_type = "application/json"
                else:
                    resp = make_response({'message': "user doesn't exist. Try POSTing it!"})
                    resp.status_code = 400
                    resp.set_cookie("auth", new_token)
            else:
                resp = make_response({'message': 'Insufficient Permissions'})
                resp.status_code = 403
                resp.set_cookie("auth", new_token)
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
            # First we need to know who's asking.
            cur = connection.cursor()
            requestor = UserModel()
            cmd = "SELECT * FROM users WHERE user_id=%s"
            cur.execute(cmd, token_user)
            d_user = cur.fetchone()
            requestor.from_dict(d_user)

            # And of course, if they're allowed to do that.
            if requestor.can_users and requestor.can_login:
                # We can't just validate the damn thing because patch.
                # The only required field is UUID. We need to validate that exists.
                # After that, we need a way to programmatically add keys.
                d_json = request.get_json()
                if d_json:
                    if "userId" in d_json.keys():
                        cmd = "SELECT * FROM users WHERE user_id=%s"
                        key = d_json["userId"]
                        cur.execute(cmd, key)
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
                    else:
                        subject_user = False
                else:
                    subject_user = False

                if subject_user:  # This will only be set if a user was found.
                    # Let's add this user to the DB!
                    d_user = subject_user.dump_dict()
                    cmd = "UPDATE users SET access=%s WHERE user_id=%s"
                    cur.execute(cmd, (d_user["access"], d_user["user_id"]))
                    connection.commit()
                    connection.close()
                    resp = make_response({'deactivated user': d_user})
                    resp.set_cookie("auth", new_token)
                    resp.status_code = 200
                    resp.content_type = "application/json"
                else:
                    resp = make_response({'message': "user doesn't exist. Try POSTing it!"})
                    resp.status_code = 400
                    resp.set_cookie("auth", new_token)
            else:
                resp = make_response({'message': 'Insufficient Permissions'})
                resp.status_code = 403
                resp.set_cookie("auth", new_token)
            return resp
        else:
            return {'message': 'unauthorized'}, 403
