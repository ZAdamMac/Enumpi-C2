"""
This script is a component of the Enumpi Project's back-end controller.
This resource is a collection of helper classes which are imported selectively
into other resources that make up part of EPiC2.

Author: Zac Adam-MacEwen (zadammac@kenshosec.com)
A Kensho Security Labs utility.

Produced under license.
Full license and documentation to be found at:
https://github.com/ZAdamMac/Enumpi-C2
"""

import base64
import bcrypt
import datetime
import hashlib
import hmac
import json


class UserModel(object):
    def __init__(self):
        """For sanity reasons, always init a blank user."""
        self.uid = None
        self.name = None
        self.fname = None
        self.lname = None
        self.email = None
        self.new_password = None
        self.force_reset = None
        self.can_login = None
        self.can_report = None
        self.can_command = None
        self.can_grant = None
        self.can_users = None
        self.last_active = None

    def from_json(self, s_json):
        """Initializes a user object from JSON, such as would be supplied by
        the create and modify user utilities. Do not use without validating
        the json string with json_validate and the appropriate dictionary.

        :param s_json: the string of serialized json to be used.
        """
        d_json = s_json
        self.uid = d_json["userId"]
        self.name = d_json["username"]
        self.fname = d_json["firstName"]
        self.lname = d_json["lastName"]
        self.email = d_json["email"]
        self.new_password = d_json["newPwd"]
        self.force_reset = bool(d_json["forceResetPwd"])
        permissions = d_json["permissions"]
        self.can_login = permissions["active"]
        self.can_report = permissions["useReportingApi"]
        self.can_command = permissions["canIssueCommands"]
        self.can_grant = permissions["canModifyClients"]
        self.can_users = permissions["isUserAdmin"]

    def from_dict(self, d_user):
        """Initialize using a dictionary of the sort returned by pymysql's
        DictCursor cursor class. Expects the actual dictionary of a single
        row. Use fetchone() iteratively or fetchall then iterate over the
        return.

        :param d_user: a dictionary.
        :return:
        """
        self.uid = d_user["user_id"]
        self.name = d_user["username"]
        self.fname = d_user["fname"]
        self.lname = d_user["lname"]
        self.email = d_user["email"]
        self.force_reset = d_user["pw_reset"]
        self.last_active = d_user["bearer_token_expiry"]
        s_permissions = bin(d_user["access"]).lstrip('0b')

        # Have to enforce a string length or bugs happen!
        bits = len(s_permissions)
        missing = 5-bits  # FUTURE: If adding bits to access, change this int!
        padding = ''
        if missing > 0:
            for i in range(missing):
                padding += '0'
        s_permissions = padding+s_permissions

        self.can_login = bool(int(s_permissions[0]))
        self.can_report = bool(int(s_permissions[1]))
        self.can_command = bool(int(s_permissions[2]))
        self.can_grant = bool(int(s_permissions[3]))
        self.can_users = bool(int(s_permissions[4]))

    def dump_json(self, serialize=True):
        """Takes the current state of the user object and returns it in a
        spec-compliant, serialized JSON object unless overridden.
        """
        d_json = {
            "userId": self.uid,
            "username": self.name,
            "firstName": self.fname,
            "lastName": self.lname,
            "email": self.email,
            "forceResetPwd": bool(self.force_reset),
            "permissions": {
                "active": self.can_login,
                "useReportingApi": self.can_report,
                "canIssueCommands": self.can_command,
                "canModifyClients": self.can_grant,
                "isUserAdmin": self.can_users
            },
            "lastActive": self.last_active
        }
        if serialize:
            out = json.dumps(d_json)
        else:
            out = d_json
        return out

    def dump_dict(self):
        """Return current state of the object as a dictionary suitable for use
        with the database. Collapses permissions back into an integer and pre-
        salted-hashes the new password value, if any."""
        if self.new_password:
            salty_pass = bcrypt.hashpw(self.new_password.encode("utf-8"), bcrypt.gensalt())
        else:
            salty_pass = None

        str_access = ''  # We need to turn this back to an int.
        permissions = [self.can_login, self.can_report, self.can_command,
                       self.can_grant, self.can_users]  # Lists are reliably ordered.
        for each in permissions:
            str_access += str(int(each))
        int_access = int(str_access, 2)

        d_user = {
            "user_id": self.uid,
            "email": self.email,
            "username": self.name,
            "fname": self.fname,
            "lname": self.lname,
            "passwd": salty_pass,
            "pw_reset": self.force_reset,
            "access": int_access
        }
        return d_user


def authenticated_exec(token_id, permission, connection, func, body):
    """
    Accepts the noted arguments to determine if a given user may take an action
    and then allows them to execute it.

    For this to work the function in question should accept the json body and
    the database connection as its only arguments and in that order.

    :param token_id: the value returned by token_validate[0].
    :param permission: A string matching the permission attribute to check
    :param connection: a database connection object.
    :param func: the function to be executed if the client is permitted
    :param body: the json body of the request.
    :return: the response body to be sent to the remote user.
    """
    cur = connection.cursor()
    requestor = UserModel()
    cmd = "SELECT * FROM users WHERE user_id=%s"
    cur.execute(cmd, token_id)
    d_user = cur.fetchone()
    requestor.from_dict(d_user)

    if requestor.can_login and requestor.__getattribute__(permission):
        response = func(body, connection)
        connection.commit()
        connection.close()
    else:
        response = {'error': 400, 'msg': "Unauthorized"}
        connection.close()

    return response


def build_auth_token(ttl, key, uuid, iss, aud):
    """Minimal tool for quickly generating a JWT and returning it along with
    the associated expiry timestamp. Built as a utility function so that it
    can be reused in all associated token operations. Signs tokens with HMAC
    SHA256.

    :param ttl: int minutes until expiry
    :param key: bytes random key used in the signing operation.
    :param uuid: UUID argued in as subject. Should be the associated user or
    client id.
    :param iss: Argued to issuer - defined in config.
    :param aud: One of "client" or "user".
    :return:
    """
    expiry = (datetime.datetime.now() + datetime.timedelta(minutes=ttl)).timestamp()
    header = {
        "alg": "HS256",
        "type": "JWT"
    }
    body = {
        "iss": iss,
        "sub": uuid,
        "aud": aud,
        "exp": expiry
    }
    msg_a = base64.b64encode(json.dumps(header).encode('utf-8')).decode('utf-8')
    msg_b = base64.b64encode(json.dumps(body).encode('utf-8')).decode('utf-8')
    msg = msg_a + "." + msg_b
    sig = hmac.new(key, msg.encode('utf-8'), digestmod=hashlib.sha256).hexdigest().upper()
    token = msg+"."+sig
    return token, expiry


def json_validate(test_json, dict_schema):
    """A simplistic JSON validator for pre-clearing missing or incorrectly-
    typed arguments in a request body. Controlled by arguments and returns
    a tuple in (boolean, errors) format indicating whether or not the body
    passed and what, if any, errors are indicated.

    :param test_json: A deserialized JSON object (usually a dict)
    :param dict_schema: a dictionary of the object schema with key-value pairs
    where value should be of the same type as the expected type in the JSON.
    :return: tuple of boolean and an error dictionary.
    """
    list_response = []
    testable = {0: (test_json, dict_schema)}
    counter = 0
    for thing in testable:
        test_object, active_schema = testable[thing]
        for field in active_schema:
            try:
                value = test_json[field]
            except KeyError:
                list_response.append({str(field): "Field missing from request"})
                continue
            expect_type = dict_schema[field]
            if not isinstance(value, type(expect_type)):
                # We use type(expect_type) here because sometimes the value is a dict or list
                # rather than being a type object
                list_response.append({str(field): ("Value is not of the expected type: %s" % type(expect_type))})
                continue
            if expect_type == dict:
                counter += 1
                testable.update({counter: (value, dict_schema[field])})
        if len(list_response) == 0:
            return True, list_response
        else:
            dict_response = {}
            for error in list_response:
                dict_response.update(error)
            return False, dict_response


def token_validate(cookie, ttl, db_conn, new_key, iss, aud, t_type):
    """Sort of a malnamed function. Both validates the argued token and
    returns a tuple depending on the results. If the token is invalid it
    returns the tuple (False, None), else it will return (users.user_id, new
    token).

    :param cookie: A cookie provided by the calling endpoint.
    :param ttl: The relevant time to live value. The bearer token will be
    re-issued with an extended time based on this time to live.
    :param db_conn: A database connection, assumed to have default DictCursor
    :param new_key: A bytestring value, should be os.urandom(64)
    :param iss: The network label value from global app config.
    :param aud: The audience value, either "user" or "client"
    :param t_type: String, one of "bearer" or "refresh", determining which is
    checked by the application.
    :return:
    """
    # First, dismantle the cookie and reconstruct our primitives
    header, body, sig = cookie.split(".")
    del header
    dict_body = base64.b64decode(body.encode('utf-8'))
    obj_body = json.loads(dict_body)
    msg = header + "." + body

    # Now, retrieve the relevant user from the db as a dictionary.
    # This is possible because we're defaulting to DictCursor for this project.
    curr = db_conn.cursor()
    if aud == "user":
        cmd = "SELECT * FROM users WHERE user_id=%s"
    else:
        cmd = "SELECT * FROM clients WHERE client_id=%s"
    uid = obj_body["sub"]
    length = curr.execute(cmd, uid)
    if length == 0:
        return False, None  # Should never happen, but might with a forged JWT
    dict_user = curr.fetchone()  # user_id is a unique value, will never be more than 1

    # Technically we could trust the expiry in the token, but I ain't about that life.
    exp_current = dict_user[("%s_token_expiry" % t_type)]
    if datetime.datetime.now() < exp_current:  # Token is not expired
        time_valid = True
    else:
        time_valid = False

    # Now we need to determine if the key is valid.
    if time_valid:
        key = dict_user[("%s_token_key" % t_type)]
        sig_expected = hmac.new(key, msg.encode('utf-8'), digestmod=hashlib.sha256).hexdigest().upper()
        if sig == sig_expected:
            sig_valid = True
        else:
            sig_valid = False
    else:
        sig_valid = False

    if time_valid and sig_valid:
        new_token, new_expiry = build_auth_token(ttl=ttl, key=new_key, uuid=uid, iss=iss, aud=aud)
        if aud == "user":
            cmd = "UPDATE users SET bearer_token_key=%s, bearer_token_expiry=FROM_UNIXTIME(%s) WHERE user_id=%s"
        elif aud == "client":
            cmd = "UPDATE users SET bearer_token_key=%s, bearer_token_expiry=FROM_UNIXTIME(%s) WHERE client_id=%s"
        curr.execute(cmd, (new_key, new_expiry, uid))
        db_conn.commit()
        return uid, new_token
    else:
        return False, None
