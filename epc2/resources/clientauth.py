"""
This script is a component of the Enumpi Project's back-end controller.
This resource handles authentication of sensor devices against the controller,
providing a session token that can be used to authenticate other controller
requests.

Author: Zac Adam-MacEwen (zadammac@kenshosec.com)
A Kensho Security Labs utility.

Produced under license.
Full license and documentation to be found at:
https://github.com/ZAdamMac/Enumpi-C2
"""

from datetime import datetime
from flask_restful import Resource
from flask import current_app, request, jsonify
import json
import pymysql



class Hello(Resource):
    def get(self):
        # Add Misdirection
        pass

    def put(self):
        try:
            connection = pymysql.connect(host="database",
                                         user=current_app.config["USERNAME"],
                                         password=current_app.config["PASSPHRASE"],
                                         db='enumpi',
                                         charset='utf8mb4',
                                         cursorclass=pymysql.cursors.DictCursor)
            connection.ping(reconnect=True)
            connected = True
        except KeyError:
            connected = False
        except pymysql.Error:
            connected = False

        if connected:
            # Only JSON Put is expected, everything else should failover.
            if request.headers["Content Type"] == "application/json":
                client_token = request.json
                have_client = True
                have_device = True
                try:
                    client_id = client_token["id"]
                except KeyError:
                    have_client = False
                try:
                    device_code = client_token["code"]
                except KeyError:
                    have_device = False
                if have_device and have_client:
                    query = "SELECT device_code FROM client_grants WHERE client_id=%s"
                    client_id = connection.escape_string(client_id)
                    cur = connection.cursor()
                    cur.execute(query, client_id)
                    expected_dc = cur.fetchone()
                    if expected_dc == device_code:
                        response = generate_full_tokens(connection, cur)
                        response.status_code = 200
                    else:
                        response = jsonify({"msg": "Unauthorized"})
                        response.status_code = 403
                    return response
                else:  # The request cannot be authenticated, and we hide.
                    self.get()

            else:  # This is not an expected response type, so we hide.
                self.get()
        else:
            response = jsonify({"msg":"Database Issue"})
            response.status_code = 500


def generate_full_tokens(conn, cursor):
