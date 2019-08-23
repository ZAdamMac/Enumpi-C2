"""
This script is a component of the Enumpi Project's back-end controller.
Specifically, it is a helper utility to be used to intialize a database for
the C2 service to operate from, provided a few basic arguments.

Author: Zac Adam-MacEwen (zadammac@kenshosec.com)
A Kensho Security Labs utility.

Produced under license.
Full license and documentation to be found at:
https://github.com/ZAdamMac/Enumpi-C2
"""

import argparse
import bcrypt
import json
import getpass
import os
import pymysql
import uuid

__version__ = "0.0.1dev1"

spec_tables = [
    """CREATE TABLE `actions` (
      `action_id` INT NOT NULL AUTO_INCREMENT,
      `action` VARCHAR(255) NOT NULL,
      `description` TEXT DEFAULT NULL,
      `dummy_command` LONGTEXT DEFAULT NULL,
      PRIMARY KEY (`action_id`)
    )""",
    """CREATE TABLE `clients` (
      `client_id` CHAR(36) NOT NULL,
      `common_name` VARCHAR(255) NOT NULL,
      `description` TEXT DEFAULT NULL,
      `placement` VARCHAR(255) DEFAULT NULL,
      `user_id` CHAR(36) DEFAULT NULL,
      PRIMARY KEY (`client_id`)
    )""",
    """CREATE TABLE `client_grants` (
      `grant_id` INT NOT NULL AUTO_INCREMENT,
      `client_id` CHAR(36) NOT NULL,
      `device_code` BLOB DEFAULT NULL,
      `device_code_expiry` TIMESTAMP,
      `bearer_token_key` BLOB DEFAULT NULL,
      `bearer_token_expiry` TIMESTAMP,
      `refresh_token_key` BLOB DEFAULT NULL,
      `refresh_token_expiry` TIMESTAMP,
      PRIMARY KEY (`grant_id`)
    )""",
    """CREATE TABLE `commands` (
      `command_id` CHAR(36) NOT NULL,
      `client_id` CHAR(36) DEFAULT NULL,
      `user_id` CHAR(36) DEFAULT NULL,
      `command` VARCHAR(255) DEFAULT NULL,
      `json_cmd` LONGTEXT DEFAULT NULL,
      `interval` VARCHAR(255) DEFAULT NULL,
      `time_next` TIMESTAMP,
      `time_logged` TIMESTAMP,
      `time_sent` TIMESTAMP,
      `time_acknowledged` TIMESTAMP,
      `msg_id` CHAR(36) DEFAULT NULL,
      PRIMARY KEY (`command_id`)
    )""",
    """CREATE TABLE `files` (
      `file_id` CHAR(36) NOT NULL,
      `client_id` CHAR(36) DEFAULT NULL,
      `filename` VARCHAR(255) DEFAULT NULL,
      `path` VARCHAR(255) DEFAULT NULL,
      PRIMARY KEY (`file_id`)
    )""",
    """CREATE TABLE `messages` (
      `msg_id` CHAR(36) NOT NULL,
      `read` BIT DEFAULT 0,
      `body` VARCHAR(255) DEFAULT NULL,
      `time` TIMESTAMP,
      PRIMARY KEY (`msg_id`)
    )""",
    """CREATE TABLE `users` (
          `user_id` CHAR(36) NOT NULL,
          `username` VARCHAR(255) DEFAULT NULL,
          `fname` VARCHAR(255) DEFAULT NULL,
          `lname` VARCHAR(255) DEFAULT NULL,
          `email` VARCHAR(255) DEFAULT NULL,
          `passwd` BLOB NOT NULL,
          `pw_reset` BIT DEFAULT 1,
          `bypass` BLOB DEFAULT NULL,
          `bypass_expiry` TIMESTAMP,
          `device_code_expiry` TIMESTAMP,
          `bearer_token_key` BLOB DEFAULT NULL,
          `bearer_token_expiry` TIMESTAMP,
          `refresh_token_key` BLOB DEFAULT NULL,
          `refresh_token_expiry` TIMESTAMP,
          `access` TINYINT DEFAULT 0,
          PRIMARY KEY (`user_id`)
        )"""
]


def connect_to_db():
    """Detects if it is necessary to prompt for the root password, and either way,
    establishes the db connection, returning it.
    :return:
    """
    print("We must now connect to the database.")
    try:
        db_user = os.environ['ENUMPI_DB_USER']
    except KeyError:
        db_user = input("Username: ")
    root_password = None
    try:
        root_password = os.environ['ENUMPI_DB_PASSWORD']
    except KeyError:
        print("The DB password was not pasted into the environment variables.")
        root_password = getpass.getpass("Password: ")
    finally:
        conn = pymysql.connect(host='127.0.0.1', user=db_user,
                               password=root_password, db='enumpi',
                               charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor)

    return conn


def create_tables(list_tables, connection):
    """Accepts a list of create statements for tables and pushes them to the DB.

    :param list_tables: A list of CREATE statements in string form.
    :param connection: a pymysql.connect() object, such as returned by connect_to_db
    :return:
    """
    cursor = connection.cursor()
    connection.begin()
    for table in list_tables:
        try:
            cursor.execute(table)
        except pymysql.err.ProgrammingError:
            print("Error in the following statement; table was skipped.")
            print(table)
        except pymysql.err.InternalError as error:
            if str(error.args[0]) == '1050':
                pass
            else:
                print(error)
    connection.commit()


def populate_actions_table(arg_obj, db):
    """A basic function to read in the jsonized actions.

    :param arg_obj: arguments object as returned by parse_args
    :param db: a database connection.
    :return:
    """
    file_action_definitions = arg_obj
    if os.path.isfile(file_action_definitions):
        with open(file_action_definitions, "r") as f:
            try:
                action_definitions = json.load(f)
            except json.decoder.JSONDecodeError:
                print("There is an issue with the action definitions file at %s" % file_action_definitions)
                print("This file is not valid JSON, or contains encoding errors.")
                print("Correct the issues and re-run the application.")
                return
    else:
        print("The definitions file at %s could not be found" % file_action_definitions)
        print("Please correct the config and re-run this application.")
        return

    if action_definitions is not None:
        cmd = "SELECT action FROM actions"
        cur = db.cursor()
        cur.execute(cmd)
        actions_tup = cur.fetchall()
        actions = []
        for each in actions_tup:
            actions.append(each['action'])
        for definition in action_definitions:
            str_dummy = json.dumps(definition["dummy"])
            #print(str_dummy)
            if definition["cmd"] in actions:
                cmd = "UPDATE actions SET description=%s, dummy_command=%s WHERE action=%s"
                cur.execute(cmd, (definition['desc'], str_dummy, definition['cmd']))
                print("Actions: updated %s" % definition["cmd"])
            else:
                cmd = "INSERT INTO actions (action, description, dummy_command) VALUES (%s,%s,%s)"
                cur.execute(cmd, (definition["cmd"], definition["desc"], str_dummy))
                print("Actions: added %s" % definition["cmd"])


def create_initial_admin(db):
    """Generates the initial admin account based on user input.

    :param db:
    :return:
    """
    usercount = db.cursor().execute("SELECT * FROM users")
    if usercount > 0:
        print("Cannot create an admin user - this db contains a users table already.")
    else:
        print("Please specify a name for the base admin user of the webapp.")
        username = input("username: ")
        print("Please enter the user's first and last names, separated by a space.")
        fname, lname = input("First Last: ").split(" ")
        print("Enter an email to associate with this user. This email will be used to reset passwords.")
        email = input("Email: ")
        passwording = True
        while passwording:
            print("Enter a password twice. Both values must match.")
            password = getpass.getpass("Password: ")
            verify = getpass.getpass("Password: ")
            if password == verify:
                passwording = False
                pwd = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
                del password
                del verify
            else:
                print("Passwords did not match.")

        cur = db.cursor()
        cmd = """INSERT INTO users 
        (user_id, username, fname, lname, email, passwd, pw_reset, access)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""
        args = (str(uuid.uuid4()), username, fname, lname, email, pwd, 1, 31)
        cur.execute(cmd, args)
        print("The default admin user has been created as you specified.")
        del pwd


def parse_args():
    """Parse arguments and return the path to the json file."""
    if __name__ == "__main__":
        parser = argparse.ArgumentParser(description="""Do the thing!""")
        parser.add_argument('json', help="Specify the path to an actions.json file to ingest.",
                            action="store")
        args = parser.parse_args()

        path_json = args.json

        return path_json


if __name__ == "__main__":
    print("Now Creating Tables")
    json_path = parse_args()
    mariadb = connect_to_db()
    create_tables(spec_tables, mariadb)
    populate_actions_table(json_path, mariadb)
    create_initial_admin(mariadb)
    mariadb.commit()
    mariadb.close()
    print("Done.")
