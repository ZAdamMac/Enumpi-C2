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
            dict_response: {}
            for error in list_response:
                dict_response.update(error)
            return False, dict_response
