import json
import os

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")


def get_value(value):

    try:
        with open(CONFIG_FILE) as jsonfile:

            data = json.load(jsonfile)

        if value in data:
            return data[value]
    except Exception as e:
        import traceback
        traceback.print_exc()
        import os
        print(os.getcwd())
        raise Exception(e)

    raise Exception(f"Unknown field: {value}. Available fields are: {data.keys()}")
