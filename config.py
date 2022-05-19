import json
import os

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")

class Config(object):
    def __init__(self):
        self.data = {}

    def load(self):
        with open(CONFIG_FILE) as jsonfile:
            self.data = json.load(jsonfile)

    def get(self, value):
        return self.data[value]
