import yaml
import os

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.yaml")

class Config(object):
    def __init__(self):
        self.data = {}

    def load(self):
        with open(CONFIG_FILE) as jsonfile:
            try:
                self.data = yaml.safe_load(jsonfile)
            except ValueError as e:
                print('Decoding {} as failed with: {}'.format(CONFIG_FILE, e))
                quit()

    def get(self, value):
        if value in self.data:
            return self.data[value]
        else:
            return ""
