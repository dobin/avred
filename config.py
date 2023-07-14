import yaml
import os

# Some static globals
MAX_HEXDUMP_SIZE = 2048
MAX_DISASM_SIZE = 512

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.yaml")

class Config(object):
    def __init__(self):
        self.data = {}

    def getConfigPath(self):
        return CONFIG_FILE
    
    def getConfig(self):
        return self.data
    
    def load(self):
        with open(CONFIG_FILE) as jsonfile:
            try:
                self.data = yaml.safe_load(jsonfile)
            except yaml.YAMLError as e:
                print('Decoding {} as failed with: {}'.format(CONFIG_FILE, e))
                quit()

    def get(self, value):
        return self.data.get(value, "")

config = Config()
