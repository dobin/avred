
from dataclasses import dataclass
import subprocess
import logging
import re
import os
import shutil
logging.basicConfig(level=logging.DEBUG)

#WDEFENDER_INSTALL_PATH = '/home/vladimir/tools/new_loadlibrary/loadlibrary/'
WDEFENDER_INSTALL_PATH = '/home/toto/loadlibrary/mpclient'
WDEFENDER_INSTALL_PATH_DIR = '/home/toto/loadlibrary'


@dataclass
class Scanner:

    scanner_path: str = ""

    def scan(self, path):
        return False


class WindowsDefender(Scanner):

    def __init__(self):
        self.scanner_path = WDEFENDER_INSTALL_PATH

    """
        Scans a file with Windows Defender and returns True if the file
        is detected as a threat.
    """
    def scan(self, file_path):

        os.chdir(os.path.dirname(self.scanner_path))
        command = [self.scanner_path, file_path]
        p = subprocess.Popen(command, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)

        while(True):

            retcode = p.poll()  # returns None while subprocess is running
            out = p.stdout.readline().decode('utf-8', errors='ignore')
            print(out)
            m = re.search('Threat', out)

            if m:
                return True

            if(retcode is not None):
                break

        return False

class DockerWindowsDefender(Scanner):

    def __init__(self):
        self.scanner_path = WDEFENDER_INSTALL_PATH

    """
        Scans a file with Windows Defender and returns True if the file
        is detected as a threat.
    """
    def scan(self, file_path):
        #file_path = "/home/toto/av-signatures-finder/test_cases/ext_server_kiwi.x64.dll"
        tmp_file_name = f"./test_cases/{os.path.basename(file_path)}"
        shutil.copyfile(file_path, tmp_file_name)
        file_path = f"/home/toto/av-signatures-finder/test_cases/{os.path.basename(file_path)}"
        cmd = "docker run -v /Users/vladimir/dev/av-signatures-finder:/home/toto/av-signatures-finder loadlibrary-working bash -c 'cd /home/toto/loadlibrary && ./mpclient /home/toto/av-signatures-finder/test_cases/ext_server_kiwi.x64.dll'"
        run_cmd = ["docker", "run", "-v", "/Users/vladimir/dev/av-signatures-finder:/home/toto/av-signatures-finder", "loadlibrary-working", "bash", f" -c 'cd /home/toto/loadlibrary'"]
        run_cmd = ["docker", "run", "-v", "/Users/vladimir/dev/av-signatures-finder:/home/toto/av-signatures-finder", "-v", "/var:/var", "loadlibrary-working", "python3", "/home/toto/av-signatures-finder/scan.py", file_path]
        p = subprocess.Popen(run_cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        ret_value = False

        while(True):

            retcode = p.poll()  # returns None while subprocess is running
            out = p.stdout.readline().decode('utf-8', errors='ignore')
            #print(out)
            m = re.search('Threat', out)

            if m:
                ret_value = True

            if(retcode is not None):
                break

        os.unlink(tmp_file_name)
        return ret_value
