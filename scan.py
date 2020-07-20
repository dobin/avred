import os
import subprocess
import sys
import re

WDEFENDER_INSTALL_PATH = '/home/toto/loadlibrary/mpclient'

os.chdir(os.path.dirname(WDEFENDER_INSTALL_PATH))
command = [WDEFENDER_INSTALL_PATH, sys.argv[1]]
p = subprocess.Popen(command, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT)

while (True):

    retcode = p.poll()  # returns None while subprocess is running
    out = p.stdout.readline().decode('utf-8', errors='ignore')
    print(out)
    m = re.search('Threat', out)

    if m:
        print("Threat found\n")
        exit(-1)

    if (retcode is not None):
        break

exit(0)
