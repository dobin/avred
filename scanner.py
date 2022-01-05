
from dataclasses import dataclass
import subprocess
import logging
import re
import os
import shutil
import tempfile
import time

#WDEFENDER_INSTALL_PATH = '/home/vladimir/tools/new_loadlibrary/loadlibrary/'
WDEFENDER_INSTALL_PATH = '/home/toto/loadlibrary/mpclient'
WDEFENDER_INSTALL_PATH_DIR = '/home/toto/loadlibrary'

logging.basicConfig(filename='debug.log',
                    filemode='a',
                    format='[%(levelname)-8s][%(asctime)s][%(filename)s:%(lineno)3d] %(funcName)s() :: %(message)s',
                    datefmt='%Y/%m/%d %H:%M',
                    level=logging.DEBUG)

@dataclass
class Scanner:

    scanner_path: str = ""
    scanner_name: str = ""

    def scan(self, path):
        return False


class WindowsDefender(Scanner):

    def __init__(self):
        self.scanner_path = WDEFENDER_INSTALL_PATH
        self.scanner_name = "Windows Defender"
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
            logging.debug(out)
            m = re.search('Threat', out)

            if m:
                return True

            if(retcode is not None):
                break

        return False

class DockerWindowsDefender(Scanner):

    def __init__(self):
        self.scanner_path = WDEFENDER_INSTALL_PATH
        self.scanner_name = "Windows Defender"

    """
        Scans a file with Windows Defender and returns True if the file
        is detected as a threat.
    """
    def scan(self, file_path, with_name=False):
        #file_path = "/home/toto/av-signatures-finder/test_cases/ext_server_kiwi.x64.dll"
        tmp_file_name = tempfile.NamedTemporaryFile().name
        #tmp_file_name = f"/tmp/{os.path.basename(file_path)}"
        shutil.copyfile(file_path, tmp_file_name)
        #file_path = f"/home/toto/av-signatures-finder/test_cases/{os.path.basename(file_path)}"
        file_path = tmp_file_name
        cmd = "docker run -v /Users/vladimir/dev/av-signatures-finder:/home/toto/av-signatures-finder loadlibrary-working bash -c 'cd /home/toto/loadlibrary && ./mpclient /home/toto/av-signatures-finder/test_cases/ext_server_kiwi.x64.dll'"
        run_cmd = ["docker", "run", "-v", "/Users/vladimir/dev/av-signatures-finder:/home/toto/av-signatures-finder", "loadlibrary-working", "bash", f" -c 'cd /home/toto/loadlibrary'"]
        run_cmd = ["docker", "run", "-v", "/Users/vladimir/dev/av-signatures-finder:/home/toto/av-signatures-finder", "-v", "/tmp:/tmp","-v", "/var:/var", "loadlibrary-working", "python3", "/home/toto/av-signatures-finder/scan.py", file_path]
        p = subprocess.Popen(run_cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        ret_value = False
        threat_name = "Nothing"
        while(True):

            retcode = p.poll()  # returns None while subprocess is running
            out = p.stdout.readline().decode('utf-8', errors='ignore').strip()
            #print(out)
            m = re.search('identified', out)

            if m:

                threat_name = out.split("Threat")[1].split("identified")[0]
                ret_value = True


            if len(out) > 0:
                logging.debug(out)

            if(retcode is not None):
                break

        os.unlink(tmp_file_name)

        if with_name:
           return ret_value, threat_name

        return ret_value


class VMWareDeepInstinct(Scanner):

    def __init__(self):
        self.scanner_path = WDEFENDER_INSTALL_PATH
        self.scanner_name = "DeepInstinct"

    """
        Scans a file with Windows Defender and returns True if the file
        is detected as a threat.
    """
    def scan(self, file_path, with_name=False):
        #file_path = "/home/toto/av-signatures-finder/test_cases/ext_server_kiwi.x64.dll"
        tmp_file_name = tempfile.NamedTemporaryFile().name
        #tmp_file_name = f"/tmp/{os.path.basename(file_path)}"
        shutil.copyfile(file_path, tmp_file_name)
        #file_path = f"/home/toto/av-signatures-finder/test_cases/{os.path.basename(file_path)}"
        file_path = tmp_file_name
        basename = os.path.basename(tmp_file_name)

        vmx_path = "../../Virtual Machines.localized/Windows_10_AV_DeepInstinct.vmwarevm/Windows_10_AV_DeepInstinct.vmx"
        copy_file_cmd = f"vmrun  -T  ws  -gu  toto  -gp  $crt1234!  CopyFileFromHostToGuest  {vmx_path}  {tmp_file_name}  C:\\Users\\toto\\Desktop\\{basename}.exe"
        file_exists_cmd = f"vmrun  -T  ws  -gu  toto  -gp  $crt1234!  fileExistsInGuest  {vmx_path}  C:\\Users\\toto\\Desktop\\{basename}.exe"
        exec_cmd = f"vmrun  -T  ws  -gu  toto  -gp  $crt1234!  runProgramInGuest  {vmx_path}  C:\\Users\\toto\\Desktop\\{basename}.exe"
        print(copy_file_cmd)
        p = subprocess.Popen(copy_file_cmd.split("  "), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        print(f"Copy file result: {p.stdout.readline().decode('utf-8', errors='ignore').strip()}")

        p = subprocess.Popen(file_exists_cmd.split("  "), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)

        print(f"File exists 1 result: {p.stdout.readline().decode('utf-8', errors='ignore').strip()}")

        p = subprocess.Popen(exec_cmd.split("  "), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)

        p = subprocess.Popen(file_exists_cmd.split("  "), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)

        ret_value = False
        threat_name = "Nothing"
        while(True):

            retcode = p.poll()  # returns None while subprocess is running
            out = p.stdout.readline().decode('utf-8', errors='ignore').strip()
            #print(out)
            m = re.search('does not exist', out)

            if m:

                threat_name = out
                ret_value = True


            if len(out) > 0:
                logging.debug(out)

            if(retcode is not None):
                break

        os.unlink(tmp_file_name)

        if with_name:
            return ret_value, threat_name

        return ret_value


class VMWareKaspersky(Scanner):

    def __init__(self):
        self.scanner_path = WDEFENDER_INSTALL_PATH
        self.scanner_name = "Kaspersky"

    """
        Scans a file with Kaspersky and returns True if the file
        is detected as a threat.
    """
    def scan(self, file_path, with_name=False):
        #file_path = "/home/toto/av-signatures-finder/test_cases/ext_server_kiwi.x64.dll"
        tmp_file_name = tempfile.NamedTemporaryFile().name
        #tmp_file_name = f"/tmp/{os.path.basename(file_path)}"
        shutil.copyfile(file_path, tmp_file_name)
        #file_path = f"/home/toto/av-signatures-finder/test_cases/{os.path.basename(file_path)}"
        file_path = tmp_file_name
        basename = os.path.basename(tmp_file_name)
        vmx_path = "../../kasp.vmx"
        copy_file_cmd = f"vmrun  -T  ws  -gu  toto  -gp  $crt1234!  CopyFileFromHostToGuest  {vmx_path}  {tmp_file_name}  C:\\Users\\toto\\Desktop\\{basename}.exe"
        file_exists_cmd = f"vmrun  -T  ws  -gu  toto  -gp  $crt1234!  fileExistsInGuest  {vmx_path}  C:\\Users\\toto\\Desktop\\{basename}.exe"
        exec_cmd = f"vmrun  -T  ws  -gu  toto  -gp  $crt1234!  runProgramInGuest  {vmx_path}  C:\\Users\\toto\\Desktop\\{basename}.exe"
        scan_cmd = ["vmrun",  "-T",  "ws",  "-gu",  "toto",  "-gp",  '$crt1234!',  "runProgramInGuest", f"{vmx_path}", "C:\\Program Files (x86)\\Kaspersky Lab\\Kaspersky Anti-Virus 21.3\\avp.exe", "SCAN", f"C:\\Users\\toto\\Desktop\\{basename}.exe", "/i0"]
        # print(f"Copy file result: {subprocess.Popen(scan_cmd.split('  '), stdout=subprocess.PIPE,stderr=subprocess.STDOUT).stdout.readline().decode('utf-8', errors='ignore').strip()}")
        p = subprocess.Popen(copy_file_cmd.split("  "), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        #print(f"Copy file result: {p.stdout.readline().decode('utf-8', errors='ignore').strip()}")

        p = subprocess.Popen(file_exists_cmd.split("  "), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)

        #print(f"File exists 1 result: {p.stdout.readline().decode('utf-8', errors='ignore').strip()}")

        #execp = subprocess.Popen(exec_cmd.split("  "), stdout=subprocess.PIPE,
        #                     stderr=subprocess.STDOUT)
        #out2 = execp.stdout.readline().decode('utf-8', errors='ignore').strip()
        #print(f"File exec result: {out2}")

        #time.sleep(1)
        #print(scan_cmd)
        p = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)

        ret_value = False
        threat_name = "Nothing"

        while(True):

            retcode = p.poll()  # returns None while subprocess is running
            out = p.stdout.readline().decode('utf-8', errors='ignore').strip()
            # out2 += execp.stdout.readline().decode('utf-8', errors='ignore').strip()
            # print(out)
            m = re.search('suspicion', out)
            # n = re.search("A program could not run", out2)
            if m:

                threat_name = out
                logging.debug("Detected")
                ret_value = True



            if retcode == 3:
                logging.debug("Detected")

                ret_value = True
                break

            """
            elif False:
                ret_value = True
                threat_name = execp
                logging.debug("Detected")
                break
            else:
                logging.debug(out2)
            """

            # logging.debug(f"Retcode:{retcode}")

            if retcode is not None:
                break

        os.unlink(tmp_file_name)

        if with_name:
            return ret_value, threat_name

        return ret_value

class VMWareAvast(Scanner):

    def __init__(self):
        self.scanner_path = WDEFENDER_INSTALL_PATH
        self.scanner_name = "Avast"

    """
        Scans a file with Kaspersky and returns True if the file
        is detected as a threat.
    """
    def scan(self, file_path, with_name=False):
        #file_path = "/home/toto/av-signatures-finder/test_cases/ext_server_kiwi.x64.dll"
        tmp_file_name = tempfile.NamedTemporaryFile().name
        #tmp_file_name = f"/tmp/{os.path.basename(file_path)}"
        shutil.copyfile(file_path, tmp_file_name)
        #file_path = f"/home/toto/av-signatures-finder/test_cases/{os.path.basename(file_path)}"
        file_path = tmp_file_name
        basename = os.path.basename(tmp_file_name)
        vmx_path = "/Users/vladimir/Virtual Machines.localized/Windows_10_Avast.vmwarevm/Windows_10_Avast.vmx"
        copy_file_cmd = f"vmrun  -T  ws  -gu  toto  -gp  $crt1234!  CopyFileFromHostToGuest  {vmx_path}  {tmp_file_name}  C:\\Users\\toto\\Desktop\\{basename}.exe"
        file_exists_cmd = f"vmrun  -T  ws  -gu  toto  -gp  $crt1234!  fileExistsInGuest  {vmx_path}  C:\\Users\\toto\\Desktop\\{basename}.exe"
        exec_cmd = f"vmrun  -T  ws  -gu  toto  -gp  $crt1234!  runProgramInGuest  {vmx_path}  C:\\Users\\toto\\Desktop\\{basename}.exe"
        # print(f"Copy file result: {subprocess.Popen(scan_cmd.split('  '), stdout=subprocess.PIPE,stderr=subprocess.STDOUT).stdout.readline().decode('utf-8', errors='ignore').strip()}")
        p = subprocess.Popen(copy_file_cmd.split("  "), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        #print(f"Copy file result: {p.stdout.readline().decode('utf-8', errors='ignore').strip()}")

        out = p.stdout.readline().decode('utf-8', errors='ignore').strip()
        logging.debug(out)
        #execp = subprocess.Popen(exec_cmd.split("  "), stdout=subprocess.PIPE,
        #                     stderr=subprocess.STDOUT)
        #out2 = execp.stdout.readline().decode('utf-8', errors='ignore').strip()
        #print(f"File exec result: {out2}")

        #time.sleep(1)
        #print(scan_cmd)
        p = subprocess.Popen(exec_cmd.split("  "), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = p.stdout.readline().decode('utf-8', errors='ignore').strip()
        logging.debug(out)
        if re.search("could not run", out):
            return True, "toto"
        logging.debug(file_exists_cmd)
        p = subprocess.Popen(file_exists_cmd.split("  "), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)

        ret_value = False
        threat_name = "Nothing"
        while True:

            retcode = p.poll()  # returns None while subprocess is running
            out = p.stdout.readline().decode('utf-8', errors='ignore').strip()
            #print(out)
            m = re.search('does not exist', out)

            if m:

                threat_name = out
                ret_value = True


            if len(out) > 0:
                logging.debug(out)

            if retcode is not None:
                break

        os.unlink(tmp_file_name)

        if with_name:
            return ret_value, threat_name

        return ret_value
