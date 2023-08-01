from flask import Blueprint, current_app, flash, request, redirect, url_for, render_template
from werkzeug.utils import secure_filename
import os
import random
import subprocess
import requests
import sys
import zipfile
import logging
import psutil
import string


EXT_INFO = ".outcome"
EXT_LOG = ".log"

views_upload = Blueprint('views_upload', __name__)


@views_upload.route("/upload_tracker/<filename>")
def upload_tracker(filename):
    # if process doesnt exist anymore, we finished
    avredRuns = False
    for proc in psutil.process_iter():
        cmdline = ' '.join(proc.cmdline())
        # bad heuristics, but works
        # "/usr/bin/python3 avred.py --server amsi --file app/upload/E0CF9EE613F1FB79.test1.exe"
        # FIXME: This can be used as an oracle to gain information about other users filenames
        if 'avred.py' in cmdline and filename in cmdline:
            avredRuns = True
            break

    if avredRuns:
        # show log file
        filepathLog = os.path.join(current_app.config['UPLOAD_FOLDER'], filename + EXT_LOG)
        logData = ""
        if os.path.isfile(filepathLog):
            with open(filepathLog) as f:
                logData = f.read()
        return render_template('upload_tracker.html', logdata=logData)
    else:
        return redirect("/file/" + filename, code=302)


@views_upload.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check all required parameters
        if 'server' not in request.form or not request.form['server'].isalnum():
            # no haxxoring in server name
            logging.error('Invalid server name')
            return 'Invalid server name', 400
        serverName = request.form['server']
        if not 'file' in request.files or request.files['file'].filename == '':
            # If the user does not select a file, the browser submits an empty file without a filename
            logging.error('No selected file')
            return 'No file selected', 400
        fileName = request.files['file'].filename
        fileData = request.files['file'].read()

        # check if server is online
        try:
            serverUrl = current_app.config['AVRED_SERVERS'][serverName]
            response = requests.get(serverUrl, timeout=1)
            if not response.ok:
                return  'Server offline: ' + serverName, 400
        except requests.exceptions.Timeout:
            return  'Server offline: ' + serverName, 400

        # handle zip file: extract inner file
        if fileName.split(".")[-1] == "zip":
            # this all works on the file-like request.files['file']
            if not zipfile.is_zipfile(request.files['file']):
                logging.error('Not a valid zip file')
            filepaths = [] # do not scan the container itself, only scan contained files
            with zipfile.ZipFile(request.files['file']) as zip_f:
                if len(zip_f.infolist()) > 1:
                     logging.error("More than one file in zip: {}".format(len(zip_f.infolist())))
                     return 'More than one file in zip', 400

                for z_file in zip_f.infolist():
                    #extracted_path = save_file(z_file.filename, zip_f.read(z_file))
                    #filepaths.append(extracted_path)
                    fileName = z_file.filename
                    fileData = zip_f.read(z_file)

        if not allowed_file(fileName):
            logging.error("Invalid file ending: {}".format(fileName))
            return  'Unsupported file ending', 400

        # Notes:
        #   fileName:       test.exe
        #   secureFilename: abcd123.test.exe
        #   uploadsPath:    app/upload/abcd123.test.exe

        # file is allowed. store it
        secureFilename = getSecureFilename(fileName)
        uploadsPath = os.path.join(current_app.config['UPLOAD_FOLDER'], secureFilename)
        with open(uploadsPath, "wb") as f:
            f.write(fileData)

        # scan the (extracted) file in the background as separate process
        cli_scanner = current_app.config['AVRED_SCANNER']
        subprocess.Popen([sys.executable, cli_scanner, "--server", serverName, "--file", uploadsPath ], shell=False)

        # redirect to the upload tracker
        return redirect(url_for('views_upload.upload_tracker', filename=secureFilename))

    # else show upload HTML
    servers = []
    for serverName, serverUrl in current_app.config['AVRED_SERVERS'].items():
        status = 'Offline'
        try:
            response = requests.get(serverUrl, timeout=1)
            if response.ok:
                status = "Online"
        except requests.exceptions.Timeout:
            status = 'Offline'

        server = {
            'name': serverName,
            'url': serverUrl,
            'status': status,
        }
        servers.append(server)

    return render_template('upload.html',
        servers=servers,
        extensions=current_app.config['ALLOWED_EXTENSIONS'])


def allowed_file(filename):
    """Return true if filename has an allowed extension"""
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']


def getSecureFilename(filename):
    """Return filename with a random string prepended and securely encoded"""
    filename = secure_filename(filename)
    rand = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(6))
    filename = rand + "." + filename
    return filename
