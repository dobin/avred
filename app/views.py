#!/usr/bin/python3

from flask import Blueprint, current_app, flash, request, redirect, url_for, render_template
from werkzeug.utils import secure_filename
import os
import random
import subprocess
import pickle
import requests
import sys
import zipfile
import logging

from model.model import *
#from waitress import serve

EXT_INFO = ".outcome"
EXT_LOG = ".log"
FILES_SEP = ","

views = Blueprint('views', __name__)


@views.route("/")
def index():
    examples = os.listdir("app/examples/")
    return render_template('index.html', examples=examples)


@views.route("/view_file/<filename>")
def view_file(filename):
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename + EXT_INFO)
    if os.path.isfile(filepath):
        return redirect("/file/" + filename, code=302)

    filepathLog = os.path.join(current_app.config['UPLOAD_FOLDER'], filename + EXT_LOG)
    logData = ""
    if os.path.isfile(filepathLog):
        with open(filepathLog) as f:
            logData = f.read()
    return render_template('view_file_refresh.html', logdata=logData)


def get_filepaths(folder, ext):
    filenames = [f for f in os.listdir(folder) if f.endswith(ext)]
    return [os.path.join(folder, f) for f in filenames]


def parse_filenames(folder, filenames):
    existing = os.listdir(folder)
    parsed = [f+EXT_INFO for f in filenames if f+EXT_INFO in existing] # re-add .outcome
    return [os.path.join(folder, f) for f in parsed]


@views.route("/files")
def files():
    if not current_app.config['LIST_FILES']:
        return render_template('index.html')
    
    examples = get_filepaths(current_app.config['UPLOAD_FOLDER'], EXT_INFO)
    res = []
    for example in examples:
        name = os.path.basename(example[:-len(EXT_INFO)])
        res.append(name)
    return render_template('list_files.html', filenames=res)


@views.route("/files_results")
def files_results():
    if not current_app.config['LIST_FILES']:
        return render_template('index.html')

    files = request.args.get('files')
    if not files: # show all files if no specific files given
        filepaths = get_filepaths(current_app.config['UPLOAD_FOLDER'], EXT_INFO)
        refresh_needed = False
    else:
        files = files.split(FILES_SEP)
        filepaths = parse_filenames(current_app.config['UPLOAD_FOLDER'], files)
        refresh_needed = True

    outcomes = []
    for filepath in filepaths:
        filepath = filepath[:-len(EXT_INFO)]

        outcome, _, errStr = getFileData(filepath)
        if errStr is not None:
            print("Err: {} {}".format(filepath, errStr))
            continue

        outcomes.append(outcome)
    
    return render_template('list_files_results.html', outcomes=outcomes, refresh_needed=refresh_needed)


def getFileData(filepath):
    verifyDataFile = filepath + EXT_INFO
    logFilename = filepath + EXT_LOG

    outcome: Outcome = None
    logData: str = None

    # Main file (exe, docx etc.)
    if not os.path.isfile(filepath):
        print("File does not exist: " + filepath)
        return None, None, 'File not found: ' + filepath

    # log file
    logData = ""
    if os.path.isfile(logFilename):
        with open(logFilename) as f:
            logData = f.read()

    # Outcome
    outcome: Outcome = None
    if os.path.isfile(verifyDataFile):
        with open(verifyDataFile, "rb") as input_file:
            outcome = pickle.load(input_file)

    return outcome, logData, None


@views.route("/file/<filename>")
def file(filename):
    if filename != secure_filename(filename):
        flash('Invalid filename')
        return redirect('index.html')
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

    outcome, logData, errStr = getFileData(filepath)
    if errStr is not None: 
        return "Error: " + errStr
    
    return render_template('file.html', outcome=outcome, logData=logData)


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']


def get_secure_filepath(filename):
    filename = secure_filename(filename)
    rand = ''.join(random.choice('0123456789ABCDEF') for i in range(16))
    filename = rand + "." + filename
    return os.path.join(current_app.config['UPLOAD_FOLDER'], filename)


def save_file_obj(file_obj):
    filepath = get_secure_filepath(file_obj.filename)
    file_obj.save(filepath)
    return filepath


def save_file(filename, content):
    filepath = get_secure_filepath(filename)
    with open(filepath, "wb") as f:
        f.write(content)
    return filepath


@views.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            logging.error('No file part')
            return redirect(request.url)
        if 'server' not in request.form:
            logging.error('No server part')
            return redirect(request.url)

        # If the user does not select a file, the browser submits an empty file without a filename
        if not 'file' in request.files or request.files['file'].filename == '':
            logging.error('No selected file')
            return redirect(request.url)
        file = request.files['file']
        
        # no haxxoring in server name
        if not request.form['server'].isalnum():
            logging.error('Invalid server name')
            return redirect(request.url)
        avred_server = request.form['server']

        if file and allowed_file(file.filename):
            filepath = save_file_obj(file)
            filepaths = [filepath] # TODO Test the zip files

            # handle zip files (check for secure filenames, extract, correctly saving and scanning)
            if filepath.split(".")[-1] == "zip":
                if not zipfile.is_zipfile(filepath):
                    logging.error('Not a valid zip file')
                filepaths = [] # do not scan the container itself, only scan contained files
                with zipfile.ZipFile(filepath) as zip_f:
                    for z_file in zip_f.infolist():
                        extracted_path = save_file(z_file.filename, zip_f.read(z_file))
                        filepaths.append(extracted_path)

            # now scan the (extracted) file(s)
            cli_scanner = current_app.config['AVRED_SCANNER']
            for filepath in filepaths:
                subprocess.Popen([sys.executable, cli_scanner, "--server", avred_server, "--file", filepath, "--logtofile" ], shell=False)
            filenames = [os.path.basename(fp) for fp in filepaths]

            # show general results page if multiple files scanned
            if len(filenames) > 1:
                files = FILES_SEP.join(filenames)
                return redirect(url_for('views.files_results', files=files))

            # show individual results for single file
            return redirect(url_for('views.view_file', filename=filenames[0]))

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


### Examples related


@views.route("/example/<filename>")
def example(filename):
    filepath = os.path.join(current_app.config['EXAMPLE_FOLDER'], filename)

    outcome, logData, errStr = getFileData(filepath)
    if errStr is not None: 
        return "Error: " + errStr
    
    return render_template('file.html', outcome=outcome, logData=logData)


@views.route("/examples")
def examples_list():
    examples = get_filepaths(current_app.config['EXAMPLE_FOLDER'], EXT_INFO)

    outcomes = []
    for example in examples:
        filepath = example[:-len(EXT_INFO)]

        outcome, fileInfo, errStr = getFileData(filepath)
        if errStr is not None:
            print("Err: {} {}".format(example, errStr))
            continue

        outcomes.append(outcome)
    
    return render_template('list_files_results.html', outcomes=outcomes, examples=True)


@views.app_template_filter('hex')
def hex_filter(s):
    return s.hex()

@views.app_template_filter('mydate')
def date_filter(s):
    return s.strftime('%Y-%m-%d %H:%M:%S')