#!/usr/bin/python3

import os
from flask import Flask, flash, request, redirect, url_for, render_template, send_from_directory
from werkzeug.utils import secure_filename
import random
import subprocess
#from waitress import serve
import glob
import pickle
from app  import app
from model.model import *

ALLOWED_EXTENSIONS = {'exe', 'ps1', 'docm', '.bin' }
EXT_INFO = ".outcome"
EXT_LOG = ".log"


@app.route("/")
def index():
    examples = os.listdir("app/examples/")
    return render_template('index.html', examples=examples)


@app.route('/examples/<path>')
def example(path):
    return send_from_directory('examples', path)


@app.route("/view_file/<filename>")
def view_file(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename + EXT_INFO)
    filepathLog = os.path.join(app.config['UPLOAD_FOLDER'], filename + EXT_LOG)
    logData = ""
    if os.path.isfile(filepathLog):
        with open(filepathLog) as f:
            logData = f.read()

    if os.path.isfile(filepath):
        return redirect("/file/" + filename, code=302)
    else:
        return render_template('view_file_refresh.html',
            logdata=logData)


@app.route("/files")
def files():
    if not app.config['LISTFILES'] == 'True':
        return render_template('index.html')

    examples = glob.glob(os.path.join(app.config['UPLOAD_FOLDER'], "*" + EXT_INFO))
    res = []
    for example in examples:
        name = os.path.basename(example[:-len(EXT_INFO)])
        res.append(name)
    return render_template('list_files.html',
        filenames=res)


@app.route("/files_results")
def files_resulsts():
    if not app.config['LISTFILES'] == 'True':
        return render_template('index.html')

    examples = glob.glob(os.path.join(app.config['UPLOAD_FOLDER'], "*" + EXT_INFO))
    outcomes = []
    for example in examples:
        name = example[:-len(EXT_INFO)]

        outcome, fileInfo, errStr = getFileData(name)
        if errStr is not None:
            print("Err: {} {}".format(example, errStr))
            continue

        outcomes.append(outcome)
    
    return render_template('list_files_results.html',
        outcomes=outcomes)


def getFileData(filename):
    verifyDataFile = filename + EXT_INFO
    logFilename = filename + EXT_LOG

    outcome: Outcome = None
    logData: str = None

    # Main file (exe, docx etc.)
    if not os.path.isfile(filename):
        print("File does not exist: " + filename)
        return None, None, 'File not found: ' + filename

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
    


@app.route("/file/<filename>")
def file(filename):
    filename: str = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    outcome, logData, errStr = getFileData(filename)
    if errStr is not None: 
        return "Error: " + errStr
    
    return render_template('file.html', 
        filename=filename, 
        outcome=outcome,
        logData=logData)


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
           

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

            rand = ''.join(random.choice('0123456789ABCDEF') for i in range(16))
            filename = rand + "." + filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            subprocess.Popen(["./avred.py", "--server", "amsi", "--file", filepath, 
                "--logtofile" ])

            return redirect(url_for('view_file', filename=filename))

    return render_template('upload.html')
