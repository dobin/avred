#!/usr/bin/python3

import os
from flask import Flask, flash, request, redirect, url_for, render_template, send_from_directory
from werkzeug.utils import secure_filename
import random
import subprocess
from waitress import serve
import json
from viewer import *
import glob
from app  import app

ALLOWED_EXTENSIONS = {'exe', 'ps1', 'docm'}
EXT_MATCHES = ".matches.json"
EXT_LOG = ".txt"


@app.route("/")
def index():
    examples = os.listdir("app/examples/")
    return render_template('index.html', examples=examples)


@app.route('/examples/<path>')
def example(path):
    return send_from_directory('examples', path)


@app.route("/view_file/<filename>")
def view_file(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename + EXT_MATCHES)
    filepathLog = os.path.join(app.config['UPLOAD_FOLDER'],filename + EXT_LOG)
    logData = ""
    if os.path.isfile(filepathLog):
        with open(filepathLog) as f:
            logData = f.read()

    if os.path.isfile(filepath):
        print("File exists!")
        matchData = None
        with open(filepath) as f:
            matchData = f.read()
            print(matchData)
        return render_template('view_file.html', 
            matches=matchData, logdata=logData)
    else:
        print("File does not exist! " + filepath)
        return render_template('view_file_refresh.html',
            logdata=logData)


@app.route("/files")
def files():
    examples = glob.glob(os.path.join(app.config['UPLOAD_FOLDER'], "*" + EXT_MATCHES))
    res = []
    for example in examples:
        name = example[:-13]
        res.append(name)
    return render_template('file_list.html',
        filenames=res)


@app.route("/file/<filename>")
def file(filename):
    filename: str = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    fileContent: bytes = None
    matches = None

    if not os.path.isfile(filename):
        print("File does not exist")
        return 'File not found: ' + filename, 500
    with open(filename, 'rb') as f:
        fileContent = f.read()

    matchesFile = filename + EXT_MATCHES
    if not os.path.isfile(matchesFile):
        print("File does not exist!")
        return 'File not found: ' + matchesFile, 500
    with open(matchesFile, 'r') as f:
        matches = json.load(f)

    matches = GetViewData(fileContent, matches, filename)
    verifyData = GetVerifyData(fileContent, matches, filename)

    return render_template('file.html', 
        matches=matches, filename=filename, verifyData=verifyData)


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

            logfilepath = filepath + ".txt"

            subprocess.Popen(["./avred.py", "--server", "Defender", "--file", filepath, 
                "--saveMatches", "--logtofile", logfilepath, "--verify"])

            return redirect(url_for('view_file', filename=filename))

    return render_template('upload.html')
