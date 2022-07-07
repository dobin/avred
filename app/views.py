#!/usr/bin/python3

import os
from flask import Flask, flash, request, redirect, url_for, render_template, send_from_directory
from werkzeug.utils import secure_filename
import random
import subprocess
from waitress import serve
import glob
import pickle
from app  import app
from model import FileData


ALLOWED_EXTENSIONS = {'exe', 'ps1', 'docm'}
EXT_INFO = ".pickle"
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
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename + EXT_INFO)
    filepathLog = os.path.join(app.config['UPLOAD_FOLDER'],filename + EXT_LOG)
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
    examples = glob.glob(os.path.join(app.config['UPLOAD_FOLDER'], "*" + EXT_INFO))
    res = []
    for example in examples:
        name = os.path.basename(example[:-len(EXT_INFO)])
        res.append(name)
    return render_template('file_list.html',
        filenames=res)


@app.route("/file/<filename>")
def file(filename):
    filename: str = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    fileContent: bytes = None
    matches = None

    # Main file
    if not os.path.isfile(filename):
        print("File does not exist")
        return 'File not found: ' + filename, 500
    with open(filename, 'rb') as f:
        fileContent = f.read()

    # VerifyData
    verifyDataFile = filename + EXT_INFO
    fileData: FileData = None
    if os.path.isfile(verifyDataFile):
        with open(verifyDataFile, "rb") as input_file:
            fileData = pickle.load(input_file)
            
    return render_template('file.html', 
        filename=filename, matches=fileData.matches, verifications=fileData.verifications)


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
                "--save", "--logtofile", logfilepath, "--verify"])

            return redirect(url_for('view_file', filename=filename))

    return render_template('upload.html')
