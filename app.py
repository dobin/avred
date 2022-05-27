#!/usr/bin/python3

from flask import Flask
import os
from flask import Flask, flash, request, redirect, url_for, render_template, send_from_directory
from werkzeug.utils import secure_filename
import random
import subprocess

UPLOAD_FOLDER = './upload'
ALLOWED_EXTENSIONS = {'exe'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

EXT_MATCHES = ".matches.json"
EXT_LOG = ".txt"

@app.route("/")
def hello_world():
    examples = os.listdir("examples/")
    return render_template('index.html', examples=examples)


@app.route('/examples/<path>')
def send_report(path):
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