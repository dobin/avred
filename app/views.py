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

views = Blueprint('views', __name__)


@views.route("/")
def index():
    examples = os.listdir("app/examples/")
    return render_template('index.html', examples=examples)


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

    filepaths = get_filepaths(current_app.config['UPLOAD_FOLDER'], EXT_INFO)
    outcomes = []
    for filepath in filepaths:
        filepath = filepath[:-len(EXT_INFO)]

        outcome, _, errStr = getFileData(filepath)
        if errStr is not None:
            logging.error("Err parsing file: {} {}".format(filepath, errStr))
            continue

        outcomes.append(outcome)
    
    return render_template('list_files_results.html', outcomes=outcomes)


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
    else:
        return None, None, 'File not found: ' + logFilename

    # Outcome
    outcome: Outcome = None
    if os.path.isfile(verifyDataFile):
        with open(verifyDataFile, "rb") as input_file:
            outcome = pickle.load(input_file)
    else:
        return None, None, 'File not found: ' + verifyDataFile

    return outcome, logData, None


@views.route("/file/<filename>")
def file(filename):
    if filename != secure_filename(filename):
        flash('Invalid filename')
        return redirect('index.html')
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

    outcome, logData, errStr = getFileData(filepath)
    if errStr is not None or outcome is None or logData is None: 
        return "Error: " + errStr
    
    return render_template('file.html', outcome=outcome, logData=logData)


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


## Filters

@views.app_template_filter('hex')
def hex_filter(s):
    return s.hex()

@views.app_template_filter('mydate')
def date_filter(s):
    return s.strftime('%Y-%m-%d %H:%M:%S')

@views.app_template_filter('prettynumber')
def date_filter(s):
    return f"{s:,}"
