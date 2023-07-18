from flask import Blueprint, current_app, flash, request, redirect, url_for, render_template, send_file, make_response, session
from werkzeug.utils import secure_filename
import os
import logging
from flask_login import login_user, login_required, current_user
import io
from typing import List
from datetime import date

from app.views_auth import load_user

from model.model_base import Outcome
from model.model_data import Match
from utils import getOutcomesFromDir, getFileData, OutcomesToCsv

#from waitress import serve


views = Blueprint('views', __name__)


@views.before_request
def before_request():
    # if no password is set, just login the user so he has access to his 
    # /files (for @login_required api's).
    # thanks chatgpt

    if not 'showDetails' in session:
        session['showDetails'] = True

    if current_app.config["PASSWORD"] == "" and not current_user.is_authenticated:
        login_user(user = load_user('1'))


@views.route("/")
def index():
    return render_template('index.html')


@views.route("/settings")
def settings():
    showDetails = request.args.get('showDetails', 'No')
    if showDetails == 'on':
        session['showDetails'] = True
    else:
        session['showDetails'] = False

    referer = request.headers.get('Referer', '/')
    response = make_response(redirect(referer))
    return response



@views.route("/files")
@login_required
def files_list():
    outcomes: List[Outcome] = getOutcomesFromDir(current_app.config['UPLOAD_FOLDER'])
    return render_template('files_list.html', outcomes=outcomes)


@views.route("/filesAsCsv")
@login_required
def files_csv():
    outcomes: List[Outcome] = getOutcomesFromDir(current_app.config['UPLOAD_FOLDER'])
    csv = OutcomesToCsv(outcomes)
    filename = 'avred-' + date.today().strftime("%Y-%m-%d") + '.csv'

    response = make_response(csv)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = "attachment; filename={}".format(filename)
    return response


@views.route("/file/<filename>")
def file(filename):
    if filename != secure_filename(filename):
        flash('Invalid filename')
        return redirect('index.html')
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

    outcome, logData, errStr = getFileData(filepath)
    if errStr is not None or outcome is None or logData is None: 
        return "Error: " + errStr
    
    return render_template('file.html',
                           outcome=outcome, 
                           logData=logData,
                           servers=current_app.config['AVRED_SERVERS']
                           )


@views.route("/file/<filename>/download")
@login_required
def fileDownload(filename):
    filename = secure_filename(filename)
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    return send_file(filepath, as_attachment=True)


@views.route("/file/<filename>/outflank")
@login_required
def fileDownloadOutflank(filename):
    if filename != secure_filename(filename):
        flash('Invalid filename')
        return redirect('index.html')
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

    outcome, logData, errStr = getFileData(filepath)
    if errStr is not None or outcome is None or logData is None: 
        return "Error: " + errStr
    
    if not os.path.isfile(filepath):
        return "Error: File not found: " + filepath
    with open(filepath, 'rb') as file:
        fileData: bytearray = bytearray(file.read())

    for patch in outcome.outflankPatches:
        fileData[patch.offset:len(patch.replaceBytes)] = patch.replaceBytes

    return send_file(
        io.BytesIO(fileData),
        mimetype='application/octet-stream',
        as_attachment=True,
        attachment_filename=filename
    )

@views.route("/file/<filename>/downloadPatchMatch/<id>")
@login_required
def fileDownloadPatchMatch(filename, id):
    id = int(id)
    if filename != secure_filename(filename):
        flash('Invalid filename')
        return redirect('index.html')
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

    outcome, logData, errStr = getFileData(filepath)
    if errStr is not None or outcome is None or logData is None: 
        return "Error: " + errStr
    
    if not os.path.isfile(filepath):
        return "Error: File not found: " + filepath
    with open(filepath, 'rb') as file:
        fileData: bytearray = bytearray(file.read())

    match: Match = outcome.matches[id]
    len = match.size
    offset = match.fileOffset
    data = b"\x00" * len
    fileData[offset:offset+len] = data

    return send_file(
        io.BytesIO(fileData),
        mimetype='application/octet-stream',
        as_attachment=True,
        attachment_filename=filename
    )

@views.route("/file/<filename>/downloadPatchMatch/")
@login_required
def fileDownloadPatchFull(filename):
    if filename != secure_filename(filename):
        flash('Invalid filename')
        return redirect('index.html')
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

    outcome, logData, errStr = getFileData(filepath)
    if errStr is not None or outcome is None or logData is None: 
        return "Error: " + errStr
    
    if not os.path.isfile(filepath):
        return "Error: File not found: " + filepath
    with open(filepath, 'rb') as file:
        fileData: bytearray = bytearray(file.read())

    for match in outcome.matches:
        print("Patch: {} {} {}".format(match.idx, match.fileOffset, match.size))
        len = match.size
        offset = match.fileOffset
        data = b"\x00" * len
        fileData[offset:offset+len] = data

    return send_file(
        io.BytesIO(fileData),
        mimetype='application/octet-stream',
        as_attachment=True,
        attachment_filename=filename
    )


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
    outcomes = getOutcomesFromDir(current_app.config['EXAMPLE_FOLDER'])
    return render_template('files_list.html', outcomes=outcomes, examples=True)


@views.route("/example/<filename>/download")
def fileDownloadExample(filename):
    filename = secure_filename(filename)
    filepath = os.path.join(current_app.config['EXAMPLE_FOLDER'], filename)
    return send_file(filepath, as_attachment=True)


## Filters

@views.app_template_filter('hex')
def hex_filter(s):
    return s.hex()

@views.app_template_filter('hexint')
def hex_filter(s):
    return hex(s)

@views.app_template_filter('mydate')
def date_filter(s):
    if s is None: 
        return ''
    return s.strftime('%Y-%m-%d %H:%M:%S')

@views.app_template_filter('prettynumber')
def date_filter(s):
    return f"{s:,}"

@views.app_template_filter('nicebool')
def nicebool_filter(s):
    if s is True:
        return "y"
    else:
        return "n"
