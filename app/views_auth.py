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
import psutil
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required

views_auth = Blueprint('views_auth', __name__)

login_manager = LoginManager()


class User(UserMixin):
    def __init__(self, username, password):
        self.id = 1  # Assuming a single user, so ID is hardcoded
        self.username = username
        self.password = password


@login_manager.user_loader
def load_user(user_id):
    if user_id == '1':
        return User('admin', 'password')
    
    
@views_auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = load_user('1')
        if user and user.password == password:
            login_user(user)
            return redirect('/')
    return render_template('login.html')
