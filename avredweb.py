#!/usr/bin/python3

import os
import argparse
from flask import Flask

from config import Config
from app.views import views
from app.views_upload import views_upload
from app.views_auth import views_auth, login_manager
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required



if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('--listenip', type=str, help='IP to listen on', default="0.0.0.0")
	parser.add_argument('--listenport', type=int, help='Port to listen on', default=5000)
	parser.add_argument('--debug', action='store_true', help='Debug', default=False)
	args = parser.parse_args()

	config = Config()
	config.load()
	root_folder = os.path.dirname(__file__)
	app_folder = os.path.join(root_folder, 'app')

	app = Flask(__name__, 
		static_folder=os.path.join(app_folder, 'static'),
		template_folder=os.path.join(app_folder, 'templates')
	)

	app.config['UPLOAD_FOLDER'] = os.path.join(app_folder, 'upload')
	app.config['EXAMPLE_FOLDER'] = os.path.join(app_folder, 'examples')

	app.config['TEMPLATES_AUTO_RELOAD'] = True
	app.config['SECRET_KEY'] = os.urandom(24)
	app.config['SESSION_TYPE'] = 'filesystem'
	app.config['AVRED_SERVERS'] = config.get('server')
	app.config['PASSWORD'] = config.get('password')
	app.config['AVRED_SCANNER'] = os.path.join(root_folder, 'avred.py')
	app.config['ALLOWED_EXTENSIONS'] = { 'exe', 'dll', 'ps1', 'docm', 'bin', 'lnk' }

	app.config.from_prefixed_env()

	for key in ('UPLOAD_FOLDER', 'EXAMPLE_FOLDER', 'ALLOWED_EXTENSIONS',):
		print("{}: {}".format(key, app.config[key]))
	print("")

	app.register_blueprint(views)
	app.register_blueprint(views_upload)
	app.register_blueprint(views_auth)

	login_manager.init_app(app)

	app.run(host=args.listenip, port=args.listenport, debug=args.debug)
