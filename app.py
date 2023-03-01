import os
import argparse
from flask import Flask

from config import Config
from app.views import views


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('--listenip', type=str, help='IP to listen on', default="0.0.0.0")
	parser.add_argument('--listenport', type=int, help='Port to listen on', default=5000)
	parser.add_argument('--debug', action='store_true', help='Debug', default=False)
	args = parser.parse_args()

	config = Config()
	config.load()

	app = Flask(__name__, 
		static_folder='./app/static',
		template_folder='./app/templates')

	app.config['UPLOAD_FOLDER'] = './app/upload'
	app.config['EXAMPLE_FOLDER'] = './app/examples'

	app.config["TEMPLATES_AUTO_RELOAD"] = True
	app.config['SECRET_KEY'] = os.urandom(24)
	app.config['SESSION_TYPE'] = 'filesystem'
	app.config['AVRED_SERVERS'] = config.get('server')
	app.config['ALLOWED_EXTENSIONS'] = { 'exe', 'ps1', 'docm', 'bin' }
	app.config['LIST_FILES'] = "True"

	app.config.from_prefixed_env()

	app.register_blueprint(views)
	app.run(host=args.listenip, port=args.listenport, debug=args.debug)
