import os
#from app import app
from flask import Flask
from config import Config
from app.views import views

if __name__ == "__main__":
	port = int(os.environ.get("PORT", 5000))
	debug = os.environ.get("DEBUG", True)
	
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
	app.run(host='0.0.0.0', port=port, debug=debug)
