from flask import Flask

UPLOAD_FOLDER = './app/upload'
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.jinja_env.auto_reload = True
app.config["TEMPLATES_AUTO_RELOAD"] = True

from app import views
