from flask import Flask
from flask import Blueprint

api = Blueprint('api',__name__)

app = Flask(__name__)

from . import post,user,comment,decorator,errors

def createApp(config_name):

    from api_1_0 import api as api_1_0_blueprint

    app.register_blueprint(api_1_0_blueprint, url_prefix='/api/v1.0')

