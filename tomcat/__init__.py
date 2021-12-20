from flask import Flask, jsonify
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import json
from datetime import datetime, date
from time import time
from flask_mail import Mail
from flask_jwt_extended import JWTManager
from flask_restful import Api
from flask_cors import CORS, cross_origin
import logging

class JSONEncoder(json.JSONEncoder):
    """extend json-encoder class"""
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, (datetime, date)):
            return o.isoformat()
        return json.JSONEncoder.default(self, o)

application = app = Flask(__name__)
app.json_encoder = JSONEncoder

# change to using .env
app.config['SECRET_KEY'] = 'some secret key of mine'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/tomcat'
app.config['JWT_SECRET_KEY'] = '*tomcat;#zw#finance'

app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['JWT_BLACKLIST_ENABLED'] = True 
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

api = Api(app)

mail_settings = {
    "MAIL_SERVER": '',
    "MAIL_PORT": 0,
    "MAIL_USE_TLS": False,
    "MAIL_USE_SSL": True,
    "MAIL_USERNAME": '',
    "MAIL_PASSWORD": ''
}
app.config.update(mail_settings)

mongo = PyMongo(app, ssl=False) #TODO put this back to false after putting database back to the original state
mail = Mail(app)
jwt = JWTManager(app)
# logger = logging.getLogger('werkzeug') # grabs underlying WSGI logger
# handler = logging.FileHandler('test.log') # creates handler for the log file
# logger.addHandler(handler) # adds handler to the werkzeug WSGI logger
handler = logging.FileHandler("test.log")  # Create the file logger
app.logger.addHandler(handler)             # Add it to the built-in logger
app.logger.setLevel(logging.DEBUG)         # Set the log level to debug

CORS(app, support_credentials=True)

from tomcat.resources import employees, index

# employee endpoints
api.add_resource(employees.Employees, '/employees') # kill endpoint 
api.add_resource(employees.Employee, '/employee') 
api.add_resource(employees.EmployeeLookup, '/employee_lookup')
api.add_resource(employees.Login, '/login_employee')
api.add_resource(employees.Logout, '/logout_employee')
api.add_resource(employees.ForgotPassword, '/employee_forgot_password')
api.add_resource(employees.ResetPassword, '/employee_reset_password') 
api.add_resource(employees.CheckOldPassword, '/employee_check_old_password') 
api.add_resource(employees.Activate, '/activate_employee')
api.add_resource(employees.ResendToken, '/resend_token')

# tomcat clients endpoints
api.add_resource(index.Tomcat, '/tomcat') #post #get
