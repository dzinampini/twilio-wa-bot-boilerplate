from flask_restful import Resource, reqparse, abort
from flask import request, jsonify
from tomcat import api
from tomcat import mongo
from tomcat import mail
from tomcat import jwt
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from flask_mail import Message
import re
from ukpostcodeutils import validation
from flask_cors import cross_origin


from flask_jwt_extended import (JWTManager, jwt_required, create_access_token, create_refresh_token, 
                                get_jwt_identity, get_jwt_claims, fresh_jwt_required, 
                                jwt_refresh_token_required, verify_jwt_in_request, get_raw_jwt)

from tomcat.models.users import UserDao
from tomcat.models.revoked_tokens import RevokedTokenDao

cln_users = mongo.db.users
cln_tokens = mongo.db.revoked_tokens

jwt_secret = '*tomcat;#zw#finance'

@jwt.user_claims_loader
def add_claims_to_access_token(user):
    return {'active': user['active'], 'emp_id': user['_id']}

@jwt.user_identity_loader
def user_identity_lookup(user):
    return user['email']


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    try:
        jti = decrypted_token['jti']
        query = cln_tokens.find_one({'jti': jti})
        return bool(query) 
    except:
        return {'message':'Token revoked'}, 200

class Employees(Resource):
    @jwt_required
    def get(self):
        # TODO clean me
        # emp_id = get_jwt_claims()['client_id']  
        # user = cln_users.find_one({'_id': ObjectId(emp_id)}) 

        # if (user["roles"] == "employee"): 
        #     return {'message':'You are not permitted to view this data') 

        # else:
        #     return jsonify(UserDao.get_all_users())
        return jsonify(UserDao.get_all_users())

class Test(Resource):
    @cross_origin(supports_credentials=True)
    def post(self):
        return {'message': 'post success'}

    def options(self):
        return {'message': 'options success'}

    def get(self):
        return {'message': 'get success'} 


class Employee(Resource):
    @jwt_required
    def get(self):
        """
        this is for getting all user profiles (admins, employees and client admins) and not just employees, 
        """
        emp_id = get_jwt_claims()['client_id']  
        user = cln_users.find_one({'_id': ObjectId(emp_id)})

        return jsonify(user)
                
    @cross_origin(supports_credentials=True)
    def post(self):
        user_obj = request.get_json()
        
        email = user_obj['email']
        password = user_obj['password']
        user_obj['first_name'] = user_obj['name']
        role = user_obj['roles']

        if not re.match(r'^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$', email):
            return {'message':'Invalid email address'}, 200

        if len(password) < 6:
            return{'message':'Password must be greater than 6 characters in length'}, 200

        user = cln_users.find_one({'email': email})

        if user:
            return {"message":"Email address is already in use"}, 200

        user_obj['password'] = generate_password_hash(password)
        user_obj['date_joined'] = datetime.datetime.utcnow() 
        user_obj['active'] = False
        user_obj['profile_completeness'] = {
            'personal_information': False,
            'academic_qualifications': False,
            'work_experience': False,
            'contact_details': False,
            'references': False,
            'bank_details': False,
            'dbs': False
        }
        user_obj['availability'] = {
            'sunday': True,
            'monday': True,
            'tuesday': True,
            'wednesday': True,
            'thursday': True,
            'friday': True,
            'saturday': True
        }
        
        inserted_user_id = cln_users.insert_one(user_obj).inserted_id
        user_obj['_id'] = inserted_user_id

        activation_code = create_access_token(identity=user_obj, expires_delta=datetime.timedelta(days=2), fresh=True)

        message = f'Welcome to tomcat\n\nFollow this link to verify your account http://z3.dzinaishempini.com/employee/{activation_code}'
        email_message = Message(sender='mupini.tandi@gmail.com',
                                recipients=[email],
                                body=message,
                                subject='Activation Code')
        mail.send(email_message)
        
        return {
            "activation_code": activation_code, 
            "message":"success"
        } 

    @jwt_required
    def patch(self):
        emp_id = get_jwt_claims()['client_id']
        employee = cln_users.find_one({'_id': ObjectId(emp_id)})

        if not employee['active']:
            return {'message':'Activate your account first'}, 200

        #get the form data for updating user
        user_obj = request.get_json()
        title = user_obj['title']
        first_name = user_obj['first_name'].replace(" ","")
        last_name = user_obj['last_name']
        dob = user_obj['dob'] # date_of_birth
        gender = user_obj['gender']
        ethnicity = user_obj['ethnicity']

        if not first_name.isalpha():
            return {'message', 'Invalid first name'}, 200
        if not last_name.isalpha():
            return {'message', 'Invalid last name'}, 200

        dob_date = datetime.datetime.strptime(dob, "%Y-%m-%dT22:00:00.000Z") #%m/%d/%Y 2020-03-02T22:00:00.000Z 
        age_in_days = (datetime.datetime.today() - dob_date).days

        if(age_in_days < 6574.5): # 18 years, considering a year has 365.25 years        
            return {'message':'Employee must be 18 years or older'}, 200

        genders = ['female', 'male', 'other']
        if gender not in genders:
            return {'message': 'Invalid gender'}, 200

        ethinicities = ['black', 'white', 'mixed', 'asian', 'other']
        if ethnicity not in ethinicities:
            return {'message': 'Invalid ethnicity'}, 200

        update_user = cln_users.update(
            {'_id': ObjectId(emp_id)}, 
            {'$set': {
                'title': title, 
                'first_name':first_name.capitalize(), 
                'last_name':last_name.capitalize(),
                'dob':dob,
                'gender':gender,
                'ethnicity':ethnicity,
                'profile_completeness.personal_information': True
                }})
        return {'message': 'success'} 

    @jwt_required
    def delete(self):
        # user_obj = request.get_json()
        # supplied_email = user_obj['email'] //delete method does not take 3 args 

        token_email = get_jwt_claims()['email']  

        # if (supplied_email != token_email):
        #     return {'message':'Invalid email'}, 200

        employee = cln_users.find_one({'email': token_email})

        if not employee:
            return {'message':'Email not found'}, 200

        deleted_employee =  cln_users.delete_one({'email': token_email});
        
        message = f'Hello\nYour tomcat account has been successfully deleted. If this was not you, respond to this email'
        email_message = Message(sender='mupini.tandi@gmail.com',
                                recipients=[token_email],
                                body=message,
                                subject='Goodbye')
        mail.send(email_message)

        return jsonify({
            'message': 'success'
        }) 


class EmployeeLookup(Resource):
    @jwt_required
    def get(self):
        """
        this is for getting all user profiles (admins, employees and client admins) and not just employees, 
        """
        emp_id = request.args.get('employee')
        employee = cln_users.find_one({'_id': ObjectId(emp_id)})
        employee['password'] = 'you cant just find someones credentials that easy'

        return jsonify(employee)

class Admin(Resource):
    @cross_origin(supports_credentials=True)
    def post(self):
        user_obj = request.get_json()
        
        email = user_obj['email']

        if not re.match(r'^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$', email):
            return {'message':'Invalid email address'}, 200

        user = cln_users.find_one({'email': email})

        if user:
            return {"message":"Email address is already in use"}, 200

        # TODO: randomly get the password 
        password = '12341234'
        user_obj['password'] = generate_password_hash(password)
        user_obj['date_joined'] = datetime.datetime.utcnow() 
        user_obj['active'] = False
        
        inserted_user_id = cln_users.insert_one(user_obj).inserted_id
        user_obj['_id'] = inserted_user_id

        activation_code = create_access_token(identity=user_obj, expires_delta=datetime.timedelta(days=2), fresh=True)

        message = f'Hello you have been created a new account on tomcat. \n Your password is {password}\n Follow the following link to activate your account http://z3.dzinaishempini.com/verify/admin/{activation_code}'
        email_message = Message(sender='mupini.tandi@gmail.com',
                                recipients=[email],
                                body=message,
                                subject='Activation Code')
        mail.send(email_message)
        return {
            "activation_code": activation_code, 
            "message":"success"
        } 

class User(Resource):
    @jwt_required
    def get(self):
        emp_id = get_jwt_claims()['client_id']  
        admin = cln_users.find_one({'_id': ObjectId(emp_id)})

        if admin['roles'] != "admin":
            return {"message": "You cannot perform this action"}, 200
        
        user_id =  request.args.get('user') 
        user =  cln_users.find_one({'_id': ObjectId(user_id)})

        return jsonify(user)

    @jwt_required
    def delete(self):
        emp_id = get_jwt_claims()['client_id']  
        user = cln_users.find_one({'_id': ObjectId(emp_id)})

        if user['roles'] != "admin":
            return {"message": "You cannot perform this action"}, 200
        
        admin =  request.args.get('user') 
        deleted_employee =  cln_users.delete_one({'_id': ObjectId(admin)})

        return {
            "message":"success"
        } 
        


class Activate(Resource):
    @jwt_required 
    def post(self):
        try:
            verify_jwt_in_request()
                
        except (DecodeError, ValueError, TypeError, WrongTokenError):
            return {'message':'Something is wrong with your activation code'}, 200

        # decode error not working 
        # something to do wth propagate exceptions in _init but still error message is needed 

        user_email = get_jwt_claims()['email']

        employee = cln_users.find_one({'email': user_email})  
                        
        updated_acc = cln_users.update({'email': user_email}, {'$set': {'active': True}})

        # now destroy this token 
        return Logout.post(self)

        
            
class ResendToken(Resource):
    def post(self):
        user_obj = request.get_json()
        
        email = user_obj['email']

        employee = cln_users.find_one({'email': email})

        if not employee:
            return {'message':'Email not found'}, 200
        
        if employee['active']:
            return {'message':'Account already activated'}, 200

        employee_name = employee['name']
        employee_role = employee['roles']
        

        activation_code = create_access_token(identity=employee, expires_delta=datetime.timedelta(hours=2))

        message = f'Hello {employee_name}\n\n Here is your new account activation link http://z3.dzinaishempini.com/verify/{employee_role}/{activation_code}\n\ntomcat Team'
        email_message = Message(sender='mupini.tandi@gmail.com',
                                recipients=[email],
                                body=message,
                                subject='Account Activation Link')
        mail.send(email_message)

        return {
            'message': 'success',
            'activation_code': activation_code
        }

class Login(Resource):
    @cross_origin(supports_credentials=True)
    def post(self):
        # email = request.json.get('email')
        # password = request.json.get('password')
        user_obj = request.get_json()
        email = user_obj['email']
        password = user_obj['password']

        emp = cln_users.find_one({'email': email})

        if not emp:
            return { 'message':'No account matching email address'}, 200

        if not check_password_hash(emp['password'], password):
            return {'message':'Incorrect password'}, 200
        
        token_expiration = datetime.timedelta(days=2)

        access_token = create_access_token(identity=emp, expires_delta=token_expiration)

        profile_completeness = True
        pca = emp['profile_completeness'] #PCA - profile completeness array

        if(pca['personal_information'] == False):
            profile_completeness=False
        # if(pca['academic_qualifications'] == False):
        #     profile_completeness=False # not considering it at the moment 
        if(pca['bank_details'] == False):
            profile_completeness=False 
        if(pca['contact_details'] == False):
            profile_completeness=False
        # if(pca['dbs'] == False):
        #     profile_completeness=False # not considering it at the moment 
        # if(pca['references'] == False):
        #     profile_completeness=False # not considering it at the moment 
        # if(pca['work_experience'] == False):
        #     profile_completeness=False # not considering it at the moment 

        return {
            'message':'success',
            'access_token': access_token,
            'profile_completeness': profile_completeness
        }


class LoginAdmin(Resource):
    @cross_origin(supports_credentials=True)
    def post(self):
        # email = request.json.get('email')
        # password = request.json.get('password')
        user_obj = request.get_json()
        email = user_obj['email']
        password = user_obj['password']

        emp = cln_users.find_one({'email': email, 'roles':'admin'})

        if not emp:
            return { 'message':'No account matching admin email address'}, 200

        if not check_password_hash(emp['password'], password):
            return {'message':'Incorrect password'}, 200
        
        token_expiration = datetime.timedelta(days=2)

        access_token = create_access_token(identity=emp, expires_delta=token_expiration)

        return {
            'message':'success',
            'access_token': access_token,
            'active': emp['active']
        }

class ResetPassword(Resource):
    @jwt_required
    def post(self):
        # get the new password and confirm password 
        user_obj = request.get_json()
        password = user_obj['password']
        confirm_password = user_obj['confirm_password']

        # get employee details from the decoding token 
        token_email = get_jwt_claims()['email']
        employee = cln_users.find_one({'email': token_email})

        # check employee details
        if not employee:
            return {'message':'Employee not found'}, 200

    
        #check password strength 
        if len(password) < 6:
            return {'message':'Password must be greater than 6 characters in length'}, 200

        password_strength = bool(re.match('((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{6,15})', password))
        if(password_strength == False):
            return {'message':'Weak Password. Password must contain at least one symbol, one small letter, one capital letter, one digit and must be between 6 and 15 characters'}, 200

        if (password != confirm_password):
            return {'message':'Your 2 passwords do not match'}, 200

        # update the password 
        update_password = cln_users.update({'email': token_email}, {'$set': {'password': generate_password_hash(password)}})

        # generate new token for use 
        # new_token = create_access_token(identity=employee, expires_delta=datetime.timedelta(days=2))

        #inform employee via email
        message = f'Hello\nYour password has been successfully changed. If you are not the one who made this action, respond to this email asap'
        email_message = Message(
            sender='mupini.tandi@gmail.com',
            recipients=[token_email],
            body=message,
            subject='Password Changed'
        )
        mail.send(email_message)


        return jsonify({
            'message': 'success'
        })

class CheckOldPassword(Resource):
    @jwt_required
    def post(self):
        # get the new password and confirm password 
        user_obj = request.get_json()
        password = user_obj['old_password']

        # get employee details from the decoding token 
        email = get_jwt_claims()['email']
        employee = cln_users.find_one({'email': email})

        # check employee details
        if not employee:
            return {'message':'Employee not found'}, 200

        if not check_password_hash(employee['password'], password):
            return {'message':'Incorrect old password'}, 200

        return jsonify({
            'message': 'success'
        })


class ForgotPassword(Resource):
    def post(self):
        # get email address from form 
        user_obj = request.get_json()        
        email = user_obj['email']

        # check if employee truly exists
        employee = cln_users.find_one({'email': email})

        if not employee:
            return {'message':'Email not found'}, 200
        
        # generate a token for use to reset password and send link for doing that 
        new_token = create_access_token(identity=employee, expires_delta=datetime.timedelta(minutes=5))

        # inform employee via email
        # message = f'Hello\nVisit the following link to reset your password. Please note that the token expires in 5 minutes\nhttp://localhost:5000/employee_reset_password?new_token={new_token}'
        email_message = Message(
            sender='mupini.tandi@gmail.com',
            recipients=[email],
            body=message,
            subject='Activation Code')
        mail.send(email_message)

        return {
            'message': 'success', 
            'new_token': new_token
        }

class Logout(Resource):
    @jwt_required
    def post(self):
        emp_id = get_jwt_claims()['client_id']
        jti = get_raw_jwt()['jti']
        date_time_logged = datetime.datetime.utcnow() 

        try:
            inserted_token_id = cln_tokens.insert_one({'jti':jti,'employee':emp_id,'date_time_logged':date_time_logged}).inserted_id
            return {
                'message': 'success' 
            }
        # if there is an exception with revoked token how do we correct it  
        except (RevokedTokenError):
            return {
                'message': 'Token Error'
            }, 200

