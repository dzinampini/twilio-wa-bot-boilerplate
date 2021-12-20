from flask_restful import Resource, reqparse, abort
from flask import request, jsonify
from tomcat import api
from tomcat import mongo
from tomcat import mail
from tomcat import jwt
from tomcat import app
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from flask_mail import Message
import re
from ukpostcodeutils import validation
from flask_cors import cross_origin
from twilio.rest import Client

from flask_jwt_extended import (JWTManager, jwt_required, create_access_token, create_refresh_token, 
                                get_jwt_identity, get_jwt_claims, fresh_jwt_required, 
                                jwt_refresh_token_required, verify_jwt_in_request, get_raw_jwt)

from tomcat.models.users import UserDao
from tomcat.models.revoked_tokens import RevokedTokenDao
from tomcat.models.sessions import SessionsDao

cln_users = mongo.db.users
cln_tokens = mongo.db.revoked_tokens
cln_sessions = mongo.db.sessions

jwt_secret = '*tomcat;#zw#finance'

account_sid = '='
auth_token = ''
client = Client(account_sid, auth_token)

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

class Tomcat(Resource):
    @cross_origin(supports_credentials=True)
    def post(self):
        # app.logger.info('post reached')
        number = request.values.get('From', '')
        cleaned_number = re.sub('[^0-9]', '', number)
        sent_text = request.values.get('Body', '')

        # data = request.get_json()
        # cleaned_number = data['from']
        # sent_text = data['body']

        # check stage that number is at in terms on communication
        session = '0'
        stage = '0'
        transfer_to_agent = False
        invalid_response = False
        


        # filters.status = 'active'
        # filters.client = cleaned_number
        chat_session = SessionsDao.get('active', cleaned_number)
        if (chat_session):
            session = chat_session['session']
            stage = chat_session['stage']

        new_status = 'active'
        new_session = session
        new_stage = stage
        new_rating = 0

        welcome_message = 'Good day! How may we assist you today? Please reply with the number of the service that you require. \n 1. Company Information \n 2. Software products \n 3. Clients portfolio \n 4. Other services'
        transfer_to_agent_text = 'Please click this link to be transfered to an agent on support to handle queries today \n put link herer \n \n May you assist in rating our services'
        rating_text = 'Thank you for getting in touch with us. How would you rate our bot on a scale of 1 to 10'
        goodbye_text = 'Thank you for getting in touch with us.'
        invalid_response_text = 'Sorry this is not a valid response to the question we sent you. Try responding again'

        if (session == '0'):
            if (stage == '0'):                
                new_message = welcome_message
                new_stage = '1'
                # app.logger.info('It was stage 0')
            elif (stage == '1'):
                # app.logger.info('It was stage 1')
                if (sent_text == '1'):
                    new_stage = '0'
                    new_session = '1'
                    new_message = 'Our company Tomcat Private Limited is based in ... and was formed in 2007. \n \n Do you want to know more about us? \n 1. Yes \n 2. No'
                elif (sent_text == '2'):
                    new_stage = '0'
                    new_session = '2'
                    new_message = 'Here is a list of our software products. Which one do you want to learn more about ? \n 1. Reconsol \n 2. Hardcat \n 3. Stock management system'
                elif (sent_text == '3'):
                    new_stage = '0'
                    new_session = '3'
                    new_message = 'Here is a list of our clients. \n ThinkPad Pvt Ltd \nPython Entreprises \n Dell Inc \nEscape Investments \n \n Do you want to know more information about our clients ? \n 1. Yes 2. No'
                elif (sent_text == '4'):
                    new_stage = '0'
                    new_session = '4'
                    new_message = 'Here is a list of our services. Please select the one you are interested in \n 1. Networking \n 2. Hardware Repairing and Servicing \n 3. Software installations'    
                else: 
                    invalid_response = True
            else:
                # app.logger.info('It should be invalid response now')
                invalid_response = True

        elif (session == '1'): # company info
            if (stage == '0'):
                if (sent_text == '1'):
                    transfer_to_agent = True
                    new_stage = '1'
                elif (sent_text == '2'):
                    new_message = rating_text
                    new_stage = '2'
                else:
                    invalid_response = True
            elif (stage == '1'): # rating 
                # if (sent_text == '1' or sent_text == '2'):
                new_message = rating_text
                new_stage = '2'
                # else:
                # invalid_response = True
            elif (stage == '2'):
                if (sent_text == '1' or sent_text == '2' or sent_text == '3' or sent_text == '4' or sent_text == '5' or sent_text == '6' or sent_text == '7' or sent_text == '8' or sent_text == '9' or sent_text == '10'):
                    new_message = rating_text
                    new_rating = sent_text
                    new_status = 'closed'
                    new_message = goodbye_text
                else:
                    invalid_response = True
        elif (session == '2'): # software products
            satisfied_stage = '4'
            transfer_stage = '5'
            rating_stage = '6'
            did_you_get_assisted_text = '\n \nDid you manage to get all the assistance you wanted? \n 1. Yes \n 2. No'

            if (stage == '0'):
                if (sent_text == '1'): # Reconsol
                    software_product = 'Reconsol'
                    SessionsDao.update(chat_session['_id'], {'software_product': software_product})
                    new_message = 'What do you wish to know about the ' + software_product + '? \n \n 1. About the software \n 2. Installation instructions \n 3. Questionnaire \n 4. Something else'
                    new_stage = '1'
                elif (sent_text == '2'): # Hardcat
                    software_product = 'Hardcat'
                    SessionsDao.update(chat_session['_id'], {'software_product': software_product})
                    new_message = 'What do you wish to know about the ' + software_product + '? \n \n 1. About the software \n 2. Installation instructions \n 3. Questionnaire \n 4. Something else'
                    new_stage = '1'
                elif (sent_text == '3'): # Stock management
                    software_product = 'Stock management system'
                    SessionsDao.update(chat_session['_id'], {'software_product': software_product})
                    new_message = 'What do you wish to know about the ' + software_product + '? \n \n 1. About the software \n 2. Installation instructions \n 3. Questionnaire \n 4. Something else'
                    new_stage = '1'
                else:
                    invalid_response = True
            elif (stage == '1'):
                if (sent_text == '1'): # wanted to know about system
                    if (chat_session['software_product'] == 'Reconsol'):
                        new_message = 'Sent Reconsole about here ' + did_you_get_assisted_text
                    elif (chat_session['software_product'] == 'Hardcat'):
                        new_message = 'Sent Hardcat about here' + did_you_get_assisted_text
                    elif (chat_session['software_product'] == 'Stock management system'):
                        new_message = 'Sent Stock management system about here' + did_you_get_assisted_text
                    else: 
                        invalid_response = True
                    new_stage = rating_stage
                elif (sent_text == '2'): # wanted to know installation
                    if (chat_session['software_product'] == 'Reconsol'):
                        new_message = 'Sent Reconsole installation instructions here ' + did_you_get_assisted_text
                    elif (chat_session['software_product'] == 'Hardcat'):
                        new_message = 'Sent Hardcat installation instructions here ' + did_you_get_assisted_text
                    elif (chat_session['software_product'] == 'Stock management system'):
                        new_message = 'Sent Stock management system installation instructions here ' + did_you_get_assisted_text
                    else: 
                        invalid_response = True
                    new_stage = satisfied_stage
                elif (sent_text == '3'): # wanted to get questionnaire questions
                    if (chat_session['software_product'] == 'Reconsol'):
                        new_message = 'First questionnaire question on Reconsol'
                    elif (chat_session['software_product'] == 'Hardcat'):
                        new_message = 'First questionnaire question on Hardcat'
                    elif (chat_session['software_product'] == 'Stock management system'):
                        new_message = 'First questionnaire question on Stock management system'
                    else: 
                        invalid_response = True
                    new_stage = '2'
                elif (sent_text == '4'): # wants something else not listed
                        new_message = transfer_to_agent_text
                        new_stage = transfer_stage
                else:
                    invalid_response = True
            elif (stage == '2'): # Questionnaire question 2
                if (chat_session['software_product'] == 'Reconsol'):
                    new_message = 'Second questionnaire question on Reconsol'
                elif (chat_session['software_product'] == 'Hardcat'):
                    new_message = 'Second questionnaire question on Hardcat'
                elif (chat_session['software_product'] == 'Stock management system'):
                    new_message = 'Second questionnaire question on Stock management system'
                new_stage = '3'
            elif (stage == '3'): # Questionnaire question 3
                if (chat_session['software_product'] == 'Reconsol'):
                    new_message = 'Third questionnaire question on Reconsol'
                elif (chat_session['software_product'] == 'Hardcat'):
                    new_message = 'Third questionnaire question on Hardcat'
                elif (chat_session['software_product'] == 'Stock management system'):
                    new_message = 'Third questionnaire question on Stock management system' 
                new_stage = transfer_stage
            elif (stage == '4'):  # satisified
                if (sent_text == '1'): # yes i got assisted
                    new_message = rating_text
                    new_stage = rating_stage
                elif (sent_text == '2'): # No I need mre help
                    transfer_to_agent = True
                    new_stage = transfer_stage
                else:
                    invalid_response = True
            elif (stage == '5'):  # after transfer to agent or after questionnaire
                new_message = rating_text
                new_stage = rating_stage
            elif (stage == '6'): # rating stage
                if (sent_text == '1' or sent_text == '2' or sent_text == '3' or sent_text == '4' or sent_text == '5' or sent_text == '6' or sent_text == '7' or sent_text == '8' or sent_text == '9' or sent_text == '10'):
                    new_rating = sent_text
                    new_status = 'closed'
                    new_message = goodbye_text
                else:
                    invalid_response = True
        elif (session == '3'): # clients/portfolio
            if (stage == '0'):
                if (sent_text == '1'):
                    transfer_to_agent = True
                    new_stage = '1'
                elif (sent_text == '2'):
                    new_message = rating_text
                    new_stage = '2'
                else:
                    invalid_response = True
            elif (stage == '1'): # rating 
                # if (sent_text == '1' or sent_text == '2'):
                new_message = rating_text
                new_stage = '2'
                # else:
                # invalid_response = True
            elif (stage == '2'):
                if (sent_text == '1' or sent_text == '2' or sent_text == '3' or sent_text == '4' or sent_text == '5' or sent_text == '6' or sent_text == '7' or sent_text == '8' or sent_text == '9' or sent_text == '10'):
                    new_message = rating_text
                    new_rating = sent_text
                    new_status = 'closed'
                    new_message = goodbye_text
                else:
                    invalid_response = True
        elif (session == '4'): # other services
            if (stage == '0'):
                if (sent_text == '1' or sent_text == '2' or sent_text == '3'):
                    new_stage = '2'
                    new_message = 'Please describe your problem to our technicians. Be as more descriptive as possible'
                else:
                    invalid_response = True
            elif (stage == '2'): # booking
                new_message = 'Sorry I could not come up with a quotation for what you want but I can still make a booking for you. When do you desire to have the problem fixed?'
                new_stage = '3'
            elif (stage == '3'): # booking
                new_message = rating_text
                new_stage = '4'
            elif (stage == '4'):
                if (sent_text == '1' or sent_text == '2' or sent_text == '3' or sent_text == '4' or sent_text == '5' or sent_text == '6' or sent_text == '7' or sent_text == '8' or sent_text == '9' or sent_text == '10'):
                    new_message = rating_text
                    new_rating = sent_text
                    new_status = 'closed'
                    new_message = goodbye_text
                else:
                    invalid_response = True

        if (invalid_response == False):
            # store the new values and the sent text and the new posed question
            if (transfer_to_agent == True):
                new_message = transfer_to_agent_text
                # new_status = 'closed'

            if chat_session:
                # app.logger.info(chat_session['_id'])
                chat_id = chat_session['_id']
                more_update_data = {
                    'session': new_session,
                    'stage': new_stage,
                    'status': new_status,
                    'rating': new_rating,
                }
                update_session = cln_sessions.update(
                    {'_id': ObjectId(chat_id)}, 
                    {
                        '$push': {
                            "messages_history": {
                                '$each': [ 
                                    { 
                                        "sent_message": sent_text, 
                                        "response": new_message, 
                                    }
                                ],
                            },
                        },
                        '$set': more_update_data,
                    },
                )
            else:
                new_session_document = {
                    'session': new_session,
                    'status': 'active',
                    'stage': new_stage,
                    'client': cleaned_number,
                    'messages_history': [
                        {
                            'sent_message': sent_text,
                            'response': new_message,
                        },
                    ] 
                }
                SessionsDao.add(new_session_document)
        else:
            new_message = invalid_response_text

        # send the new posed question
        message_body = new_message
        recipient = 'whatsapp:+'+cleaned_number
        Tomcat.get(self, message_body, recipient)
        

        return {
            'success': True,
            'message': new_message,
        }

    def get(self, message, recipient):
        # app.logger.info('get reached')
        message = client.messages.create(
            body=message,
            from_='whatsapp:+14155238886',
            to=recipient
        )
        # app.logger.info(recipient)
        # app.logger.info(message)
        # print(message.sid)
        return {'message': 'get success'}
