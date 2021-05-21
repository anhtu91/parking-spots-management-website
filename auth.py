########################################################################################
######################          Import packages      ###################################
########################################################################################
from flask import Blueprint, render_template, redirect, url_for, request, flash, session, jsonify
from hashlib import sha256 #Covert to SHA256
from pymongo import MongoClient # Database connector
import os
from os import path
import requests

import smtplib #Email connection
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import jwt
import qrcode
import PIL
import configparser


#######################################################################################
# Current folder 

current_folder = os.path.dirname(os.path.abspath(__file__))

#######################################################################################
# Read config.conf

config = configparser.ConfigParser()

config.read(current_folder+'/config.conf')

#######################################################################################
# Geofence Tile38 Server configuration

ip_address_tile38 = config.get('Tile38', 'ip')
port_tile38 = config.get('Tile38', 'port')
http_link_tile38 = 'http://'+ip_address_tile38+':'+port_tile38+'/'
get_all_keys_tile38_link = http_link_tile38+'KEYS *'
get_field_name_base_link = http_link_tile38+'SCAN '

#######################################################################################
# Email configuration

smtp_server = config.get('Email', 'smtp_server')
sender_email = config.get('Email', 'email')
password = config.get('Email', 'password')

#######################################################################################
# Folder

mqtt_client_key_folder = config.get('Folder', 'mqtt_client_key') #Change if change name of mqtt client key
invite_qr_code_folder = config.get('Folder', 'invite_qr_code')

#######################################################################################
# Setup mongodb connection

ip_address_mongodb = config.get('Mongodb', 'ip') #change to correct IP of mongodb
port_mongodb = config.get('Mongodb', 'port') 

mongodb_host = os.environ.get('MONGO_HOST', ip_address_mongodb)
mongodb_port = int(os.environ.get('MONGO_PORT', port_mongodb))
client = MongoClient(mongodb_host, mongodb_port)    #Configure the connection to the database
db = client.mqtt    #Select the database
mqtt_user_collection = db.mqtt_user #Select the defined user collection
mqtt_acl_collection = db.mqtt_acl   #Select access control list of user collection

#######################################################################################
# QR Code 

qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )

#######################################################################################
# JWT

private_key = config.get('JWT', 'private_key') #Get JWT private key
jwt_algorithm = config.get('JWT', 'algorithm')

#######################################################################################
# MQTT certificate

require_info = config.get('MQTT_certificate', 'require_info')
valid_day = config.get('MQTT_certificate', 'valid_day')
size_of_key_to_generate_in_bits = config.get('MQTT_certificate', 'size_of_key_to_generate_in_bits')

#######################################################################################

auth = Blueprint('auth', __name__) # create a Blueprint object that we name 'auth'

@auth.route('/login', methods=['GET', 'POST']) # define login page path
def login(): # define login page fucntion
    if request.method=='GET': # if the request is a GET we return the login page
        return render_template('login.html')
    else: # if the request is POST the we check if the user exist and with te right password
        _username = request.form.get('username')
        _password = request.form.get('password')
        user_query = mqtt_user_collection.find_one({"username":_username})
                
        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the hashed password in the database
        if not user_query:
            flash('Please sign up before!', 'danger')
            return redirect(url_for('auth.signup'))
        elif sha256(_password.encode('utf-8')).hexdigest() != user_query["password"]:
            flash('Please check your login details and try again.', 'danger')
            return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page
        # if the above check passes, then we know the user has the right credentials
        session['username'] = _username
        return redirect(url_for('main.profile'))

@auth.route('/signup', methods=['GET', 'POST'])# we define the sign up path
def signup(): # define the sign up function
    if request.method=='GET': # If the request is GET we return the sign up page and forms
        return render_template('signup.html')
    else: # if the request is POST, then we check if the email doesn't already exist and then we save data
        _username = request.form.get('username')
        _password = request.form.get('password')
        _email = request.form.get('email')
        _mqttPassword = request.form.get('mqttPassword')

        user_query = mqtt_user_collection.find_one({"username":_username}) # if this returns a user, then the username already exists in database
        email_query = mqtt_user_collection.find_one({"email":_email})

        if user_query: # if a user is found, we want to redirect back to signup page so user can try again
            flash('Username already exists', 'danger')
            return redirect(url_for('auth.signup'))
        if email_query: # if email is found, we want to redirect back to signup page so user can try again
            flash('Email address already exists', 'danger')
            return redirect(url_for('auth.signup'))

        insert_new_user_to_database(_username, _password, _email) #Add new user info to database

        create_mqtt_certificate(_username, _mqttPassword) #Create MQTT Certificate and encryption by password

        send_signup_email(_username, _email) #Send confirmation email with MQTT Certificate to user

        flash('An email with MQTT certificate is sent to your email '+_email, 'success')
        return redirect(url_for('auth.signup'))

@auth.route('/logout') # define logout path
def logout(): #define the logout function
    session.clear() #session.pop('username')
    return redirect(url_for('main.index'))

@auth.route('/fieldname', methods=['POST'])
def get_fieldname_list(): #Get fieldname from selected keyid
    if 'username' in session:
        json_data = request.json
        selected_keyid = json_data['keyid']
        fieldname = get_field_name_from_keyid(selected_keyid)
        return jsonify(fieldname)

@auth.route('/invite', methods=['POST'])
def invite(): #Use to invite visitor
    if 'username' in session:
        try:
            json_data = request.json #Get json data from post request
            _keyid = json_data['keyid']
            _fieldname = json_data['fieldname']
            _date = json_data['date']
            _time = json_data['time']
            _email = json_data['email']

            invite_json = { #Create json
                "keyid": _keyid,
                "fieldname": _fieldname,
                "date": _date,
                "time": _time,
                "email": _email
            }
            #Create jwt from invite info using private key
            encoded = jwt.encode(invite_json, private_key, algorithm=jwt_algorithm)

            #Create qr code
            qr.add_data(encoded)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")
            if path.exists(current_folder+invite_qr_code_folder+'/'+session['username']) is False: #Check folder for user exist
                os.chdir(current_folder+invite_qr_code_folder)
                os.system('mkdir '+session['username']) #Create a folder for every user
            qr_file_path = current_folder+invite_qr_code_folder+"/"+session['username']+"/"+_email+'_'+_keyid+'_'+_fieldname+'_'+_date+'_'+_time+".png"
            iml = img.save(qr_file_path)
            
            #Send email to visitor
            send_invite_email(session['username'], _email, _keyid, _fieldname, _time, _date, qr_file_path)
            return jsonify({'result': 'Send successful invitation to your visitor'})
        except Exception as e:
            print('Error while sending email to visitor '+str(e))
            return jsonify({'result': 'Error while sending email to visitor'})
        

@auth.route('/addspots', methods=['POST'])
def add_spots(): #Add select spots to mongodb
    if 'username' in session:
        json_data = request.json #Get json data from post request
        _keyid = json_data['keyid']
        _fieldname = json_data['fieldname']
        _username = session['username']
        try:
            user_data = mqtt_user_collection.find_one({"username":_username}) #Find user query in mongodb
            all_selected_parking_spots = user_data['allSelectedLocations'] #Get selected parking spot of user
            
            if check_user_already_select_spot(_keyid, _fieldname, all_selected_parking_spots): #User select spot which already existed his selected parking spots
                return jsonify({'result': 'You have already selected this parking spot'})

            new_selected_parking_spot = {"keyID": _keyid, "fieldName": _fieldname, "inside": False}
            all_selected_parking_spots.append(new_selected_parking_spot) #Add new selected parking spot

            selected_locations = {"$set": {"allSelectedLocations":all_selected_parking_spots}}
            mqtt_user_collection.update_one({"username":_username}, selected_locations) #Update to mongodb

            return jsonify({'result': 'success', 'selectParkingSpots' : get_all_selected_parking_spots()})
        except Exception as e:
            print('Error while adding spot '+str(e))
            return jsonify({'result': 'Fail to add new parking spot '+_keyid+" - "+_fieldname})

@auth.route('/removespots', methods=['POST'])
def remove_spots(): #Remove select spots 
    if 'username' in session:
        json_data = request.json #Get json data from post request
        _keyid = json_data['keyid']
        _fieldname = json_data['fieldname']
        _username = session['username']
        try:
            user_data = mqtt_user_collection.find_one({"username":_username}) #Find user query in mongodb
            all_selected_parking_spots = user_data['allSelectedLocations'] #Get selected parking spot of user

            if check_user_already_select_spot(_keyid, _fieldname, all_selected_parking_spots): #User select spot which already existed his selected parking spots
                for spot in all_selected_parking_spots:
                    if spot['keyID'] == _keyid and spot['fieldName'] == _fieldname:
                        all_selected_parking_spots.remove(spot) #Remove spot from selected list
                        break

                selected_locations = {"$set": {"allSelectedLocations":all_selected_parking_spots}}
                mqtt_user_collection.update_one({"username":_username}, selected_locations) #Update to mongodb
                return jsonify({'result': 'success', 'selectParkingSpots' : get_all_selected_parking_spots()})
            else:
                return jsonify({'result': 'You have not selected this parking spot'})

        except Exception as e:
            print('Error while removing spot '+str(e))
            return jsonify({'result': 'Fail to remove parking spot '+_keyid+" - "+_fieldname})

@auth.route('/resendmqttcert', methods=['POST'])
def resend_mqtt_cert():
    if 'username' in session:
        try:
            json_data = request.json #Get json data from post request
            _pwd = json_data['pwd'] #Get new password

            create_mqtt_certificate(session['username'], _pwd) #Create new certificate with new password

            user_data = mqtt_user_collection.find_one({"username":session['username']}) #Find user query in mongodb
            email = user_data['email'] #Get email of user

            resend_mqtt_cert(session['username'], email)
            return jsonify({'result': 'Send new MQTT Certificate to your email successful'})
        except Exception as e:
            print('Error while resend mqtt certificate '+str(e))
            return jsonify({'result': 'Fail to send new MQTT Certificate'})


def get_all_selected_parking_spots(): #Get all selected parking spots of current user
    username = session['username']
    user_data = mqtt_user_collection.find_one({"username":username})
    all_selected_parking_spots = user_data['allSelectedLocations']
    parking_spots =[]

    for spot in all_selected_parking_spots:
        parking_spots.append({"keyid": spot['keyID'],"fieldname": spot['fieldName']})

    return parking_spots

def check_user_already_select_spot(_keyid, _fieldname, all_selected_parking_spots): #Check if user already selected parking spot. Return true if already selected and save in mongodb
    for spot in all_selected_parking_spots:
        if spot['keyID'] == _keyid and spot['fieldName'] == _fieldname:
            return True
    return False

def get_data_from_geofence_server(http_link): #Use to ask tile38
    r = requests.get(http_link)
    if r.status_code != 200:
        flash('No connection with geofence server - Tile38!', 'danger')
        return
    return_data = r.json()
    ok = return_data['ok']
    if ok is False:
        flash('Cannot get keyID from geofence server - Tile38!', 'danger')
        return
    return return_data

def get_key_id_from_geofence_server(): #Get all keyid from tile38
    return_data = get_data_from_geofence_server(get_all_keys_tile38_link)
    keyIDs = return_data['keys']
    return keyIDs

def get_field_name_from_keyid(keyid): #Get fieldname from keyid 
    return_data = get_data_from_geofence_server(get_field_name_base_link+keyid)
    fieldname = [] #get all field name which belongs to keyid
    objects = return_data['objects']

    for object in objects:
        fieldname.append(object['id'])

    return fieldname

def create_mqtt_certificate(_username, _mqttPassword): #Create MQTT Certificate and encryption by password
    os.chdir(current_folder+mqtt_client_key_folder)
    os.system('openssl genrsa -out '+_username+'.key '+size_of_key_to_generate_in_bits)
    os.system('openssl req -new -key '+_username+'.key -out '+_username+'.csr -subj "'+require_info+'"')
    os.system('openssl x509 -req -days '+valid_day+' -in '+_username+'.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out '+_username+'.pem')
    os.system('openssl pkcs12 -export -in '+_username+'.pem -inkey '+_username+'.key -name "$'+_username+' certificate/key" -out '+_username+'.p12 -password pass:'+_mqttPassword)
    
    if path.exists(current_folder+mqtt_client_key_folder+'/'+_username) is False:
        os.system('mkdir '+_username)

    os.system('mv '+_username+'.csr '+_username) #Move file to user folder
    os.system('mv '+_username+'.key '+_username)
    os.system('mv '+_username+'.p12 '+_username)
    os.system('mv '+_username+'.pem '+_username)

def insert_new_user_to_database(_username, _password, _email): #Insert new user to mongodb
    mqtt_user_post = {
        "username":_username,
        "password": sha256(_password.encode('utf-8')).hexdigest(),
        "email": _email,
        "allSelectedLocations": []
    }
        
    mqtt_acl_post = {

    }

    mqtt_user_collection.insert(mqtt_user_post)

def resend_mqtt_cert(username, receiver_email):
    subject = "Resend MQTT Certificate - Parking spots management system"
    body = "Dear "+username+",\n\nYou have requested for new MQTT Certificate. The MQTT Certificate for securing MQTT Connection by Owntracks can be found in attachment.\n\nBest regrad,\nFH Dortmund - Parking spots management system"
    files_path = [current_folder+mqtt_client_key_folder+'/ca.pem', current_folder+mqtt_client_key_folder+'/'+username+'/'+username+'.p12']
    send_email_to_user(receiver_email, files_path, subject, body)

def send_signup_email(username, receiver_email): #Send registration email to user
    subject = "Registration confirm - Parking spots management system"
    body = "Dear "+username+",\n\nYou have registered by Parking spots management system. MQTT Certificate for securing MQTT Connection by Owntracks can be found in attachment.\n\nBest regrad,\nFH Dortmund - Parking spots management system"
    files_path = [current_folder+mqtt_client_key_folder+'/ca.pem', current_folder+mqtt_client_key_folder+'/'+username+'/'+username+'.p12']
    send_email_to_user(receiver_email, files_path, subject, body)

def send_invite_email(username, receiver_email, keyid, fieldname, time, date, qr_file_path): #Send invitation email to user
    subject = "Invite to parking spots by "+username
    body = "Dear visitor,\n\nUser "+username+" has invited you to this following parking spot "+keyid+" - "+fieldname+" at "+time+" "+date+".\n\nBest regrad,\nFH Dortmund - Parking spots management system"
    files_path = [qr_file_path]
    send_email_to_user(receiver_email, files_path, subject, body)

def send_email_to_user(receiver_email, files_path, subject, body):
    # Create a multipart message and set headers
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    message["Bcc"] = receiver_email  # Recommended for mass emails

    # Add body to email
    message.attach(MIMEText(body, "plain"))

    for file_path in files_path:
        with open(file_path, "rb") as attachment:
            part = MIMEBase('application', "octet-stream")
            part.set_payload((attachment).read())
            # Encoding payload is necessary if encoded (compressed) file has to be attached.
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', "attachment; filename= %s" % os.path.basename(file_path))
            message.attach(part)

    # Start SMTP server at port 587
    server = smtplib.SMTP(smtp_server, 587)
    server.starttls()
    # Enter login credentials for the email you want to sent mail from
    server.login(sender_email, password)
    text = message.as_string()
    # Send mail
    server.sendmail(sender_email, receiver_email, text)

    server.quit()


