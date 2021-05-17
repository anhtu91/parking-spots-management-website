########################################################################################
######################          Import packages      ###################################
########################################################################################
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from hashlib import sha256 #Covert to SHA256
from pymongo import MongoClient # Database connector
import os
import requests
#from requests.api import request #HTTP get request

import smtplib #Email connection
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


#######################################################################################
# Geofence Tile38 Server configuration

ip_address_tile38 = '172.18.0.4'
port_tile38 = '9851'
http_link_tile38 = 'http://'+ip_address_tile38+':'+port_tile38+'/'
get_all_keys_tile38_link = http_link_tile38+'KEYS *'
get_field_name_base_link = http_link_tile38+'SCAN '

#######################################################################################
# Email configuration

subject = "Registration confirm - Parking spots management system"
smtp_server = "smtp.gmail.com"
sender_email = "tuoithantienchukodien@gmail.com"
password = "01672280954"

#######################################################################################
# MQTT folder

mqtt_client_key_folder = '/mqtt_client_key' #Change if change name of mqtt client key

#######################################################################################
# Setup mongodb connection

ip_address_mongodb = '172.18.0.5' #change to correct IP of mongodb
port_mongodb = '27017'

mongodb_host = os.environ.get('MONGO_HOST', ip_address_mongodb)
mongodb_port = int(os.environ.get('MONGO_PORT', port_mongodb))
client = MongoClient(mongodb_host, mongodb_port)    #Configure the connection to the database
db = client.mqtt    #Select the database
mqtt_user_collection = db.mqtt_user #Select the defined user collection
mqtt_acl_collection = db.mqtt_acl   #Select access control list of user collection

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

        send_email_to_user(_username, _email) #Send confirmation email with MQTT Certificate to user

        flash('An email with MQTT certificate is sent to your email '+_email, 'success')
        return redirect(url_for('auth.signup'))

@auth.route('/logout') # define logout path
def logout(): #define the logout function
    session.clear() #session.pop('username')
    return redirect(url_for('main.index'))

@auth.route('/fieldname', methods=['POST'])
def get_fieldname_list():
    selected_keyid = request.get_json(force=True)
    fieldname = get_field_name_from_keyid(selected_keyid)
    return tuple(fieldname)

def get_data_from_geofence_server(http_link):
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

def get_key_id_from_geofence_server():
    return_data = get_data_from_geofence_server(get_all_keys_tile38_link)
    keyIDs = return_data['keys']
    return keyIDs

def get_field_name_from_keyid(keyid):
    return_data = get_data_from_geofence_server(get_field_name_base_link+keyid)
    fieldname = [] #get all field name which belongs to keyid
    objects = return_data['objects']

    for object in objects:
        fieldname.append(object['id'])

    return fieldname

def create_mqtt_certificate(_username, _mqttPassword):
    #Create MQTT Certificate and encryption by password
    os.chdir(os.path.dirname(os.path.abspath(__file__))+mqtt_client_key_folder)
    os.system('openssl genrsa -out '+_username+'.key 2048')
    os.system('openssl req -new -key '+_username+'.key -out '+_username+'.csr -subj "/C=DE/ST=NRW/L=Dortmund/O=EMQX/CN=client"')
    os.system('openssl x509 -req -days 3650 -in '+_username+'.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out '+_username+'.pem')
    os.system('openssl pkcs12 -export -in '+_username+'.pem -inkey '+_username+'.key -name "$'+_username+' certificate/key" -out '+_username+'.p12 -password pass:'+_mqttPassword)

def insert_new_user_to_database(_username, _password, _email):
    mqtt_user_post = {
        "username":_username,
        "password": sha256(_password.encode('utf-8')).hexdigest(),
        "email": _email
    }
        
    mqtt_acl_post = {

    }

    mqtt_user_collection.insert(mqtt_user_post)

def send_email_to_user(username, receiver_email):
    body = "Hi, "+username+"\n\nYou have registered by Parking spots management system. MQTT Certificate for securing MQTT Connection by Owntracks can be found in attachment.\n\n Best regrad,\nFH Dortmund - Parking spots management system"

    # Create a multipart message and set headers
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    message["Bcc"] = receiver_email  # Recommended for mass emails

    # Add body to email
    message.attach(MIMEText(body, "plain"))

    files_path = [os.path.dirname(os.path.abspath(__file__))+'/mqtt_client_key/ca.pem', os.path.dirname(os.path.abspath(__file__))+'/mqtt_client_key/'+username+'.p12']

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


