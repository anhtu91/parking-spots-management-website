########################################################################################
######################          Import packages      ###################################
########################################################################################
from flask import Blueprint, render_template, session, request
from flask import Flask
import os

from auth import get_key_id_from_geofence_server, get_all_selected_parking_spots, config

########################################################################################
# our main blueprint
main = Blueprint('main', __name__)

@main.route('/') # home page that return 'index'
def index():
    return render_template('index.html')

@main.route('/profile') # profile page that return 'profile'
def profile():
    try:
        if 'username' in session:
            keyids = get_key_id_from_geofence_server()
            all_selected_parking_spots = get_all_selected_parking_spots()
            return render_template('profile.html', name=session['username'], keyids=keyids, user_parking_spots=all_selected_parking_spots)
        else:
            return render_template('index.html')
    except Exception as e:
        return render_template('index.html', error_message="Connection error. Please contact admin for more information!")
        
if __name__ == '__main__':
    app = Flask(__name__) # creates the Flask instance, __name__ is the name of the current Python module
    app.config['SECRET_KEY'] = config.get('SecretKey', 'key') # it is used by Flask and extensions to keep data safe
    
    from auth import auth as auth_blueprint
    # blueprint for auth parts of app
    app.register_blueprint(auth_blueprint)
    # blueprint for non-auth parts of app
    app.register_blueprint(main)

    env = os.environ.get('APP_ENV', 'development')
    webport = int(os.environ.get('PORT', 5000))
    debug = False if env == 'production' else True
    app.run(host='0.0.0.0', port=webport, debug=debug)