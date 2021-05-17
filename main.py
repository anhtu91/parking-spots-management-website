########################################################################################
######################          Import packages      ###################################
########################################################################################
from flask import Blueprint, render_template, session, flash
from flask import Flask
import os
from auth import get_key_id_from_geofence_server

########################################################################################
# our main blueprint
main = Blueprint('main', __name__)

@main.route('/') # home page that return 'index'
def index():
    return render_template('index.html')

@main.route('/profile') # profile page that return 'profile'
def profile():
    if 'username' in session:
        keyIDs = get_key_id_from_geofence_server()
        return render_template('profile.html', name=session['username'], keyIDs=keyIDs)
    else:
        return render_template('index.html')


if __name__ == '__main__':
    app = Flask(__name__) # creates the Flask instance, __name__ is the name of the current Python module
    app.config['SECRET_KEY'] = 'Anh.Tu.Nguyen-anhtu91@gmail.com-FH-Dortmund-2021' # it is used by Flask and extensions to keep data safe
    
    from auth import auth as auth_blueprint
    # blueprint for auth parts of app
    app.register_blueprint(auth_blueprint)
    # blueprint for non-auth parts of app
    app.register_blueprint(main)

    env = os.environ.get('APP_ENV', 'development')
    webport = int(os.environ.get('PORT', 5000))
    debug = False if env == 'production' else True
    app.run(host='0.0.0.0', port=webport, debug=debug)