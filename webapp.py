from flask import Flask, redirect, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth
from flask import render_template
from flask import flash
import pprint
import os

#
app = Flask(__name__)

app.debug = True 
app.secret_key = os.environ['SECRET_KEY']
oauth = OAuth(app)

github = oauth.remote_app(
    'github',
    consumer_key=os.environ['GITHUB_CLIENT_ID'], 
    consumer_secret=os.environ['GITHUB_CLIENT_SECRET'], 
    request_token_params={'scope': 'user:email'},
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',  
    authorize_url='https://github.com/login/oauth/authorize'


@app.context_processor
def inject_logged_in():
    return {"logged_in":('github_token' in session)}

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():   
    return github.authorize(callback=url_for('authorized', _external=True, _scheme='https'))                                                                                                                   

@app.route('/logout')
def logout():
    session.clear()
    return render_template('message.html', message='You were logged out')

@app.route('/login/authorized')
def authorized():
    resp = github.authorized_response()
    if resp is None:
        session.clear()
        flash('Access denied: reason=' + request.args['error'] + ' error=' + request.args['error_description'])     
    else:
        try:
            
            session['github_token']=(resp['access_token'],'')
            session['user_data']=github.get('user').data
            flash('You were successfully logged in as ' +  session['user_data']['login'])  
        except:
           
            session.clear()
            flash('Unable to login. Please try again.')
    return render_template('home.html')


@app.route('/page1')
def renderPage1():
    if 'user_data' in session:
        user_data_pprint = pprint.pformat(session['user_data']
    else:
        user_data_pprint = '';
    return render_template('page1.html',dump_user_data=user_data_pprint)

@app.route('/page2')
def renderPage2():
    countDRACULA = 0
    if 'user_data' in session:
        if 'public_repos' in session['user_data']:
            countDRACULA = session['user_data']['public_repos']
    return render_template('page2.html', publicrepocount = countDRACULA)

                                          
@github.tokengetter
def get_github_oauth_token():
    return session.get('github_token')


if __name__ == '__main__':
    app.run()
    
   
    
