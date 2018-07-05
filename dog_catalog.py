from flask import Flask, render_template, request
from flask import redirect, url_for, flash, jsonify
from flask import session as login_session
from sqlalchemy import create_engine
from sqlalchemy import desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, DogBreeds, User, DogTypes
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import bleach


app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Dogs Breed App"

engine = create_engine('sqlite:///dogbreeds.sqlite?check_same_thread=False')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data.decode("utf-8")
    print("access token received %s " % access_token)

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']

    url = 'https://graph.facebook.com/v3.0/me?fields=name,birthday,email,'
    url += 'gender,location,picture{url}&access_token=%s' % (access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1].decode('utf-8'))
    print(result)
    token = access_token
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = result
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]
    login_session['picture'] = data["picture"]["data"]["url"]

# The token must be stored in the login_session in order to properly logout,
# let's strip out the information before the equals sign in our token.
    stored_token = token
    login_session['access_token'] = stored_token

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += login_session['username']

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += login_session['username']
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Show all dog types
@app.route('/')
@app.route('/dogtypes')
def showDogTypes():
    dogtypes = session.query(DogTypes).order_by('type').all()
    latestAddedDogs = session.query(DogBreeds).order_by(
            desc(DogBreeds.datetime)).limit(5).all()
    if 'username' not in login_session:
        return render_template(
            'publicDogTypes.html',
            dogtypes=dogtypes, latestAddedDogs=latestAddedDogs)
    else:
        return render_template(
            'showDogTypes.html',
            dogtypes=dogtypes, latestAddedDogs=latestAddedDogs)


# Create a new dog type
@app.route('/dogtypes/new', methods=['GET', 'POST'])
def newDogType():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newDogType = DogTypes(id=random.randint(40, 999999),
                              type=request.form['newDogTypeName'],
                              user_id=login_session['user_id'])
        session.add(newDogType)
        flash('New Dog Type %s Successfully Created' % newDogType.type)
        session.commit()
        return redirect(url_for('showDogTypes'))
    else:
        return render_template('newDogType.html')


# Edit a dog type
@app.route('/dogtype/<int:id>/edit',
           methods=['GET', 'POST'])
def editDogType(id):
    dogtype = session.query(DogTypes).filter_by(
        id=id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if dogtype.user_id != login_session['user_id']:
        flash("You are not authorized to edit this type.")
        flash("Please create your own type in order to edit!")
        return redirect(url_for('showDogTypes'))
    if request.method == 'POST':
        if request.form['newDogBreedName']:
            dogtype.name = request.form['newDogBreedName']
            flash("%s Succesfully Edited!" % dogtype.name)
            return redirect(url_for('showDogTypes'))
    else:
        return render_template(
            'editDogType.html', id=id, dogtype=dogtype)


# Delete a dog type and all of the  breeds in it
@app.route('/dogtype/<int:id>/delete',
           methods=['GET', 'POST'])
def deleteDogType(id):
    dogtype = session.query(DogTypes).filter_by(
        id=id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if dogtype.user_id != login_session['user_id']:
        flash("You are not authorized to delete this type.")
        flash("Please create your own type in order to delete it!")
        return redirect(url_for('showDogTypes'))
    if request.method == 'POST':
        session.delete(dogtype)
        session.commit()
        flash('%s Successfully Deleted' % dogtype.type)
        return redirect(url_for('showDogTypes'))
    else:
        return render_template('deleteDogType.html', id=id, dogtype=dogtype)


# Show a dog breed
@app.route('/dogtype/<int:type_id>')
@app.route('/dogtype/<int:type_id>/breed/')
def showBreed(type_id):
    dogtype = session.query(DogTypes).filter_by(
        id=type_id).one()
    creator = getUserInfo(dogtype.user_id)
    dogs = session.query(DogBreeds).filter_by(
        type_id=type_id).all()
    if ('username' not in login_session or
       creator.id != login_session['user_id']):
        return render_template('publicBreed.html',
                               dogs=dogs,
                               dogtype=dogtype,
                               creator=creator)
    else:
        return render_template('showBreed.html',
                               dogs=dogs,
                               dogtype=dogtype,
                               creator=creator)


# Show a specific dog
@app.route('/dogtype/<int:type_id>/breed/<int:breed_id>')
def showBreedInfo(type_id, breed_id):
    dogtype = session.query(DogTypes).filter_by(id=type_id).one()
    breed = session.query(DogBreeds).filter_by(
        id=breed_id).one()
    creator = getUserInfo(dogtype.user_id)
    if 'username' not in login_session:
        return render_template('showBreedInfo.html',
                               breed=breed,
                               dogtype=dogtype,
                               creator=creator)
    else:
        return render_template('showBreedInfo.html',
                               breed=breed,
                               dogtype=dogtype,
                               creator=creator)


# Create a dog entry
@app.route('/dogtype/<int:type_id>/breed/new', methods=['GET', 'POST'])
def newDogBreed(type_id):
    if 'username' not in login_session:
        return redirect('/login')
    dogtype = session.query(DogTypes).filter_by(
        id=type_id).one()
    if login_session['user_id'] != dogtype.user_id:
        flash("You are not authorized to add a new dog breed to this type.")
        flash("Please create your own type in order to add one!")
        return redirect(url_for('showBreed', typ_id=type_id))
    if request.method == 'POST':
        newDogBreed = DogBreeds(
            id=random.randint(361, 999999),
            type_id=dogtype.id,
            name=request.form['name'],
            country=request.form['country'],
            image=request.form['image'],
            description=request.form['description'],
            user_id=dogtype.user_id)
        session.add(newDogBreed)
        session.commit()
        flash("%s added to the menu!" % (newDogBreed.name))
        return redirect(url_for('showBreed', type_id=type_id))
    else:
        return render_template('newDogBreed.html', type_id=type_id)


# Edit a dog
@app.route('/dogtype/<int:type_id>/breed/<int:breed_id>/edit',
           methods=['GET', 'POST'])
def editDogBreed(type_id, breed_id):
    if 'username' not in login_session:
        return redirect('/login')
    dogtype = session.query(DogTypes).filter_by(id=type_id).one()
    editedBreed = session.query(DogBreeds).filter_by(id=breed_id).one()
    if login_session['user_id'] != dogtype.user_id:
        flash("You are not authorized to edit breeds in this dog type.")
        return redirect(url_for('showBreed', typ_id=type_id))
    if request.method == 'POST':
        if request.form['name']:
            editedBreed.name = request.form['name']
        if request.form['country']:
            editedBreed.country = request.form['country']
        if request.form['image']:
            editedBreed.image = request.form['image']
        if request.form['description']:
            editedBreed.description = request.form['description']
        session.add(editedBreed)
        session.commit()
        flash("%s has been edited!" % (editedBreed.name))
        return redirect(url_for(c))
    else:
        return render_template('editDogBreed.html',
                               type_id=type_id,
                               breed_id=breed_id,
                               breed=editedBreed)


# Delete a dog
@app.route('/dogtype/<int:type_id>/breed/<int:breed_id>/delete',
           methods=['GET', 'POST'])
def deleteDogBreed(type_id, breed_id):
    if 'username' not in login_session:
        return redirect('/login')
    dogtype = session.query(DogTypes).filter_by(id=type_id).one()
    breedToDelete = session.query(DogBreeds).filter_by(id=breed_id).one()
    if login_session['user_id'] != dogtype.user_id:
        flash("You are not authorized to delete breeds in this dog type.")
        return redirect(url_for('showBreed', type_id=type_id))
    if request.method == 'POST':
        session.delete(breedToDelete)
        session.commit()
        flash("Dog breed has been deleted!")
        return redirect(url_for('showBreed', type_id=type_id))
    else:
        return render_template('deleteDogBreed.html',
                               type_id=type_id,
                               breed=breedToDelete)


# JSON APIs to view Dog Breed Informations
@app.route('/dogtypes/JSON')
def dogTypesJSON():
    dogtypes = session.query(DogTypes).all()
    return jsonify(Dogtypes=[i.serialize for i in dogtypes])


@app.route('/dogtype/<int:type_id>/JSON')
def breedsJSON(type_id):
    breeds = session.query(DogBreeds).filter_by(type_id=type_id).all()
    return jsonify(Breeds=[i.serialize for i in breeds])


@app.route('/dogtype/<int:type_id>/breed/<int:breed_id>/JSON')
def breedJSON(type_id, breed_id):
    dogtype = session.query(DogTypes).filter_by(id=type_id).one()
    breed = session.query(DogBreeds).filter_by(
        id=breed_id).one()
    return jsonify(Breed=[breed.serialize])


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showDogTypes'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showDogTypes'))


@app.template_filter('linkify')
def linkify(s):
    return bleach.linkify(s)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000, ssl_context=('adhoc'))
