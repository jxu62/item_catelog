# ======================================
# Import
# ======================================
import random
import string
import httplib2
import json
import requests

from database_setup import *
from functools import wraps
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker

from flask import session as login_session
from flask import make_response
from flask import (Flask,
                   render_template,
                   request,
                   redirect,
                   jsonify,
                   url_for,
                   flash)

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

# ======================================
# Flask Object Creation
# ======================================
app = Flask(__name__)

# ======================================
# GConnect Read from client secrets
# ======================================
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"

# ======================================
# DB instance created and linked
# ======================================
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# ======================================
# Funct to do the login check
# ======================================


def checkLogin(funct):
    @wraps(funct)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in login_session:
            return redirect(url_for('showLogin'))
        return funct(*args, **kwargs)
    return decorated_function

# ======================================
# Google Single Sign On (SSO)
# ======================================


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(
        string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('auth_page.html', STATE=state)

# Google SSO


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
        oauth_flow = flow_from_clientsecrets(
            'client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = (
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
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
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.to_json()
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    return "Welcome!"


# ======================================
# SSO sign out
# ======================================


@app.route('/gdisconnect')
def gdisconnect():
    # only disconnect a connected user
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-type'] = 'application/json'
        return response
    # execute HTTP GET request to revoke current token
    access_token = credentials.access_token
    url = (
        'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

    else:
        # valid token, proceed to reset current login session
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']

        response = make_response(
            json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/disconnect')
def disconnect():
    gdisconnect()
    del login_session['gplus_id']
    del login_session['username']
    del login_session['email']
    del login_session['user_id']
    del login_session['provider']
    flash("You are now signed out.")
    return redirect(url_for('showCatalog'))

# ======================================
# Category Basic Functions-C, R, U, D
# ======================================


# C
@app.route('/all/newcategory', methods=['GET', 'POST'])
@checkLogin
def createCategory():
    if request.method == 'POST':
        """first check the user information"""
        if 'user_id' not in login_session and 'email' in login_session:
            login_session['user_id'] = getUserID(login_session['email'])

        """Check if name is filled"""
        if (request.form['name'] == ''):
            flash("You must enter something for category name!")
            return redirect(url_for('showCatalog'))
        """Create the query for getting the category added"""
        entry = Category(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(entry)
        session.commit()
        flash("Your new category is added!")
        return redirect(url_for('showCatalog'))

    else:
        return render_template('add_cat.html')

# R


@app.route('/')
@app.route('/all/')
def showCatalog():
    categories = session.query(Category).all()
    items = session.query(
        CatalogItem).order_by(CatalogItem.id.desc()).limit(10)
    count = items.count()

    """This is to make sure even if user not signed in,
    they could still view the items on the website"""
    if 'username' in login_session:
        return render_template(
            'signed_in_landing.html', categories=categories,
            items=items, quantity=count)
    else:
        return render_template(
            'not_signed_in_landing.html', categories=categories,
            items=items, quantity=count)

# U


@app.route('/all/<int:category_id>/edit/', methods=['GET', 'POST'])
@checkLogin
def editCategory(category_id):
    editedCategory = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(editedCategory.user_id)
    """Make sure the current user is only modifying his or her own stuff"""
    if creator.id != login_session['user_id']:
        flash("You are not authorized! This is %s 's stuff" % creator.name)
        return redirect(url_for('showCatalog'))

    if request.method == 'POST':
        """Make sure the edit has something"""
        if request.form['name']:
            editedCategory.name = request.form['name']
            flash('Category Successfully Edited')
            return redirect(url_for('showCatalog'))
    else:
        return render_template('edit_cat.html', category=editedCategory)

# D


@app.route('/all/<int:category_id>/delete/', methods=['GET', 'POST'])
@checkLogin
def deleteCategory(category_id):
    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(categoryToDelete.user_id)
    """Make sure the current user is only deleting his or her own stuff"""
    if creator.id != login_session['user_id']:
        flash("You are not authorized! This is %s 's stuff" % creator.name)
        return redirect(url_for('showCatalog'))

    if request.method == 'POST':
        session.delete(categoryToDelete)
        session.commit()
        flash(categoryToDelete.name + ' is successfully Deleted!')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('delete_cat.html', category=categoryToDelete)

# ======================================
# Item Baisc Func.-C, R, U, D
# ======================================

# C


@app.route('/all/item/newitem', methods=['GET', 'POST'])
@checkLogin
def newCatalogItem():
    categories = session.query(Category).all()
    if request.method == 'POST':

        """Check if name is filled"""
        if (request.form['name'] == ''):
            flash("You must enter something for item name!")
            return redirect(url_for('showCatalog'))

        entry = CatalogItem(
            name=request.form['name'],
            description=request.form['description'],
            price=request.form['price'],
            category_id=request.form['category'],
            user_id=login_session['user_id'])
#       print entry
        session.add(entry)
        session.commit()

        flash("You added an item!")
        return redirect(url_for('showCatalog'))
    else:
        return render_template('add_item.html', categories=categories)

# R - list information about specific item


@app.route('/all/<int:category_id>/item/<int:catalog_item_id>/')
def showOneItem(category_id, catalog_item_id):
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(CatalogItem).filter_by(id=catalog_item_id).one()
    creator = getUserInfo(category.user_id)

    return render_template(
        'specific_item.html', category=category,
        item=item, creator=creator)

# R - list all items of a specific category


@app.route('/all/<int:category_id>/')
@app.route('/all/<int:category_id>/items/')
def showAllItems(category_id):
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(
        CatalogItem).filter_by(
        category_id=category_id).order_by(CatalogItem.id.desc())
    creator = getUserInfo(category.user_id)
    count = items.count()
    return render_template(
        'all_item_of_specific_cat.html', categories=categories,
        category=category, items=items, creator=creator, quantity=count)

# U


@app.route(
    '/all/<int:category_id>/item/<int:catalog_item_id>/edit',
    methods=['GET', 'POST'])
@checkLogin
def editCatalogItem(category_id, catalog_item_id):
    categories = session.query(Category).all()
    editedItem = session.query(CatalogItem).filter_by(id=catalog_item_id).one()
    creator = getUserInfo(editedItem.user_id)
    """Make sure the current user is only modifying his or her own stuff"""
    if creator.id != login_session['user_id']:
        flash("You are not authorized! This is %s 's stuff" % creator.name)
        return redirect(url_for('showCatalog'))

    """This is the same order as the page"""
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['category']:
            editedItem.category_id = request.form['category']

        session.add(editedItem)
        session.commit()
        flash("You updated your item successfully!")
        return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'edit_item.html', categories=categories, item=editedItem)

# D


@app.route(
    '/all/<int:category_id>/item/<int:catalog_item_id>/delete',
    methods=['GET', 'POST'])
@checkLogin
def deleteCatalogItem(category_id, catalog_item_id):
    itemToDelete = session.query(
        CatalogItem).filter_by(id=catalog_item_id).one()
    creator = getUserInfo(itemToDelete.user_id)
    """Make sure the current user is only deleting his or her own stuff"""
    if creator.id != login_session['user_id']:
        flash("You are not authorized! This is %s 's stuff" % creator.name)
        return redirect(url_for('showCatalog'))

    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('You deleted the item successfully')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('delete_item.html', item=itemToDelete)

# ======================================
# User helper functions
# ======================================


def createUser(login_session):
    newUser = User(
        name=login_session['username'], email=login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

# ======================================
# JSON API Endpoints
# ======================================


@app.route('/all/item/JSON')
def showAllItemJSON():
    items = session.query(CatalogItem).order_by(CatalogItem.id.desc())
    return jsonify(AllItems=[i.serialize for i in items])


@app.route('/all/<int:category_id>/item/<int:catalog_item_id>/JSON')
def showOneItemJSON(category_id, catalog_item_id):
    Catalog_Item = session.query(
        CatalogItem).filter_by(id=catalog_item_id).one()
    return jsonify(SpecificItem=Catalog_Item.serialize)


@app.route('/all/category/JSON')
def showAllCategoriesJSON():
    categories = session.query(Category).all()
    return jsonify(AllCategory=[c.serialize for c in categories])

# ======================================
# Important Stuff
# ======================================


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
