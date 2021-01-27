from flask import Flask, render_template, request, session, redirect, url_for, jsonify, make_response, abort
#from flask_jwt_extended import JWTManager, create_access_token, jwt_required, jwt_refresh_token_required, create_refresh_token, get_jwt_identity
from const import *
from functools import wraps
from random import randint
from login_app import Package
import datetime
import redis
import os
import re
import jwt
import hashlib

from courier_const import *
from authlib.integrations.flask_client import OAuth
from functools import wraps




app = Flask(__name__, static_url_path="")
app.config.update(SESSION_COOKIE_NAME="courier_cookie")
#app.secret_key = "whatever2"
app.debug = True
app.secret_key = SECRET_KEY
oauth = OAuth(app)

auth0 = oauth.register(
    "courier_app",
    api_base_url=OAUTH_BASE_URL,
    client_id=OAUTH_CLIENT_ID,
    client_secret=OAUTH_CLIENT_SECRET,
    access_token_url=OAUTH_ACCESS_TOKEN_URL,
    authorize_url=OAUTH_AUTHORIZE_URL,
    client_kwargs={"scope": OAUTH_SCOPE})
    
def authorization_required(fun):
    @wraps(fun)
    def authorization_decorator(*args, **kwds):
        if NICKNAME not in session:
            return redirect("/login")

        return fun(*args, **kwds)

    return authorization_decorator   

    

db = redis.Redis(host="redis-db", port=6379, decode_responses=True)

if db.hget('currentCourierID','current_id') == None:
    db.hset('currentCourierID','current_id','c0')
    
if not db.keys(pattern='VERSION'):
    db.set('VERSION','0')
    
site_version = int(db.get('VERSION')) 
   
#app.config["JWT_SECRET_KEY"] = app.secret_key 
#app.config['SECRET_KEY'] = 'whatever2'
#app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 60
#app.config["JWT_TOKEN_LOCATION"] = ["headers", "query_string"]
app.permanent_session_lifetime = datetime.timedelta(minutes=5)
access_token=''


#jwt = JWTManager(app)

#if not db.keys(pattern='JWT'):
#    db.hset('JWT','current_token',access_token)
    
accountsNumber = 0

@app.route("/")
def home():  
    #return render_template('testowy.html')
    m = request.args.get("m")
    m2 = request.args.get("m2")
    type = request.args.get("type")
    type2 = request.args.get("type2")
    if request.args.get("index") == None or request.args.get("index") == '':
        index = 0 
    else:
        index = int(request.args.get("index"))
    
    if type == '' or type == None:
        type ='blank'
    if m == None:
        m =''    
    if type2 == '' or type2 == None:
        type2 ='blank'
    if m2 == None:
        m2 =''     
    
    if 'loggedinCourier' in session: 
        username=session['usernameCourier']    
        my_files=getFiles(username)
        #IDs = getPackagesToPickupID()  
        #to_pickup = returnFileList(IDs)
        package_number = len(my_files) 
        segment = my_files[index:index+5] 
        page  = int(1+index/5)
        return render_template('courier.html', page = page, msg="Logout", method="logout", username=username, my_files=segment, package_number=len(my_files), m = m, type = type, m2=m2, type2=type2, index = index )
    return redirect(url_for('login'))          

@app.route("/callback")
def oauth_callback():
    auth0.authorize_access_token()
    resp = auth0.get("userinfo")
    nickname = resp.json()["nickname"]
    session["nickname2"] = nickname
    session['usernameCourier'] = nickname
    
    return redirect("/secure")

@authorization_required
@app.route("/secure")
def secure():
    return redirect(url_for('home'))
    
    m = request.args.get("m")
    m2 = request.args.get("m2")
    type = request.args.get("type")
    type2 = request.args.get("type2")
    if request.args.get("index") == None or request.args.get("index") == '':
        index = 0 
    else:
        index = int(request.args.get("index"))
    
    if type == '' or type == None:
        type ='blank'
    if m == None:
        m =''    
    if type2 == '' or type2 == None:
        type2 ='blank'#
    if m2 == None:
        m2 ='' 
    username=session["nickname2"] 
    if findUserKey(username) == None:
        lastID = db.hget('currentCourierID','current_id')
        currentID = generateCourierID(lastID)
        db.hset(currentID,'username',username)
        #db.hset(currentID,'password',password)          
        db.hset(currentID,'packages','')           
        db.hset('currentCourierID','current_id',currentID)
        
    my_files=getFiles(username)
    
    package_number = len(my_files) 
    segment = my_files[index:index+5] 
    page  = int(1+index/5)  
    return render_template('courier.html', page = page, msg="Logout", method="logout", username=username, my_files=segment, package_number=len(my_files), m = m, type = type, m2=m2, type2=type2, index = index )

@app.route("/offline")
def offline():
    return render_template("offline.html")


@app.route("/error")
def error():
    return render_template("error.html")


@app.route("/service-worker.js")
def service_worker():
    return app.send_static_file("service-worker.js")
     
@app.route('/logout2')
def logout2():
   session.pop('loggedinCourier', None)
   session.pop('idCourier', None)
   session.pop('usernameCourier', None)
   
   return redirect(url_for('home')) 
   
@app.route("/logout")
def logout():
    url_params = "returnTo=" + url_for("logout_info", _external=True)
    url_params += "&"
    url_params += "client_id=" + OAUTH_CLIENT_ID
    
    session.clear()
    #session.pop("nickname2",None)
    return redirect(auth0.api_base_url + "/v2/logout?" + url_params)
   
@app.route("/login2")
def login2():
    session['loggedinCourier'] = True
    return auth0.authorize_redirect(
            redirect_uri=OAUTH_CALLBACK_URL,
            audience="")
            
@app.route("/logout_info")
def logout_info():
    return redirect(url_for('home'))       

@app.route("/login", methods=['GET', 'POST'])
def login():
    msg = ''
    type='msg'
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form["username"]
        password = request.form["password"]
        if isUserInDatabase(username,password)!=None:
            key = isUserInDatabase(username,password)
            session['loggedinCourier'] = True
            session['idCourier'] = key
            session['usernameCourier'] = db.hget(key,'username')           
            #access_token = create_access_token(identity=username) 
            #db.hset('JWT','current_token',access_token)       
            #name_hash = hashlib.sha512(username.encode('utf-8')).hexdigest()  
            return redirect(url_for('home')) 
            #my_files=getFiles(username) 
            #IDs = getPackagesToPickupID()  
            #to_pickup = returnFileList(IDs)
            #access_token=db.hget('JWT','current_token')            
            #response = make_response(render_template('courier.html', username=session['username'], msg = "Logout",method="logout", my_files=my_files, package_number=len(my_files)))
            #response.set_cookie(session['id'], name_hash,
            #                max_age=30, secure=True, httponly=True)
            #return response
         
        else:
            msg = 'Incorrect username/password!'
    if msg=='':
        type='blank'
    return render_template('loginC.html', msg=msg, type=type)
 
@app.route("/register", methods=['GET', 'POST'])
def register():
    msg = ''
    type='blank'
    
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'repeat_password' in request.form:
 
        username = request.form["username"]
        password = request.form["password"]
        repeat_password = request.form["repeat_password"]
        
        
        
        if isUserInDatabase(username,password)!=None:
            msg = 'Account already exists'
            type='msg'
        elif isOccupiedLogin(username) == True:
            msg = 'Username occupied!'
            type='msg'
        elif usernameCorrect(username) == False:
            msg = 'Username invalid!'
            type='msg'
        elif passwordCorrect(password) == False:
            msg = 'Password invalid'
            type='msg'
        elif repasswordCorrect(password, repeat_password) == False:
            msg = 'Repeated password invalid!'
            type='msg'    
        else:          
            lastID = db.hget('currentCourierID','current_id')
            currentID = generateCourierID(lastID)
            db.hset(currentID,'username',username)
            db.hset(currentID,'password',password)          
            db.hset(currentID,'packages','') 
            
            
            db.hset('currentCourierID','current_id',currentID)
            
            
            msg = 'You have successfully registered!'
            type='msg-success'
           
        
    elif request.method == 'POST':     
        msg = 'Please fill out the form!'
        type='msg'
       
  
    return render_template('registerC.html', msg=msg, type=type) 
    
@app.route("/pickup-from-sender")
def pickup_sender(): 
    msg = ''
    type='blank'
    username = request.args.get("courier_username")
    package_id = request.args.get("package_id")
       
    if db.hget(package_id, 'status')!= 'oczekująca u nadawcy':
        msg = 'Package is not available!'
        type='msg'
        
    elif findUserKey(username) == None:
        msg = 'Courier is not available!'
        type='msg'
                
    else:
        userKey = findUserKey(username)        
        package_list = db.hget(userKey,'packages')     
        package_list = package_list + package_id + ","
        db.hset(userKey,'packages',package_list)
        db.hset(package_id,'status','odebrana')
        version = int(db.get('VERSION'))
        version = version + 1
        db.set('VERSION',version)
        msg = 'Success!'
        type='msg-success'
        
    url="https://localhost:8083/?m="+msg+"&type="+type
    return redirect(url)
    
@app.route("/next")
def next():  
    if request.args.get("index") == None or request.args.get("index") == '':
        index = 0 
    else:
        index = int(request.args.get("index"))  
    
    len = int(request.args.get("package_number"))
    index = index + 5
    if index >= len:
        index = index-5
    index = str(index)
    url="https://localhost:8083/?index="+index
    return redirect(url)

@app.route("/previous")
def previous():  
    if request.args.get("index") == None or request.args.get("index") == '':
        index = 0 
    else:
        index = int(request.args.get("index"))
    index = index - 5
    if index<0:
        index = 0
    index = str(index)
    url="https://localhost:8083/?index="+index
    return redirect(url)
    
@app.route("/pickup-from-locker")
def pickup_locker(): 
    msg = ''
    type='blank'   
    username = request.args.get("courier_username")
    locker_id = request.args.get("locker_id")
    
       
    if db.hget(locker_id, 'packages')== None:
        msg = 'Locker is not available!'
        type='msg'
    elif findUserKey(username) == None:
        msg = 'Courier is not available!'
        type='msg'
    else:
        courier_id = findUserKey(username)       
        access_token = generate_token()
        date = datetime.datetime.now()
        date = str(date)
        db.hset(locker_id, 'token', access_token)
        db.hset(courier_id, 'token', access_token)
        db.hset(locker_id, 'date', date)
        db.hset(courier_id, 'date', date)
        msg = "token: "+access_token
        type='msg-success'
        
    url="https://localhost:8083/?m2="+msg+"&type2="+type
    return redirect(url)

@app.route("/refresh")
def refresh():
    global site_version
    VERSION = int(db.get('VERSION'))
    if site_version != VERSION:
        site_version = VERSION
        return jsonify(answer = "True")              
    return jsonify(answer = "False") 
       
def isUserInDatabase(username, password):
    accounts = db.keys(pattern='*')
    for key in accounts:
        if db.hget(key,'username') == username and db.hget(key,'password') == password:
            return key
    return None
    
def findUserKey(username):
    accounts = db.keys(pattern='c[0-9]*')
    for key in accounts:   
        if db.hget(key,'username') == username:       
            return key
    return None
    
def getFiles(username):
    userKey = findUserKey(username)
    packages = db.hget(userKey, 'packages')
    files = []
    if packages != '':   
        IDs = packages.split(",")
        files = returnFileList(IDs[:-1])
        return files           
    return files  
    
     
def returnFileList(IDs):
    files = []
    for id in IDs:
        idd = db.hget(id,'id')
        date = db.hget(id,'date')
        name = db.hget(id,'name')
        surname = db.hget(id,'surname')
        country = db.hget(id,'country')
        city = db.hget(id,'city')
        street = db.hget(id,'street')
        number = db.hget(id,'number')
        contact_number = db.hget(id,'contact_number')
        image = db.hget(id,'image')
        status = db.hget(id,'status')
        select = db.hget(id,'select')
        file = Package(idd, name, surname, contact_number, country, city, street, number, image, date, status, select)
        files.append(file)
    return files 
    
def generate_token():
    token = ''.join(["{}".format(randint(0, 9)) for num in range(0, 6)])
    return token
    
def generateCourierID(lastID):
    id = lastID[1:]
    id = int(id)+1
    id = "c"+str(id)
    return id
    
def isOccupiedLogin(username):
    accounts = db.keys(pattern='*')
    for key in accounts:
        if db.hget(key,'username') == username:
            return True
    return False

def usernameCorrect(username):
    if len(username) <5 or not username.isalpha():
                return False;
    return True;
    
def passwordCorrect(password):
    if len(password) <8:
                return False;
    return True;
    
def repasswordCorrect(password, repeat_password):
    if password != repeat_password:
                return False;
    return True;
    
    
@app.errorhandler(400)
def page_not_found(error):
    return {"info:": "error 400"}
    
@app.errorhandler(401)
def page_unauthorized(error):
    return {"info:": "error 401"}
    
@app.errorhandler(403)
def page_not_found(error):
    return {"info:": "error 403"}

#@app.errorhandler(404)
#def page_not_found(error):
#    return {"info:": "error 404"}

#@app.errorhandler(Exception)
#def exception_handler(error):   
#    return {"info:": "error 500"}
   

    
app.config['PROPAGATE_EXCEPTIONS'] = True 
     
if __name__ == '__main__':
    app.run(debug=False)
  