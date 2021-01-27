from flask import Flask, render_template, request, session, redirect, url_for, jsonify, make_response, abort
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, jwt_refresh_token_required, create_refresh_token, get_jwt_identity
#from const import *
import const
from functools import wraps
import datetime
import redis
import os
import re
import jwt
import hashlib

from client_const import *
from authlib.integrations.flask_client import OAuth
from functools import wraps


app = Flask(__name__, static_url_path="")
#app.secret_key = 'whatever'
app.secret_key = const.SECRET_KEY
app.config.update(SESSION_COOKIE_NAME="client_cookie")
oauth = OAuth(app)

auth0 = oauth.register(
    "client_app",
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

if not db.keys(pattern='*'):
    db.hset('currentID','current_id','0')
if not db.keys(pattern='p*'):
    db.hset('currentPackageID','current_id','p0')
if not db.keys(pattern='VERSION'):
    db.set('VERSION','0')
    
site_version = int(db.get('VERSION'))    
app.config["JWT_SECRET_KEY"] = app.secret_key 
app.config['SECRET_KEY'] = 'whatever'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = const.TOKEN_EXPIRES_IN_SECONDS
app.config["JWT_TOKEN_LOCATION"] = ["headers", "query_string"]
app.permanent_session_lifetime = datetime.timedelta(minutes=5)
access_token=''

jwt = JWTManager(app)

if not db.keys(pattern='JWT'):
    db.hset('JWT','current_token',access_token)
    
accountsNumber = 0

class ListItem(object):   
    def __init__(self, id, date, link):
        self.id = id
        self.date = date
        self.link = link 


class Package(object):   
    def __init__(self, id, name, surname, contact_number, country, city, street, number, image, date, status, select):
        self.id = id
        self.name = name
        self.surname = surname
        self.contact_number = contact_number
        self.country = country
        self.city = city
        self.street = street
        self.number = number
        self.image = image
        self.date = date
        self.status = status
        self.select = select
    def str_full(self):
        result = ""    
        result += "\n{}".format("ID: "+self.id)
        result += "\n{}".format("name: "+self.name)
        result += "\n{}".format("surname: "+self.surname)
        result += "\n{}".format("phone: "+self.contact_number)
        result += "\n{}".format("country: "+self.country)
        result += "\n{}".format("city: "+self.city)
        result += "\n{}".format("street: "+self.street)
        result += "\n{}".format("number: "+self.number)

        return result 

@app.route("/callback")
def oauth_callback():
    auth0.authorize_access_token()
    resp = auth0.get("userinfo")
    nickname = resp.json()["nickname"]
    
    session["nickname"] = nickname
    session['usernameUser'] = nickname
    access_token = create_access_token(identity=nickname) 
    db.hset('JWT','current_token',access_token)
    return redirect("/secure")   

@authorization_required
@app.route("/secure")
def secure():
    return redirect(url_for('parcel'))
    
@app.route("/logout")
def logout():
    url_params = "returnTo=" + url_for("logout_info", _external=True)
    url_params += "&"
    url_params += "client_id=" + OAUTH_CLIENT_ID
    session.clear()
    #session.pop("nickname",None)
    
    return redirect(auth0.api_base_url + "/v2/logout?" + url_params)
   
@app.route("/login2")
def login2():

    session['loggedinUser'] = True
    return auth0.authorize_redirect(
            redirect_uri=OAUTH_CALLBACK_URL,
            audience="")
            
@app.route("/logout_info")
def logout_info():
    return redirect(url_for('home'))    

@app.route("/")
def home():       
    if 'loggedinUser' in session:             
        return render_template('home.html', msg="Logout", method="logout")
    return render_template('home.html', msg="Login", method="login")   
    
  
@app.route("/add", methods=['GET', 'POST'])
def add(): 
    msg = ''
    type='blank'
    if 'loggedinUser' in session: 
        if request.method == 'POST' and 'name' in request.form and 'surname' in request.form and 'contact_number' in request.form and 'street' in request.form and 'number' in request.form and 'country' in request.form and 'city' in request.form:  
                
            currentPackageID = generatePackageID(db.hget('currentPackageID','current_id'))
            id = currentPackageID    
            name = request.form["name"]       
            surname = request.form["surname"]           
            country = request.form["country"]
            city = request.form["city"]
            street = request.form["street"]
            number = request.form["number"]
            contact_number = request.form["contact_number"]
            fileImage = request.files["image"]
            save_file(fileImage)
            image = fileImage.filename
            
                
            db.hset(currentPackageID,'name',name)
            db.hset(currentPackageID,'surname',surname)
            db.hset(currentPackageID,'country',country)
            db.hset(currentPackageID,'city',city)
            db.hset(currentPackageID,'street',street)
            db.hset(currentPackageID,'number',number)
            db.hset(currentPackageID,'contact_number',contact_number)
            db.hset(currentPackageID,'image',image)
            db.hset(currentPackageID,'id',id)
            db.hset(currentPackageID,'status','nowa')
            time = datetime.datetime.now() + datetime.timedelta(hours = 1)
            time = time.strftime("%Y/%m/%d, %H:%M:%S")
            db.hset(currentPackageID,'date',time)
            username=session['usernameUser']
            userKey = findUserKey(username)
            package_list = db.hget(userKey,'packages')
            package_list = package_list + id + ","
            db.hset(userKey,'packages',package_list)
            db.hset('currentPackageID','current_id',currentPackageID)             
            msg = 'You have successfully added your package!'
            type='msg-success'
                       
        elif request.method == 'POST':     
            msg = 'Please fill out the form!'
            type='msg'
            
        return render_template('add.html', msg=msg, type=type)  
    return redirect(url_for('login'))    
            
    

@app.route("/parcel")
def parcel():
    if 'loggedinUser' in session:  
        if request.args.get("index") == None or request.args.get("index") == '':
            index = 0 
        else:
            index = int(request.args.get("index"))
        username = session['usernameUser'] 
        my_files=getFiles(username) 
        segment = my_files[index:index+5] 
        page  = int(1+index/5)        
        access_token=db.hget('JWT','current_token')        
        return render_template('parcel.html', page = page, username=username, msg = "Logout",method="logout", my_files=segment, package_number=len(my_files), removeFile=removeFile, access_token= access_token,index = index)     
    return redirect(url_for('login'))
      
      
@app.route('/logout2')
def logout2():
   session.clear()
   
   return redirect(url_for('home')) 

@app.route("/login", methods=['GET', 'POST'])
def login():
    msg = ''
    type='msg'
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form["username"]
        password = request.form["password"]
        if isUserInDatabase(username,password)!=None:
            if request.args.get("index") == None or request.args.get("index") == '':
                index = 0 
            else:
                index = int(request.args.get("index"))
            key = isUserInDatabase(username,password)
            session['loggedinUser'] = True
            session['idUser'] = key
            session['usernameUser'] = db.hget(key,'username')                        
            return redirect(url_for('parcel'))         
            #response = make_response(render_template('parcel.html', page = page, access_token=access_token, username=session['usernameUser'], msg = "Logout",method="logout", my_files=segment, package_number=len(my_files),removeFile=removeFile))
            #response.set_cookie(session['idUser'], name_hash,
            #                max_age=30, secure=True, httponly=True)
            #return response
         
        else:
            msg = 'Incorrect username/password!'
    if msg=='':
        type='blank'
    return render_template('index.html', msg=msg, type=type)
 
@app.route("/register", methods=['GET', 'POST'])
def register():
    msg = ''
    type='blank'
    
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'repeat_password' in request.form and 'name' in request.form and 'surname' in request.form and 'birth' in request.form and 'street' in request.form and 'number' in request.form and 'postal_code' in request.form and 'country' in request.form and 'pesel' in request.form and 'city' in request.form:
 
        username = request.form["username"]
        password = request.form["password"]
        repeat_password = request.form["repeat_password"]
        pesel = request.form["pesel"]
        name = request.form["name"]
        
        surname = request.form["surname"]
        birth = request.form["birth"]
        country = request.form["country"]
        city = request.form["city"]
        street = request.form["street"]
        number = request.form["number"]
        postal_code = request.form["postal_code"] 
        
        
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
        elif peselCorrect(pesel) == False:
            msg = 'Pesel invalid!'
            type='msg'
        elif nameCorrect(name) == False:
            msg = 'Name cannot be empty!'
            type='msg'
        elif surnameCorrect(surname) == False:
            msg = 'Surname cannot be empty!'
            type='msg'
        elif birthCorrect(birth) == False:
            msg = 'Birth invalid!'
            type='msg'
        elif countryCorrect(country) == False:
            msg = 'Country cannot be empty!'
            type='msg'
        elif cityCorrect(city) == False:
            msg = 'City cannot be empty!'
            type='msg'
        elif streetCorrect(street) == False:
            msg = 'Street cannot be empty!'
            type='msg'
        elif numberCorrect(number) == False:
            msg = 'Number invalid!'
            type='msg'
        elif postalCorrect(postal_code) == False:
            msg = 'Postal code invalid!' 
            type='msg'
        else:
            currentID = int(db.hget('currentID','current_id'))+1
            
            db.hset(currentID,'username',username)
            db.hset(currentID,'password',password)
            db.hset(currentID,'pesel',pesel)
            db.hset(currentID,'name',name)
            db.hset(currentID,'surname',surname)
            db.hset(currentID,'birth',birth)
            db.hset(currentID,'country',country)
            db.hset(currentID,'city',city)
            db.hset(currentID,'street',street)
            db.hset(currentID,'number',number)
            db.hset(currentID,'postal',postal_code) 
            db.hset(currentID,'packages','') 
            
            
            db.hset('currentID','current_id',currentID)
            
            
            msg = 'You have successfully registered!'
            type='msg-success'
           
        
    elif request.method == 'POST':     
        msg = 'Please fill out the form!'
        type='msg'
       
  
    return render_template('register.html', msg=msg, type=type) 
    
def download_access(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return redirect(url_for('login'))
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return redirect(url_for('downloadFile'))
         
        return f(*args, **kwargs)
        
    return wrapper    
    
def save_file(file_to_save):
    if len(file_to_save.filename) > 0:
        path_to_file = os.path.join(const.FILES_PATH, file_to_save.filename)
        file_to_save.save(path_to_file)
    else:
        log.warn("Empty content of file!")
        
def isUserInDatabase(username, password):
    accounts = db.keys(pattern='*')
    for key in accounts:
        if db.hget(key,'username') == username and db.hget(key,'password') == password:
            return key
    return None
    
def findUserKey(username):
    accounts = db.keys(pattern='[0-9]*')
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
    
@app.route('/delete')    
def removeFile(): 
    username = request.args.get('username')
    id = request.args.get('id')  
    userKey = findUserKey(username)    
    packages = db.hget(userKey, 'packages')
    IDs = packages.split(",")
    path=FILES_PATH_PDF+"/"+id+".pdf"
    if os.path.exists(path):
        os.remove(path)
    if id in IDs:
        IDs.remove(id)
    packages=','.join(IDs)
    db.hset(userKey,'packages',packages)
    return redirect(url_for('parcel'))
    
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
    url="https://localhost:8080/parcel?index="+index
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
    url="https://localhost:8080/parcel?index="+index
    return redirect(url)


def refreshJWT():
    
    username = get_jwt_identity()  
    access_token = create_access_token(identity=username)
    db.hset('JWT','current_token',access_token)
    name_hash = hashlib.sha512(username.encode('utf-8')).hexdigest()  
    my_files=getFiles(username) 
    access_token=db.hget('JWT','current_token')            
    response = make_response(render_template('parcel.html', access_token=access_token, username=session['usernameUser'], msg = "Logout",method="logout", my_files=my_files, package_number=len(my_files),removeFile=removeFile))
    response.set_cookie(session['idUser'], name_hash,max_age=30, secure=True, httponly=True)
    return response
 
@app.route('/preload')   
def preload():   
    access_token = db.hget('JWT','current_token') 
    username = request.args.get('username') 
    id = request.args.get('id')
    return redirect(url_for('downloadFile',username=username, id=id, jwt=access_token))
    
@app.route('/download')  
@jwt_required  
def downloadFile(): 
    username = request.args.get('username')    
    key = findUserKey(username)
    session['loggedinUser'] = True
    session['idUser'] = key
    session['usernameUser'] = db.hget(key,'username') 
    refreshJWT()
    access_token = db.hget('JWT','current_token')           
    id = request.args.get('id')
    url="https://localhost:8081/download-file?id="+id+"&jwt="+access_token
    return redirect(url, code=301)
    
@app.route('/locker')  
def redirectToLocker():  
    id = request.args.get('id')
    url="https://localhost:8082/lockers?id="+id
    return redirect(url, code=301)

@app.route('/courier')   
def notifyCourier():
    id = request.args.get('id')   
    db.hset(id,'status','oczekująca u nadawcy')
    return redirect(url_for('parcel'))

@app.route("/refresh")
def refresh():
    global site_version
    VERSION = int(db.get('VERSION'))
    if site_version != VERSION:
        site_version = VERSION
        return jsonify(answer = "True")              
    return jsonify(answer = "False")    
        

def generatePackageID(lastID):
    id = lastID[1:]
    id = int(id)+1
    id = "p"+str(id)
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
    
def peselCorrect(pesel):
    
    if len(pesel)!=11:
        return False
      
    return True
    
        
def nameCorrect(name):
    if len(name) == 0:
        return False
    return True
    
def surnameCorrect(surname):
    if len(surname) == 0:
        return False
    return True
  
def birthCorrect(birth):
    pattern = re.compile("\d{4}[-/]\d{2}[-/]\d{2}")
    if pattern.match(birth):
        return True
    return False
  
def countryCorrect(country):
    if len(country) == 0:
        return False
    return True
    
def cityCorrect(city):
    if len(city) == 0:
        return False
    return True
  
def streetCorrect(street):
    if len(street) == 0:
        return False
    return True
    
def numberCorrect(number):
    if number == "0" or not number.isnumeric():
        return False
    return True
    
def postalCorrect(postal_code):
    pattern = re.compile("\d{2}-\d{3}")
    if pattern.match(postal_code):
        return True
    return False
    
@app.errorhandler(400)
def page_not_found(error):
    return {"info:": "error 400"}
    
@app.errorhandler(401)
def page_unauthorized(error):
    return {"info:": "error 401"}
    
@app.errorhandler(403)
def page_not_found(error):
    return {"info:": "error 403"}

@app.errorhandler(404)
def page_not_found(error):
    return {"info:": "error 404"}

#@app.errorhandler(Exception)
#def exception_handler(error):   
#    return {"info:": "error 500"}
   

    
app.config['PROPAGATE_EXCEPTIONS'] = True 
     
if __name__ == '__main__':
    app.run(debug=False)
  

    