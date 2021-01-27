from flask import Flask, render_template, send_file, request, redirect, url_for, make_response
import logging
#from const import *
import const
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from login_app import Package
import redis
import datetime
import os
import requests
import time

app = Flask(__name__, static_url_path="")
log = app.logger

app.config["JWT_SECRET_KEY"] = os.environ.get(const.SECRET_KEY)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = const.TOKEN_EXPIRES_IN_SECONDS
db = redis.Redis(host="redis-db", port=6379, decode_responses=True)
app.config["JWT_TOKEN_LOCATION"] = ["headers", "query_string"]
jwt = JWTManager(app)

if db.hget('currentLockerID','current_id') == None:
    db.hset('currentLockerID','current_id','L0')
    
if not db.keys(pattern='VERSION'):
    db.set('VERSION','0')
    
class Locker(object):   
    def __init__(self, id, packages, count):
        self.id = id
        self.packages = packages
        self.count = count 
        


def setup():
    log.setLevel(logging.DEBUG)


@app.route("/")
def index():
    return redirect(url_for('lockers')) 

@app.route("/lockers")
def lockers():
    msg = ''
    type= ''
    id = request.args.get('id')
    lockers = getLockers()
    if 'msg' in request.form and 'type' in request.form:
        msg = request.form["msg"]
        type = request.form["type"]
    return render_template('lockers.html', lockers = lockers, id = id, msg = msg, type = type) 
    
@app.route("/add-locker")
def add_locker():
    
           
    currentLockerID = generateLockerID(db.hget('currentLockerID','current_id'))
    id = currentLockerID   
    db.hset(id,'id',id)        
    db.hset(id,'packages','') 
    db.hset(id,'count',0)
    db.hset('currentLockerID','current_id',id)
              
    return redirect(url_for('lockers')) 
 

@app.route("/add-package", methods=['GET', 'POST'])
def add_package():

    packageID = request.args.get('id')
    lockerID = request.args.get('locker_id')
    state = db.hget(packageID,'status')
    if packageID != '' and state == 'nowa': 
        package_list = db.hget(lockerID,'packages')
        package_list = package_list + packageID  + ","
        db.hset(lockerID,'packages',package_list)
        
        count = int(db.hget(lockerID,'count'))+1
               
        db.hset(lockerID,'count',count) 
        db.hset(packageID, 'status', 'oczekująca w paczkomacie')        
        version = int(db.get('VERSION'))
        version = version + 1
        db.set('VERSION',version)
    return redirect(url_for('lockers'))             


@app.route("/inside") 
def inside(): 
    locker_id = request.args.get("locker_id")
    access_token = request.args.get("token")
    #if 'access_token' in request.args:
    #    access_token = request.args.get("access_token")         
    #    db.hget(locker_id, 'token', access_token)
    #else:
    #    access_token = db.hget(locker_id, "token")
        
    #if access_token == locker_id and db.exists(locker_id):
    if db.hget(locker_id, "date")==None:
        return redirect(url_for('lockers'))
    if request.args.get("index") == None or request.args.get("index") == '':
        index = 0 
    else:
        index = int(request.args.get("index"))
        
    creation = datetime.datetime.strptime(db.hget(locker_id, "date"), '%Y-%m-%d %H:%M:%S.%f')
    time = datetime.datetime.now() - creation
    time = time.total_seconds()
   
    if access_token == db.hget(locker_id, "token") and time < 60:     
        count = db.hget(locker_id,"count")
        packages = getPackagesInlocker(locker_id)   
        segment = packages[index:index+5] 
        page  = int(1+index/5)
        return render_template('inside.html',page = page, packages = segment, locker_id = locker_id, count = count, token = access_token, index = index)   
    else:
        return redirect(url_for('lockers'))    
 
@app.route("/select")
def select():  
    
    id = request.args.get("package_id")
    locker_id = request.args.get("locker_id")
    access_token = request.args.get("token")
    
    select = db.hget(id, 'select')
    if select == '' or select == None:
        db.hset(id, 'select',-1)
    select = int(db.hget(id, 'select')) 
    select = select*(-1)
    db.hset(id, 'select',select)
    url = 'https://localhost:8082/inside?locker_id='+locker_id+"&token="+access_token
    return redirect(url) 
    
@app.route("/pickup")
def pickup(): 
    locker_id = request.args.get("locker_id")
    token = request.args.get("token")
    courier_id = findCourierByToken(token)
    IDs = getSelectedPackages()
    courier_packages = db.hget(courier_id,"packages")
    for id in IDs:
        db.hset(id,"status","odebrana")   
        db.hset(id,"select","-1")          
        courier_packages = courier_packages + id  + ","
        
    db.hset(courier_id,'packages',courier_packages)        
    count = int(db.hget(locker_id,'count'))-len(IDs)          
    db.hset(locker_id,'count',count) 
    version = int(db.get('VERSION'))
    version = version + 1
    db.set('VERSION',version)
    url = 'https://localhost:8082/inside?locker_id='+locker_id+"&token="+token
    return redirect(url) 
    
    
def to_seconds(date):
    return time.mktime(date.timetuple())    
def getLockers():
    keys = db.keys(pattern ='L*')
    lockers = returnLockerList(keys)
    return lockers
    #return redirect(url_for('inside'))
   
def getPackagesInlocker(lockerKey):
    packages = db.hget(lockerKey, 'packages')
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
        if status != "odebrana":
            files.append(file)
    return files 

@app.route("/next")
def next():    
    if request.args.get("index") == None or request.args.get("index") == '':
        index = 0 
    else:
        index = int(request.args.get("index"))
    locker_id = request.args.get("locker_id")
    token = request.args.get("token")
    len = int(request.args.get("package_number"))
    index = index + 5
    if index >= len:
        index = index-5
    index = str(index)
    url="https://localhost:8082/inside?index="+index+'&locker_id='+locker_id+"&token="+token
    return redirect(url)

@app.route("/previous")
def previous():  
    if request.args.get("index") == None or request.args.get("index") == '':
        index = 0 
    else:
        index = int(request.args.get("index"))
    locker_id = request.args.get("locker_id")
    token = request.args.get("token")
    index = index - 5
    if index<0:
        index = 0
    index = str(index)
    url="https://localhost:8082/inside?index="+index+'&locker_id='+locker_id+"&token="+token
    return redirect(url)
   
def returnLockerList(IDs):
    lockers = []
    for id in IDs:
        idd = db.hget(id,'id')
        packages = db.hget(id,'packages')
        count = db.hget(id,'count')
        locker = Locker(idd, packages, count)
        lockers.append(locker)
    return lockers 
    
def generateLockerID(lastID):
    id = lastID[1:]
    id = int(id)+1
    id = "L"+str(id)
    return id
    
def findCourierByToken(token):
    keys = db.keys(pattern="c[0-9]*")
    for key in keys:
        if db.hget(key,"token") == token:
            return key
    return None   
    
def getSelectedPackages():
    keys = db.keys(pattern="p[0-9]*")
    IDs = []
    for key in keys:
        if db.hget(key,"select") == "1" and db.hget(key,"status") == "oczekująca w paczkomacie":
            IDs.append(key)
    return IDs               
            
            