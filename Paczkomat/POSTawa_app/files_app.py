from flask import Flask, render_template, send_file, request, redirect, url_for, make_response
import logging
from const import *
from flask_jwt_extended import JWTManager, jwt_required
from fpdf import FPDF
from login_app import Package
import redis
import os
import requests

app = Flask(__name__, static_url_path="")

log = app.logger

app.config["JWT_SECRET_KEY"] = os.environ.get(SECRET_KEY)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = TOKEN_EXPIRES_IN_SECONDS
db = redis.Redis(host="redis-db", port=6379, decode_responses=True)
app.config["JWT_TOKEN_LOCATION"] = ["headers", "query_string"]
#jwt = JWTManager(app)


def setup():
    log.setLevel(logging.DEBUG)


@app.route("/")
def index():
    return render_template("index-files.html")

@app.route("/download-file")
def download_file():
    packageID = request.args.get('id')
    name=db.hget(packageID,'name')
    surname=db.hget(packageID,'surname')
    country=db.hget(packageID,'country')
    city=db.hget(packageID,'city')
    street=db.hget(packageID,'street')
    number=db.hget(packageID,'number')
    contact_number=db.hget(packageID,'contact_number')
    image=db.hget(packageID,'image')
    date=db.hget(packageID,'date')
    status=db.hget(packageID,'status')
    select=db.hget(packageID,'select')
    data = Package(packageID, name, surname, contact_number, country, city, street, number, image, date, status, select) 
   
    path=FILES_PATH_PDF+"/"+data.id+".pdf"
    
    pdf_name=''
    if not os.path.isfile(path):
        pdf_name = generatePdf(data)      
    with open(path) as pdf_file:
        return send_file(path, as_attachment=True)       
    
    access_token = request.args.get('jwt')
    return redirect('https://localhost:8080/parcel/?jwt='+access_token)
    
 
def generatePdf(data):
    
    pdf = FPDF()  
    pdf.add_page()
    pdf.set_font("Arial", size=8)
    add_table_to_pdf(data, pdf)
    filename = data.id+".pdf"
    pdf.output(FILES_PATH_PDF+"/"+filename)
    return filename

def add_table_to_pdf(data, pdf):
    n_cols = 7
    col_width = (pdf.w - pdf.l_margin - pdf.r_margin) / n_cols 
    font_size = pdf.font_size
    n_lines = 4
    
    pdf.cell(col_width, n_lines * font_size, "Package info:", border=1)
    pdf.multi_cell(col_width, font_size, txt=data.str_full(), border=1)
    pdf.ln(0)
        
    path2=FILES_PATH+"/"+data.image
    
    
   
    if os.path.isfile(path2):
        path = FILES_PATH+"/"+data.image   
        
        pdf.image(path, x=0, y=15*font_size, w=100, h=50)
            
    else:
        pdf.write(5, 'Brak zdjecia!')
    
def save_pdf(filename):
    if len(filename) > 0:
        path_to_file = os.path.join(FILES_PATH_PDF, filename)
        file_to_save.save(path_to_file)
    else:
        log.warn("Empty content of file!")