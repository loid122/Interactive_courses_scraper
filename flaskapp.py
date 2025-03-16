from flask import Flask, render_template,request,jsonify,redirect,render_template_string,abort,flash,url_for,session,make_response
from bs4 import BeautifulSoup
import html
from flask_cors import CORS
import requests
import re
from collections import defaultdict
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import base64
import time 
import json
import jwt
import datetime
import pprint
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


KEY = get_random_bytes(32)     #SAVE ONCE AND KEEP IT CONSTANT
SECRET_KEY = 'my_jwt_secret_key'   #JWT SIGNING KEY

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  #key for flashes

CORS(app)
@app.route('/')
def home():
    return(render_template('home.html'))


def decode_jwt(token):
    try:
        print(token.count('.'))
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}


def encrypt_jwt(pt,KEY):
    cipher = AES.new(KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(pt.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_jwt(ct,KEY):
    decoded = base64.b64decode(ct)
    nonce, tag, ciphertext = decoded[:16], decoded[16:32], decoded[32:]
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

@app.before_request
def check_auth():
    token = request.cookies.get('jwt_token')

    if request.endpoint == 'userdashboard':
        if not token:
            return redirect(url_for('login'))

        try:
            # Decode the JWT token
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_rollno = data.get('user_rollno')

            if not user_rollno:
                abort(401)

            # Valid token, allow access without redirect
            return None

        except jwt.ExpiredSignatureError:
            flash('Session expired. Please log in again.', 'error')
            return redirect(url_for('login'))

        except jwt.InvalidTokenError:
            flash('Invalid session. Please log in again.', 'error')
            return redirect(url_for('login'))

    elif request.endpoint in ['attendance', 'viewgrades', 'expenditure','inmoodle']:
        if not token:
            return jsonify({"error": "Missing token"}), 401

        decoded = decode_jwt(token)
        if 'error' in decoded or not decoded.get('user_rollno'):
            return jsonify(decoded), 401

        # Attach decoded payload to request context
        request.decoded_jwt = decoded

    return None  # Allow request to proceed if no issues

        
@app.route('/dashboard')
def userdashboard():
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('jwt_token')
    flash('Logged out successfully!', 'success')
    return resp

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_rollno = request.form['username']
        user_pw = request.form['password']
        user_digi_pw = request.form['digipassword']
        url = "https://discourse.iitm.ac.in/auth/ldap/callback"

        headers = {
            "Host": "discourse.iitm.ac.in",
            "Cache-Control": "max-age=0",
            "Sec-Ch-Ua": '"Chromium";v="133", "Not(A:Brand";v="99"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": "Windows",
            "Accept-Language": "en-US,en;q=0.9",
            "Origin": "https://discourse.iitm.ac.in",
            "Content-Type": "application/x-www-form-urlencoded",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Referer": "https://discourse.iitm.ac.in/auth/ldap",
            "Accept-Encoding": "gzip, deflate, br",
            "Priority": "u=0, i",
            "Connection": "keep-alive"
        }

        payload = {
                    "username": user_rollno,
                    "password": user_pw
                }

        response = requests.post(url, headers=headers, data=payload)
        if 'error authorizing your account' not in response.text:
            payload = {
                'user_rollno': user_rollno,  # Unique ID for the account
                'user_pw': encrypt_jwt(user_pw,KEY),
                'user_digi_pw': encrypt_jwt(user_digi_pw,KEY),
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expiration
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

            flash('Login successful!', 'success')

            # Set JWT token as a cookie (HttpOnly prevents JS access)
            resp = make_response(jsonify({
                'redirect_url': url_for('userdashboard'),
                'messages': [('success', 'Login successful!')]
            }))
            resp.set_cookie('jwt_token', token, httponly=True, samesite='Strict')
            return resp
        else:
            flash('Invalid username or password', 'error')
            return jsonify({
                'error': 'Invalid credentials',
                'redirect_url': url_for('login'),
                'messages': [('error', 'Invalid username or password')]
            }), 401

    elif request.method == 'GET':
        return render_template('login.html')
    else:
        abort(405)




@app.route('/findcurriculum')
def findcurriculum():
    return(render_template('indo.html'))

@app.route('/map/<dept>')
def map(dept,period = 'JAN-MAY 2025'):
    if dept.lower() in ['cs','ee','me','ed','mm','oe','ch','cy','ma','ce','ae','bt']:
        pp=process_prerequisites(get_all_courses_courseprereq_dict(dept,period),get_all_courses_with_names(dept,period))
        pp_data = get_all_courses_courseprereq_dict(dept,period)
    elif dept in ['ph','ep']:
        pp=process_prerequisites(get_all_courses_courseprereq_dict('ph',period),get_all_courses_with_names_for_ep('ph',period))
        pp_data = get_all_courses_courseprereq_dict('ph',period)
    else:
        abort(404)
    return render_template('index.html',courseprereq=pp,coursedata=pp_data)

def get_all_courses_with_names_for_ep(dept,period='JAN-MAY 2025'):

    url = "https://academic.iitm.ac.in/load_record1.php"
    headers = {
        "Host": "academic.iitm.ac.in",  
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"133\", \"Not(A:Brand\";v=\"99\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://academic.iitm.ac.in",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://academic.iitm.ac.in/slotwise1.php",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i",
        "Connection": "keep-alive",
    }

    data = {
        "pid": "Slot",
        "peroid_wise": period,
        "dept_code": dept
    }

    response = requests.post(url, headers=headers, data=data)

    raw_html = (response.text)  # Print response content
    html_data = raw_html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("\/", "/")
    soup = BeautifulSoup(html_data,'html.parser')
    details = {}
    for row in soup.find_all("tr"):
        columns = row.find_all("td")
        if len(columns) > 3:
            details[columns[3].text.strip()] = {"Course Name": columns[4].text.strip()}
    return (details) if details else None

def get_all_courses_courseprereq_dict(dept,period='JAN-MAY 2025'):
    url = "https://academic.iitm.ac.in/load_record1.php"
    headers = {
        "Host": "academic.iitm.ac.in",  
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"133\", \"Not(A:Brand\";v=\"99\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://academic.iitm.ac.in",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://academic.iitm.ac.in/slotwise1.php",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i",
        "Connection": "keep-alive",
    }

    data = {
        "pid": "Slot",
        "peroid_wise": period,
        "dept_code": dept
    }

    response = requests.post(url, headers=headers, data=data)

    raw_html = (response.text)  # Print response content
    html_data = raw_html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("\/", "/")
    soup = BeautifulSoup(html_data,'html.parser')
    course_prereq=dict()
    # Loop through all table rows
    for row in soup.find_all("tr"):
        columns = row.find_all("td")
        if len(columns) > 9:  # Ensure enough columns exist
            course_prereq[columns[3].text.strip()]=columns[9].text.strip()
    #print('get_all_courses_courseprereq_dict working')
    return(course_prereq)

def get_specific_course_details(courseid,dept,period='JAN-MAY 2025'):
    url = "https://academic.iitm.ac.in/load_record1.php"
    headers = {
        "Host": "academic.iitm.ac.in",  
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"133\", \"Not(A:Brand\";v=\"99\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://academic.iitm.ac.in",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://academic.iitm.ac.in/slotwise1.php",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i",
        "Connection": "keep-alive",
    }

    data = {
        "pid": "Slot",
        "peroid_wise": period,
        "dept_code": dept
    }

    response = requests.post(url, headers=headers, data=data)

    raw_html = (response.text)  # Print response content
    html_data = raw_html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("\/", "/")
    soup = BeautifulSoup(html_data,'html.parser')
    for row in soup.find_all("tr"):
        columns = row.find_all("td")
        if len(columns) > 3 and columns[3].text.strip() == courseid:  # Check if course number matches
            details = {
                "Course Name": columns[4].text.strip(),
                "Course Number": columns[3].text.strip(),
                "Instructor Name": columns[5].text.strip(),
                "New Credit": columns[7].text.strip(),
                "Room": columns[8].text.strip(),
                "tobematchedprereq": columns[9].text.strip(),
                "Offered for BTech": columns[12].text.strip()
            }
            #print('getspecificcourse working')
            return details  # Return details as a dictionary
    #print('course no not found')    
    return None  # Return None if course number is not found

def get_all_courses_with_names(dept,period='JAN-MAY 2025'):
    url = "https://academic.iitm.ac.in/load_record1.php"
    headers = {
        "Host": "academic.iitm.ac.in",  
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"133\", \"Not(A:Brand\";v=\"99\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://academic.iitm.ac.in",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://academic.iitm.ac.in/slotwise1.php",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i",
        "Connection": "keep-alive",
    }

    data = {
        "pid": "Slot",
        "peroid_wise": period,
        "dept_code": dept
    }

    response = requests.post(url, headers=headers, data=data)

    raw_html = (response.text)  # Print response content
    html_data = raw_html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("\/", "/")
    soup = BeautifulSoup(html_data,'html.parser')
    for row in soup.find_all("tr"):
        columns = row.find_all("td")
        if len(columns) > 3 :  # Check if course number matches
            details = {
                (columns[3].text.strip):{"Course Name": columns[4].text.strip()}

            }
            #print('get_all_courses_with_names working')
            return details  # Return details as a dictionary
    return None  


def process_prerequisites(all_courses_prereq_dict, all_courses_with_names_dict):
    filtered_prereqs = {}
    invalid_values = {"NULL", "NIL", "None", "NA", "-", "Null", "Nil"} 

    for course, tobematchedprereq in all_courses_prereq_dict.items():
        prereq_list = []
        tobematchedprereq = tobematchedprereq.strip() 


        if tobematchedprereq in invalid_values:
            filtered_prereqs[course] = []
            continue
        matches = re.findall(r'\b[A-Z]{2}\d{4}\b', tobematchedprereq)
        prereq_list.extend(matches)

        for course_id, details in all_courses_with_names_dict.items():
            course_title = details['Course Name'].strip().lower()

            # Check if the entire course title is present in the prerequisite text  (still not fixed)
            if course_title in tobematchedprereq.lower():
                prereq_list.append(course_id)

        prereq_list = [i for i in prereq_list if isinstance(i, str)]

        filtered_prereqs[course] = list(set(prereq_list))
    return filtered_prereqs

@app.route('/courses', methods=['POST'])
def course():
    c_id = request.json.get('courseid')
    if type(c_id)==type('a'):
        if c_id[:2]=='AS':
            return(jsonify(get_specific_course_details(c_id,'AE')))
        elif c_id[:2]=='EP':
            return(jsonify(get_specific_course_details(c_id,'PH')))
        
        elif c_id[:2]=='EP':
            return(jsonify(get_specific_course_details(c_id,'PH')))
        
        elif c_id[:2]=='CA':
            return(jsonify(get_specific_course_details(c_id,'CH')))


        return(jsonify(get_specific_course_details(c_id,c_id[:2])))  
    else:
        return (jsonify({'error':'courseid not string'}))

#GETTING CURRICULUM DICTS FOR SPECIFIC BRANCH AND DEGREE
@app.route('/curriculum/2019_btech')
def get_curriculum_2019btech():
    return(redirect('https://www.iitm.ac.in/sites/default/files/Academic Curricula Files/B.Tech-Curriculum-2019.pdf'))

@app.route('/curriculum/2019_mtech')
def get_curriculum_2019mtech():
    return(redirect('https://www.iitm.ac.in/sites/default/files/Academic Curricula Files/DualDegree-Curriculum-2019.pdf'))

@app.route('/curriculum/cs')
def get_curriculum_cs():
    res = requests.get('https://www.cse.iitm.ac.in/pages.php?pages=MzA=')

    raw_html = res.text
    html_data = raw_html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("\/", "/")
    soup = BeautifulSoup(html_data,'html.parser')


    result = {}

    for table in soup.find_all('table'):
        for row in table.find_all('tr')[1:-1]:  # Skip the header and total row
            cells = row.find_all('td')
            if len(cells) >= 11:  # Ensure there are enough columns
                semester = f"sem{cells[0].get_text(strip=True)}"
                course_code = cells[1].get_text(strip=True)
                course_title = cells[2].get_text(strip=True)
                credits = cells[9].get_text(strip=True)
                category = cells[10].get_text(strip=True)

                if semester not in result:
                    result[semester] = {}

                if course_code:  
                    result[semester][course_code] = [course_title, credits, category]
    return(jsonify(result))  # Final nested dict

@app.route('/curriculum/me')
def get_curriculum_me():
    res = requests.get('https://mech.iitm.ac.in/curriculum.php')
    raw_html = res.text
    html_data = raw_html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("\/", "/")
    soup = BeautifulSoup(html_data,'html.parser')

    result = {}

    # Identify the table
    for table in soup.find_all('table'):
        current_sem = None

        # Iterate through rows
        for row in table.find('tbody').find_all('tr'):
            cells = [td.get_text(strip=True) for td in row.find_all('td')]

            # Check if the row indicates a new semester
            if 'Semester' in cells[0]:
                current_sem = cells[0].replace(' ', '').lower()
                result[current_sem] = {}

            # Add course details to the current semester
            elif current_sem and all(cells[:2]):
                course_code = cells[0]
                course_name = cells[1]
                credits = cells[8]
                category = cells[9]
                result[current_sem][course_code] = [course_name, credits, category]

    return(jsonify(result))  # Final mech dictionary for old curriculum

@app.route('/curriculum/ee/old')
def get_curriculum_ee_old():
    return(redirect('https://www.ee.iitm.ac.in/eeimg/UG-curriculum_2023_and_older_batches.pdf'))

@app.route('/curriculum/ee/new')
def get_curriculum_ee_new():
    return(redirect('https://www.ee.iitm.ac.in/eeimg/UG-curriculum_2024_onward_batches.pdf'))

@app.route('/curriculum/ae/dual')
def get_curriculum_ae_dual():
    return(redirect('https://ae.iitm.ac.in/documents/BTech_dd_ae_2015_batch.pdf'))

@app.route('/curriculum/ae/btech')
def get_curriculum_ae():
    return(redirect('https://ae.iitm.ac.in/documents/BT_curriculum.pdf'))

@app.route('/curriculum/ep/btech')
def get_curriculum_ep():
    return(redirect('https://physics.iitm.ac.in/dashboard/download/EP_curriculum_official.pdf'))

@app.route('/curriculum/ep/dual')
def get_curriculum_ep_dual():
    return(redirect('https://physics.iitm.ac.in/dashboard/download/DD_curriculum_official.pdf'))

@app.route('/curriculum/civil/22/btech')
def get_curriculum_civil_22():
    return(redirect('https://civil.iitm.ac.in//admin/coursedetailimage/2022%20Batch%20-%20B.Tech%20Curriculum.pdf'))

@app.route('/curriculum/civil/22/mtech')
def get_curriculum_civil_22_mtech():
    return(redirect('https://civil.iitm.ac.in//admin/coursedetailimage/2022%20Batch%20-%20MTech%20Curriculum.pdf'))

@app.route('/curriculum/civil/24/btech')
def get_curriculum_civil_24():
    return(redirect('https://civil.iitm.ac.in//admin/coursedetailimage/B.Tech 2024 curriculum.pdf'))

@app.route('/curriculum/oe/btech')
def get_curriculum_oe():
    res = requests.get('https://doe.iitm.ac.in/courses/')
    raw_html = res.text
    html_data = raw_html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("\/", "/")
    soup = BeautifulSoup(html_data, 'html.parser')
    target_section = None

    # Locate the target section
    for section in soup.find_all('div', class_='su-spoiler-title'):
        if 'B.Tech (Naval Architecture & Ocean Engineering Syllabus)' in section.text:
            target_section = section.find_next_sibling('div')
            break

    # Extract data only from the target section
    data = defaultdict(lambda: defaultdict(list))
    unknown_count = 1

    if target_section:
        for pane in target_section.find_all('div', class_='su-tabs-pane'):
            semester = pane.get('data-title', 'Unknown Semester')

            for row in pane.find_all('tr'):
                cells = row.find_all('td')

                # Skip rows without enough columns or header rows
                if len(cells) >= 9 and not cells[0].text.strip().lower().startswith("course"):

                    # Helper function to extract text or provide placeholder
                    def get_text_or_dash(cell):
                        return cell.a.text.strip() if cell.a else (cell.text.strip() or '-')

                    # Extract values, replacing empty ones with '-'
                    course_code = get_text_or_dash(cells[0])
                    course_title = get_text_or_dash(cells[1])
                    credits = get_text_or_dash(cells[7])
                    category = get_text_or_dash(cells[8])

                    # Skip rows where course title is '-'
                    if course_title == '-':
                        continue

                    # Ensure course_code has a placeholder if empty
                    if course_code == '-':
                        course_code = f"XXXXXX-{unknown_count}"
                        unknown_count += 1

                    # Replace 'Total' with '~' in course_code
                    if course_title == 'Total':
                        course_code = '~'

                    # Store the extracted information
                    data[semester][course_code] = [course_title, credits, category]

    return jsonify(data)

@app.route('/curriculum/oe/bmtech')
def get_curriculum_oe_bmtech():
    res = requests.get('https://doe.iitm.ac.in/courses/')
    raw_html = res.text
    html_data = raw_html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("\/", "/")
    soup = BeautifulSoup(html_data,'html.parser')



    target_section = None
    for section in soup.find_all('div', class_='su-spoiler-title'):
        if 'B.Tech & M.Tech( Naval Architecture & Ocean Engineering)' in section.text:
            target_section = section.find_next_sibling('div')
            break

    # Extract data only from the target section
    data = defaultdict(lambda: defaultdict(list))

    if target_section:
        for pane in target_section.find_all('div', class_='su-tabs-pane'):
            semester = pane.get('data-title', 'Unknown Semester')

            for row in pane.find_all('tr'):
                cells = row.find_all('td')

                # Skip rows without enough columns or header rows
                if len(cells) >= 9 and not cells[0].text.strip().lower().startswith("course"):
                    course_code = cells[0].text.strip()
                    course_title = cells[1].a.text.strip() if cells[1].a else cells[1].text.strip()
                    credits = cells[7].text.strip()  # 'Cr' value
                    category = cells[8].text.strip() # 'Cat' value

                    # Store the required information
                    data[semester][course_code] = [course_title, credits, category]

    return(jsonify(data))

@app.route('/curriculum/oe/mtech_oceanstructures_stream1')
def get_curriculum_oe_mtech_oceanstructures_s1():
    res = requests.get('https://doe.iitm.ac.in/courses/')
    raw_html = res.text
    html_data = raw_html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("\/", "/")
    soup = BeautifulSoup(html_data,'html.parser')
    target_section = None
    for section in soup.find_all('div', class_='su-spoiler-title'):
        if 'Stream - 1 : Offshore and Ship structures' in section.text:
            target_section = section.find_next_sibling('div')
            break

    # Extract data only from the target section
    data = defaultdict(lambda: defaultdict(list))

    if target_section:
        for pane in target_section.find_all('div', class_='su-tabs-pane'):
            semester = pane.get('data-title', 'Unknown Semester')

            for row in pane.find_all('tr'):
                cells = row.find_all('td')

                # Skip rows without enough columns or header rows
                if len(cells) >= 9 and not cells[0].text.strip().lower().startswith("course"):
                    course_code = cells[1].text.strip()
                    course_title = cells[2].a.text.strip() if cells[2].a else cells[2].text.strip()
                    credits = cells[8].text.strip()  # 'Cr' value
                    #category = cells[8].text.strip() # 'Cat' value
                    
                    if course_title == 'Total Credits :':
                        course_code='~'
                    if course_title.startswith('SEMESTER'):
                        continue
                    # Store the required information
                    data[semester][course_code] = [course_title, credits,'']

    return(jsonify(data))

@app.route('/curriculum/oe/mtech_oceanstructures_stream2')
def get_curriculum_oe_mtech_oceanstructures_s2():
    res = requests.get('https://doe.iitm.ac.in/courses/')
    raw_html = res.text
    html_data = raw_html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("\/", "/")
    soup = BeautifulSoup(html_data,'html.parser')
    target_section = None
    for section in soup.find_all('div', class_='su-spoiler-title'):
        if 'Stream - 2 : Port, Harbour and Coastal Structure' in section.text:
            target_section = section.find_next_sibling('div')
            break

    # Extract data only from the target section
    data = defaultdict(lambda: defaultdict(list))

    if target_section:
        for pane in target_section.find_all('div', class_='su-tabs-pane'):
            semester = pane.get('data-title', 'Unknown Semester')

            for row in pane.find_all('tr'):
                cells = row.find_all('td')

                # Skip rows without enough columns or header rows
                if len(cells) >= 9 and not cells[0].text.strip().lower().startswith("course"):
                    course_code = cells[1].text.strip()
                    course_title = cells[2].a.text.strip() if cells[2].a else cells[2].text.strip()
                    credits = cells[8].text.strip()  # 'Cr' value
                    #category = cells[8].text.strip() # 'Cat' value
                    
                    if course_title == 'Total Credits :':
                        course_code='~'
                    if course_title.startswith('SEMESTER'):
                        continue
                    # Store the required information
                    data[semester][course_code] = [course_title, credits,'']

    return(jsonify(data))
    
@app.route('/curriculum/oe/mtech_oceantech')
def get_curriculum_oe_mtech_oceantech():
    res = requests.get('https://doe.iitm.ac.in/courses/')
    raw_html = res.text
    html_data = raw_html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("\/", "/")
    soup = BeautifulSoup(html_data,'html.parser')
    target_section = None
    for section in soup.find_all('div', class_='su-spoiler-title'):
        if 'M.Tech Ocean Technology (NIOT UOP - OE2)' in section.text:
            target_section = section.find_next_sibling('div')
            break

    # Extract data only from the target section
    data = defaultdict(lambda: defaultdict(list))

    if target_section:
        for pane in target_section.find_all('div', class_='su-tabs-pane'):
            semester = pane.get('data-title', 'Unknown Semester')

            for row in pane.find_all('tr'):
                cells = row.find_all('td')

                # Skip rows without enough columns or header rows
                if len(cells) >= 9 and not cells[0].text.strip().lower().startswith("course"):
                    course_code = cells[1].text.strip()
                    course_title = cells[2].a.text.strip() if cells[2].a else cells[2].text.strip()
                    credits = cells[8].text.strip()  # 'Cr' value
                    #category = cells[8].text.strip() # 'Cat' value
                    
                    if course_title == 'Total Credits :':
                        course_code='~'
                    if course_title.startswith('SEMESTER'):
                        continue
                    # Store the required information
                    data[semester][course_code] = [course_title, credits,'']

    return(jsonify(data))

@app.route('/curriculum/oe/mtech_petroleum')
def get_curriculum_oe_mtech_petroleum():
    res = requests.get('https://doe.iitm.ac.in/courses/')
    raw_html = res.text
    html_data = raw_html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("\/", "/")
    soup = BeautifulSoup(html_data,'html.parser')
    target_section = None
    for section in soup.find_all('div', class_='su-spoiler-title'):
        if 'M.Tech Petroleum Engineering' in section.text:
            target_section = section.find_next_sibling('div')
            break

    # Extract data only from the target section
    data = defaultdict(lambda: defaultdict(list))

    if target_section:
        for pane in target_section.find_all('div', class_='su-tabs-pane'):
            semester = pane.get('data-title', 'Unknown Semester')

            for row in pane.find_all('tr'):
                cells = row.find_all('td')

                # Skip rows without enough columns or header rows
                if len(cells) >= 9 and not cells[0].text.strip().lower().startswith("course"):
                    course_code = cells[1].text.strip()
                    course_title = cells[2].a.text.strip() if cells[2].a else cells[2].text.strip()
                    credits = cells[8].text.strip()  # 'Cr' value
                    #category = cells[8].text.strip() # 'Cat' value
                    
                    if course_title == 'Total Credits :':
                        course_code='~'
                    if course_title.startswith('SEMESTER'):
                        continue
                    # Store the required information
                    data[semester][course_code] = [course_title, credits,'']

    return(jsonify(data))



@app.route('/curriculum/ed/auto_old')
def get_curriculum_ed_auto_old():
    return(redirect('https://ed.iitm.ac.in/img/files/Revised curriculum Auto from July 2019 Batch 22.06.2021.pdf'))

@app.route('/curriculum/ed/auto_new')
def get_curriculum_ed_auto_new():
    return(redirect('https://ed.iitm.ac.in/img/files/ED_Automotive_DD_Credit_2024_Batch_Onward.pdf'))

@app.route('/curriculum/ed/bio_old')
def get_curriculum_ed_bio_old():
    return(redirect('https://ed.iitm.ac.in/img/files/Revised curriculum Bio from July 2019 Batch 22.06.21.pdf'))

@app.route('/curriculum/ed/bio_new')
def get_curriculum_ed_bio_new():
    return(redirect('https://ed.iitm.ac.in/img/files/ED_Biomedical_DD_Credit_2024_Batch_Onward.pdf'))

@app.route('/curriculum/ed/iddd_robo_old')
def get_curriculum_ed_iddd_robo_old():
    return(redirect('https://ed.iitm.ac.in/img/files/IDDD.pdf'))

@app.route('/curriculum/ed/iddd_robo_new')
def get_curriculum_ed_iddd_robo_new():
    return(redirect('https://ed.iitm.ac.in/img/files/IDDD_Robotics_2025.pdf'))

@app.route('/curriculum/ed/iddd_ev_old')
def get_curriculum_ed_iddd_ev_old():
    return(redirect('https://ed.iitm.ac.in/img/files/IDDD-EV-Curriculum_Senate_Approved_Jan_2022.pdf'))

@app.route('/curriculum/ed/iddd_ev_new')
def get_curriculum_ed_iddd_ev_new():
    return(redirect('https://ed.iitm.ac.in/img/files/IDDD-EV-Curriculum_2025_Onward.pdf'))


@app.route('/ikollege/NFC_expenditure')
def expenditure():
    user_rollno = request.decoded_jwt['user_rollno']
    user_pw = decrypt_jwt(request.decoded_jwt['user_pw'])
    options = Options()
    options.add_argument("--headless")  # Uncomment for headless mode

    # Initialize driver
    driver = webdriver.Firefox(options=options)

    driver.get("https://ikollege.iitm.ac.in/iitmhostel/login.do?method=userlogin&loginType=student")

    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "loginid"))).send_keys(user_rollno)
    driver.find_element(By.ID, "passwordid").send_keys(user_pw)

    # Click the login button
    login_button = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.XPATH, "//input[@type='submit' and @value='Login']"))
    )
    login_button.click()
    customer_login = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.LINK_TEXT, "Click here to View the Food Court Report"))
        )
    current_url = driver.current_url
    customer_login.click()
    WebDriverWait(driver, 20).until(lambda d: d.current_url != current_url)
    raw_html = driver.page_source  
    html_data = raw_html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("\/", "/")
    soup = BeautifulSoup(html_data,'html.parser')
    table = soup.find('table')
    headings = [th.text.strip() for th in table.find_all('th')]
    rows = []
    for tr in table.find_all('tr'):
        cells = [td.text.strip() for td in tr.find_all('td')]
        if cells and "Total :" not in cells:
            rows.append(cells)
    data = {
        "headings": headings,
        "rows": rows
    }
    driver.quit()
    pprint.pprint(data)
    return(render_template('nfc_expenditure.html',data = data))


@app.route('/viewgrades')
def viewgrades():
    user_rollno = request.decoded_jwt['user_rollno']
    user_pw = decrypt_jwt(request.decoded_jwt['user_pw'])
    options = Options()
    options.add_argument("--headless")
    driver = webdriver.Firefox(options=options)
    driver.get("https://www.iitm.ac.in/viewgrades/")

    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "username"))).send_keys(user_rollno)
    driver.find_element(By.ID, "password").send_keys(user_pw)

    # Click the login button
    login_button = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.XPATH, "//input[@type='submit' and @value='LogIn']"))
    )
    current_url = driver.current_url
    login_button.click()

    WebDriverWait(driver, 20).until(lambda d: d.current_url != current_url)

    raw_html = driver.page_source  # Updated content
    html_data = raw_html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("\/", "/")
    soup = BeautifulSoup(html_data,'html.parser')

    headers = [th.get_text(strip=True) for th in soup.find_all('th')]

    # Initialize output
    output = {}

    # Find all semesters and corresponding tables
    semester_tables = soup.find_all('table')[1:]  # Ignore first table (header)

    current_semester = None
    for table in semester_tables:
        rows = table.find_all('tr')

        for row in rows:
            cols = [td.get_text(strip=True) for td in row.find_all('td')]

            # Identify semester row
            if len(cols) == 1 and 'Semester' in cols[0]:
                current_semester = cols[0]
                output[current_semester] = {}
            elif len(cols) == 1 and ' (' in cols[0]:
                current_semester = cols[0]
                output[current_semester] = {}
            elif len(cols) == 1 and 'Earned Credit:' in cols[0]:
                output[current_semester]['sem_gpa'] = cols[0]
            # Regular course rows
            elif len(cols) == 7 and current_semester:
                course_no = cols[1]
                output[current_semester][course_no] = cols[2:]
    driver.quit()   
    return render_template('viewgrades.html', output=output)




@app.route('/attendance')
def attendance():
    user_rollno = request.decoded_jwt['user_rollno']
    user_digi_pw = decrypt_jwt(request.decoded_jwt['user_digi_pw'])
    options = Options()
    options.add_argument("--headless")
    driver = webdriver.Firefox(options=options)
    driver.get("https://iitm.digiicampus.com/home")
    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, 'input[data-cy="loginform.email"]'))).send_keys(user_rollno)
    driver.find_element(By.CSS_SELECTOR, 'input[data-cy="loginform.pwd"]').send_keys(user_digi_pw)
    print('entered data')
    sign_in_button = driver.find_element(By.CSS_SELECTOR, 'button[data-cy="loginform.signIn"]')
    sign_in_button.click()
    print('logged in!')
    time.sleep(5)
    # Get all cookies
    cookies = driver.get_cookies()
    #print("All Cookies (after delay):", cookies)
    cookie = (cookies[-1])
    val = (cookie['value'])
    print('jwt token inside digicampus')
    def decode_jwt(token):
        header, payload, _ = token.split('.')
        decoded_header = json.loads(base64.urlsafe_b64decode(header + '==').decode())
        decoded_payload = json.loads(base64.urlsafe_b64decode(payload + '==').decode())
        return(decoded_payload['ukid'])
    uid = decode_jwt(val)
    driver.get("https://iitm.digiicampus.com/userProfileCard/academics/"+str(uid))
    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
    time.sleep(5)  # Allow JS to load (adjust as needed)
    driver.execute_script("return document.readyState == 'complete'")
    raw_html = driver.page_source
    html_data = raw_html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("\/", "/")
    #pprint.pprint(html_data)
    soup = BeautifulSoup(html_data, 'html.parser')
    # Extract Total Sessions, Present, and Absent
    attendance_data = {}
    attendance_divs = soup.find_all('div', class_='att-total-count')
    for div in attendance_divs:
        label = div.find('div', class_='col-xs-4').text.strip()
        value = div.find('div', class_='ng-binding').text.strip()
        attendance_data[label] = value
    #print(attendance_data)

    # Extract course data
    course_data = {}
    course_rows = soup.find_all('div', class_='att-agg-course-header')
    for row in course_rows:
        course_name = row.find('div', class_='col-xs-4').text.strip()
        attended = row.find_all('div', class_='col-xs-2 text-center ng-binding')[0].text.strip()
        scheduled = row.find_all('div', class_='col-xs-2 text-center ng-binding')[1].text.strip()
        percentage = row.find_all('div', class_='col-xs-2 text-center ng-binding')[2].text.strip()
        course_data[course_name] = [attended, scheduled, percentage]
    print(type(course_data))
    print(type(attendance_data))
    result = attendance_data | {"subjects":course_data}

    print(result)
    return render_template('attendance.html', data=result)


@app.route('/moodle')
def inmoodle():
    user_rollno = request.decoded_jwt['user_rollno']
    user_pw = decrypt_jwt(request.decoded_jwt['user_pw'])
    session = requests.Session()
    login_url = "https://courses.iitm.ac.in/login/index.php"
    response = session.get(login_url)
    token_pattern = r'name="logintoken" value="(.*?)"'
    logintoken = re.search(token_pattern, response.text).group(1)
    post_data = {
        "logintoken": logintoken,
        "username": user_rollno,
        "password": user_pw
    }
    post_response = session.post(login_url, data=post_data, allow_redirects=True)
    print(post_response.url)
    flask_response = make_response(redirect(post_response.url))
    for cookie in session.cookies:
            flask_response.set_cookie(cookie.name, cookie.value, domain='courses.iitm.ac.in')
    return flask_response
            

if __name__ == '__main__':
    app.run(debug=True)
