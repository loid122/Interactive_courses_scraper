from flask import Flask, render_template,request,jsonify
from bs4 import BeautifulSoup
import html
import requests
import re

app = Flask(__name__)

@app.route('/')
def home():
    dept='ME'
    ch=process_prerequisites(get_all_courses_courseprereq_dict(dept),get_all_courses_with_names(dept))
    ch_data = get_all_courses_courseprereq_dict(dept)
    return render_template('index.html',courseprereq=ch,coursedata=ch_data)


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
    return(course_prereq)
'''
def get_all_courses_prereq(dept,period='JAN-MAY 2025'):
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
    for row in soup.find_all("tr"):
        columns = row.find_all("td")
        if len(columns) > 9:  # Ensure enough columns exist
            course_prereq[columns[3].text.strip()]=columns[9].text.strip()
    return(course_prereq)

'''
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
            return details  # Return details as a dictionary
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
            return details  # Return details as a dictionary
    return None  # Return None if course number is not found


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
    print(filtered_prereqs)
    return filtered_prereqs




@app.route('/courses', methods=['POST'])
def course():
    c_id = request.json.get('courseid')
    if type(c_id)==type('a'):
        print((get_specific_course_details(c_id,c_id[:2])))
        return(jsonify(get_specific_course_details(c_id,c_id[:2])))
        
    else:
        return ('courseid not string')



if __name__ == '__main__':
    app.run(debug=True)