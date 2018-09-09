import io
import requests
import json
import time
import urllib3
import config
import xml.etree.ElementTree as ET
import csv
import re
import os.path
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Beginning of REQUEST Frunctions ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def authenticate():
    try:

        print("[+] Authenticating... Please wait \n")

        headers = {
            'X-ApiKeys': 'accessKey=%s; secretKey=%s' %(accessKey, secretKey) ,
        }

        response = requests.get(config.API_URL+':'+config.API_PORT+'/scans',
                                headers=headers,
                                verify=False)

        print response.text
        if response.text == '{"error":"Invalid Credentials"}':
            print("[!] Invalid Credentials")
            exit(0)
        else:
            print("[+] Credentials accepted... Proceeding")
    except Exception as e:
        print("Error Hit in Requests.py. Check the log")
        # logging.error(e, exc_info=True)
        logger.warning(e, exc_info=True)

def get_scan():
    try:
        print("\n[+] Getting Scan Info...\n")
        headers = {
            'X-ApiKeys': 'accessKey=%s; secretKey=%s' % (accessKey, secretKey),
        }
        response = requests.get(config.API_URL+':'+config.API_PORT+'/scans', headers=headers, verify=False)
        r_json = response.json()
        # print type(r_json)
        with open('folders.json', 'w+') as outfile:
            json.dump(r_json, outfile)
            outfile.close()
    except Exception as e:
        print("Error Hit in Requests.py. Check the log")
        # logging.error(e, exc_info=True)
        logger.warning(e, exc_info=True)

def get_id():  # compares the dates and grabs the latest "id" of the most recent scan
    dates = []                                # list of epoch dates
    json_file = io.open("folders.json", "r", encoding="utf-8") # opens JSON file
    file = json.load(json_file)
    for f in file["scans"]:                 # we need to add all dates to list first
        dates.append(f["last_modification_date"])
    big = max(dates)                        # finds max date
    for f in file["scans"]:                 # loop goes through JSON comparing dates in list
        if f["last_modification_date"] == big:
            #print f["id"]
            id = f["id"]
            try:
                print ("Scan ID: "+ str(id))
                return id  # returns ID of scan here
            except Exception as e:
                print("Error Hit in Requests.py. Check the log")
                # logging.error(e, exc_info=True)
                logger.warning(e, exc_info=True)

def get_file_id(id):  # Takes same id. This is needed to get the file_id from the API.
    print("\n[+] Getting Field ID info ...\n")
    headers = {
        'X-ApiKeys': 'accessKey=%s; secretKey=%s' % (accessKey, secretKey),
        'Content-Type': 'application/json',
    }
    data = '{"scan_id":"'+str(id)+'","format":"nessus"}'

    response = requests.post(config.API_URL+':'+config.API_PORT+'/scans'+str(id)+'/export', headers=headers, data=data,
                             verify=False)
    r_json = response.json()
    with open('file_id.json', 'w+') as outfile:
        json.dump(r_json, outfile)
        outfile.close()
    print("[*] Done getting field ID info")


def file_id():
    print("\n[+] Extracting Field ID ...\n")
    json_file = io.open("file_id.json", "r", encoding="utf-8")  # opens JSON file
    file = json.load(json_file)
    if file == '{"error": "Scan is already being exported"}':
        print("[!] File is already being Exported")
        pass
    elif file != '{"error": "Scan is already being exported"}':
        id = file["file"]  # treat JSON as a dictionary
        print("File Id: " + str(id))
        return id

def get_download(fileid, id):
    print("\n[+] Downloading...\n")
    headers = {
        'X-ApiKeys': 'accessKey=%s; secretKey=%s' % (accessKey, secretKey),
    }

    response = requests.get(config.API_URL+':'+config.API_PORT+'/scans'+str(id)+'/export/'+str(fileid)+'/download',
                            headers=headers,verify=False)
    open('output.nessus', 'w+').write(response.content)
    print("[*] Done Downloading")

def get_status(fileid, id):
    print("[+] Checking Status")
    headers = {
        'X-ApiKeys': 'accessKey=%s; secretKey=%s' % (accessKey, secretKey),
    }
    # print (id)
    # print(fileid)
    response = requests.get(config.API_URL+':'+config.API_PORT+'/scans'+str(id)+'/export/'+str(fileid)+'/status',
                            headers=headers,
                            verify=False)
    data = response.json()
    print data['status']
    if data['error']:
        print("[!] error... Download does not exist yet? Please Investigate")
        exit(0)
    elif data['status'] == 'ready':
        print("[+] Download is ready... Downloading")
        # Calling Get download on the file, below.
        # get_download(fileid, id)
        exit()
    else:
        while data['status'] == 'loading': # while teh data is loading
            print("[+] Waiting for file to be ready. Please wait")
            time.sleep(5)   # give the
            response = requests.get(
                config.API_URL+':'+config.API_PORT+'/scans' + str(id) + '/export/' + str(fileid) + '/status',
                headers=headers,
                verify=False)
            data = response.json()  # make the request again
            print data['status']   # to check the status of the file
            if data['status'] == 'ready':
                get_download(fileid, id)
            else:
                pass

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ End of REQUEST Functions ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Beginning of PARSING Functions ~~~~~~~~~~~~~~~~~~~~~~~~~~~
def getSeverity(sub):
    severity = sub.get('severity')  # Report > ReportHost > ReportItem  > tag name
    return severity


def getProtocol(sub):
    protocol = sub.get('protocol')  # Report > ReportHost > ReportItem  > tag name
    return protocol

def getPort(sub):
    port = sub.get('port')  # Report > ReportHost > ReportItem  > tag name
    return port

def getPlugin(sub):
    pluginName = sub.get('pluginName')  # Report > ReportHost > ReportItem  > tag name
    return pluginName

def getCVE(sub):
    '''
    Loop through N amount of CVE and add to a list.
    Make sure that they are all unique numbers.
    Join them by a comma
    Return the CVE list
    '''
    CVE = []
    for child in sub:
        if child.tag == 'cve':
            cve = child.text
            CVE.append(cve)
            CVE = set(CVE)
            CVE = ", ".join(CVE)
        else:

            pass
    return "\t"

def getCVSS(items):
    for sub in items:
        if sub.tag == 'cvss_base_score':
            cvss_base_score = sub.text
            return cvss_base_score
        else:
            pass
    return "\t"

def getDesc(items):
    for sub in items:
        if sub.tag == 'description':
            description = sub.text
            return description
        else:
            pass
    return "\t"

def getSolution(items):
    for sub in items:
        if sub.tag == 'solution':
            solution = sub.text
            return solution
        else:
            pass
    return "\t"

def getModDate(items):
    for sub in items:
        if sub.tag == 'plugin_modification_date':
            mod_date = sub.text
            return mod_date
        else:
            pass
    return "\t"

def getPubDate(items):
    for sub in items:
        if sub.tag == 'plugin_publication_date':
            pub_date = sub.text
            return pub_date
        else:
            pass
    return "\t"

def getCVSS(items):
    for sub in items:
        if sub.tag == 'cvss_base_score':
            cvss_base_score = sub.text
            return cvss_base_score
        else:
            pass
    return "\t"

def getDesc(items):
    for sub in items:
        if sub.tag == 'description':
            description = sub.text
            return description
        else:
            pass
    return "\t"

def getSolution(items):
    for sub in items:
        if sub.tag == 'solution':
            solution = sub.text
            return solution
        else:
            pass
    return "\t"

def getModDate(items):
    for sub in items:
        if sub.tag == 'plugin_modification_date':
            mod_date = sub.text
            return mod_date
            # print cve
        else:
            pass
    return "\t"

def getPubDate(items):
    for sub in items:
        if sub.tag == 'plugin_publication_date':
            pub_date = sub.text
            return pub_date
            # print cve
        else:
            pass
    return "\t"


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ End of PARSING Functions ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Beginning of the SENDING EMAIL Functions ~~~~~~~~~~~~~~~~~

def send_email(email,name):

    try:
        email_user = config.EMAIL_ADDRESS
        email_password = config.PASSWORD
        email_send = email

        subject = 'Nessus Machine Scan Update'

        msg = MIMEMultipart()
        msg['From'] = email_user
        msg['To'] = email_send
        msg['Subject'] = subject

        body = 'Hi there, sending this email from Python!'
        msg.attach(MIMEText(body, 'plain'))


        filename = name+".csv"
        attachment = open(filename, 'rb')
        print filename
        part = MIMEBase('application', 'octet-stream')
        part.set_payload((attachment).read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', "attachment; filename= "+filename)
        msg.attach(part)
        text = msg.as_string()
        server = smtplib.SMTP('mail.fairfield.edu:25')
        try:
            server.connect()
        except Exception as e:
            logger.warning(e, exc_info=True)
        # server.ehlo()
        # server.starttls()
        # server.login(email_user, email_password)
        server.sendmail(email_user,email_send,text)
        server.quit()
        print("Email Sent")

    except Exception as e:
        print("Email Failed to send")
        logger.warning(e, exc_info=True)

def owner():
    '''
    Open the Dictionary and grab the owners and put them in a list
    '''
    owner = []
    with open("Contacts/Directory.txt", 'r') as f:
        for line in f:
            (key, val) = line.split(config.Delimiter)
            val = val.strip("\n")
            val = val.strip(" ")
            owner.append(val)
        return owner


def email():
    '''
    Open the Email.txt and grab the emails
    '''
    email = {}
    with open("Contacts/Email.txt", 'r') as f:
        for line in f:
           (key, val) = line.split(config.Delimiter)
           key = key.strip(" ")
           val = val.strip(" ")
           email[key] = val.strip("\n")
           # val = val.strip("\n")error
           # print val
        return email


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ End of the SENDING EMAIL Functions ~~~~~~~~~~~~~~~~~~~~~~~

if __name__ == "__main__":

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    ''' Error Log Information '''
    logging.basicConfig(filename='errors.log', level=logging.WARNING,
                        format=' \n %(levelname)s - %(asctime)s - %(message)s - %(filename)s - Line: %(lineno)d')
    logger = logging.getLogger()
    ''' End of Error Log information'''

    accessKey = config.ACCESS_KEY
    secretKey = config.SECRET_KEY

    authenticate()
    get_scan()
    get_file_id(get_id())
    get_status(file_id(), get_id())

    tree = ET.parse('output.nessus') # named by
    root = tree.getroot()

    print os.system("cd")
    for report in root:
        if report.tag == 'Report':  # Start at sub tag named Report
            for reportHost in report:  # for testing, limited to fist host [:1]:
                '''The attributes are each ReportHost'''
                if reportHost.tag == 'ReportHost':  # Report > ReportHost
                    with open("Sorted/testFile.csv", "a+") as myfile:
                        wr = csv.writer(myfile, dialect='excel')
                        header = ["IP", "Severity", "Protocol", "Port", "CVE", "CVSS_BASE_SCORE", "Plugin Name",
                                  "Description", "Solution", "Discovery Date",
                                  "Plugin Publication Date"]
                        wr.writerow(header)

                        for items in reportHost:  # items = ReportItems
                            Masterlist = []
                            try:
                                if items.tag == 'HostProperties':  # Report > ReportHost > HostProperties
                                    for property in items:
                                        if property.get(
                                                'name') == 'host-ip':  # Report > ReportHost > HostProperties >tag name
                                            IP = property.text
                                            print "[+] Adding New IP to File"
                                            Masterlist.append(IP.strip("\n"))
                                            wr.writerow(Masterlist)
                                            print Masterlist

                                        else:
                                            pass
                                else:
                                    pass

                                if items.tag == 'ReportItem':  # Report > ReportHost > ReportItem
                                    if items.get('severity') >= config.SEVERITY:
                                        Severity = getSeverity(items)
                                        Protocol = getProtocol(items)
                                        Port = getPort(items)
                                        Plugin = getPlugin(items)
                                        CVE = getCVE(items)  # returns a list
                                        # print CVE

                                        Masterlist.append(Severity)
                                        Masterlist.append(Protocol)
                                        Masterlist.append(Port)
                                        Masterlist.append(Plugin)
                                        Masterlist.append(CVE)

                                        CVSS_Base_score = getCVSS(items)
                                        Description = getDesc(items)
                                        Solution = getSolution(items)
                                        Discovery_date = getModDate(items)
                                        Publication_date = getPubDate(items)

                                        Masterlist.append(CVSS_Base_score)
                                        Masterlist.append(Description)
                                        Masterlist.append(Solution)
                                        Masterlist.append(Discovery_date)
                                        Masterlist.append(Publication_date)

                                        Masterlist = ['\t', Severity, Protocol, Port, Plugin, CVE, CVSS_Base_score,
                                                      Description, Solution, Discovery_date, Publication_date]
                                        # Masterlist = ["\t",Severity, Protocol, Port,CVSS_Base_score ,CVE, Plugin, Description]
                                        # print Masterlist
                                        # stripped_line = [str.rstrip, Masterlist]
                                        # print stripped_line
                                        wr.writerow(Masterlist)
                                        del Masterlist


                            except Exception as e:
                                logger.warning(e, exc_info=True)
                    print("Done!")
                    myfile.close()

    d = {}
    header = ["IP", "Severity", "Protocol", "Port", "Plugin Name", "CVE", "CVSS_BASE_SCORE",
              "Description", "Solution", "Discovery Date",
              "Plugin Publication Date"]
    if config.DIRECTORY == True:
        with open("Contacts/Directory.txt", 'r') as f:
            for line in f:
                (key, val) = line.split(config.Delimiter)
                key = key.strip(" ")
                d[key] = val
            # open the master file
        with open("Sorted/testFile.csv", 'r') as in_file:
            csv_reader = csv.reader(in_file)
            # skip the first line
            # next(csv_reader)
            # if the first part of the line is an ip, check if its in dictionary
            for line in csv_reader:
                # print len(line)
                IP = line[0]  # IP should be the first part
                IPv4_Checker = re.compile(
                    "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
                Valid = IPv4_Checker.match(IP)
                if IP == "IP":
                    pass
                elif Valid:

                    # if its in dictionary, open the file with the name as the Value
                    # write that line to new file as well as following lines
                    # search = IP
                    try:
                        if IP not in d:
                            with open("CSV_Files/Unassigned/" + IP + ".csv", "a+") as unassigned:
                                csv_write = csv.writer(unassigned)
                                # csv_write.writerow(IP + "\t\n")
                                csv_write.writerow(header)
                                csv_write.writerow(line)
                                print("[-] %s not in dictionary" % IP)
                        else:
                            pass
                    except Exception as e:
                        print("Error Hit in Sort.py. Check the log")
                        logger.warning(e, exc_info=True)
                    try:
                        for key, value in d.items():
                            if key == IP:
                                # print key, value
                                value = value.strip("\n")
                                value = value.strip(" ")
                                with open("CSV_Files/" + value + ".csv", "a+") as owner:
                                    try:
                                        csv_write = csv.writer(owner)
                                        csv_write.writerow(header)
                                        csv_write.writerow(line)
                                        print("adding %s to file %s" % (key, value))
                                        # if next line in file is a space, write
                                        i = 1
                                        for b_line in csv_reader:  # for the lines beginning with a tab...
                                            if b_line[0] == "\t":
                                                csv_write.writerow(b_line)
                                                # print("We have a line! %d" %(i))
                                                i += 1
                                            # elif next line begins with ip, break out of this loop
                                            elif b_line[0] != "\t":
                                                break
                                        owner.close()
                                    except Exception as e:
                                        logger.warning(e, exc_info=True)
                            else:
                                pass
                    except Exception as e:
                        logger.warning(e, exc_info=True)

                elif IP == "\t":
                    pass

            in_file.close()
    else:
        pass

    if config.EMAIL == True:
        email = email()
        owner = owner()
        owner = set(owner)

        os.chdir("CSV_Files")
        for key, value in email.iteritems():
            for o in owner:
                if key == o:
                    try:
                        # print value # this is the email
                        email = value
                        name = key

                        send_email(email, name)
                        # print email, name+'.csv'
                    except Exception as e:
                        logger.warning(e, exc_info=True)
    else:
        pass