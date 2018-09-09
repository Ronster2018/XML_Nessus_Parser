# XML_Nessus_Parser ![CI status](https://img.shields.io/badge/python-2.7-green.svg)

The XML Nessus Parser is a tool that makes requests to the Nessus API, 
downloads, sorts the information to csv files, and optionally emails those files to who needs to see it.

## Installation

### Requirements
* Windows
* Python 2.7
* requests
* urllib3

`$ pip install -r requirements.txt`

## Set Up
* Run setup.py first. This should create the required file structure for the project.

* Edit the config.py and add your API credentials along with other important information.
```python
# Your Nessus Scanner API Keys
ACCESS_KEY = "Your_Nessus_Access_Key"
SECRET_KEY = "Your_Nessus_SecretKey"

# Your URL for the API
API_URL = "https://nessus.yourInfo.com"

# The Port Number
API_PORT = "1234"

# Warnings Greater than or equal to the number you want
SEVERITY = '1'  # Meaning we will see 1 and above

# Before we can sort the devices to their owners, we need a directory.
# The set up of the Directory is represented with key, value pairs.
# This is represented with the IP on the left, followed by a delimiter, and then the Owners name.

# EX: 10.10.10.10 : Mike
DIRECTORY = False

# Enabling the email functionality. Change to True if you want emails to be sent
# The set up of the Directory is represented with key, value pairs.
# This is represented with the Name on the left and the email on the right with a space in between

# EX: Mike mike@gmail.com
EMAIL = False

# The email address that will be sending the emails
EMAIL_ADDRESS = "Send_Emails_From_Here@site.com"
PASSWORD = ""

# When writing your dictionary of IP and Owner, and the email file of Owners and Email
# make sure to include a delimiter that is unique and does not show in the .txt file
# of your choosing
Delimiter = ":"
```


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)