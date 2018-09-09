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

# Enabling the email functionality. Change to True if you want to emails to be sent
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