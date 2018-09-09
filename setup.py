'''
This file will set up the needed files and directories within the program folder
4/18/2018
K'Ron Simmons

1) Contacts Folder
2) CSV Folder
3) Sorted folder
    3.5) Unassigned folder

'''
import os
import logging

''' Error Log Information '''
logging.basicConfig(filename='errors.log', level=logging.WARNING,
                    format='\n %(levelname)s - %(asctime)s - %(message)s - %(filename)s - Line: %(lineno)d')
logger = logging.getLogger()
''' End of Error Log information'''

def set_up():
    try:
        if os.path.isdir("Contacts") == False:  # if the directory does not exist, Make it and make file
            # create the file
            os.mkdir("Contacts")
            open('Directory.txt', 'a').close()
        else:
            pass

        if os.path.isdir("CSV_Files") == False:
            os.makedirs("CSV_Files/Unassigned")
        else:
            pass
        if os.path.isdir("Contacts") == False:
            # create the file
            os.mkdir("Contacts")
            open('Dictionary.txt', 'a').close()
            open('Email.txt', 'a').close()
        else:
            pass
    except Exception as e:
        logger.warning(e, exc_info=True)
set_up()