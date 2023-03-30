#!/usr/bin/python
"""
Copyright 2017 - Arnold Holzel

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
##################################################################
# Author        : Arnold Holzel
# Creation date : 2017-05-31
# Description   : Script to download attachments from a mailbox and store it
#                 localy on disk. The script is made to download DMARC RUA reports
#                 so is specifically looks for mails with a subject that contains:
#                 "Report Domain".
#                 The script can handle POP3, POP3 SSL, IMAP and IMAP SSL
#
# Version history
# change log is now moved to the CHANGELOG.md file in the root of the app.
#
##################################################################

import argparse
import email
import email.header
import imaplib 
import os
import poplib
import re
import sys

from io import StringIO

# add the lib dir to the path to import libs from there
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "lib"))

from classes import splunk_info as si
from classes import custom_logger as c_logger

__version__ = "3.3.0"
__author__ = 'Arnold Holzel'
__license__ = 'Apache License 2.0'

delete_files_after = 7 # days after which old parser files will be deleted 
max_emails_per_fetch = 1000
allowed_mail_subjects = [
                        'report domain', 
                        'dmarc aggregate report', 
                        'report_domain', 
                        '[dmarc report]', 
                        '[Preview] Report Domain:'
                        ]
allowed_content_types = [
                        'application/zip',
                        'application/gzip',
                        'application/xml',
                        'text/xml'
                        ]

#########################################
# NO NEED TO CHANGE ANYTHING BELOW HERE #
#########################################

script_dir = os.path.dirname(os.path.abspath(__file__)) # The directory of this script

# Get the command line arguments passed to the script
options = argparse.ArgumentParser(epilog='Example: %(prog)s  -s mailserver.example.test -p 993 -y IMAPS -u dmarc@example.test -f inbox ')
options.add_argument('--use_conf_file', action='store_true')
options.add_argument('-s', '--host', help='mail server; eg. 10.10.10.10 OR mailserver.example.test')
options.add_argument('-p', '--port', help='mail server port; POP3 is 110, POP3S is 995, IMAP is 143, IMAPS is 993', default=110)
options.add_argument('-u', '--user', help='user\'s email id')
options.add_argument('-f', '--folder', help='mail folder from which the mail to retrieve')
options.add_argument('-x', '--password', help='User password')
options.add_argument('-y', '--protocol', help='The mail protocol to use POP3, POP3S, IMAP OR IMAPS', default='POP3')
options.add_argument('--sessionKey', help='The splunk session key to use')
args = options.parse_args()

if len(args.sessionKey) != 0:
    sessionKey = args.sessionKey
if len(args.sessionKey) == 0:
    sessionKey = sys.stdin.readline().strip()

splunk_info = si.Splunk_Info(sessionKey)
splunk_paths = splunk_info.give_splunk_paths(script_dir)

# Set all the directory's based on the directory this script is in.
app_root_dir = splunk_paths['app_root_dir']                                             # The app root directory
log_root_dir = os.path.normpath(app_root_dir + os.sep + 'logs')                         # The root directory for the logs
attachment_dir = os.path.normpath(log_root_dir + os.sep + 'attach_raw')                 # The directory to store the attachments 
app_log_dir = os.path.normpath(log_root_dir + os.sep + 'dmarc_splunk')                  # The directory to store the output for Splunk

# Set the logfile to report everything in
script_log_file = os.path.normpath(app_log_dir + os.sep + 'mail_parser.log')

# Create al the directory's if they don't exist
if not os.path.exists(log_root_dir):
    os.makedirs(log_root_dir)
if not os.path.exists(attachment_dir):
    os.makedirs(attachment_dir)
if not os.path.exists(app_log_dir):
    os.makedirs(app_log_dir)
    
# Prepare the logger
log_level = splunk_info.get_config(str(splunk_paths['app_name'].lower()) + '.conf', 'main', 'log_level')
logger = c_logger.Logger()
script_logger = logger.logger_setup('script_logger', level=log_level)

if args.use_conf_file:
    custom_conf_file = f"{splunk_paths['app_name'].lower()}.conf"
    script_logger.info(f"Getting configuration from conf file: '{custom_conf_file}'")
    
    args.host = splunk_info.get_config(custom_conf_file, 'main', 'mailserver_host')
    args.port = splunk_info.get_config(custom_conf_file, 'main', 'mailserver_port')
    args.protocol = splunk_info.get_config(custom_conf_file, 'main', 'mailserver_protocol')
    args.user = splunk_info.get_config(custom_conf_file, 'main', 'mailserver_user')                                                                    
    args.password = splunk_info.get_credentials(args.user)
    args.folder = splunk_info.get_config(custom_conf_file, 'main', 'mailserver_mailboxfolder')
    
    script_logger.debug(f"host: {args.host}; port: {args.port}; protocol: {args.protocol}; user: {args.user}; folder: {args.folder}")
else:
    # just to be sure
    if not args.folder:
        args.folder = 'Inbox'

def imap_mailbox():
    global args, script_logger
    # Set a counter to count the number of messages we processed
    count = 0

    # Make a IMAP or IMAPS connection to the given server and on the given port
    if args.protocol == 'IMAPS':
        script_logger.debug(f"Setting up a IMAP SSL connection to server: {args.host} on port: {args.port}")
        try:
            connection = imaplib.IMAP4_SSL(args.host, args.port)
        except:
            script_logger.exception('Something went wrong with the IMAP4 SSL connection. Traceback: ')
            exit(1)
    else:
        script_logger.warning('Please consider using IMAPS instead of IMAP, now plain text passwords are send to the server.')
        script_logger.debug(f"Setting up a IMAP (No SSL) connection to server: {args.host} on port: {args.port}")
        try:
            connection = imaplib.IMAP4(args.host, args.port)
        except:
            script_logger.exception('Something went wrong with the IMAP4 connection. Traceback: ')
            exit(1)
 
    # Login to the mailbox
    script_logger.info(f"Logging in as user: {args.user}")
    
    # Try to connect with the username and decoded password
    try :
        response, data = connection.login(args.user, args.password)
        script_logger.debug(f"Authentication succesfull for user: {args.user}")
    except imaplib.IMAP4.error as error:
        script_logger.exception(f"Authentication failed for user: {args.user}; error: {error}")
        exit(1)

    # Select the correct mailbox (folder) and check number of messages
    response, data = connection.select(args.folder)
    if response == 'OK':
        num_of_msgs = data[0]
        script_logger.info(f"There are {num_of_msgs0} messages in folder: {args.folder}")
    else:
        error = str(data[0])
        script_logger.critical(f"There was a error selecting the folder: {args.folder} the error was: {error}")
    
    # Check the mailbox status
    mailbox_status = connection.status(args.folder, '(MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN)')
    script_logger.debug(f"Mailbox status: {mailbox_status}")

    unseen_rex = re.search(r'(?:.*UNSEEN\s*)(\d+)', str(mailbox_status))
    unseen_count = int(unseen_rex.group(1))
    
    # if unseen count is to high get the mails in batch mode
    if unseen_count > max_emails_per_fetch:
        msg_id_list = list(range(1,max_emails_per_fetch))
        script_logger.warning(f"There are to many mails in the mailbox to get them all at once, only get the first {max_emails_per_fetch}")
    else:
        # Search for all messages
        try:
            response, msg_id_list = connection.search(None, 'ALL')
            msg_id_list = msg_id_list[0].split()
        except Exception as e:
            script_logger.exception(f"Something did't go as expected: {e}")
    
    # loop through the mails in the mailbox and download the attachtments
    for emailid in msg_id_list:
        _, flag_before_response = connection.fetch(emailid, '(FLAGS)')
        script_logger.debug(f"Message id: {emailid}, flags: {flag_before_response}")
        
        fetch_response, msg_data = connection.fetch(emailid, '(RFC822)')
        message = email.message_from_bytes(msg_data[0][1])
        subject = str(email.header.make_header(email.header.decode_header(message['Subject']))) 

        if fetch_response == 'OK' and any(sub in subject.lower() for sub in allowed_mail_subjects):
            # Search for all the dmarc messages, they should always contain the string 'Report Domain' but I check
            # for a variety of strings from the allowed_mail_subjects list.
            script_logger.debug(f"Message id: {emailid}, Response is OK, continue.")
            sender = message['From']
            
            # Check to see if there is an actual sender....
            if len(sender) == 0:
                sender = 'unknown'
            
            script_logger.debug(f"Message id: {emailid}, Sender: {sender}")
            script_logger.debug(f"Message id: {emailid}, Content main type: {message.get_content_maintype()}, content type: {message.get_content_type()}")
            
            # Get the attachment if it is a zip or gzip file and store it on disk
            if message.get_content_maintype() == 'multipart' or any(ctype in message.get_content_type().lower() for ctype in allowed_content_types):
                for part in message.walk():
                    if part.get_content_maintype() != 'multipart' and part.get('Content-Disposition') is not None:
                        # Save the attachement in the given directory
                        filename = part.get_filename()

                        if filename != None and (filename[-3:] == '.gz' or filename[-4:] == '.zip' or filename[-5:] == '.gzip'):
                            script_logger.debug(f"Message id: {emailid}, Attachment found, name: {filename}")
                            # Replace the '!' for a '_' so is doesn't need to be escaped later on
                            filename = re.sub(r'(\!)', r'_', filename)
                        
                            file_path = open(os.path.normpath(attachment_dir + os.sep + filename), 'wb')
                            script_logger.debug(f"Message id: {emailid}, Store attachement as: {os.path.normpath(attachment_dir + os.sep + filename)}")
                            file_path.write(part.get_payload(decode=True))
                            file_path.close()
                        else:
                            script_logger.warning(f"Message id: {emailid}, No valid attachement found. Attachement found: {filename}")
            
                # Give the mail the delete flag after reading and downloading attachments or if it doesn't have a zip/gzip attachement
                _, response = connection.store(emailid, '+FLAGS', r'(\Deleted)')
                
        elif not any(sub in subject.lower() for sub in allowed_mail_subjects):
            script_logger.info(f"Message id: {emailid}, is not a DMARC message. Message subject: {subject}")
        else:
            script_logger.warning(f"Response is NOT OK, response: {response}")

        # Check if there where to many mails to process at once, if so append 1 to the end of the msg_id_list
        if msg_id_list[-1] < unseen_count:
            msg_id_list.append(msg_id_list[-1]+1)

        count +=1
    
    script_logger.info(f"Processed {count} messages.")
    
    # Delete all the messages with the delete flag set
    _, response = connection.expunge()
    
    # Close the mailbox
    connection.close()
    
    # Logout
    connection.logout()
 
def pop3_mailbox():
    global args, script_logger
    import fnmatch
    # Set a counter to count the number of messages we processed
    count = 0
    
    if args.protocol == 'POP3S':
        # Make a secure POP3 connection to the given server and on the given port
        script_logger.debug(f"Setting up a secure POP3 connection to server: {args.host} on port: {args.port}")
        try:
            connection = poplib.POP3_SSL(args.host, args.port)
        except:
            script_logger.exception('Something went wrong with the POP3 SSL connection. Traceback: ')
            exit(1)
    else:
        # Make a POP3 connection to the given server and on the given port
        script_logger.warning("A unscure connection will be used to connect to the mail server! Please consider upgrading to a secure connection.")
        script_logger.debug(f"Setting up a POP3 connection to server: {args.host} on port: {args.port}")
        try:
            connection = poplib.POP3(args.host, args.port)
        except:
            script_logger.exception('Something went wrong with the POP3 connection. Traceback: ')
            exit(1)

    # Set the POP3 connection debug level based on the log_level of the script
    # and redirct the output to a variable so we can write it to a logfile.
    if log_level >= 20:
        pop3_debug_level = 0
    elif log_level == 10:
        pop3_debug_level = 1
        sys.stdout = StringIO()
    else:
        pop3_debug_level = 2
        sys.stdout = StringIO()
    
    script_logger.debug(f"Setting POP3 connection debug level to : {pop3_debug_level}")
    connection.set_debuglevel(pop3_debug_level)
        
    # Login to the mailbox
    script_logger.info(f"Logging in as user: {args.user}")
    
    user_string = connection.user(args.user)
    script_logger.debug(f"Response on sending the username: {user_string}")
    
    pass_string = connection.pass_(args.password)
    script_logger.debug(f"Response on sending the password: {pass_string}")
    
    # count te number of messages in the mailbox and loop through them
    totalcount, size = connection.stat()
    script_logger.debug(f"There are {totalcount} messages to process. Mailbox size is {size} bytes")
    
    for emailid in range(totalcount):
        (server_msg, lines, _) = connection.retr(emailid+1)
        script_logger.debug(f"Server response for fetching mail with id {emailid}; {server_msg}")

        raw_email = b'\r\n'.join(lines)
        parsed_email = email.message_from_bytes(raw_email)
        message_subject = str(email.header.make_header(email.header.decode_header(parsed_email['Subject'])))
            
        actual_email_id = emailid + 1

        # Check the subject, only process the dmarc messages, they always contain one of the strings from the allowed_mail_subjects
        if any(sub in message_subject.lower() for sub in allowed_mail_subjects):
            # Get email sender
            sender = parsed_email['From']
            
            # Check to see if there is an actual sender....
            if len(sender) > 0:
                sender = str(sender[0])
            else:
                sender = 'unknown'
            
            script_logger.debug(f"Message id: {actual_email_id}, Sender: {sender}")
            script_logger.debug(f"Message id: {actual_email_id}, Content main type: {parsed_email.get_content_maintype()}, content type: {parsed_email.get_content_type()}")
            
            # Get the attachment if it is a zip or gzip file and store it on disk
            if parsed_email.get_content_maintype() == 'multipart' or any(ctype in parsed_email.get_content_type().lower() for ctype in allowed_content_types):
                for part in parsed_email.walk():
                    if part.get_content_maintype() != 'multipart' and part.get('Content-Disposition') is not None:
                        
                        # Save the attachement in the given directory
                        filename = part.get_filename()
                        if filename != None and (filename[-3:] == '.gz' or filename[-4:] == '.zip' or filename[-5:] == '.gzip'):
                            script_logger.debug(f"Message id: {actual_email_id}, Attachment found, name: {filename}"")
                            # Replace the '!' for a '_' so is doesn't need to be escaped later on
                            filename = re.sub(r'(\!)', r'_', filename)
                        
                            file_path = open(os.path.normpath(attachment_dir + os.sep + filename), 'a+b')
                            script_logger.debug(f"Message id: {actual_email_id}, Store attachement as: {os.path.normpath(attachment_dir + os.sep + filename)}")
                            file_path.write(part.get_payload(decode=True))
                            file_path.close()
                        else:
                            script_logger.warning(f"Message id: {actual_email_id}, No valid attachement found. Attachement found: {filename}")
            # Delete mail after reading and downloading attachments or if it doesn't have a zip/gzip attachement
            connection.dele(actual_email_id)
            count += 1
        else:
            script_logger.debug(f"Message id: {actual_email_id}, is not a DMARC message. Message subject: {message_subject}; body: {parsed_email}")
        
        emailid += 1
 
    script_logger.info(f"Total attachments downloaded: {count}")
    # Do a clean exit of the mailbox so all the mails will be deleted
    connection.quit()
    
    if log_level < 20:
        stdout_output = sys.stdout.getvalue()
        sys.stdout.close()
        
        # remove the cleartext password from the log
        stdout_output = re.sub(r'\*cmd\*\s\'PASS\s[^\']*', r'*cmd* \'PASS\' **MASKED**', stdout_output)
        stdout_output = re.sub(r'\*put\*\s\'PASS\s[^\']*', r'*put* \'PASS\' **MASKED**', stdout_output)
        
        script_logger.debug(f"Raw POP3 log: {stdout_output}")

if args.protocol.upper() == 'IMAP' or args.protocol.upper() == 'IMAPS':
    imap_mailbox()
    sys.exit(0)
elif args.protocol.upper() == 'POP3' or args.protocol.upper() == 'POP3S':
    pop3_mailbox()
    sys.exit(0)
else:
    script_logger.critical(f"Unknown mail protocol given: {args.protocol}")
    sys.exit(2)
 
