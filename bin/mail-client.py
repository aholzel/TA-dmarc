#!/usr/bin/python
"""
Copyright 2017- Arnold Holzel

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
 
import sys
import imaplib, email, email.header, poplib
import os
import errno
import re
import argparse
import inspect

from io import StringIO
from datetime import datetime

import classes.splunk_info as si
import classes.custom_logger as c_logger

delete_files_after = 7 # days after which old parser files will be deleted 

allowed_mail_subjects = ['report domain', 'dmarc aggregate report', 'report_domain', '[dmarc report]', '[Preview] Report Domain:']

#########################################
# NO NEED TO CHANGE ANYTHING BELOW HERE #
#########################################

script_dir = os.path.dirname(os.path.abspath(__file__))                                     # The directory of this script

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
    custom_conf_file = str(splunk_paths['app_name'].lower()) + '.conf'
    script_logger.info('Getting configuration from conf file ' + str(custom_conf_file))
    
    args.host = splunk_info.get_config(custom_conf_file, 'main', 'mailserver_host')
    args.port = splunk_info.get_config(custom_conf_file, 'main', 'mailserver_port')
    args.protocol = splunk_info.get_config(custom_conf_file, 'main', 'mailserver_protocol')
    args.user = splunk_info.get_config(custom_conf_file, 'main', 'mailserver_user')                                                                    
    args.password = splunk_info.get_credentials(args.user)
    args.folder = splunk_info.get_config(custom_conf_file, 'main', 'mailserver_mailboxfolder')
    
    script_logger.debug('host: {0}; port: {1}; protocol: {2}; user: {3}; folder: {4}'.format(args.host, args.port, args.protocol, args.user, args.folder))
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
        script_logger.debug('Setting up a IMAP SSL connection to server: {0} on port: {1}'.format(args.host, args.port))
        try:
            connection = imaplib.IMAP4_SSL(args.host, args.port)
        except:
            script_logger.exception('Something went wrong with the IMAP4 SSL connection. Traceback: ')
            exit(1)
    else:
        script_logger.warning('Please consider using IMAPS instead of IMAP, now plain text passwords are send to the server.')
        script_logger.debug('Setting up a IMAP (No SSL) connection to server: {0} on port: {1}'.format(args.host, args.port))
        try:
            connection = imaplib.IMAP4(args.host, args.port)
        except:
            script_logger.exception('Something went wrong with the IMAP4 connection. Traceback: ')
            exit(1)
 
    # Login to the mailbox
    script_logger.info('Logging in as user: {0}'.format(args.user))
    
    # Try to connect with the username and decoded password
    try :
        response, data = connection.login(args.user, args.password)
        script_logger.debug('Authentication succesfull for user: {0}'.format(args.user))
    except imaplib.IMAP4.error as error:
        script_logger.exception('Authentication failed for user: {0}; error: {1}'.format(args.user, error))
        exit(1)

    # Select the correct mailbox (folder) and check number of messages
    response, data = connection.select(args.folder)
    if response == 'OK':
        num_of_msgs = data[0]
        script_logger.info('There are {0} messages in folder: {1}'.format(num_of_msgs,args.folder))
    else:
        error = str(data[0])
        script_logger.critical('There was a error selecting the folder: {0} the error was: {1}'.format(args.folder,error))
    
    # Check the mailbox status
    mailbox_status = connection.status(args.folder, '(MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN)')
    script_logger.debug('Mailbox status: {0}'.format(mailbox_status))
    
    # Search for all messages
    response, msg_id_list = connection.search(None, 'ALL')

    script_logger.debug('Message ID\'s currently in the mailbox: {0}'.format(msg_id_list))
    msg_id_list = msg_id_list[0].split()
    
    # loop through the mails in the mailbox and download the attachtments
    for emailid in msg_id_list:
        _, flag_before_response = connection.fetch(emailid, '(FLAGS)')
        script_logger.debug('Message id: {0}, flags: {1}'.format(emailid,flag_before_response))
        
        fetch_response, msg_data = connection.fetch(emailid, '(RFC822)')
        message = email.message_from_bytes(msg_data[0][1])
        subject = message['Subject'] 

        if fetch_response == 'OK' and any(sub in subject.lower() for sub in allowed_mail_subjects):
            # Search for all the dmarc messages, they should always contain the string 'Report Domain' but I check
            # for a variety of strings from the allowed_mail_subjects list.
            script_logger.debug('Message id: {0}, Response is OK, continue.'.format(emailid))
            sender = message['From']
            
            # Check to see if there is an actual sender....
            if len(sender) == 0:
                sender = 'unknown'
            
            script_logger.debug('Message id: {0}, Sender: {1}'.format(emailid, sender))
            script_logger.debug('Message id: {0}, Content main type: {1}, content type: {2}'.format(emailid, message.get_content_maintype(), message.get_content_type()))
            
            # Get the attachment if it is a zip or gzip file and store it on disk
            if message.get_content_maintype() == 'multipart' or message.get_content_type() == 'application/zip' or message.get_content_type() == 'application/gzip':
                for part in message.walk():
                    if part.get_content_maintype() != 'multipart' and part.get('Content-Disposition') is not None:
                        
                        # Save the attachement in the given directory
                        filename = part.get_filename()
                        if filename != None and (filename[-3:] == '.gz' or filename[-4:] == '.zip' or filename[-5:] == '.gzip'):
                            script_logger.debug('Message id: {0}, Attachment found, name: {1}'.format(emailid, filename))
                            # Replace the '!' for a '_' so is doesn't need to be escaped later on
                            filename = re.sub(r'(\!)', r'_', filename)
                        
                            file_path = open(os.path.normpath(attachment_dir + os.sep + filename), 'wb')
                            script_logger.debug('Message id: {0}, Store attachement as: {1}'.format(emailid, os.path.normpath(attachment_dir + os.sep + filename)))
                            file_path.write(part.get_payload(decode=True))
                            file_path.close()
                        else:
                            script_logger.warning('Message id: {0}, No valid attachement found. Attachement found: {1}'.format(emailid, filename))
            
                # Give the mail the delete flag after reading and downloading attachments or if it doesn't have a zip/gzip attachement
                _, response = connection.store(emailid, '+FLAGS', r'(\Deleted)')
                
        elif not any(sub in subject.lower() for sub in allowed_mail_subjects):
            script_logger.info('Message id: {0}, is not a DMARC message. Message subject: {1}'.format(emailid, subject))
        else:
            script_logger.warning('Response is NOT OK, response: {0}'.format(response))

        count +=1
    
    script_logger.info('Processed {0} messages.'.format(count))
    
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
        script_logger.debug('Setting up a secure POP3 connection to server: {0} on port: {1}'.format(args.host, args.port))
        try:
            connection = poplib.POP3_SSL(args.host, args.port)
        except:
            script_logger.exception('Something went wrong with the POP3 SSL connection. Traceback: ')
            exit(1)
    else:
        # Make a POP3 connection to the given server and on the given port
        script_logger.warning('A unscure connection will be used to connect to the mail server! Please consider upgrading to a secure connection.')
        script_logger.debug('Setting up a POP3 connection to server: {0} on port: {1}'.format(args.host, args.port))
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
    
    script_logger.debug('Setting POP3 connection debug level to : {0}'.format(pop3_debug_level))
    connection.set_debuglevel(pop3_debug_level)
        
    # Login to the mailbox
    script_logger.info('Logging in as user: {0}'.format(args.user))
    
    user_string = connection.user(args.user)
    script_logger.debug('Response on sending the username: {0}'.format(user_string))
    
    pass_string = connection.pass_(args.password)
    script_logger.debug('Response on sending the password: {0}'.format(pass_string))
    
    # count te number of messages in the mailbox and loop through them
    totalcount, size = connection.stat()
    script_logger.debug('There are {0} messages to process. Mailbox size is {1} bytes'.format(totalcount, size))
    
    for emailid in range(totalcount):
        (server_msg, lines, _) = connection.retr(emailid+1)
        script_logger.debug('Server response for fetching mail with id {0}; {1}'.format(emailid, server_msg))

        raw_email = b'\r\n'.join(lines)
        parsed_email = email.message_from_bytes(raw_email)
        message_subject = parsed_email['Subject']
        actual_email_id = emailid + 1

        # Check the subject, only process the dmarc messages, they always contain one of the strings from the allowed_mail_subjects
        if any(sub in message_subject.lower() for sub in allowed_mail_subjects):
            #script_logger.debug('Message id: ' + str(emailid+1) + ', is a DMARC message, ' + str(parsed_email))

            # Get email sender
            sender = parsed_email['From']
            
            # Check to see if there is an actual sender....
            if len(sender) > 0:
                sender = str(sender[0])
            else:
                sender = 'unknown'
            
            script_logger.debug('Message id: {0}, Sender: {1}'.format(actual_email_id, sender))
            script_logger.debug('Message id: {0}, Content main type: {1}, content type: {2}'.format(actual_email_id, parsed_email.get_content_maintype(), parsed_email.get_content_type()))
            
            # Get the attachment if it is a zip or gzip file and store it on disk
            if parsed_email.get_content_maintype() == 'multipart' or parsed_email.get_content_type() == 'application/zip' or parsed_email.get_content_type() == 'application/gzip':
                for part in parsed_email.walk():
                    if part.get_content_maintype() != 'multipart' and part.get('Content-Disposition') is not None:
                        
                        # Save the attachement in the given directory
                        filename = part.get_filename()
                        if filename != None and (filename[-3:] == '.gz' or filename[-4:] == '.zip' or filename[-5:] == '.gzip'):
                            script_logger.debug('Message id: {0}, Attachment found, name: {1}'.format(actual_email_id, filename))
                            # Replace the '!' for a '_' so is doesn't need to be escaped later on
                            filename = re.sub(r'(\!)', r'_', filename)
                        
                            file_path = open(os.path.normpath(attachment_dir + os.sep + filename), 'a+b')
                            script_logger.debug('Message id: {0}, Store attachement as: {1}'.format(actual_email_id, os.path.normpath(attachment_dir + os.sep + filename)))
                            file_path.write(part.get_payload(decode=True))
                            file_path.close()
                        else:
                            script_logger.warning('Message id: {0}, No valid attachement found. Attachement found: {1}'.format(actual_email_id, filename))
            # Delete mail after reading and downloading attachments or if it doesn't have a zip/gzip attachement
            connection.dele(actual_email_id)
            count += 1
        else:
            script_logger.debug('Message id: {0}, is not a DMARC message. Message subject: {1}; body: {2}'.format(actual_email_id, message_subject, parsed_email))
        
        emailid += 1
 
    script_logger.info('Total attachments downloaded: {0}'.format(count))
    # Do a clean exit of the mailbox so all the mails will be deleted
    connection.quit()
    
    if log_level < 20:
        stdout_output = sys.stdout.getvalue()
        sys.stdout.close()
        
        # remove the cleartext password from the log
        stdout_output = re.sub(r'\*cmd\*\s\'PASS\s[^\']*', r'*cmd* \'PASS\' **MASKED**', stdout_output)
        stdout_output = re.sub(r'\*put\*\s\'PASS\s[^\']*', r'*put* \'PASS\' **MASKED**', stdout_output)
        
        script_logger.debug('Raw POP3 log:\n' + str(stdout_output))

if args.protocol.upper() == 'IMAP' or args.protocol.upper() == 'IMAPS':
    imap_mailbox()
    sys.exit(0)
elif args.protocol.upper() == 'POP3' or args.protocol.upper() == 'POP3S':
    pop3_mailbox()
    sys.exit(0)
else:
    script_logger.critical('Unknown mail protocol given: ' + str(args.protocol))
    sys.exit(2)
 
