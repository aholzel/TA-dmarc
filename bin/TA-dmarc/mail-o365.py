#!/usr/bin/python
"""
Copyright 2023- Arnold Holzel

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
# Creation date : 2023-03-23
# Description   : Script to download DMARC RUA mails from a o365 mailbox                 
#
# Version history
# Change log is in the CHANGELOG.md file in the readme dir of the app
#
##################################################################

import argparse
import base64
import datetime
import json
import os
import re
import requests
import sys

# add the lib dir to the path to import libs from there
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "lib"))

import msal

from classes import splunk_info as si
from classes import custom_logger as c_logger

__version__ = "1.2.0"
__author__ = 'Arnold Holzel'
__license__ = 'Apache License 2.0'

max_emails_per_fetch = 500
allowed_mail_subjects = [
                        'report domain', 
                        'dmarc aggregate report', 
                        'report_domain', 
                        '[dmarc report]', 
                        '[preview] report domain:'
                        ]
allowed_content_types = [
                        'application/zip',
                        'application/gzip',
                        'application/xml',
                        'text/xml'
                        ]

LOGIN_URL = 'https://login.microsoftonline.com'
GRAPH_URL = 'https://graph.microsoft.com'

#########################################
# NO NEED TO CHANGE ANYTHING BELOW HERE #
#########################################

script_dir = os.path.dirname(os.path.abspath(__file__)) # The directory of this script

# Get the command line arguments passed to the script
options = argparse.ArgumentParser(epilog='Example: %(prog)s -u dmarc@example.test -f inbox ', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
options.add_argument('--use_conf_file', action='store_true', help='Get all the info from the config file in the default and/or local directory')
options.add_argument('-c', '--client_id', help='The clientID to use for the connection')
options.add_argument('-t', '--tenant_id', help='The tenantID to use for the connection')
options.add_argument('-s', '--client_secret', help='The client secret to use for the connection')
options.add_argument('-u', '--user', help='user\'s email id')
options.add_argument('-f', '--folder', help='mail folder from which the mail to retrieve', default='Inbox')
options.add_argument('-a', '--action', help='The action to take when a mail is processed; move/delete/mark_read', default='mark_read')
options.add_argument('-m', '--move_to', help='The folder to move emails to the following variables can be used \
    [year] [month] [day] [ week] Example: Inbox/done/[year]/week_[week] will become Inbox/done/2023/week_03', default='Inbox/done/[year]/week_[week]')
options.add_argument('--proxy', action='store_true', help='Use a proxy server to connect to the internet' )
options.add_argument('-x', '--proxy_server', help='The proxy server + port to use. IE: https://10.20.30.40:5060')
options.add_argument('-y', '--proxy_user', help='The user to authenticate to the proxy to if needed', default='default_None')
options.add_argument('-z', '--proxy_pwd', help='The password for the proxy user if needed', default='default_None')
options.add_argument('-v', '--verbose', action='store_true', help='enable verbose logging on the CLI')
options.add_argument('--sessionKey', help='The splunk session key to use')
args = options.parse_args()

if args.sessionKey is None:
    logger = c_logger.Logger()
    script_logger = logger.logger_setup('script_logger', level=20)
    script_logger.error("Please provide a valid sessionKey")
    options.print_help(sys.stderr)
    exit(1)
elif len(args.sessionKey) != 0:
    sessionKey = args.sessionKey
elif len(args.sessionKey) == 0:
    sessionKey = sys.stdin.readline().strip()
else:
    logger = c_logger.Logger()
    script_logger = logger.logger_setup('script_logger', level=20)
    script_logger.error(f"There is something wrong with the provided sessionKey: {args.sessionKey}")
    options.print_help(sys.stderr)
    exit(1)
        
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
log_level = splunk_info.get_config(f"{splunk_paths['app_name'].lower()}.conf", 'main', 'log_level')
logger = c_logger.Logger()
script_logger = logger.logger_setup('script_logger', level=log_level)

# check if a conf file is used or that the info is past via de CLI
if args.use_conf_file:
    custom_conf_file = f"{splunk_paths['app_name'].lower()}.conf"
    script_logger.info(f"Getting configuration from conf file {custom_conf_file}")
    
    client_id = splunk_info.get_config(custom_conf_file, 'main', 'o365_client_id') 
    tenant_id = splunk_info.get_config(custom_conf_file, 'main', 'o365_tenant_id')
    client_secret = splunk_info.get_credentials(client_id)
    user = splunk_info.get_config(custom_conf_file, 'main', 'mailserver_user') 
    mailfolder = splunk_info.get_config(custom_conf_file, 'main', 'mailserver_mailboxfolder')
    action = splunk_info.get_config(custom_conf_file, 'main', 'mailserver_action')
    move_to_folder = splunk_info.get_config(custom_conf_file, 'main', 'mailserver_moveto')

    proxy_use = splunk_info.get_config(custom_conf_file, 'main', 'proxy_use')
    proxy_server = splunk_info.get_config(custom_conf_file, 'main', 'proxy_server')
    proxy_username = splunk_info.get_config(custom_conf_file, 'main', 'proxy_username')
    proxy_pwd = splunk_info.get_credentials(proxy_username)
else:
    client_id = args.client_id
    tenant_id = args.tenant_id
    client_secret = args.client_secret
    user = args.user
    mailfolder = args.folder
    action = args.action
    move_to_folder = args.move_to

    if args.proxy:
        proxy_use = True
        proxy_server = args.proxy_server
        proxy_username = args.proxy_user
        proxy_pwd = args.proxy_pwd

if proxy_use or proxy_use == 1 or proxy_use.lower() == 't' or proxy_use.lower() == 'true':
    script_logger.debug(f"A proxy needs to be used to connect to internet. The following will be used: {proxy_server}")
    proxy_use = True
    proxy_regex = re.search(r"(?:^([htps]*)(?=[:]+)(?:\:\/\/)|^)(.*)", proxy_server)

    if not proxy_regex.group(1):
        script_logger.warning(f"No schema provided with the proxy_server:{proxy_server} will assume HTTP, please adjust the config via the setup page!")

    if proxy_username != 'default_None' and proxy_username is not None and proxy_pwd != 'default_None' and proxy_pwd is not None:
        # there is a proxy user name and password configured
        if proxy_regex.group(1):
            # the url has a schema provided rebuild the proxy_server variable with the username and password
            proxy_server = f"{proxy_regex.group(1)}://{proxy_username}:{proxy_pwd}@{proxy_regex.group(2)}"
        else:
            proxy_server = f"http://{proxy_username}:{proxy_pwd}@{proxy_regex.group(2)}"
    elif proxy_username != 'default_None' and proxy_username is not None:
        if proxy_regex.group(1):
            # the url has a schema provided rebuild the proxy_server variable with the username and password
            proxy_server = f"{proxy_regex.group(1)}://{proxy_username}@{proxy_regex.group(2)}"
        else:
            proxy_server = f"http://{proxy_username}@{proxy_regex.group(2)}"

    proxies = { 'http': proxy_server, 'https': proxy_server }

if client_id is None or tenant_id is None or client_secret is None or user is None:
    script_logger.error("Not all the needed o365 fields are configured or accessable.")
    exit(1)

FOLDER_ENDPOINT = f"{GRAPH_URL}/v1.0/users/{user}/mailFolders"
MESSAGE_ENDPOINT = f"{GRAPH_URL}/v1.0/users/{user}/messages"

app = msal.ConfidentialClientApplication(
    client_id=client_id,
    client_credential=client_secret,
    authority=f'{LOGIN_URL}/{tenant_id}')

def get_request(endpoint, token):
    """
    Perform a get request against the GRAPH API.
    
    INPUT
    endpoint            | string    | The endpoint to talk to and get the info from
    token               | string    | The authentication token for the Graph api

    OUTPUT:
    value               | dict      | The JSON response from the request converted into a dict
    """
    if not token:
        return None
    
    headers = { 'Authorization': f'Bearer {token}' }
    
    try:
        if proxy_use:
            response = requests.get(endpoint, headers=headers, proxies=proxies)
        else:
            response = requests.get(endpoint, headers=headers)
    except Exception as exception:
        script_logger.exception(f"Connection error {type(exception).__name__}; ")


    if response.status_code != 200:
        return None

    return json.loads(response.text)['value']

def get_folder_id(folder_name, token, parent_folder_id=None):
    """
    Get the folder ID of a given (nested) folder
    
    INPUT:
    folder_name         | string    | The (nested) folder to get the ID for, format: Inbox/done/2023
    token               | string    | The authentication token for the Graph api
    parent_folder_id    | string    | The ID of the parent folder.

    OUTPUT:
    folder_id           | string    | The folder ID of the searched folder
    """
    folder_id = None

    parent_endpoint = f"{FOLDER_ENDPOINT}?includeHiddenFolders=true$top=1000"
    child_endpoint = f"{FOLDER_ENDPOINT}{parent_folder_id}/childFolders?$top=1000"

    if '/' in folder_name:
        # look for a nested folder, get the first folder to look for
        folder_list = folder_name.split('/', 1)
        
        if parent_folder_id is None:
            folder_data = get_request(parent_endpoint, token)
            
            if folder_data is not None:
                for folder_info in folder_data:
                    if folder_info['displayName'].lower().strip() == folder_list[0].lower().strip():
                        folder_id = f"/{folder_info['id']}"
                        return get_folder_id(folder_list[1], token, folder_id)
        else:
            folder_data = get_request(child_endpoint, token)

            for folder_info in folder_data:
                if folder_info['displayName'].lower().strip() == folder_list[0].lower().strip():
                    folder_id = f"/{folder_info['id']}"
                    return get_folder_id(folder_list[1], token, folder_id)

    else:
        # look for a single folder
        if parent_folder_id is None:
            folder_data = get_request(parent_endpoint, token)
            
            if folder_data is not None:
                for folder_info in folder_data:
                    if folder_info['displayName'].lower().strip() == folder_name.lower().strip():
                        folder_id = f"/{folder_info['id']}"
                        break
        else:
            folder_data = get_request(child_endpoint, token)
            
            for folder_info in folder_data:
                if folder_info['displayName'].lower().strip() == folder_name.lower().strip():
                    folder_id = f"/{folder_info['id']}"
                    return folder_id
        
    return folder_id

def create_folder(folder_name, token, parent_folder_id=None, root_folder=1):
    """
    Create a given folder (path) in the mailbox

    INPUT:
    folder_name         | string    | The (nested) folder to create. format: Inbox/done/2023
    token               | string    | The authentication token for the Graph api
    parent_folder_id    | string    | The ID of the parent folder.
    root_folder         | int       | Number to determine if the folder is a root folder or not
                                    | 1 = root folder; 0 = non root folder

    OUTPUT:
    folder_id           | string    | The folder_id of the either just created folder or the already existing one
    """
    # First check if the folder doesn't already exists
    folder_exists = get_folder_id(folder_name, token)

    if folder_exists is not None:
        script_logger.debug(f"The folder (path) '{folder_name}' already exists.")
        return folder_exists
    else:
        script_logger.debug(f"The folder (path) '{folder_name}' doesn't exist.")

    # split the folder to create in two to work with
    folder_list = folder_name.split('/', 1)
    script_logger.debug(f"Folder to create: '{folder_name}'")

    if parent_folder_id is None:
        folder_id = get_folder_id(folder_list[0], token)
    else:
        folder_id = get_folder_id(folder_list[0], token, parent_folder_id)
    
    if folder_id is not None:
        # the folder already exists so continue on to the next one if needed
        if len(folder_list) == 2:
            # another folder needs to be created
            return create_folder(folder_list[1], token, folder_id, root_folder=0)
        else:
            return folder_id
    else:
         # the folder doesn't exist, so create it
        content = f"{{ 'displayName' : '{folder_list[0]}' }}"
        headers = { 'Authorization' : f'Bearer {token}', 'Accept' : 'application/json', 'Content-Type' : 'application/json' }

        if root_folder == 1:
            # this folder needs to be created in the root of the mailbox
            F_ENDPOINT = FOLDER_ENDPOINT
        else:
            # this folder needs to be created below an already existing folder
            F_ENDPOINT = f"{FOLDER_ENDPOINT}{parent_folder_id}/childFolders"
        try:
            if proxy_use:
                create_request = requests.post(F_ENDPOINT, data=content, headers=headers, proxies=proxies)
            else:
                create_request = requests.post(F_ENDPOINT, data=content, headers=headers)
        except Exception as exception:
            script_logger.exception(f"Connection error {type(exception).__name__}; ")

        if create_request.status_code != 201:
            script_logger.error(f"Something went wrong creating the folder: {json.loads(create_request.content)['error']['message']}")
            exit(1)
        
        # get the ID of the just created folder, based on the response
        folder_id = f"/{create_request.json()['id']}"
        
        if len(folder_list) == 2:
            # We need to create another folder
            return create_folder(folder_list[1], token, folder_id, root_folder=0)
        else:
            return folder_id

scopes = [f'{GRAPH_URL}/.default']
result = None

try:
    result = app.acquire_token_silent(scopes, account=None)

    if not result:
        script_logger.debug("No suitable token exists in cache, getting a new one.")
        result = app.acquire_token_for_client(scopes=scopes)

    if "access_token" in result:
        # get all the mail folders and search for the one we need
        all_folders_endpoint = f"{FOLDER_ENDPOINT}?includeHiddenFolders=true"
        all_folders_data = get_request(all_folders_endpoint, result['access_token'])

        if all_folders_data is not None:
            # succesfull connection, first find the id of the folder we are looking for
            folder_id = get_folder_id(mailfolder, result['access_token'])
            
            if folder_id is not None:
                # get the messages from the folder
                messages_endpoint = f"{FOLDER_ENDPOINT}{folder_id}/messages?$filter=isRead ne true&$top={max_emails_per_fetch}&$select=sender,subject,hasAttachments,receivedDateTime"
                message_data = get_request(messages_endpoint, result['access_token'])
                
                count = 0

                for message in message_data:
                    # check if this is a dmarc message, only allow messages with a specific subject and a attachment
                    if message['hasAttachments'] == True and any(sub in message['subject'].lower() for sub in allowed_mail_subjects):
                        attachment_endpoint = f"{MESSAGE_ENDPOINT}/{message['id']}/attachments/"
                        attachment_data = get_request(attachment_endpoint, result['access_token'])

                        # loop through the attachments and only allow specific contentTypes
                        for attachment in attachment_data:
                            if any(ctype in attachment['contentType'].lower() for ctype in allowed_content_types):
                                raw_data = base64.b64decode(attachment['contentBytes'])
                                filename = re.sub(r'(\!)', r'_', attachment['name'])
                                
                                with open(os.path.normpath(attachment_dir + os.sep + filename), 'wb') as file_path:
                                    file_path.write(raw_data)
                                
                        # check if the mails needs to be moved, deleted or just marked read
                        if action.lower() == 'move':
                            # get the message time to prepare a move to a date folder
                            receivedDate = None
                            receivedDate = message['receivedDateTime'][0:10]
                            year = receivedDate[0:4]
                            month = receivedDate[5:7]
                            day = receivedDate[8:10]
                            week = datetime.date(int(year), int(month), int(day)).isocalendar()[1]
                            
                            if (month == 1 or month == "01") and week == 52:
                                # with ISO time formatting the first week of the year is the week containing the first Thursday
                                year = int(year) - 1

                            if len(str(week)) == 1:
                                # for sorting...
                                week = f"0{week}"

                            # prep the "move to folder" and replace the "variables" with the needed values
                            move_to_folder_new = move_to_folder
                            move_to_folder_new = move_to_folder_new.replace("[YEAR]", str(year))
                            move_to_folder_new = move_to_folder_new.replace("[MONTH]", str(month))
                            move_to_folder_new = move_to_folder_new.replace("[DAY]", str(day))
                            move_to_folder_new = move_to_folder_new.replace("[WEEK]", str(week))
                            
                            move_folder_id = None
                            move_folder_id = create_folder(move_to_folder_new, result['access_token'])
                            
                            move_content = f"{{ 'destinationId' : '{move_folder_id.lstrip('/')}' }}"
                            move_headers = { 'Authorization' : f"Bearer {result['access_token']}", 'Accept' : 'application/json', 'Content-Type' : 'application/json' }
                            
                            try:
                                if proxy_use:
                                    move_request = requests.post(f"{MESSAGE_ENDPOINT}/{message['id']}/move", data=move_content, headers=move_headers, proxies=proxies)
                                else:
                                    move_request = requests.post(f"{MESSAGE_ENDPOINT}/{message['id']}/move", data=move_content, headers=move_headers)
                            except Exception as exception:
                                script_logger.exception(f"Connection error {type(exception).__name__}; ")

                            if move_request.status_code != 201:
                                script_logger.error(f"HTTP {move_request.status_code} recieved. Error message: {json.loads(move_request.content)['error']['message']}")
                        elif action.lower() == "delete":
                            # delete the message
                            delete_header = { 'Authorization': f"Bearer {result['access_token']}" }
                            
                            try:
                                if proxy_use:
                                    delete_request = requests.delete(f"{MESSAGE_ENDPOINT}/{message['id']}", headers=delete_header, proxies=proxies)
                                else:
                                    delete_request = requests.delete(f"{MESSAGE_ENDPOINT}/{message['id']}", headers=delete_header)
                            except Exception as exception:
                                script_logger.exception(f"Connection error {type(exception).__name__}; ")

                            if delete_request.status_code != 204:
                                script_logger.error(f"HTTP {delete_request.status_code} recieved. Error message: {json.loads(delete_request.content)['error']['message']}")
                        else:
                            # Just mark the message as read and continue
                            if action.lower() != "mark_read":
                                script_logger.error(f"Unknown mail action: {action}; mails will be marked as read but please fix this!")
                            
                            mark_content = f"{{ 'isRead' : 'True' }}"
                            mark_headers = { 'Authorization' : f"Bearer {result['access_token']}", 'Accept' : 'application/json', 'Content-Type' : 'application/json' }

                            try:
                                if proxy_use:
                                    mark_request = requests.patch(f"{MESSAGE_ENDPOINT}/{message['id']}", data=mark_content, headers=mark_headers, proxies=proxies)
                                else:
                                    mark_request = requests.patch(f"{MESSAGE_ENDPOINT}/{message['id']}", data=mark_content, headers=mark_headers)
                            except Exception as exception:
                                script_logger.exception(f"Connection error {type(exception).__name__}; ")

                            if mark_request.status_code != 201:
                                script_logger.error(f"HTTP {mark_request.status_code} recieved. Error message: {json.loads(mark_request.content)['error']['message']}")
                    count+=1

            script_logger.info(f"Processed {count} messages.")
        else:
            script_logger.error(f"No folders where found: {all_folders_data}")
    else:
        script_logger.critical(f"No access token found in the response, error: {result.get('error')} {result.get('error_description')}")
    
    
except Exception as error:
    script_logger.exception(f"Something went wrong: {error}")