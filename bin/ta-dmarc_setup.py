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
# Description   : Script to handle the input from the app setup page
#
# The changelog can be found in the readme dir of this app
##################################################################
import json
import os
import sys

# add the lib dir to the path to import libs from there
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib"))

from splunk import admin as admin
from splunklib import client as client

from classes import custom_logger as c_logger

__version__ = '2.1.0'
__author__ = 'Arnold Holzel'
__license__ = 'Apache License 2.0'

script_log_level = 20 # 10=DEBUG, 20=INFO, 30=WARNING, 40=ERROR, 50=CRITICAL

splunk_home_dir = os.environ['SPLUNK_HOME']                                             # Get the environment variable for SPLUNK_HOME
splunk_apps_dir = os.path.normpath(splunk_home_dir + os.sep + "etc" + os.sep + "apps")  # create the path to the apps directory
script_dir = os.path.dirname(os.path.abspath(__file__))                                 # The directory of this script
app_name = script_dir.replace(splunk_apps_dir + "/", "").split(os.sep,1)[0]             # The name of the app this script is in
app_root_dir = os.path.normpath(splunk_apps_dir + os.sep + app_name)                    # The app root directory
log_root_dir = os.path.normpath(app_root_dir + os.sep + "logs")                         # The root directory for the logs
script_log_file = os.path.normpath(log_root_dir + os.sep + "app_setup.log")             # The file to write all to logs to if nothing is provided to the logger_setup function

logger = c_logger.Logger()
script_logger = logger.logger_setup(name="setup", log_file=script_log_file, level=script_log_level)

class ConfigApp(admin.MConfigHandler):
    # setup the supported arguments, the fields that are defined on the setup page
    def setup(self):
        if self.requestedAction == admin.ACTION_EDIT:
            for arg in [
                'mailserver_host', 'mailserver_port', 'mailserver_protocol', 'mailserver_mailboxfolder', 
                'mailserver_user', 'mailserver_pwd', 'o365_client_id', 'o365_tenant_id', 'o365_client_secret', 
                'mailserver_action', 'mailserver_moveto', 'skip_mail_download', 'log_level',  'output', 'resolve_ips',
                'proxy_use', 'proxy_server', 'proxy_username', 'proxy_pwd'
            ]:
                self.supportedArgs.addOptArg(arg)

    # Read the inital values of the options from the file <<app_name>>.conf and place them in the setup page.
    # If no setup has been done before read from the app default file
    # If the setup has been done before read from the app local file first and if a field has no value there
    # fallback to the default values
    def handleList(self, confInfo):
        # Connect to Splunk to update or read some values if needed
        # username
        # password
        sessionKey = self.getSessionKey()
        if len(sessionKey) == 0:
            script_logger.critical("Did not receive a session key from splunkd. Please enable passAuth in inputs.conf for this script.")
        else:
            try:
                service = client.connect(token=sessionKey, app=app_name)
            except Exception:
                script_logger.exception("An error occurred connecting to splunkd")
                
        confDict = self.readConf(app_name.lower())
        
        if confDict is not None:
            for stanza, settings in confDict.items():
                for key, val in settings.items():
                    if (key in ['mailserver_host', 'mailserver_port', 'mailserver_protocol', 'mailserver_mailboxfolder', 'mailserver_user', 'mailserver_pwd', 'output', 'o365_client_id', 'o365_tenant_id', 'o365_client_secret', 'mailserver_action', 'mailserver_moveto', 'proxy_server', 'proxy_username', 'proxy_pwd'] and val in [None, '', 'configured']):
                        val = ''
                        
                    if key in ['skip_mail_download', 'resolve_ips', 'proxy_use']:
                        if int(val) == 1 or str(val.lower()) == "true" :
                            val = '1'
                        else:
                            val = '0'

                    if key == 'log_level':
                        # make sure we have a valid value for log_level
                        if int(val) > 0 and int(val) < 20:
                            val = '10'
                        elif int(val) >= 20 and int(val) < 30:
                            val = '20'
                        elif int(val) >= 30 and int(val) < 40:
                            val = '30'
                        elif int(val) >= 40 and int(val) < 50:
                            val = '40'
                        elif int(val) >= 50:
                            val = '50'
                        else:
                            val = '20' 
                            
                    confInfo[stanza].append(key, val)

    # After the user clicks the "SAVE" button, take the updated settings, 
    # normalize them and then save them.
    def handleEdit(self, confInfo):
        # Connect to Splunk to update or read some values if needed
        sessionKey = self.getSessionKey()
        if len(sessionKey) == 0:
            script_logger.critical("Did not receive a session key from splunkd. Please enable passAuth in inputs.conf for this script.")
        else:
            try:
                service = client.connect(token=sessionKey, app=app_name)
            except Exception:
                script_logger.exception("An error occurred connecting to splunkd")
                
        # Make two lists with field names, 
        # one with the text fields, minus the usernames, passwords and o365 fields, one with the boolean fields. 
        # this is so we don't have to make a if else loop for each field.
        text_fields_list = [ 'mailserver_host', 'mailserver_port', 'mailserver_protocol', 'mailserver_mailboxfolder', 'output', 'mailserver_action', 'mailserver_moveto', 'proxy_server' ]
        boolean_fields_list = [ 'skip_mail_download', 'resolve_ips', 'proxy_use' ]
        
        args_data = self.callerArgs.data
        
        # Loop through the text fields if the field is None or empty make it empty
        for field_name in text_fields_list:
            if args_data[field_name][0] in [None, '']:
                args_data[field_name][0] = ''

        # loop through the boolean fields
        for field_name in boolean_fields_list:
            if int(args_data[field_name][0]) == 1:
                args_data[field_name][0] = '1'
            else:
                args_data[field_name][0] = '0'
        
        # Check the username, password and o365 fields if they are None or empty
        # set a variable so we know we don't have to store them in the Splunk
        # credential store later.
        ############ Mailbox credentials ############
        if args_data['mailserver_user'][0] in [None, '']:
            mailserver_user = 0
            args_data['mailserver_user'][0] = 'None'
        else:
            mailserver_user = args_data['mailserver_user'][0]

        if args_data['mailserver_pwd'][0] in [None, '', 'configured']:
            mailserver_pwd = 0
            args_data['mailserver_pwd'][0] = ''
        else:
            mailserver_pwd = args_data['mailserver_pwd'][0]
            args_data['mailserver_pwd'][0] = 'configured'
        
        ############ Proxy credentials ############
        if args_data['proxy_username'][0] in [None, '']:
            proxy_username = 0
            args_data['proxy_username'][0] = 'None'
        else:
            proxy_username = args_data['proxy_username'][0]
        
        if args_data['proxy_pwd'][0] in [None, '', 'configured']:
            proxy_pwd = 0
            args_data['proxy_pwd'][0] = ''
        else:
            proxy_pwd = args_data['proxy_pwd'][0]
            args_data['proxy_pwd'][0] = 'configured'
        
        ############ o365 credentials ############
        if args_data['o365_client_id'][0] in [None, '']:
            o365_client_id = 0
            args_data['o365_client_id'][0] = 'None'
        else:
            o365_client_id = args_data['o365_client_id'][0]

        if args_data['o365_tenant_id'][0] in [None, '']:
            o365_tenant_id = 0
            args_data['o365_tenant_id'][0] = 'None'
        else:
            o365_tenant_id = args_data['o365_tenant_id'][0]
        
        if args_data['o365_client_secret'][0] in [None, '', 'configured']:
            o365_client_secret = 0
            args_data['o365_client_secret'][0] = ''
        else:
            o365_client_secret = args_data['o365_client_secret'][0]
            args_data['o365_client_secret'][0] = 'configured'

        # Make sure the log_level is set to a valid value before we save it.
        if int(args_data['log_level'][0]) > 0 and int(args_data['log_level'][0]) < 20:
            args_data['log_level'][0] = '10'
        elif int(args_data['log_level'][0]) >= 20 and int(args_data['log_level'][0]) < 30:
            args_data['log_level'][0] = '20'
        elif int(args_data['log_level'][0]) >= 30 and int(args_data['log_level'][0]) < 40:
            args_data['log_level'][0] = '30'
        elif int(args_data['log_level'][0]) >= 40 and int(args_data['log_level'][0]) < 50:
            args_data['log_level'][0] = '40'
        elif int(args_data['log_level'][0]) >= 50:
            args_data['log_level'][0] = '50'
        else:
            args_data['log_level'][0] = '20' 
        
        # write everything to the custom config file
        self.writeConf(app_name.lower(), 'main', args_data)

        # Store the username and password if they are not empty
        if mailserver_user != 0 and mailserver_pwd != 0:
            try:
                # If the credential already exists, delete it.
                for storage_password in service.storage_passwords:
                    if storage_password.username == mailserver_user:
                        service.storage_passwords.delete(username=storage_password.username)
                        break

                # Create the credentials 
                service.storage_passwords.create(mailserver_pwd, mailserver_user)

            except Exception:
                script_logger.exception("An error occurred updating mailbox credentials. Please ensure your user account has admin_all_objects and/or list_storage_passwords capabilities.")

        # Store the o365 credentials if they are not empty
        if o365_client_id != 0 and o365_client_secret != 0:
            try:
                for storage_password in service.storage_passwords:
                    if storage_password.username == o365_client_id:
                        service.storage_passwords.delete(username=storage_password.username)
                        break
                
                service.storage_passwords.create(o365_client_secret, o365_client_id)
            except Exception:
                script_logger.exception("An error occurred updating o365 credentials. Please ensure your user account has admin_all_objects and/or list_storage_passwords capabilities.")
        
        # Store the proxy credentials if they are not empty
        if proxy_username != 0 and proxy_pwd != 0:
            try:
                # If the credential already exists, delete it.
                for storage_password in service.storage_passwords:
                    if storage_password.username == proxy_username:
                        service.storage_passwords.delete(username=storage_password.username)
                        break

                # Create the credentials 
                service.storage_passwords.create(proxy_pwd, proxy_username)

            except Exception:
                script_logger.exception("An error occurred updating mailbox credentials. Please ensure your user account has admin_all_objects and/or list_storage_passwords capabilities.")

admin.init(ConfigApp, admin.CONTEXT_NONE)

