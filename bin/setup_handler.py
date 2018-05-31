"""
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
##################################################################
# Description   : Script to handle the input from the app setup page
#
# Version history
# Date          Version     Author              Description
# ?             1.0         Arnold Holzel       initial version
# 2017-12-14    1.1         Arnold Holzel       Added comments to make clear what is done where (and why)
#                                               Added this change log
#                                               Added logging to the app log file.
# 2017-12-15    1.2         Arnold Holzel       Changed all the path variables so that is doesn't matter where this script is placed
#                                               directly in the /bin dir or in /bin/other/dir 
# 2017-12-28    1.3         Arnold Holzel       Made changes to the custom config file name to make it the same as the app name
# 2018-05-07    1.4         Arnold Holzel       Added the output and resolve_ips options
#                                               Replaced hard reverse to the app name in the connection string to the "app_name" variable
#
##################################################################
import json
import os

import splunk.admin as admin
import splunklib.client as client

import classes.custom_logger as c_logger

__author__ = 'Arnold Holzel'
__version__ = '1.4'
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
                'mailserver_user', 'mailserver_pwd', 'skip_mail_download', 'log_level',  'output', 'resolve_ips'
            ]:
                self.supportedArgs.addOptArg(arg)

    # Read the inital values of the options from the file ta-dmarc.conf and place them in the setup page.
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
                
        confDict = self.readConf("ta-dmarc")
        
        if confDict is not None:
            for stanza, settings in confDict.items():
                for key, val in settings.items():
                    if (key in ['mailserver_host', 'mailserver_port', 'mailserver_protocol', 'mailserver_mailboxfolder', 'mailserver_user', 'mailserver_pwd', 'output'] and val in [None, '', 'configured']):
                        val = ''
                        
                    if key in ['skip_mail_download', 'resolve_ips']:
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
        # one with the text fields, minus the username and password fields, one with the boolean fields. 
        # this is so we don't have to make a if else loop for each field.
        text_fields_list = [ 'mailserver_host', 'mailserver_port', 'mailserver_protocol', 'mailserver_mailboxfolder', 'output' ]
        boolean_fields_list = [ 'skip_mail_download', 'resolve_ips' ]
        
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
        
        # Check the user name and password fields if they are None or empty
        # set a variable so we know we don't have to store them in the Splunk
        # credential store later.
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
        self.writeConf('ta-dmarc', 'main', args_data)
          
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
                script_logger.exception("An error occurred updating credentials. Please ensure your user account has admin_all_objects and/or list_storage_passwords capabilities.")

admin.init(ConfigApp, admin.CONTEXT_NONE)

