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
# Creation date : 2017-05-25
# Description   : Wrapper script to download and process DMARC RUA files                 
#
# Version history
#| Date       | Version | Author  | **[Type]** Description                                                                |
#|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
#| 2021-02-19 | 4.0.0   | Arnold  | **[MOD]** Changes in the way the size of a uncompressed file is checked.
#                                   **[MOD]** Changed everything to Python3 
#                                   **[DEL]** Old change log is now moved to the CHANGELOG.md file in the root of the app.
#
##################################################################

import os, sys, subprocess, shutil
import errno, mimetypes
import zipfile, gzip, zlib
from datetime import datetime, timedelta
import re, struct
import inspect
import time
import argparse

import splunklib.client as client

import classes.splunk_info as si
import classes.custom_logger as c_logger

delete_files_after = 7              # days after which old log files will be deleted 
max_decompressed_file_size = 100    # Max size in MB that a decompressed XML may be, this to prevent gzip/zip bombs

#########################################
# NO NEED TO CHANGE ANYTHING BELOW HERE #
#########################################
def make_sure_path_exists(path):
    try:
        os.makedirs(path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            script_logger.exception("Problem with creating directory: \"" + path + "\" error number: " + exception.errno)
            raise
        else:
            script_logger.debug("Directory \"" + path + "\" already exists")

def nonblank_lines(file):
    for lines in file:
        line = lines.rstrip()
        if line:
            yield line

def infile_replace(file, pattern, subst):
    # Read contents from file as a single string
    file_handle = open(file, 'rb')
    file_string = file_handle.read()
    file_handle.close()

    # Use RE package to allow for replacement (also allowing for (multiline) REGEX)
    file_string = (re.sub(pattern, subst, file_string))

    # Write contents back to the file, the 'w' option makes sure the file is first truncated
    file_handle = open(file, 'wb')
    file_handle.write(file_string)
    file_handle.close()

def make_binary(input):
    if input == "0" or input.lower() == "false" or input.lower() == "f" or int(input) == 0:
        output = 0
    elif input == "1" or input.lower() == "true" or input.lower() == "t" or int(input) == 1:
        output = 1
    else:
        output = 0
        
    return output
    
def getsize(gzipfile): 
    import struct 
    
    with open(gzipfile, 'rb') as f:
        f.seek(-4, 2)
        return struct.unpack('I', f.read(4))[0]
    
if __name__ == '__main__':
    options = argparse.ArgumentParser(epilog='Example: %(prog)s --sessionKey <SPLUNK SESSIONKEY>')
    options.add_argument("--sessionKey", help="The splunk session key to use")
    args = options.parse_args()

    if args.sessionKey is None:
        sessionKey = sys.stdin.readline().strip()
    elif len(args.sessionKey) != 0:
        sessionKey = args.sessionKey
    elif len(args.sessionKey) == 0:
        sessionKey = sys.stdin.readline().strip()

    script_dir = os.path.dirname(os.path.abspath(__file__))                                     # The directory of this script
    
    splunk_info = si.Splunk_Info(sessionKey)
    splunk_paths = splunk_info.give_splunk_paths(script_dir)

    # Set all the directory's based on the directory this script is in.
    app_root_dir = splunk_paths['app_root_dir']                                                 # The app root directory
    app_default_dir = os.path.normpath(app_root_dir + os.sep + "default")                       # The Splunk app default directory                                               
    app_local_dir = os.path.normpath(app_root_dir + os.sep + "local")                           # The Splunk app local directory
    log_root_dir = os.path.normpath(app_root_dir + os.sep + "logs")                             # The root directory for the logs
    attachment_dir = os.path.normpath(log_root_dir + os.sep + "attach_raw")                     # The directory to store the attachments 
    problem_dir = os.path.normpath(log_root_dir + os.sep + "problems")                          # The directory to place attachments in that couldn't be processed
    xml_dir = os.path.normpath(log_root_dir + os.sep + "dmarc_xml")                             # The directory to store the XML's
    app_log_dir = os.path.normpath(log_root_dir + os.sep + "dmarc_splunk")                      # The directory to store the output for Splunk
    splunk_bin_dir = os.path.normpath(str(splunk_paths['splunk_home_dir']) + os.sep + "bin")    # The Splunk bin directory
    
    # Prepare the logger
    try:
        log_level = splunk_info.get_config(str(splunk_paths['app_name']).lower() + ".conf", 'main', 'log_level')
    except Exception:
        log_level = 10
        
    logger = c_logger.Logger()
    script_logger = logger.logger_setup("dmarc_converter", level=log_level)

    if len(sessionKey) == 0:
        script_logger.critical("Did not receive a session key from splunkd. Please enable passAuth in inputs.conf for this script")
        sys.exit(2)

    splunk_command = os.path.normpath(splunk_bin_dir + os.sep + "splunk")                       # The splunk command in the bin dir
    custom_conf_file = str(splunk_paths['app_name'].lower()) + ".conf"

    # Set all the values based on the content of the local or default file
    skip_mail_download = splunk_info.get_config(custom_conf_file, "main", "skip_mail_download")
    resolve_ips = splunk_info.get_config(custom_conf_file, "main", "resolve_ips")
    output = splunk_info.get_config(custom_conf_file, "main", "output")
    
    # Set the logfile to report everything in
    if output == "json":
        parser_log_file = os.path.normpath(app_log_dir + os.sep + "output_json.log")
    else:
        parser_log_file = os.path.normpath(app_log_dir + os.sep + "output.log")
    
    if resolve_ips is not None:
        resolve_ips = make_binary(resolve_ips)

        if str(resolve_ips) == "1":
            resolve = "--resolve"
        else:
            resolve = "" 
    else:
        resolve = ""

    if skip_mail_download is not None:
        skip_mail_download = make_binary(skip_mail_download)
    else:
        skip_mail_download = 0
        
    # If mail needs to be downloaded get the needed info from the config file
    if skip_mail_download == 0:
        mailserver_host = splunk_info.get_config(custom_conf_file, "main", "mailserver_host")
        mailserver_port = splunk_info.get_config(custom_conf_file, "main", "mailserver_port")
        mailserver_protocol = splunk_info.get_config(custom_conf_file, "main", "mailserver_protocol")
        mailserver_user = splunk_info.get_config(custom_conf_file, "main", "mailserver_user")                                                      
        mailserver_mailboxfolder = splunk_info.get_config(custom_conf_file, "main", "mailserver_mailboxfolder")
        
        script_logger.debug("mailserver_host: " + str(mailserver_host))
        script_logger.debug("mailserver_port: " + str(mailserver_port))
        script_logger.debug("mailserver_protocol: " + str(mailserver_protocol))
        script_logger.debug("mailserver_user: " + str(mailserver_user))
        script_logger.debug("mailserver_mailboxfolder: " + str(mailserver_mailboxfolder))
        
        # check if there are no default values
        if mailserver_user in ['DMARC_MAILBOX_USERNAME', None, '']:
            script_logger.critical("Mail needs to be downloaded but only default values are set, please change ta-dmarc.conf in default or local directory. Or use the setup page for the app.")
            sys.exit(0)
     
    ### VERBOSE log of all the directory's that are used and the mail server configuration
    script_logger.debug("script_dir=" + str(script_dir))
    script_logger.debug("app_root_dir=" + str(app_root_dir))
    script_logger.debug("log_root_dir=" + str(log_root_dir))
    script_logger.debug("attachment_dir=" + str(attachment_dir))
    script_logger.debug("problem_dir=" + str(problem_dir))
    script_logger.debug("xml_dir=" + str(xml_dir))
    script_logger.debug("app_log_dir=" + str(app_log_dir))
    script_logger.debug("splunk_bin_dir=" + str(splunk_bin_dir))
     
    if skip_mail_download == 0:
        script_logger.debug("mailserver_host=" + str(mailserver_host))
        script_logger.debug("mailserver_port=" + str(mailserver_port))
        script_logger.debug("mailserver_protocol=" + str(mailserver_protocol))
        script_logger.debug("mailserver_user=" + str(mailserver_user))
        script_logger.debug("mailserver_mailboxfolder=" + str(mailserver_mailboxfolder))
        
    script_logger.debug("skip_mail_download=" + str(skip_mail_download) + ", (0 = download mails from server, 1 =  do not download mails from server)")
     
    # Create al the directory's if they don't exist
    make_sure_path_exists(log_root_dir)
    make_sure_path_exists(attachment_dir)
    make_sure_path_exists(problem_dir)
    make_sure_path_exists(xml_dir)
    make_sure_path_exists(app_log_dir)
    make_sure_path_exists(app_local_dir)

    # just in case, remove deployment server placeholders
    if os.path.isfile(os.path.normpath(attachment_dir + os.sep + "placeholder")):
        os.remove(os.path.normpath(attachment_dir + os.sep + "placeholder"))
        script_logger.debug("Removing placeholder file in attachment directory")
        
    if os.path.isfile(os.path.normpath(xml_dir + os.sep + "placeholder")):
        os.remove(os.path.normpath(xml_dir + os.sep + "placeholder"))
        script_logger.debug("Removing placeholder file in xml directory")
        
    if os.path.isfile(os.path.normpath(app_log_dir + os.sep + "placeholder")):
        os.remove(os.path.normpath(app_log_dir + os.sep + "placeholder"))
        script_logger.debug("Removing placeholder file in app log directory")

    if os.path.isfile(os.path.normpath(problem_dir + os.sep + "placeholder")):
        os.remove(os.path.normpath(problem_dir + os.sep + "placeholder"))
        script_logger.debug("Removing placeholder file in problem log directory")

    #########################################################################
   # STEP 1: Download the mail from the mailbox if needed                  #
    #########################################################################
    if skip_mail_download == 0:
        # Mail needs to be collected from the mailserver
        # start the mail-client.py script and let the script get all the needed info from the config file
        script_logger.info("Start the download of mails")
        try:
            mail_client_script =  os.path.normpath(script_dir + os.sep + "mail-client.py")
            mail_client_command = [splunk_command, "cmd", "python", mail_client_script, "--use_conf_file", "--sessionKey", str(sessionKey)]
            script_logger.debug("mail_client_command: " + str(mail_client_command))
            run_mail_client = subprocess.Popen(mail_client_command)
            run_mail_client_data = run_mail_client.communicate()[0]
            run_mail_client_return_code = run_mail_client.returncode
        except Exception:
            script_logger.exeption("mail-client.py exited with an error, something went wrong fetching the emails. ")
            sys.exit(1)
        finally:
            script_logger.info("Done fetching emails.")
    else:
        script_logger.info("No mails will be downloaded.")
     
    #########################################################################
    # STEP 2: Uncompress the files that are in the attachment_dir and store #
    #         the content in the XML directory                              #
    #########################################################################
    script_logger.info("Start uncompressing files in the attachment directory")
    count_attachments = 0
     
    for filename in os.listdir(attachment_dir):
        script_logger.debug("Start processing file: \"" + str(filename) + "\"")
        file_mime_type, file_encoding = mimetypes.guess_type(filename)
        file_name_split, file_extention = os.path.splitext(filename)
        
        if str(file_extention) == ".zip" or str(file_mime_type) == "application/zip":
            # The file is a zipfile
            script_logger.debug("File: \"" + str(filename) + "\" is a zip file with mimetype: " + str(file_mime_type) + " and encoding: " + str(file_encoding))
            
            # To make sure we are dealing with a zip that contains a XML file and not some malicious
            # .docm or .jar file we check the files in the zip before we extract them.
            with open(os.path.normpath(attachment_dir + os.sep + filename), 'rb') as file_handle:
                zf = zipfile.ZipFile(file_handle)          
                zipinfolist = zf.infolist()
                
                for zipinfo in zipinfolist:
                    # check for the size of the uncompressed data if it is larger than 100MB skip it because
                    # that can not be right.....
                    if zipinfo.file_size <= (max_decompressed_file_size*1024*1024):
                        # for some reason some report providers remove the "." and replace it with a " " so we 
                        # cannot check for the file extension, we just check the last 3 characters of the filename
                        if zipinfo.filename[-3:] == "xml":
                            script_logger.debug("There is a XML file in the zip: " + str(filename))
                            xml_dir = os.path.normpath(xml_dir + os.sep)
                            
                            org_filename = filename
                            # Here we place the dots back in
                            # And replace "!" with "_" to prevent escaping problems
                            zipinfo.filename = re.sub(r'(\s)', r'.', zipinfo.filename)
                            zipinfo.filename = re.sub(r'(\!)', r'_', zipinfo.filename)
                            try: 
                                zf.extract(zipinfo, xml_dir)
                            except zipfile.BadZipfile:
                                script_logger.exception("Skipping file: " + str(org_filename) + " file check gave a error. Will move file to problem dir and continue.")
                                shutil.copy2(os.path.normpath(attachment_dir + os.sep + filename), problem_dir)
                                continue
                        else:
                            script_logger.critical("Skipping attachment. The zip file doesn't contain a XML file! File in attachment: " + str(filename))
                    else:
                        sizeMB = zipinfo.file_size/1024/1024
                        script_logger.critical("Skipping attachement. The size of the uncompressed file is to big: " + str(sizeMB) + "MB, max size is " + str(max_decompressed_file_size) + "MB" )
                zf.close()
        elif str(file_extention) == ".gz" or str(file_extention) == ".gzip" or str(file_encoding) == "gzip" or str(file_mime_type) == "application/gzip":
            # The file is a gzip file
            script_logger.debug("File: \"" + str(filename) + "\" is a gzip file with mimetype: " + str(file_mime_type) + " and encoding: " + str(file_encoding))
            
            if getsize(os.path.normpath(attachment_dir + os.sep + filename)) <= (max_decompressed_file_size*1024*1024):
                try:
                    gz = gzip.open(os.path.normpath(attachment_dir + os.sep + filename), 'rb')

                    data = gz.read()
                    # us the .gz name minus the extention
                    header_filename = file_name_split
                    header_filename = re.sub(r'(\s)', r'.', header_filename)
                    header_filename = re.sub(r'(\!)', r'_', header_filename)

                    #new_location = os.path.normpath(xml_dir + os.sep + header_filename)
                    xml_output_file = open(os.path.normpath(xml_dir + os.sep + header_filename), 'wb')
                    xml_output_file.write(data)
                    xml_output_file.close()
                except Exception:
                    script_logger.exception("Something went wrong reading the gz file \"" + str(filename) + "\" with mimetype: " + str(file_mime_type) + " and encoding: " + str(file_encoding) + " Traceback: ")
                    pass
            else:
                sizeMB = getsize(os.path.normpath(attachment_dir + os.sep + filename))/1024/1024
                script_logger.critical("Skipping attachement. The size of the uncompressed file is to big: " + str(sizeMB) + "MB, max size is " + str(max_decompressed_file_size) + "MB" )
        else:
            script_logger.error("There is a problem with file: \"" + str(filename) + "\", mimetype:\"" + str(file_mime_type) + "\", encoding: \"" + str(file_encoding) + " and it cannot be processed. Will move file to problem dir and continue.")
            shutil.copy2(os.path.normpath(attachment_dir + os.sep + filename), problem_dir)
        
        script_logger.debug("Done processing file: \"" + str(filename) + "\", delete it now.")
        
        # Try to remove the file so we don't process it again the next time the script runs
        # If the remove fails write it to the log and just continue
        try:
            os.remove(os.path.normpath(attachment_dir + os.sep + filename))
        except OSError:
            script_logger.exception("Unable to remove file: \"" + str(attachment_dir) + str(os.sep) + str(filename) + "\" ")
            pass
            
        count_attachments += 1
        
    script_logger.info("Done uncompressing " + str(count_attachments) + " file(s) in the attachment directory")
    
    ########################################################################
    # STEP 3: Check the created XML file to see if it is just 1 report     #
    ########################################################################
    for xmlfile in os.listdir(xml_dir):
        script_logger.debug("Start the content checking of: \'" + str(xmlfile) + "\'")
        
        # Check if we didn't already processed the file. 
        firstCharFileName = xmlfile[:1]
        if not isinstance(firstCharFileName,int):
            # if we are dealing with a file 
            if os.path.isfile(os.path.normpath(xml_dir + os.sep + xmlfile)):
                with open(os.path.normpath(xml_dir + os.sep + xmlfile),'r') as file:
                    data = file.read()
                
                # count the number of reports in the xml file. normaly there will be only one but I have seen it 
                # multiple times that for some reason there are 2 or more reports in one xml. The etree parser will than
                # raise the following error and stop processing the file.
                #  ParseError: junk after document element: line X, column Y
                
                # test number 1
                numberOfReports = data.count('<?xml')
                
                if numberOfReports > 1:
                    script_logger.info("Test #1, Found " + str(numberOfReports) + " reports in file: \'" + str(xmlfile) + "\'")
                    found = re.findall(r'(\<\?xml.*?\<\/feedback\>)', data, re.M | re.S)
                    
                    # create for every regex group a new file and put a number in front of it.
                    for i in range(1, len(found)+1):
                        open(os.path.normpath(xml_dir + os.sep + str(i) + '_' + str(xmlfile)),'w').write(found[i-1])
                        script_logger.debug("Created new file: \'" + str(xml_dir) + os.sep + str(i) + '_' + str(xmlfile) + "\'")
                    
                        # try to remove the original file 
                        try:
                            script_logger.debug('Removing original file: \'' + str(xml_dir) + os.sep + str(xmlfile) + '\'')
                            os.remove(os.path.normpath(xml_dir + os.sep + xmlfile))
                        except OSError:
                            script_logger.exception("Unable to remove original file: \"" + str(xml_dir) + os.sep + str(xmlfile) + "\" ")
                            pass
                
                # test number 2
                numberOfReports_test2 = data.count('<feedback>')

                if numberOfReports_test2 > 1 and numberOfReports <= 1:
                    script_logger.info("Test #2, Found " + str(numberOfReports_test2) + " reports in file: \'" + str(xmlfile) + "\'")
                    found_test2 = re.findall(r'(\<feedback\>.*?\<\/feedback\>)', data, re.M | re.S)

                    # create for every regex group a new file and put a number in front of it.
                    for j in range(1, len(found_test2)+1):
                        open(os.path.normpath(xml_dir + os.sep + str(j) + '_' + str(xmlfile)),'w').write(found_test2[j-1])
                        script_logger.debug("Created new file: \'" + str(xml_dir) + os.sep + str(j) + '_' + str(xmlfile) + "\'")
                    
                        # try to remove the original file 
                        try:
                            script_logger.debug('Removing original file: \'' + str(xml_dir) + os.sep + str(xmlfile) + '\'')
                            os.remove(os.path.normpath(xml_dir + os.sep + xmlfile))
                        except OSError:
                            script_logger.exception("Unable to remove original file: \"" + str(xml_dir) + os.sep + str(xmlfile) + "\" ")
                            pass
            else:
                # the current item is a directory, that is not what we expect or can deal with so remove it.
                # this can occure when zip files are repacked on Mac systems, you than get a directory
                # named "__MACOSX"
                try:
                    script_logger.warning('Found a directory named: "' + str(xmlfile) + '" deleting it')
                    shutil.rmtree(os.path.normpath(xml_dir + os.sep + xmlfile))
                except Exception:
                    script_logger.exception('Problems deleting directory "' + str(os.path.normpath(xml_dir + os.sep + xmlfile)) + '" :')
    ########################################################################
    # STEP 4: Process the XML files that are in the xml_dir                #
    ########################################################################
    script_logger.info("Start processing files in the xml directory")
    count_xml_files = 0
     
    # check if we need to roll-over the log file
    if os.path.isfile(parser_log_file):
        now = datetime.now()
        
        today = datetime.today()
        yesterday = today - timedelta(days=1)
     
        # Only roll over at midnight, save the "old" logfile in a zip file with the day of the log.
        if now.hour == 0 or now.hour == 00 or now.hour == 24:
            with zipfile.ZipFile(parser_log_file + "_" + str(yesterday.strftime("%G")) + str(yesterday.strftime("%m")) + str(yesterday.strftime("%d")) + ".zip", "w", zipfile.ZIP_DEFLATED) as zip_file:
                zip_file.write(parser_log_file, os.path.basename(parser_log_file))
                zip_file.close()
            
            # Remove the old log file
            os.remove(parser_log_file)
            
            # check if there are files older than x day that need to be deleted
            for file in os.listdir(app_log_dir):
                full_file_path = os.path.normpath(app_log_dir + os.sep + file)
                creation_time = os.path.getctime(full_file_path)
                file_age = int(now.strftime("%s")) - int(creation_time)
                max_age = delete_files_after * 86400
     
                # only delete old .zip files!!
                if int(file_age) >= int(max_age) and os.path.isfile(full_file_path) and full_file_path.endswith(".zip"):
                    os.remove(full_file_path)
     
    for xmlfile in os.listdir(xml_dir):
        script_logger.debug("Start processing file: \'" + str(xmlfile) + "\'")
        
        # Make sure that the Splunk Python is used to proces the dmarc-parser.py script
        dmarc_parser_script = os.path.normpath(script_dir + os.sep + "dmarc-parser.py")
        
        if resolve not in [None, ""]:
            dmarc_parser_commands = [splunk_command, "cmd", "python", dmarc_parser_script, "--file", os.path.normpath(xml_dir + os.sep + xmlfile), "--logfile", str(parser_log_file), "--output", str(output), str(resolve), "--sessionKey", sessionKey ]
        else:
            dmarc_parser_commands = [splunk_command, "cmd", "python", dmarc_parser_script, "--file", os.path.normpath(xml_dir + os.sep + xmlfile), "--logfile", str(parser_log_file), "--sessionKey", sessionKey]
            
        script_logger.debug("Passing the following options to the parser script: " + str(dmarc_parser_commands))
        run_dmarc_parser = subprocess.Popen(dmarc_parser_commands)
        run_dmarc_parser_data = run_dmarc_parser.communicate()[0]
        run_dmarc_parser_return_code = run_dmarc_parser.returncode
        
        script_logger.debug("Done processing file: \"" + str(xmlfile) +"\"")
        
        # The dmarc-parser.py script takes care of the removal of the file 
        # so we don't process it again the next time the script runs
        
        count_xml_files +=1
        
    script_logger.info("Done processing "+ str(count_xml_files) +" file(s) in the xml directory")

    ############################################################################
    # STEP 5: Try to remove the files again that failed removal the first time #
    ############################################################################

    # Check if there are any files left in the attachment_dir that could not be removed
    # Wait for 10 seconds before re-trying to delete files from the attachement directory
    # this gives the OS (mainly Windows....) time to release the file
    script_logger.debug("Check to see if there are still files left in the attachment_dir.")

    if not os.listdir(attachment_dir) == []: 
        script_logger.warning("There are some files left in \"" + attachment_dir + "\", wait 10 seconds and try to move them.")
        time.sleep(10)

        # loop through the files that are still in the directory and try to delete them
        for filename in os.listdir(attachment_dir):
            try:
                os.remove(os.path.normpath(attachment_dir + os.sep + filename))
            except OSError:
                script_logger.exception("Still unable to remove file: \"" + str(attachment_dir) + str(os.sep) + str(filename) + "\" ")
                try:
                    script_logger.info("Try to move " + str(attachment_dir) + str(os.sep) + str(filename) + " to " + problem_dir)
                    shutil.move(os.path.normpath(attachment_dir + os.sep + filename), problem_dir)
                except OSError:
                    script_logger.exeption("Cannot move file: \"" + str(attachment_dir) + str(os.sep) + str(filename) + "\" to the problem dir, please remove file manually! ")
                    pass
                pass
    else:
        script_logger.debug("No files left in \"" + attachment_dir + "\"")
