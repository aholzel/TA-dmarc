#!/usr/bin/python
"""
Copyright 2017-2019 Arnold Holzel

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
# Author        : SMT - Arnold
# Creation date : 2017-05-25
# Description   : Script to parse the DMARC RUA XML files into key=value pairs so it can be
#                 ingested into Splunk. This script pulls all the possible information out of
#                 the XML, it is compatible with RUA version 1.0

#
# Version history
# Date          Version     Author      Description
# 2017-05-27    1.0         Arnold      Initial version
# 2017-05-31    1.1         Arnold      Changes some parts of the main() function to deal with xml files
#                                       that have set the encoding to windows-1252 because lxml doesn't
#                                       like that. Also made this script responsable for the removal of
#                                       the xml files that it processes (and creates for the decoding)  
# 2017-06-06    1.2         Arnold      Forced lowercase on parts of the output, so the Splunk stats 
#                                       results will work correct in the SA-dmarc dashboards.
#                                       Minor bugfixes        
# 2017-06-07    1.3         Arnold      More bugfixes, removed some unneeded code, cleaned up the code
# 2017-06-20    1.4         Arnold      Added option to resolve ip's to hostnames and add these to the 
#                                       logs. (Beta testing only, and disabled for now)
# 2017-12-04    1.5         Arnold      Removed the custom log function and rownumber function, and replaced it with the default Python
#                                       logging function. This makes it also possible to log the exception info to the logfile. Only 
#                                       downside is that the VERBOSE option is now removed and all those messages are now on DEBUG level.
# 2017-12-28    1.6         Arnold      Rewritten and removed parts to make use of the (external) Splunk_Info and Logger classes.
#                                       Changed the regex to remove the <?xml ....> part of the xml because sometimes the removal didn't 
#                                       went as expected, made the regex simpler and it now works as expected.
# 2018-03-02    1.7         Arnold      "fixed" the timeout problem with nslookup so this can now be used, default timeout is now 2 secondes
#                                       if within that time there is no response from the nslookup subprocess the process will be killed 
#                                       and an NXDOMAIN will be assumed.
# 2018-04-01    1.8         Arnold      Made it possible to set the output to JSON.
# 2019-03-25    2.0         Arnold      Rewritten the 'process_dmarc_xml' function entirely, to make it more clear what is done and how.
#                                       Now using xml.etree instead of lxml.etree module xml.etree is less picky about the encoding, 
#                                       so less manipulation is needed before processing. This reduced the script with almost 100 lines.
#                                 NOTE: If you also use the SA-dmarc app please upgrade that app to 3.6.1 or higher for the correct 
#                                       field extracts.
#
##################################################################

import xml.etree.ElementTree as ET
import argparse, json
import re, os, sys
from datetime import datetime
from collections import defaultdict

import classes.splunk_info as si
import classes.custom_logger as c_logger

def nested_dict(n, type):
    if n == 1:
        return defaultdict(type)
    else:
        return defaultdict(lambda: nested_dict(n-1, type))

def del_none(d):
    for key, value in list(d.items()):
        if value is None:
            del d[key]
        elif isinstance(value, dict):
            del_none(value)
    return d  

def get_kv_dict(d, out=dict()):
    for k, v in d.items():
        if isinstance(v, dict):
            get_kv_dict(v)
        else:
            out[k] = v.strip()  
            
    return out
    
report_defaultdata = nested_dict(6, dict)

def process_dmarc_xml(xml_file, output="json", resolve=0, resolve_timeout=2):
    # open the provided xml file and read the content into a string.
    try:
        with open(xml_file, 'rb') as content_file:
            script_logger.debug("Reading the XML file content.")
            xml = content_file.read()
    except EnvironmentError:
        script_logger.exception("Cannot open file '" + str(dmarc_rua_xml) + "'\" traceback=")
        exit(0)
        
    # find the root element of the xml, this should be the feedback element
    try:
        root = ET.fromstring(xml)

        # loop trough the xml and find al the possible items that the xml can have. And store everything
        # in a multidimensional dict. if an item is not found a None value will be set, this will later on be removed
        # this dict will later on either be converted into a json or in key=value pairs.
        
        # find the "feedback" item of the xml, and all the items directly below that, that can only occur once
        for feedback in root.iter('feedback'):
            report_defaultdata["feedback"]["version"] = feedback.findtext('version',None)
            report_defaultdata["feedback"]["file_name"] = str(os.path.basename(os.path.normpath(xml_file)))
            
            # find the report_metadata info
            report_defaultdata["feedback"]["report_metadata"]["org_name"] = feedback.findtext('report_metadata/org_name',None)
            report_defaultdata["feedback"]["report_metadata"]["email"] = feedback.findtext('report_metadata/email',None)
            report_defaultdata["feedback"]["report_metadata"]["extra_contact_info"] = feedback.findtext('report_metadata/extra_contact_info',None)
            report_defaultdata["feedback"]["report_metadata"]["report_id"] = feedback.findtext('report_metadata/report_id',None)
            
            # find the date_range info
            report_defaultdata["feedback"]["report_metadata"]["date_range"]["begin"] = feedback.findtext('report_metadata/date_range/begin',None)
            report_defaultdata["feedback"]["report_metadata"]["date_range"]["end"] = feedback.findtext('report_metadata/date_range/end',None)
            
            # find the policy_published info
            report_defaultdata["feedback"]["policy_published"]["domain"] = feedback.findtext('policy_published/domain',None)
            report_defaultdata["feedback"]["policy_published"]["adkim"] = feedback.findtext('policy_published/adkim',None)
            report_defaultdata["feedback"]["policy_published"]["aspf"] = feedback.findtext('policy_published/aspf',None)
            report_defaultdata["feedback"]["policy_published"]["p"] = feedback.findtext('policy_published/p',None)
            report_defaultdata["feedback"]["policy_published"]["sp"] = feedback.findtext('policy_published/sp',None)
            report_defaultdata["feedback"]["policy_published"]["pct"] = feedback.findtext('policy_published/pct',None)

            # find the record info, this tag can occure multiple times, so loop through all of them
            for record in feedback.iter('record'):
                report_recorddata = report_defaultdata

                # find the identifiers per record.
                for identifiers in record.findall('identifiers'):
                    report_recorddata["feedback"]["record"]["identifiers"]["header_from"] = identifiers.findtext('header_from',None)
                    report_recorddata["feedback"]["record"]["identifiers"]["envelope_from"] = identifiers.findtext('envelope_from',None)
                    report_recorddata["feedback"]["record"]["identifiers"]["envelope_to"] = identifiers.findtext('envelope_to',None)

                for dkim in record.findall('./auth_results/dkim'):
                    report_recorddata["feedback"]["record"]["auth_results"]["dkim"]["domain"] = dkim.findtext('domain',None)
                    report_recorddata["feedback"]["record"]["auth_results"]["dkim"]["selector"] = dkim.findtext('selector',None)
                    report_recorddata["feedback"]["record"]["auth_results"]["dkim"]["result"] = dkim.findtext('result',None)
                    report_recorddata["feedback"]["record"]["auth_results"]["dkim"]["result"] = dkim.findtext('human_result',None)

                for spf in record.findall('./auth_results/spf'):
                    report_recorddata["feedback"]["record"]["auth_results"]["spf"]["domain"] = spf.findtext('domain',None)
                    report_recorddata["feedback"]["record"]["auth_results"]["spf"]["scope"] = spf.findtext('scope',None)
                    report_recorddata["feedback"]["record"]["auth_results"]["spf"]["result"] = spf.findtext('result',None)
                
                # a record can have multiple rows, loop through all of them.
                for row in record.iter('row'):
                    
                    source_ip = row.findtext('source_ip',None)
                    
                    if resolve == 1:
                        # Resolve ip adresses to hostnames, this might take some time but this way we have the
                        # hostname associated with the ip at the time of the report.
                        # The socket.gethostbyip option might take very long to resolve nxdomain's because of the 
                        # 30 sec. timeout. To get around this we use a subprocess to do an nslookup and use a timeout
                        # to kill the process if it takes to long
                        import subprocess, shlex
                        from threading import Timer

                        # define two method's to run the nslookup and kill it if it runs longer than x sec
                        def kill_process(process, timeout):
                            timeout["value"] = True
                            process.kill()

                        def run(cmd, timeout_sec):
                            process = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            timeout = {"value": False}
                            timer = Timer(timeout_sec, kill_process, [process, timeout])
                            timer.start()
                            stdout, stderr = process.communicate()
                            timer.cancel()
                            # return the process returncode, whether or not we run into the set timeout, stdout, stderr
                            return process.returncode, timeout["value"], stdout.decode("utf-8"), stderr.decode("utf-8")

                        cli_output = run("nslookup -q=a " + str(source_ip), resolve_timeout)

                        if str(cli_output[0]) == "0":
                            # The below regex searches for the PTR and can handle both Windows and Linux returns
                            search = re.search("(?:n|N)ame\s*(?:\=|\:)\s*([^\s]*)", cli_output[2])
                            
                            if search:
                                # Check if we have a result
                                hostname = search.group(1)
                                hostname = hostname.lower()
                                hostname = hostname.rstrip('.')
                            else:
                                hostname = "NXDOMAIN"
                        else:
                            hostname = "NXDOMAIN"
                    else:
                        hostname = "-"
                        
                    report_recorddata["feedback"]["record"]["row"]["source_ip"] = str(source_ip)
                    report_recorddata["feedback"]["record"]["row"]["source_hostname"] = str(hostname).lower()
                    report_recorddata["feedback"]["record"]["row"]["count"] = row.findtext('count',None)
                    report_recorddata["feedback"]["record"]["row"]["policy_evaluated"]["disposition"] = row.findtext('policy_evaluated/disposition',None)
                    report_recorddata["feedback"]["record"]["row"]["policy_evaluated"]["dkim"] = row.findtext('policy_evaluated/dkim',None)
                    report_recorddata["feedback"]["record"]["row"]["policy_evaluated"]["spf"] = row.findtext('policy_evaluated/spf',None)
                    
                # remove the empty values from the dict
                report_recorddata = del_none(report_recorddata)

                if output == 'json':
                    # create a json from the dict
                    jsondata = json.dumps(report_recorddata)
                    result_logger.info(jsondata)
                elif output == 'kv':
                    # create a 1 dimensional dict from with the keys and values from the multidimensional dict. 
                    kvdata = get_kv_dict(report_recorddata)
                    kv = ''
                    for k,v in kvdata.iteritems():
                        kv = kv + k + '="' + v + '", '
                        
                    kv = kv.strip(' ,')
                    result_logger.info(kv)
    except Exception:
        script_logger.exception('A exception occured with file \'' + str(xml_file) +'\', traceback=')
        exit(0)
   
if __name__ == "__main__":
    logger = c_logger.Logger()
    
    # Get the arguments from the commandline input.
    options = argparse.ArgumentParser(epilog="Example: %(prog)s --file dmarc-xml-file --resolve --logfile outfile.log")
    options.add_argument("--file", help="dmarc file in XML format")
    options.add_argument("--resolve", action="store_true")
    options.add_argument("--logfile", help="the log file to write to")
    options.add_argument("--output", help="the output of the log: kv or json (default)", default="json")
    options.add_argument("--sessionKey", help="the Splunk sessionKey to use")
    args = options.parse_args()
  
    # Splunk sessionKey info
    if args.sessionKey is None:
        sessionKey = sys.stdin.readline().strip()
    elif len(args.sessionKey) != 0:
       sessionKey = args.sessionKey
    elif len(args.sessionKey) == 0:
        sessionKey = sys.stdin.readline().strip()

    splunk_info = si.Splunk_Info(sessionKey)

    # Set all the needed directory's based on the directory this script is in.
    script_dir = os.path.dirname(os.path.abspath(__file__))                     # The directory of this script
    splunk_paths = splunk_info.give_splunk_paths(script_dir)
    app_root_dir = splunk_paths['app_root_dir']                                 # The app root directory
    log_root_dir = os.path.normpath(app_root_dir + os.sep + "logs")             # The root directory for the logs
    app_log_dir = os.path.normpath(log_root_dir + os.sep + "dmarc_splunk")      # The directory to store the output for Splunk

    log_level = splunk_info.get_config(str(splunk_paths['app_name'].lower()) + ".conf", 'main', 'log_level')

    # Get the dmarc RUA file name
    dmarc_rua_xml = args.file
    
    # set the output mode of the logs (kv or json)
    output = args.output
    
    # Set the logfile to report everything in
    script_log_file = os.path.normpath(app_log_dir + os.sep + "dmarc_parser.log")
    result_log_file = args.logfile
    
    script_logger = logger.logger_setup(name="script_logger", level=log_level)
    result_logger = logger.logger_setup(name="result_logger", log_file=result_log_file, level=10, format="raw")

    if args.resolve:
        resolve = 1
    else:
        resolve = 0

    script_logger.debug("Start processing file " + str(dmarc_rua_xml) + " resolve dns: " + str(resolve))
    script_logger.debug("results file: " + str(result_log_file))
    
    # In theory all xml files are in UTF-8 format but that is just theory.... I have seens some 
    # files in the wild that have encoding="windows-1252" for example, 
    # and lxml doesn't like that... so we just replace remove everything from <xml version...> to
    # (but not including) <feedback> 
    # Also in theory all files have a extention, but again "in the wild" I have seen reports where 
    # all the dots (.) where replaced with spaces ( ) so the files don't have a extention anymore
    if not dmarc_rua_xml.endswith(".xml"):
        script_logger.warning("File '" + str(dmarc_rua_xml) + "' doesn't have a .xml extention")
        new_dmarc_rua_xml = dmarc_rua_xml + ".xml"
    else:
        new_dmarc_rua_xml = dmarc_rua_xml

    # Get all the info from the report
    script_logger.debug("Start getting the data from " + str(os.path.basename(os.path.normpath(new_dmarc_rua_xml))))
    process_dmarc_xml(new_dmarc_rua_xml, output, resolve)
    
    if new_dmarc_rua_xml == dmarc_rua_xml:
        # Remove the original file so we don't process it again the next time the script runs
        try:
            script_logger.debug("Delete file \"" + str(dmarc_rua_xml) + "\" now")
            os.remove(dmarc_rua_xml)
        except Exception:
            script_logger.exception("Unable to delete file \"" + str(dmarc_rua_xml) + " ")
    else:
        try:
            # Remove the original file so we don't process it again the next time the script runs
            script_logger.debug("Delete file \"" + str(dmarc_rua_xml) + "\" now")
            os.remove(dmarc_rua_xml)
        except Exception:
            script_logger.exception("Unable to delete file \"" + str(dmarc_rua_xml) + " ")
            
        try:
            # Remove the newly created file so we don't process it again the next time the script runs
            script_logger.debug("Delete file \"" + str(new_dmarc_rua_xml) + "\" now")
            os.remove(new_dmarc_rua_xml)
        except Exception:
            script_logger.exception("Unable to delete file \"" + str(new_dmarc_rua_xml) + " ")
