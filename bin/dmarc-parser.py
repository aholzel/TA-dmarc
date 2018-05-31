#!/usr/bin/python
"""
Copyright 2017-2018 Arnold Holzel

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
#                 Converting an XML file that is +/- 1 million rows takes about 12 sec.
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
#
##################################################################

from lxml import etree
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

def process_dmarc_xml(xml_file, output="kv", resolve=0, resolve_timeout=2):
    # Go through the xml_file and look voor the <report_metadata> and <policy_published> elements
    metatree = etree.iterparse(xml_file, events=('end',), tag=('report_metadata', 'policy_published'))
    
    if output == "kv":
        # clean out the report_defaultdata variable just in case...
        report_defaultdata = ""
    elif output == "json":
        report_defaultdata = nested_dict(6, dict)

    for event, metainfo in metatree:
        # loop through the data
        if event == 'end' and metainfo.tag == 'report_metadata':
            # this is the <report_metadata> element, so get all the info that is in there and if 
            # not available set a default value
            org_name = metainfo.findtext('org_name', default="not_set")
            email = metainfo.findtext('email', default="not_set")
            extra_contact_info = metainfo.findtext('extra_contact_info', default="not_set")
            report_id = metainfo.findtext('report_id', default="not_set")
            date_range_begin = metainfo.findtext('date_range/begin', default="not_set")
            date_range_end = metainfo.findtext('date_range/end', default="not_set")
      
            # Set some variables for potentially looping through the <error> element.
            error_data = ""
            error_count = 1
      
            for metainfo_error in metainfo.findall('error'):
                # The <report_metadata> element can contain multiple or non <error> elements this
                # for loop loops through them and collects the info.
                # The <error> element doesn't have any subelements so just get the text between the 
                # start and end of the element.
                error = metainfo_error.text
        
                error_data += "error_" + str(error_count) + "=\"" + str(error) + "\", "
                error_count += 1
            
            if output == "kv":
                # Put everything together, put quotes around all the values even if they are in theory numbers only, 
                # cast everything to a string to prevent errors if something is not a string..
                report_defaultdata += "org_name=\"" + str(org_name) + "\", email=\"" + str(email) \
                + "\", extra_contact_info=\"" + str(extra_contact_info) + "\", report_id=\"" + str(report_id) \
                + "\", date_range_begin=\"" + str(date_range_begin) + "\", date_range_end=\"" + str(date_range_end) \
                + "\", " + str(error_data)
            elif output == "json":
                report_defaultdata["feedback"]["report_metadata"]["org_name"] = str(org_name)
                report_defaultdata["feedback"]["report_metadata"]["email"] = str(email)
                report_defaultdata["feedback"]["report_metadata"]["extra_contact_info"] = str(extra_contact_info)
                report_defaultdata["feedback"]["report_metadata"]["report_id"] = str(report_id)
                report_defaultdata["feedback"]["report_metadata"]["date_range"]["begin"] = str(date_range_begin)
                report_defaultdata["feedback"]["report_metadata"]["date_range"]["end"] = str(date_range_end)
  
        if event == "end" and metainfo.tag == "policy_published":
            # this is the <policy_published> element, so get all the info that is in there and if 
            # not available set a default value based on the DMARC RFC
            domain = metainfo.findtext('domain', default="not_set")
            adkim = metainfo.findtext('adkim', default="r")
            aspf = metainfo.findtext('aspf', default="r")
            p = metainfo.findtext('p', default="none")
            sp = metainfo.findtext('sp', default="none")
            pct = metainfo.findtext('pct', default=100)
            fo = metainfo.findtext('fo', default=0)

            if output == "kv":
                # put everything together with the report_metadata info. Again put quotes around everthing 
                # that is not numbers only, cast everything to a string to prevent errors just in case..
                report_defaultdata += "published_domain=\"" + str(domain) + "\", published_adkim=\"" \
                + str(adkim) + "\", published_aspf=\"" + str(aspf) + "\", published_p=\"" + str(p) \
                + "\", published_sp=\"" + str(sp) + "\", published_pct=\"" + str(pct) + "\", fo=\"" \
                + str(fo) + "\""
            elif output == "json":
                report_defaultdata["feedback"]["policy_published"]["domain"] = str(domain).lower()
                report_defaultdata["feedback"]["policy_published"]["adkim"] = str(adkim).lower()
                report_defaultdata["feedback"]["policy_published"]["aspf"] = str(aspf).lower()
                report_defaultdata["feedback"]["policy_published"]["p"] = str(p).lower()
                report_defaultdata["feedback"]["policy_published"]["sp"] = str(sp).lower()
                report_defaultdata["feedback"]["policy_published"]["pct"] = str(pct).lower()
                report_defaultdata["feedback"]["policy_published"]["fo"] = str(fo).lower()
                
        # Clear the info from memory.    
        metainfo.clear()

    # Go through the xml_file and look voor the <record> elements (this element can occur a lot of times)
    recordtree = etree.iterparse(str(xml_file), events=('end',), tag='record')
  
    for event, recordinfo in recordtree:
        if output == "kv":
            # make sure the report_recorddata variable is empty
            report_recorddata = ""
        elif output == "json":
            report_recorddata = report_defaultdata
    
        # Get all the available options and set a default value if not present
        source_ip = recordinfo.findtext('row/source_ip', default="not_set")
        count = recordinfo.findtext('row/count', default=0)
        disposition = recordinfo.findtext('row/policy_evaluated/disposition', default="none")
        dkim = recordinfo.findtext('row/policy_evaluated/dkim', default="not_set")
        spf = recordinfo.findtext('row/policy_evaluated/spf', default="not_set")
        header_from = recordinfo.findtext('identifiers/header_from', default="not_set")
        envelope_to = recordinfo.findtext('identifiers/envelope_to', default="not_set")
        envelope_from = recordinfo.findtext('identifiers/envelope_from', default="not_set")
        
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

            output = run("nslookup -q=a " + str(source_ip), resolve_timeout)
            
            if str(output[0]) == "0":
                # The below regex searches for the PTR and can handle both Windows and Linux returns
                search = re.search("(?:n|N)ame\s*(?:\=|\:)\s*([^\s]*)", output[2])

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
        
        if output == "kv":
            # put all the fields that can only occur one time in the <record> element
            report_recorddata += "source_ip=\"" + str(source_ip) + ", source_hostname=\"" + str(hostname) \
            + "\"" + "\", count=\"" + str(count) + "\", evaluated_disposition=\"" + str(disposition) \
            + "\", evaluated_dkim=\"" + str(dkim) + "\", evaluated_spf=\"" + str(spf) +  "\", header_from=\"" + str(header_from) \
            + "\", envelope_from=\"" + str(envelope_from) + "\", envelope_to=\"" + str(envelope_to) + "\""
        
            # make everything lowercase 
            report_recorddata = report_recorddata.lower()
        elif output == "json":
            report_recorddata["feedback"]["record"]["row"]["source_ip"] = str(source_ip).lower()
            report_recorddata["feedback"]["record"]["row"]["source_hostname"] = str(hostname).lower()
            report_recorddata["feedback"]["record"]["row"]["count"] = str(count).lower()
            report_recorddata["feedback"]["record"]["row"]["policy_evaluated"]["disposition"] = str(disposition).lower()
            report_recorddata["feedback"]["record"]["row"]["policy_evaluated"]["dkim"] = str(dkim).lower()
            report_recorddata["feedback"]["record"]["row"]["policy_evaluated"]["spf"] = str(spf).lower()
            report_recorddata["feedback"]["record"]["identifiers"]["header_from"] = str(header_from).lower()
            report_recorddata["feedback"]["record"]["identifiers"]["envelope_to"] = str(envelope_to).lower()
            report_recorddata["feedback"]["record"]["identifiers"]["envelope_from"] = str(envelope_from).lower()
            
        # set some variables before going to 3 elements that can occur more than one time in the 
        # <record> element
        dkim_count = spf_count = reason_count = 1
        dkim_data = spf_data = reason_data = ""
    
        for reason_results in recordinfo.findall('row/policy_evaluated/reason'):
            # The first element that can occur more than once but at the same time can also not occur at
            # all is the <reason> element within the <policy_evaluated> element
            reason_type = reason_results.findtext('type', default="not_set")
            reason_comment = reason_results.findtext('comment', default="not_set")
      
            if output == "kv":
                # put all the found reasons together in the reason_data variable, use the reason_count 
                # variable to later match the reason_type with the reason_comment
                reason_data += "evaluated_reason_type_" + str(reason_count) + "=\"" + str(reason_type) \
                + "\", evaluated_reason_comment_" + str(reason_count) + "=\"" + str(reason_comment) + "\", "
            elif output == "json":
                report_recorddata["feedback"]["record"]["row"]["policy_evaluated"]["reason"]["type"] = str(reason_type)
                report_recorddata["feedback"]["record"]["row"]["policy_evaluated"]["reason"]["comment"] = str(reason_comment)
                
            reason_count += 1
    
        for dkim_result in recordinfo.findall('auth_results/dkim'):
            # The second element that can occur multiple times or not at all is the dkim element
            # Check for all possible elements and set default values if the don't exist
            domain = dkim_result.findtext('domain', default="not_set")
            result = dkim_result.findtext('result', default="not_set")
            selector = dkim_result.findtext('selector', default="not_set")
            human_result = dkim_result.findtext('human_result', default="not_set")
            
            if output == "kv":
                dkim_data += "dkim_domain_" + str(dkim_count) + "=\"" + str(domain) + "\", dkim_result_" \
                + str(dkim_count) + "=\"" + str(result) + "\", dkim_selector_"+ str(dkim_count) + "=\"" \
                + str(selector) + "\", dkim_human_result_" + str(dkim_count) + "=\"" + str(human_result) + "\", "
            elif output == "json":
                report_recorddata["feedback"]["record"]["row"]["auth_results"]["dkim"]["domain"] = str(domain)
                report_recorddata["feedback"]["record"]["row"]["auth_results"]["dkim"]["result"] = str(result)
                report_recorddata["feedback"]["record"]["row"]["auth_results"]["dkim"]["selector"] = str(selector)
                report_recorddata["feedback"]["record"]["row"]["auth_results"]["dkim"]["human_result"] = str(human_result)
                
            dkim_count += 1

        for spf_result in recordinfo.findall('auth_results/spf'):
            # The third and last element that can occur multiple times is the spf element
            domain = spf_result.findtext('domain', default="not_set")
            result = spf_result.findtext('result', default="not_set")
            scope = spf_result.findtext('scope', default="not_set")
        
            if output == "kv":
                spf_data += "spf_domain_" + str(spf_count) + "=\"" + str(domain) + "\", spf_result_" \
                + str(spf_count) + "=\"" + str(result) + "\", spf_scope_"+ str(spf_count) + "=\"" + str(scope) + "\", "
            elif output == "json":
                report_recorddata["feedback"]["record"]["row"]["auth_results"]["spf"]["domain"] =  str(domain)
                report_recorddata["feedback"]["record"]["row"]["auth_results"]["spf"]["result"] = str(result)
                report_recorddata["feedback"]["record"]["row"]["auth_results"]["spf"]["scope"] = str(scope)
                
            spf_count += 1
         
        if output == "kv": 
            # put all the data together in the report_recorddata variable
            # make sure all the dkim and spf data is in all lower case for the splunk stats query's
            report_recorddata += ", " + reason_data + dkim_data.lower() + spf_data.lower()    
    
            # print the result for this <record> element
            result_logger.info(default_data + ", " + report_recorddata)
        elif output == "json":
            jsondata = json.dumps(report_recorddata)
            result_logger.info(jsondata)
                  
        # clear the processed <record> element from memory
        recordinfo.clear()
   
if __name__ == "__main__":
    logger = c_logger.Logger()
    
    sessionKey = sys.stdin.readline().strip()
    splunk_info = si.Splunk_Info(sessionKey)
    
    # Set all the needed directory's based on the directory this script is in.
    script_dir = os.path.dirname(os.path.abspath(__file__))                     # The directory of this script
    splunk_paths = splunk_info.give_splunk_paths(script_dir)
    app_root_dir = splunk_paths['app_root_dir']                                 # The app root directory
    log_root_dir = os.path.normpath(app_root_dir + os.sep + "logs")             # The root directory for the logs
    app_log_dir = os.path.normpath(log_root_dir + os.sep + "dmarc_splunk")      # The directory to store the output for Splunk
    
    log_level = splunk_info.get_config(str(splunk_paths['app_name'].lower()) + ".conf", 'main', 'log_level')
    
    # Get the arguments from the commandline input.
    options = argparse.ArgumentParser(epilog="Example: %(prog)s --file dmarc-xml-file --resolve --logfile outfile.log")
    options.add_argument("--file", help="dmarc file in XML format")
    options.add_argument("--resolve", action="store_true")
    options.add_argument("--logfile", help="the log file to write to")
    options.add_argument("--output", help="the output of the log: kv or json (default)", default="json")
    args = options.parse_args()
  
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

    try:
        with open(dmarc_rua_xml, 'rb') as content_file:
            script_logger.debug("Reading the XML file content.")
            # Read the original file in a string to work with
            xml_content = content_file.read()
    except EnvironmentError:
        script_logger.exception("Cannot open file '" + str(dmarc_rua_xml) + "'\" traceback=")
        exit(0)
    
    try:
        with open(new_dmarc_rua_xml, "wb") as out:
            script_logger.debug("Removing the <xml version> tag and write everything to file '" + str(new_dmarc_rua_xml) + "'")
            # Just in case do a decode of the string
            valid_xmlstring = xml_content.encode('latin1','xmlcharrefreplace').decode('utf8','xmlcharrefreplace')
            # remove the xml version info
            pattern = re.compile (r'(\<\?xml\s+.+?\>)')
            valid_xmlstring = pattern.sub(r' ', valid_xmlstring)
            # write everything back to a xml file on disk
            out.write(valid_xmlstring)
    except EnvironmentError:
        script_logger.exception("Cannot write file '" + str(new_dmarc_rua_xml) + "'\" traceback=")
        exit(0)

    # Get all the info from the report
    script_logger.debug("Start getting the data from the XML")
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