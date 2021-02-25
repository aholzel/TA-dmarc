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
# Description   : Script to parse the DMARC RUA XML files into key=value pairs so it can be
#                 ingested into Splunk. This script pulls all the possible information out of
#                 the XML, it is compatible with RUA version 1.0
#
# Version history
# Date          Version     Author      Type    Description
# 2021-02-19    3.0.0       Arnold      MOD     Changes to make the script python3 compatible
#                                       MOD     Changed the way dns lookups are done, from now on pythonDNS is used
#                                       MOD     Changed the error handling on 'problem' XMLs with a wrong first line.
#                                       DEL     Old change log is now moved to the CHANGELOG.md file in the root
#                                               of the app.
##################################################################

import argparse
import json
import re
import os
import sys
import shutil
import copy

import xml.etree.ElementTree as ET

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

def process_dmarc_xml(xml_file, output='json', resolve=0, resolve_timeout=2):
    # open the provided xml file and read the content into a string.
    try:
        with open(xml_file, 'rb') as content_file:
            script_logger.debug('Reading the XML file content.')
            xml = content_file.read()
    except EnvironmentError:
        script_logger.exception('Cannot open file="{0}" traceback='.format(dmarc_rua_xml))
        exit(0)

    try:
        # try to read the xml file
        root = ET.fromstring(xml)   
    except Exception as exception:
        # some files are not correctly constructed and that will give a exception 
        # if the exception is a parseerror that remove the problem line and try again.
        error = str(type(exception).__name__)
        script_logger.exception('Problem with the xml tree: {0}'.format(error))

        if error == 'ParseError':
            line_number = False
            
            if 'line' in str(exception) and 'column' in str(exception):
                line_regex = re.search(r'line\s+(\d+)', str(exception))
                line_number = int(line_regex.group(1))
                
            del xml
            
            source_file = open(xml_file, 'r')
            s_lines = source_file.readlines()
            source_file.close()
            
            if line_number:
                script_logger.debug('Problem line: {0}'.format(s_lines[line_number-1]))
                del s_lines[line_number-1]

            with open(xml_file, 'w+') as target_file:
                for line in s_lines:
                    target_file.write(line)

            with open(xml_file, 'rb') as content_file:
                script_logger.debug('Reading the XML file content again.')
                xml = content_file.read()
        else:
            try:
                problem_dir     = os.path.normpath(app_log_dir + os.sep + 'problems')
                problem_file    = os.path.basename(xml_file)
                new_problem_file= os.path.normpath(problem_dir + os.sep + problem_file)
                os.rename(xml_file,new_problem_file)
                
                script_logger.warning('The file is moved to the problem directory please review the file to fix the problem')
            except Exception:
                script_logger.exception('Could not move file to the problem directory, please remove the file manually')
            exit(0)
        

    # find the root element of the xml, this should be the feedback element
    try:
        root = ET.fromstring(xml)

        # loop trough the xml and find al the possible items that the xml can have. And store everything
        # in a multidimensional dict. if an item is not found a None value will be set, this will later on be removed
        # this dict will later on either be converted into a json or in key=value pairs.
        
        # find the 'feedback' item of the xml, and all the items directly below that, that can only occur once
        for feedback in root.iter('feedback'):
            report_defaultdata['feedback']['version'] = feedback.findtext('version',None)
            report_defaultdata['feedback']['file_name'] = str(os.path.basename(os.path.normpath(xml_file)))
            
            # find the report_metadata info
            report_defaultdata['feedback']['report_metadata']['org_name'] = feedback.findtext('report_metadata/org_name',None)
            report_defaultdata['feedback']['report_metadata']['email'] = feedback.findtext('report_metadata/email',None)
            report_defaultdata['feedback']['report_metadata']['extra_contact_info'] = feedback.findtext('report_metadata/extra_contact_info',None)
            report_defaultdata['feedback']['report_metadata']['report_id'] = feedback.findtext('report_metadata/report_id',None)
            
            # find the date_range info
            report_defaultdata['feedback']['report_metadata']['date_range']['begin'] = feedback.findtext('report_metadata/date_range/begin',None)
            report_defaultdata['feedback']['report_metadata']['date_range']['end'] = feedback.findtext('report_metadata/date_range/end',None)
            
            # find the policy_published info
            report_defaultdata['feedback']['policy_published']['domain'] = feedback.findtext('policy_published/domain',None)
            report_defaultdata['feedback']['policy_published']['adkim'] = feedback.findtext('policy_published/adkim',None)
            report_defaultdata['feedback']['policy_published']['aspf'] = feedback.findtext('policy_published/aspf',None)
            report_defaultdata['feedback']['policy_published']['p'] = feedback.findtext('policy_published/p',None)
            report_defaultdata['feedback']['policy_published']['sp'] = feedback.findtext('policy_published/sp',None)
            report_defaultdata['feedback']['policy_published']['pct'] = feedback.findtext('policy_published/pct',None)

            # find the record info, this tag can occure multiple times, so loop through all of them
            for record in feedback.iter('record'):
                report_recorddata = copy.deepcopy(report_defaultdata)

                # find the identifiers per record.
                for identifiers in record.findall('identifiers'):
                    report_recorddata['feedback']['record']['identifiers']['header_from'] = identifiers.findtext('header_from',None)
                    report_recorddata['feedback']['record']['identifiers']['envelope_from'] = identifiers.findtext('envelope_from',None)
                    report_recorddata['feedback']['record']['identifiers']['envelope_to'] = identifiers.findtext('envelope_to',None)

                for dkim in record.findall('./auth_results/dkim'):
                    report_recorddata['feedback']['record']['auth_results']['dkim']['domain'] = dkim.findtext('domain',None)
                    report_recorddata['feedback']['record']['auth_results']['dkim']['selector'] = dkim.findtext('selector',None)
                    report_recorddata['feedback']['record']['auth_results']['dkim']['result'] = dkim.findtext('result',None)
                    report_recorddata['feedback']['record']['auth_results']['dkim']['human_result'] = dkim.findtext('human_result',None)

                for spf in record.findall('./auth_results/spf'):
                    report_recorddata['feedback']['record']['auth_results']['spf']['domain'] = spf.findtext('domain',None)
                    report_recorddata['feedback']['record']['auth_results']['spf']['scope'] = spf.findtext('scope',None)
                    report_recorddata['feedback']['record']['auth_results']['spf']['result'] = spf.findtext('result',None)
                
                # a record can have multiple rows, loop through all of them.
                for row in record.iter('row'):
                    
                    source_ip = row.findtext('source_ip',None)
                    
                    if resolve == 1:
                        from dns import resolver,reversename
                        errors              = ''
                        timeout             = float(resolve_timeout)
                        resolver            = resolver.Resolver()
                        resolver.timeout    = timeout
                        resolver.lifetime   = timeout

                        try:
                            addr = reversename.from_address(source_ip)    
                            answer = resolver.resolve(addr, 'PTR') 
                        except Exception as exception:
                            # catch the exeption and give that back (NXDOMAIN/NoAnswer/....)
                            errors = str(type(exception).__name__)
                            script_logger.debug('There was a problems with the dns query for {0}'.format(source_ip))

                            if errors.lower() == 'timeout':
                                try:
                                    addr = reversename.from_address(source_ip)    
                                    answer = resolver.resolve(addr, 'PTR') 
                                except Exception as exception:
                                    # catch the exeption and give that back (NXDOMAIN/NoAnswer/....)
                                    errors = str(type(exception).__name__)
                        
                        if not errors:
                            for rr in answer:
                                hostname = rr
                        else:
                            hostname = errors
                    else:
                        hostname            = '-'
                        
                    report_recorddata['feedback']['record']['row']['source_ip']                             = str(source_ip)
                    report_recorddata['feedback']['record']['row']['source_hostname']                       = str(hostname).lower()
                    report_recorddata['feedback']['record']['row']['count']                                 = row.findtext('count',None)
                    report_recorddata['feedback']['record']['row']['policy_evaluated']['disposition']       = row.findtext('policy_evaluated/disposition',None)
                    report_recorddata['feedback']['record']['row']['policy_evaluated']['dkim']              = row.findtext('policy_evaluated/dkim',None)
                    report_recorddata['feedback']['record']['row']['policy_evaluated']['spf']               = row.findtext('policy_evaluated/spf',None)
                    report_recorddata['feedback']['record']['row']['policy_evaluated']['reason']['type']    = row.findtext('policy_evaluated/reason/type',None)
                    
                # remove the empty values from the dict
                report_recorddata           = del_none(report_recorddata)

                if output == 'json':
                    # create a json from the dict
                    jsondata                = json.dumps(report_recorddata)
                    result_logger.info(jsondata)
                elif output == 'kv':
                    # create a 1 dimensional dict from with the keys and values from the multidimensional dict. 
                    kvdata                  = get_kv_dict(report_recorddata)
                    kv                      = ''
                    for k,v in kvdata.items():
                        kv                  = kv + k + '="' + v + '", '
                        
                    kv                      = kv.strip(' ,')
                    result_logger.info(kv)
    except Exception:
        script_logger.exception('A exception occured with file="{0}", traceback='.format(xml_file))
        try:
            problem_dir     = os.path.normpath(app_log_dir + os.sep + 'problems')
            problem_file    = os.path.basename(xml_file)
            new_problem_file= os.path.normpath(problem_dir + os.sep + problem_file)
            os.rename(xml_file,new_problem_file)
            
            script_logger.warning('The file is moved to the problem directory please review the file to fix the problem')
        except Exception:
            script_logger.exception('Could not move file to the problem directory, please remove the file manually')
        exit(0)
   
if __name__ == '__main__':
    logger = c_logger.Logger()
    
    # Get the arguments from the commandline input.
    options                 = argparse.ArgumentParser(epilog='Example: %(prog)s --file dmarc-xml-file --resolve --logfile outfile.log')
    options.add_argument('--file', help='dmarc file in XML format')
    options.add_argument('--resolve', action='store_true')
    options.add_argument('--logfile', help='the log file to write to')
    options.add_argument('--output', help='the output of the log: kv or json (default)', default='json')
    options.add_argument('--sessionKey', help='the Splunk sessionKey to use')
    args                    = options.parse_args()
  
    # Splunk sessionKey info
    if args.sessionKey is None:
        sessionKey          = sys.stdin.readline().strip()
    elif len(args.sessionKey) != 0:
       sessionKey           = args.sessionKey
    elif len(args.sessionKey) == 0:
        sessionKey          = sys.stdin.readline().strip()

    splunk_info = si.Splunk_Info(sessionKey)

    # Set all the needed directory's based on the directory this script is in.
    script_dir              = os.path.dirname(os.path.abspath(__file__))                    # The directory of this script
    splunk_paths            = splunk_info.give_splunk_paths(script_dir)
    app_root_dir            = splunk_paths['app_root_dir']                                  # The app root directory
    log_root_dir            = os.path.normpath(app_root_dir + os.sep + 'logs')              # The root directory for the logs
    app_log_dir             = os.path.normpath(log_root_dir + os.sep + 'dmarc_splunk')      # The directory to store the output for Splunk
    problem_dir             = os.path.normpath(app_log_dir + os.sep + 'problems')           # The directory for problem files

    log_level               = splunk_info.get_config(str(splunk_paths['app_name'].lower()) + '.conf', 'main', 'log_level')

    # Get the dmarc RUA file name
    dmarc_rua_xml           = args.file
    
    # set the output mode of the logs (kv or json)
    output                  = args.output
    
    # Set the logfile to report everything in
    script_log_file         = os.path.normpath(app_log_dir + os.sep + 'dmarc_parser.log')
    result_log_file         = args.logfile
    
    script_logger           = logger.logger_setup(name='script_logger', level=log_level)
    result_logger           = logger.logger_setup(name='result_logger', log_file=result_log_file, level=10, format='raw')

    if args.resolve:
        resolve             = 1
    else:
        resolve             = 0

    script_logger.debug('Start processing file="{0}" resolve dns: {1}'.format(dmarc_rua_xml, resolve))
    script_logger.debug('results file: ' + str(result_log_file))
    
    # In theory all files have a extention, but "in the wild" I have seen reports where 
    # all the dots (.) where replaced with spaces ( ) so the files don't have a extention anymore
    if not dmarc_rua_xml.endswith('.xml'):
        # do a very crude check if this is a xml file, read the first line and see if it starts with a < 
        script_logger.warning('file="{0}" doesn\'t have a .xml extention'.format(dmarc_rua_xml))
        
        with open(dmarc_rua_xml) as unknown_file:
            content = unknown_file.read(1)
            if content != '<':
                script_logger.warning('file="{0}" doesn\'t look like a xml file, it will be moved to the problem dir.'.format(dmarc_rua_xml))
                shutil.move(dmarc_rua_xml, problem_dir)
                exit(0)
            else:
                script_logger.info('file="{0}" seems to be a XML file, so continue processing it.'.format(dmarc_rua_xml))
    

    # Get all the info from the report
    script_logger.debug('Start getting the data from file="{0}"'.format(os.path.basename(os.path.normpath(dmarc_rua_xml))))
    process_dmarc_xml(dmarc_rua_xml, output, resolve)
    
    # Remove the original file so we don't process it again the next time the script runs
    try:
        script_logger.debug('Delete file="{0}" now'.format(dmarc_rua_xml))
        os.remove(dmarc_rua_xml)
    except Exception:
        script_logger.exception('Unable to delete file="{0}"'.format(dmarc_rua_xml))