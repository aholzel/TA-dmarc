# CHANGELOG
This file will contain the changes to the script files. The file is split up in two parts, to make it easier to find the latest changes. The top part contains the latest changes per script and in general for the app. The bottom part contains all the changes.

# Latest version:
## General app changes
| Date       | Version | Author  | **[Type]** Description                                                                |
|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
| 2023-04-14 | 5.1.0   | Arnold  | **[ADD]** Proxy support for the o365 script.<br />**[MOD]** Setup page to add proxy config.

## dmarc-parser.py
| Date       | Version | Author  | **[Type]** Description                                                                |
|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
| 2023-03-31 | 3.1.1   | Arnold  | **[FIX]** Typo fix

## ta-dmarc_converter.py
This use to be the `dmarc_converter.py` script.
| Date       | Version | Author  | **[Type]** Description                                                                |
|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
| 2023-03-24 | 5.0.0   | Arnold  | **[ADD]** Support for downloading mails from o365. <br />  **[MOD]** Adapted the script for the new Splunk app layout guidelines. <br />  **[MOD]** Changed script name to comply with the new Splunk app layout guidelines.<br /> **[MOD]** Changed all the logging strings to python3 f-strings to make them more readable.

## mail-client.py
| Date       | Version | Author  | **[Type]** Description                                                                |
|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
| 2023-03-24 | 3.3.0   | Arnold  | **[MOD]** Adapted the script for the new Splunk app layout. <br />  **[MOD]** Made a list for the allowed content types to make it easier to change.<br />  **[MOD]** Changed all the logging strings to python3 f-strings to make them more readable.

## mail-o365.py
| Date       | Version | Author  | **[Type]** Description                                                                |
|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
| 2023-04-14 | 1.2.0   | Arnold  | **[ADD]** Made the script proxy aware

## ta-dmarc_setup.py 
This use to be the `setup_handler.py` script.
| Date       | Version | Author  | **[Type]** Description                                                                |
|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
| 2023-04-14 | 2.1.0   | Arnold  | **[ADD]** Added handeling logic for the proxy fields.

# All changes
## General app changes
| Date       | Version | Author  | **[Type]** Description                                                                |
|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
| -          | 1.0     | Arnold  | initial version
| -          | 1.1     | Arnold  | bug fixes
| 2017-05-17 | 1.2     | Arnold  | Made the mail-client.py script IMAP compatible
| 2017-05-18 | 1.3     | Arnold  | Added the option to not download mail from mailbox but just parse the<br />files in the attach_raw and/or dmarc_xml folder
| 2017-05-29 | 2.0     | Arnold  | Dropped the dmarc-converter.sh script for a .py version to be platform<br />independent. Added a dmarc_mailserver.conf file so that the script <br />file doesn't need to be changed. Place you own config in de local dir.<br />Rewritten the parser script because it missed fields.
| 2017-05-31 | 2.1     | Arnold  | Rewritten the mail-client.py script, this now also logs to a file
| 2017-06-05 | 2.2     | Arnold  | Added the enc_dec.py script to encode/decode a string (password in <br />this case) to eliminate the need for a plaintext password in the conf<br />file. Changed the mail-client.py and dmarc-converter.py script to use<br />the encode/decode functions
| 2017-06-20 | 2.3     | Arnold  | Added option to resolve the source IP's from the xml file to hostnames<br />(PTR) and add them to the logs (beta testing only, disabled for now).
| 2017-06-26 | 2.4     | Arnold  | Changes to the scripts, changed the sourcetype for the script output,<br />added mail client output file in the inputs.conf
| 2017-07-06 | 2.5     | Arnold  | Changes to the mail-parser and dmarc-converter scripts, made POP3S an<br />option.
| 2017-07-12 | 2.6     | Arnold  | Changes to the dmarc-converter script to catch some (Windows) errors
| 2017-07-17 | 2.7     | Arnold  | Changes to the dmarc-converter script to handle the new processing of<br />other scripts beter. <br />Changes to the mail-parser script to fix some bugs
| 2017-08-08 | 2.8     | Arnold  | Changes to the mail-parser script, and the dmarc-converter script
| 2017-11-24 | 3.0     | Arnold  | Changes to the dmarc-converter script, it now finaly also works<br />correct on Windows 2008 R2
| 2017-12-28 | 3.1     | Arnold  | Made a setup page<br />Make use of the custom Splunk_Info class to get Splunk info and write<br />and read the password for the mailbox account. <br />Make use of the custom Logger class to create a log instance and log everything to files.
| 2018-01-12 | 3.2     | Arnold  | Multiple bugfixes in the python scripts
| 2018-05-07 | 3.3     | Arnold  | Multiple changes to the python scripts, most important:<br />Added option to output JSON and resolve IP's at ingestion time<br />Added the new options to the setup page.<br />
| 2018-05-31 | 3.4     | Arnold  | mail-client.py : Added the download option for .gzip files <br />dmarc-converter.py : Added support for .gzip files also created some<br />additional checks on the file mime type to make sure everything is <br />done to process a file before it is ignored.
| 2019-03-25 | 3.5.1   | Arnold  | dmarc-parser.py : rewriten a big part of the script to convert the XMLs to json/kv.<br />dmarc-converter.py : added the sessionKey option.<br />email-client.py : made a list of allowed subjects, and check to see if there is a sender.<br />**NOTE:** If you also use my SA-dmarc you need to upgrade that to 3.6.1<br />or higher because of the new json layout.
| 2019-08-29 | 3.5.2   | Arnold  | Bug fixes in the dmarc-parser.py file 
| 2019-11-21 | 3.6.0   | Arnold  | Changes to the dmarc-converter.py script
| 2019-11-21 | 3.6.1   | Arnold  | Fixed typo in function name in the Splunk_Info class.
| 2020-01-09 | 3.6.2   | Arnold  | Fixed some typo's in the python scripts.
| 2020-01-15 | 3.6.3   | Arnold  | Fixed problem in the dmarc-converter.py script
| 2020-08-28 | 3.7.0   | Arnold  | Changes to the dmarc-converter.py and dmarc-parser.py scripts
| 2021-02-25 | 4.0.0   | Arnold  | **[FIX]** Made all scripts python3<br /> **[MOD]** Updated the Splunk SDK<br />
| 2021-10-14 | 4.0.1   | Arnold  | **[FIX]** mail-client.py referenced before assignment error<br />**[ADD]** Subject for Microsoft DMARC reports<br />**[FIX]** dmarc-parcer.py Typo in log message<br />
| 2022-10-06 | 4.0.2   | Arnold  | **[FIX]** mail-client.py mail subject decoding <br />**[ADD]** `__version__` in all scripts
| 2022-10-18 | 4.1.0   | Arnold  | **[FIX]** mail-client.py for to many emails in IMAP mailbox
| 2023-03-25 | 5.0.0   | Arnold  | **[NEW]** Support for MS GRAPH API, to support Microsoft O365. <br />  **[MOD]** Changes to comply with the new Splunk app layout guidelines.<br />  **[MOD]** Setup page and setup script to support the o365 fields
| 2023-03-31 | 5.0.1   | Arnold  | **[FIX]** Minor typo fix in the `dmarc-parser.py`
| 2023-04-04 | 5.0.2   | Arnold  | **[FIX]** Put the `lib` dir back that because of .gitignore didn't made it in the previous version.
| 2023-04-05 | 5.0.3   | Arnold  | **[MOD]** Added `[trigger]` stanza to `app.conf` to prevent unnecessary restart after install

## dmarc-parser.py
| Date       | Version | Author  | **[Type]** Description                                                                |
|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
| 2017-05-27 | 1.0     | Arnold  | Initial version
| 2017-05-31 | 1.1     | Arnold  | Changes some parts of the main() function to deal with xml files that have set <br />the encoding to windows-1252 because lxml doesn't like that. Also made this script <br />responsable for the removal of the xml files that it processes (and creates for the decoding) 
| 2017-06-06 | 1.2     | Arnold  | Forced lowercase on parts of the output, so the Splunk stats results will work <br />correct in the SA-dmarc dashboards.<br />Minor bugfixes        
| 2017-06-07 | 1.3     | Arnold  | More bugfixes, removed some unneeded code, cleaned up the code
| 2017-06-20 | 1.4     | Arnold  | Added option to resolve ip's to hostnames and add these to the logs. <br />(Beta testing only, and disabled for now)
| 2017-12-04 | 1.5     | Arnold  | Removed the custom log function and rownumber function, and replaced it with the <br />default Python logging function. This makes it also possible to log the exception <br />info to the logfile. Only downside is that the VERBOSE option is now removed and <br /> all those messagesare now on DEBUG level.
| 2017-12-28 | 1.6     | Arnold  | Rewritten and removed parts to make use of the (external) Splunk_Info and Logger <br />classes. Changed the regex to remove the `<?xml ....>` part of the xml because <br />sometimes the removal didn't went as expected, made the regex simpler and it <br />now works as expected.
| 2018-03-02 | 1.7     | Arnold  | "fixed" the timeout problem with nslookup so this can now be used, default timeout <br />is now 2 secondes if within that time there is no response from the nslookup <br />subprocess the process will be killed and an NXDOMAIN will be assumed.
| 2018-04-01 | 1.8     | Arnold  | Made it possible to set the output to JSON.
| 2019-03-25 | 2.0     | Arnold  | Rewritten the 'process_dmarc_xml' function entirely, to make it more clear what is <br />done and how. Now using xml.etree instead of lxml.etree module xml.etree is less picky <br />about the encoding, so less manipulation is needed before processing. This reduced the <br />script with almost 100 lines.<br />**NOTE:** If you also use the SA-dmarc app please <br />upgrade that app to 3.6.1 or higher for the correct field extracts.
| 2019-08-29 | 2.1     | Arnold  | **[FIX]** DKIM result was always "not_set", because that field was overwritten (set to NONE) by <br />the human_result field.<br />**[ADD]** Files that cannot be processed due to format errors are now <br />also moved to the problem dir
| 2020-08-28 | 2.2.0   | Arnold  | **[FIX]** Changed the way how report_recorddata is getting filled by report_defaultdata 
| 2021-02-19 | 3.0.0   | Arnold  | **[MOD]** Changed everything to Python3 <br />**[MOD]** Changed the way dns lookups are done, from now on pythonDNS is used<br />**[MOD]** Changed the error handling on 'problem' XMLs with a wrong first line.<br />
| 2021-10-14 | 3.0.1   | Arnold  | **[FIX]** dmarc-parcer.py Typo in log message<br />
| 2023-03-24 | 3.1.1   | Arnold  | **[MOD]** Adapted the script for the new Splunk app layout. <br /> **[MOD]** Changed all the logging strings to python3 f-strings to make them more readable.

## dmarc-converter.py
| Date       | Version | Author  | **[Type]** Description                                                                |
|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
| 2017-05-29 | 1.0     | Arnold  | Initial version
| 2017-05-29 | 1.1     | Arnold  | Made it possible to roll over logfiles
| 2017-05-31 | 1.2     | Arnold  | Removed a print development statement Moved the removal of the XML files to the dmarc-parcer.py <br /> script.
| 2017-06-01 | 1.3     | Arnold  | Added check to see if there realy is a XML file inside the attachment this to (somewhat) protect <br />agains malware mails/attachments
| 2017-06-05 | 1.4     | Arnold  | Added the obfuscation/de-obfuscation of the mail account password If the password is comming <br />from the .conf file from the default dir it is assumed to be in plaintext, is is obfustated, writen to <br />the .conf file in the local dir and the row from the default conf file is removed.
| 2017-06-07 | 1.5     | Arnold  | Bugfixes
| 2017-06-20 | 1.6     | Arnold  | Added option to resolve ip's to hostnames (BETA testing only)
| 2017-06-26 | 1.7     | Arnold  | Added function to write line numbers to log files to make trouble shouting easier.<br />Fixed problem with gz files that have complete paths in it, in combination with Windows <br />Other minor changes
| 2017-06-29 | 1.8     | Arnold  | Fixed issue with os.system calls on installations where de Splunk installation path has a space <br />in it. (C:\Program Files\Splunk\...)
| 2017-07-10 | 1.9     | Arnold  | Bugfixes
| 2017-07-17 | 2.0     | Arnold  | Fixed problem where due to the change from os.system to subprocess.Popen the returncode didn't <br />return correct (was never 0 even if everything was ok)
| 2017-08-04 | 2.1     | Arnold  | Bugfix in gzip open.
| 2017-08-05 | 2.2     | Arnold  | Remove the placeholder file in the problem dir
| 2017-11-24 | 2.3     | Arnold  | Added a try - except for the removal of the attachment so if the removal fails the script continues<br />Added a step 4 to re-try to remove the files in the attachment dir that failed removal the first time.
| 2017-11-29 | 2.4     | Arnold  | Removed the custom log function and rownumber function, and replaced it with the default Python <br />logging function. This makes it also possible to log the exception info to the logfile. Only downside is <br />that the VERBOSE option is now removed and all those messages are now on DEBUG level.
| 2017-12-01 | 2.5     | Arnold  | Minor bugfixes<br />Added code to try to move files that can not be deleted to the problem directory
| 2017-12-28 | 2.6     | Arnold  | Rewritten and removed parts to make use of the (external) Splunk_Info and Logger classes.<br />The password is not in the config file anymore but in the Splunk password store, so get it from there<br />The custom config file has a new name, adjusted script to this.<br />Removed method to get the config and use the one in the Splunk_Info class
| 2018-01-12 | 2.7     | Arnold  | Added the sessionKey for the mail-client script.
| 2018-03-02 | 2.8     | Arnold  | "Fixed" the timeout problems with nslookup, so the resolve_ips option is now available and honored. <br />Included an max file size check to prevent the opening of zip bombs.
| 2018-03-29 | 2.9     | Arnold  | Added support for .gzip files also created some additional checks on the file mime type to make <br />sure everything is done to process a file before it is ignored.
| 2019-03-25 | 3.0     | Arnold  | Added the sessionKey parameter for this script and to pass is to the dmarc-parcer script.
| 2019-11-21 | 3.1     | Arnold  | **[DEL]** Migration code blocks<br />**[ADD]** Extra step (new step 3) to check the content of the XML to make sure there is only one <br />reportin there. If there is more than one report in the XML, split it into multiple reports
| 2019-12-13 | 3.2.0   | Arnold  | **[FIX]** Fixed some bugs in the check if there are multiple reports in the XML<br />**[ADD]** Added additional check to see if there are multiple reports in the XML<br />**[FIX]** Fixed some typos
| 2020-01-15 | 3.2.1   | Arnold  | **[FIX]** Problems in the size check loop that made the script crash.
| 2020-08-28 | 3.3.0   | Arnold  | **[FIX]** Fixed a bug that made the script crash if there was a directory in the <br />dmarc_xml dir for example a "__MACOSX" dir <br />**[DEL]** Variable from the old code/migration
| 2021-02-19 | 4.0.0   | Arnold  | **[MOD]** Changes in the way the size of a uncompressed file is checked.<br />**[MOD]** Changed everything to Python3 <br />**[DEL]** Old change log is now moved to the CHANGELOG.md file in the root of the app.

## mail-client.py
| Date       | Version | Author  | **[Type]** Description                                                                |
|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
| 2017-05-31 | 1.0     | Arnold  | Initial version 
| 2017-06-01 | 1.1     | Arnold  | Added POP3 support
| 2017-06-05 | 1.2     | Arnold  | Added the obfuscation/de-obfuscation of the mail account password.<br />Removed the Write_to_log function and import it from the dmarc_converter.py script
| 2017-06-07 | 1.3     | Arnold  | Bug fixes, moved the Write_to_log function back in because import <br />didn't always work
| 2017-06-26 | 1.4     | Arnold  | Added function to write line numbers to log files to make trouble <br />shooting easier
| 2017-07-06 | 1.5     | Arnold  | Made the option to use POP3 secure.<br />Made the POP3 function similar to the IMAP function and made more <br />logging availableSmall bugfixes
| 2017-07-10 | 1.6     | Arnold  | Bugfixes 
| 2017-07-17 | 1.7     | Arnold  | Bugfix in the imap mail function, the search did't return the correct<br />mails in all cases.<br />Bugfix in the pop3 mail function, the connection wasn't closed correct so mails were not deleted.<br />Changed the pop3 mail search, subject doesn't need to start with <br />"Report Domain" anymore it just needs to contain in, so forwarded <br />messages are also picked up.
| 2017-08-08 | 1.8     | Arnold  | Redirected the stdout to a variable to catch the POP3 debug info.<br />Changed some options in the opening of files because in Windows <br />it resulted in errors<br />Added code to prevent the creation of .pyc file
| 2017-11-23 | 1.9     | Arnold  | Minor bug fix
| 2017-11-29 | 2.0     | Arnold  | Removed the custom log function and rownumber function, and replaced<br />it with the default Python logging function. This makes it also possible<br />to log the exception info to the logfile. Only downside is that the <br />VERBOSE option is now removed and all those messages are now on DEBUG level.
| 2017-12-04 | 2.1     | Arnold  | Bug fix in IMAP function.
| 2017-12-08 | 2.2     | Arnold  | Typo correction<br />Changed the subject checking to check in lowercase.
| 2017-12-28 | 2.3     | Arnold  | Rewritten and removed parts to make use of the (external) Splunk_Info<br />and Logger classes.<br />The password is not in the config file anymore but in the Splunk <br />password store, so get it from there<br />The custom config file has a new name, adjusted script to this.
| 2018-01-12 | 2.4     | Arnold  | Replaced and removed some parts of the code of fix some problems.<br />Added --sessionKey option to pass the sessionKey via the cli<br />Fixed a bug that deleted non dmarc related emails in POP3(s) setup.
| 2018-05-31 | 2.5     | Arnold  | Added .gzip files to the allowed attachements to download, <br />because despite the RFC specs this is also used.
| 2019-03-25 | 2.6     | Arnold  | Made a list with the allowed mail subjects because dispite the RFC <br />there is a large variety of subjects used.<br />Made a check to see if there is a actual sender.
| 2019-11-21 | 2.6.1   | Arnold  | **[FIX]** Type in the get_credentials name
| 2021-02-25 | 3.0.0   | Arnold  | **[MOD]** Changed everything to Python3 <br />**[DEL]** Old change log is now moved to the CHANGELOG.md file in the root of the app.<br />**[MOD]** Quote use consistancy, log format consistancy
| 2021-10-14 | 3.0.1   | Arnold  | **[FIX]**  referenced before assignment error<br />**[ADD]** Microsoft is sending DMARC report (finally!) with a different subject... added this to the allowed subject list<br />
| 2022-10-06 | 3.1.0   | Arnold  | **[FIX]**  The mail subject is now always decoded before furter processing.<br />
| 2022-10-18 | 3.2.0   | Arnold  | **[FIX]**  Fixed problem where there where to many emails in a IMAP mailbox to fetch in 1 run.

## mail-o365.py
| Date       | Version | Author  | **[Type]** Description                                                                |
|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
| 2023-03-24 | 1.0.0   | Arnold  | **[NEW]** initial version
| 2023-04-04 | 1.1.0   | Arnold  | **[FIX]** Not all folders where reviewed when checking if a folder already existed

## ta-dmarc_setup.py 
This use to be the `setup_handler.py` script.
| Date       | Version | Author  | **[Type]** Description                                                                |
|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
| 2017-05-17 | 1.0.0   | Arnold  | initial version
| 2017-12-14 | 1.1.0   | Arnold  | Added comments to make clear what is done where (and why)<br />Added this change log<br />Added logging to the app log file.
| 2017-12-15 | 1.2.0   | Arnold  | Changed all the path variables so that is doesn't matter where this script is placed<br />directly in the /bin dir or in /bin/other/dir 
| 2017-12-28 | 1.3.0   | Arnold  | Made changes to the custom config file name to make it the same as the app name
| 2018-05-07 | 1.4.0   | Arnold  | Added the output and resolve_ips options<br />Replaced hard reference to the app name in the connection string to the "app_name" variable
| 2023-03-24 | 2.0.0   | Arnold  | **[ADD]** Added the o365 fields to the setup page<br />  **[MOD]** Removed the last hardcoded name of the app, the app name is now fully based on the directory name.