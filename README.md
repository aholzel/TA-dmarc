# TA-dmarc

## WARNING for SA-dmarc users
If you also use the SA-dmarc found on my Github, please note that if you use version 3.5.1 or higher of the TA-dmarc you need to use version 3.6.1 or higher of the SA-dmarc app

## Description
Splunk of for the processing and ingestion of DMARC RUA reports. The app can download email attachments from a mail server via POP3/POP3s/IMAP/IMAPs, you can choose the mailbox folder where the mails are stored. If no connection to the mail server is possible you can manually place the attachments in a directory within the app and they will also be processed.

## Installation
The app needs to be installed on a Splunk Heavy Forwarder

## Configuration

### Setup page
The app contains a setup page to do all the setup. Setup options:
- **Don't download mails** : If no connection to the mail server is possible check the "Don't download mails" option
- **FQDN or IP of the mailserver**
- **Port to connect**
- **Protocol to use** : POP3/POP3S/IMAP/IMAPS
- **Mailbox folder** : Mailbox folder where the mail is stored (default is Inbox)
- **Username** : Mailbox username
- **Password** : Mailbox password (will be stored in the Splunk credential store)
- **Output format for the dmarc log** : kv or json
- **Resolve IP's** : Resolve IP's that are in the XML's to there PTR's (this makes the dashboards faster)
- **Scripts Log Level** : 10=DEBUG, 20=INFO, 30=WARNING, 40=ERROR, 50=CRITICAL

## Content
### Scripts
The app contains a couple of scripts to download and process the DMARC RUA reports, in addition, the Splunk Python SDK is also present to connect to the Spunk instance.  

#### dmarc-convertor.py
This is the main script. This script calls the other 2 scripts to download the reports from the mail server and to convert the XML. After the processing the mail is deleted from the mailbox and the attachments and XML files are deleted from the Splunk server.
The script has 4 stages:
1. Download the mail from the mailbox if needed. (This calls the *mail-client.py* script)
2. Uncompress the files that are in the attachment_dir and store the content in the XML directory. Before this is done there are some checks to make sure the attachment is a normal zip file and that is contains an xml file, and that the decompressed xml is not bigger than 100 MB (this can be changed in the script if needed).
3. Process the XML files that are in the XML directory. (This calls the *dmarc-parser.py* script)
4. Try to remove the files again that failed removal the first time 

#### mail-client.py
Script to download attachments from a mailbox and store it localy on disk. The script is made to download DMARC RUA reports so is specifically looks for mails with a subject that contains: "Report Domain".
The script can handle POP3, POP3 SSL, IMAP and IMAP SSL. It will connect to the mail server and search for emails with a subject that contains "Report Domain", it will download the attachment if that attachment is a .gz, .zip or .gzip file. After the mail has been processed it will be deleted from the mailbox.

#### dmarc-parser.py
Script to process the XML files that where in the attachment. The script will output the content in either key=value or JSON, it can also do DNS lookups for the source IP's that are in the RUA reports. The benefit of doing the DNS lookups is that you have the PTR of the source IP at the time of the arrival of the report, which is also the time the mail was send (give or take a couple of hours). An other benefit is that this will make the dashboards of the SA-dmarc faster because you don't have the resolve the PTR's at dashboard load time.

#### setup_handler.py
Script to handle the setup page.

All the custom python scripts have extensive commentary and explanation about what is done, so if you want to know more about what they do and why, have a look at the scripts themselves.

## Logs
All the above scripts have the ability to log (extensively) you can control the log level via the setup page or directly in the *ta-dmarc.conf* file. All logs (except for the setup log) are written to the *logs/dmarc_splunk* directory