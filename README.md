Google_Workspace_Email_Archiving - Rev 1.0 Sep, 7, 2025

A code built to archive Email & Google Drive Data for different email accounts in a Google Workspace tenant. No Google Vault needed. This code runs on Python.



+++++++++++++++++++++++++++++++++++++++ INSTRUCTIONS ++++++++++++++++++++++++++++++++++++++++

Pre-requisites:

-  Google Workspace Super Admin access 
-  Google Cloud Project access
- A google sheet template with four headers - Email | Department Name | Status | Log
- A Google shared drive to upload the Email & Drive Data

Main (Python.py):

1. Ensure you have created a new Google Project, you can name it as Google Workspace Email Archiving. You can then create a service account with domain wide delegation access, for this part you need to also be a super admin in the google workspace account you are planning to archive email data from. The super admin account should have been delegated access to required Google Workspace APIs, Sheets, Drive, Admin SDK.
2. Create a new google spreadsheet within the same organization with the headers mentioned above in the pre-requisites.
3. Create a repository Google Shared Drive for archiving the email data. You can delegate the earlier created service account with full access to the shared drive.
4. Add an admin workspace user account if you wish to do impersonation of individual email IDs, otherwise the script will be adding the target users email ID as a collaborator of the Google shared drive during archiving. Once archiving of an email ID is completed the script will also revoke the access of the target users email ID.
5. Ensure the archive.py and the email.json file is in the same location and execute the code.

Edit the archive.py fields linked in this project:

- SERVICE_ACCOUNT_FILE = 'sample.json' (this should be the service account JSON file which was created in the Google Project)
- SPREADSHEET_ID = '1NCJUz7WyRJKWCIJejeIEolz'  (this will be the spreadsheet which you are using as a sample for adding the email IDs which will be archived).
- SHEET_NAME = 'Archive' (Sheet name in the Google spreadsheet)
- SHARED_DRIVE_ID = '0AFHixIq4EWE2' (The Google Shared Drive ID which will be used to archive the data from your organization)
- ADMIN_USER_EMAIL = 'email.archiver@example.com' # Admin user to impersonate for user/group management, need to change this


Verify the uploaded data (Compare_mbox.py):

- Run the script with the uploaded file of the email archive in comparison to a google takeout download if you have any doubts whether some details were missed.

Final notes:

- This script will start by reading the google sheet which contains the list of email IDs you wish to archive.
- The script will then start by downloading the email messages directly from the target account to your local system/server
- Then the script will complete the download of the emails bundled in a .mbox format (which you can later open in Outlook/Thunderbird or some other mail importint service) and continue to move the Google Drive content in the target email IDs "My Drive" to the target destination Shared Drive. Having the content moved from the source to the target ensures that any delegated permissions to the owners files remains intact.
- Once the mbox and drive processes are complete the script will then upload the mbox file to the shared drive location and post the result in the Google spreadsheet ID you provided earlier.
- After the upload is completed you can verify the data consistency between Google takeout and the python script downloaded version.
- This script works on batch processing mode to avoid hitting the free API hourly/daily limit while archiving via a free Google Cloud platform service account.
- The data cache while this program is running for large email inboxes (ex. above 20GB) does not store in memory and will instead write to disk first. You can run multiple instance of the code safely, renaming the google sheet name referenced in each script FIRST!
- In case of any failed email messages, there is an automatic retry built-into the code. Do not stop the code during run as the retry rate can go up to about 3 times if failed.
- You can see the error/success details and time taken stored in a separately created log file per individual email ID & in a separate summary email ID. The same will be updated in the google spreadsheet which is used for the target email list.
- The script will create a separate folder for the department mentioned for each indvidiual, if none exist already. In case there is no department mentioned, the script will add the email IDs to a separate Google Shared drive folder for departmentless members.


Thanks for checking out this script. If you have any feedback please do share. 


