# --- Imports ---
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from googleapiclient.errors import HttpError
import os
import io
import sys
import zipfile
import base64
import shutil
from email import message_from_bytes
from email.utils import parsedate_to_datetime, formatdate
from datetime import datetime, timezone
import re
import json
import time
import traceback
import random

# ==============================================================================
# ---  Configuration ---
# ==============================================================================
SERVICE_ACCOUNT_FILE = 'sample.json' 
SPREADSHEET_ID = ''1NCJUz7WyRJKWCIJejeIEolz'
SHEET_NAME = 'Archive'
SHARED_DRIVE_ID = '0AFHixIq4UPtUUk9PVA'

# NEW: Name of the top-level folder under SHARED_DRIVE_ID that must exist.
ARCHIVED_DATA_ROOT_FOLDER_NAME = "Archived Data"

# Admin SDK Configuration
ADMIN_USER_EMAIL = 'email.archiver@example.com' # Admin user to impersonate for user/group management, need to change this

DRY_RUN = False
DETAILED_CONSOLE_LOGGING = True

TEMPORARY_ROLE = 'writer'
PERMISSION_PROPAGATION_DELAY = 15
USER_ACTIVATION_DELAY = 20
GROUP_MEMBERSHIP_DELAY = 20
COPY_API_DELAY = 0.3
DRIVE_COPY_MAX_RETRIES = 3
DRIVE_COPY_RETRY_BASE_DELAY = 2

DRY_RUN_PERMISSIONS = DRY_RUN
DRY_RUN_ADMIN_OPS = DRY_RUN
DRY_RUN_UPLOAD = DRY_RUN
DRY_RUN_COPY = DRY_RUN
DRY_RUN_FOLDER_CREATION = DRY_RUN

MBOX_FILE_SUFFIX = ".mbox"
ZIP_FILE_SUFFIX = "_archive.zip" # This zip will now only contain MBOX
LOGS_SUBFOLDER_NAME = "Logs" # Subfolder for individual log files
MYDRIVE_COPY_SUBFOLDER_NAME = "MyDrive_Content_Backup"
LOG_FILE_ENCODING = 'utf-8'
TEMP_PROCESSING_DIR_BASE = "./temp_user_processing"
# ==============================================================================
# --- Combined Scopes ---
# ==============================================================================
SCOPES = [
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/spreadsheets',
    'https://mail.google.com/',
    'https://www.googleapis.com/auth/admin.directory.user',
    'https://www.googleapis.com/auth/admin.directory.group.member'
]
# ==============================================================================
# --- Constants ---
# ==============================================================================
FOLDER_MIME_TYPE = 'application/vnd.google-apps.folder'
SHORTCUT_MIME_TYPE = 'application/vnd.google-apps.shortcut'
SITE_MIME_TYPE = 'application/vnd.google-apps.site'
MAX_CELL_LENGTH = 50000
# ==============================================================================
# --- Global Variables ---
# ==============================================================================
credentials_sa = None; sa_email_address = "Service Account (Unknown)"
drive_service_sa = None; sheets_service = None; admin_service_global = None
rowcol_to_a1 = None; original_stdout = sys.stdout; original_stderr = sys.stderr
detailed_log_file_handler = None; summary_log_file_handler = None; current_run_id = None
# ==============================================================================
# --- Logging Setup ---
# ==============================================================================
class Tee(object):
    def __init__(self, *files): self.files = files
    def write(self, obj):
        for f_idx, f_obj in enumerate(self.files):
            try: f_obj.write(obj); f_obj.flush()
            except Exception as e:
                if f_obj is not original_stdout and f_obj is not original_stderr: original_stdout.write(f"Tee write error to file {f_idx}: {e}\n")
    def flush(self):
        for f_obj in self.files:
            try: f_obj.flush()
            except Exception as e:
                 if f_obj is not original_stdout and f_obj is not original_stderr: original_stdout.write(f"Tee flush error: {e}\n")

def setup_user_logging(user_email_sanitized, temp_user_dir):
    global detailed_log_file_handler, summary_log_file_handler, original_stdout, original_stderr, current_run_id
    current_run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = os.path.join(temp_user_dir, "Logs"); os.makedirs(log_dir, exist_ok=True) # Logs subfolder in temp
    detailed_log_path = os.path.join(log_dir, f"{user_email_sanitized}_{current_run_id}_detailed.log")
    summary_log_path = os.path.join(log_dir, f"{user_email_sanitized}_{current_run_id}_summary.log")
    try:
        detailed_log_file_handler = open(detailed_log_path, 'w', encoding=LOG_FILE_ENCODING, buffering=1)
        summary_log_file_handler = open(summary_log_path, 'w', encoding=LOG_FILE_ENCODING, buffering=1)
        if DETAILED_CONSOLE_LOGGING: sys.stdout = Tee(original_stdout, detailed_log_file_handler)
        else: sys.stdout = Tee(detailed_log_file_handler)
        sys.stderr = Tee(original_stderr, detailed_log_file_handler)
        print(f"--- LOGGING INITIALIZED for {user_email_sanitized} (Run ID: {current_run_id}) ---")
        print(f"Detailed log: {detailed_log_path}"); print(f"Summary log: {summary_log_path}")
        log_summary(f"--- SUMMARY LOG for {user_email_sanitized} (Run ID: {current_run_id}) ---")
        return detailed_log_path, summary_log_path
    except Exception as e:
        original_stdout.write(f"FATAL: Could not set up logging for {user_email_sanitized}: {e}\n"); traceback.print_exc(file=original_stderr)
        sys.stdout = original_stdout; sys.stderr = original_stderr; return None, None

def log_summary(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S"); full_message = f"[{timestamp}] {message}"
    if summary_log_file_handler:
        try: summary_log_file_handler.write(full_message + "\n"); summary_log_file_handler.flush()
        except Exception as e: original_stdout.write(f"Error writing to summary log: {e}\n")
    print(f"SUMMARY: {message}") # Keep console output for summary for visibility

def close_user_logging():
    global detailed_log_file_handler, summary_log_file_handler, original_stdout, original_stderr, current_run_id

    if summary_log_file_handler:
        log_summary("--- End of User Processing Log Session ---") 

    if sys.stdout is not original_stdout and hasattr(sys.stdout, 'flush'):
        sys.stdout.flush()
    if sys.stderr is not original_stderr and hasattr(sys.stderr, 'flush'):
        sys.stderr.flush()

    sys.stdout = original_stdout
    sys.stderr = original_stderr

    if detailed_log_file_handler:
        try:
            detailed_log_file_handler.flush()
            detailed_log_file_handler.close()
        except Exception as e:
            original_stdout.write(f"Error closing detailed_log_file_handler: {e}\n")
    detailed_log_file_handler = None 

    if summary_log_file_handler:
        try:
            summary_log_file_handler.flush()
            summary_log_file_handler.close()
        except Exception as e:
            original_stdout.write(f"Error closing summary_log_file_handler: {e}\n")
    summary_log_file_handler = None 
    
    current_run_id = None
# ==============================================================================
# --- Initial Authentication & Service Building ---
# ==============================================================================
try:
    original_stdout.write("Authenticating Service Account...\n")
    credentials_sa = Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
    sa_email_address = credentials_sa.service_account_email
    original_stdout.write(f"Service Account Email: {sa_email_address}\n")
    original_stdout.write("Building base services (Sheets, Drive SA, Admin SDK)...\n")
    sheets_service = build('sheets', 'v4', credentials=credentials_sa, cache_discovery=False)
    drive_service_sa = build('drive', 'v3', credentials=credentials_sa, cache_discovery=False)
    if ADMIN_USER_EMAIL and ADMIN_USER_EMAIL != 'x' and ADMIN_USER_EMAIL.strip() != '':
        try:
            admin_creds = credentials_sa.with_subject(ADMIN_USER_EMAIL)
            admin_service_global = build('admin', 'directory_v1', credentials=admin_creds, cache_discovery=False)
            original_stdout.write(f"Successfully built Admin SDK service impersonating {ADMIN_USER_EMAIL}.\n")
        except Exception as e:
            original_stdout.write(f"WARNING: Failed to build Admin SDK service: {e}\nAdmin ops might fail.\n"); admin_service_global = None
    else:
        original_stdout.write("Admin SDK service not built (ADMIN_USER_EMAIL not configured or is placeholder 'x').\n")
        admin_service_global = None
    try:
        from gspread.utils import rowcol_to_a1
    except ImportError:
        original_stdout.write("WARNING: gspread.utils.rowcol_to_a1 not found. Using fallback.\n")
        def rowcol_to_a1_fallback(row, col):
            if col <= 0: return f"InvalidCol{col}Row{row}"
            col_str = "";
            while col > 0: col, rem = divmod(col - 1, 26); col_str = chr(65 + rem) + col_str
            return f"{col_str}{row}"
        rowcol_to_a1 = rowcol_to_a1_fallback
    original_stdout.write(f"Successfully authenticated Service Account ({sa_email_address}).\n")
except Exception as auth_err:
    original_stdout.write(f"FATAL ERROR: Could not authenticate or build base services: {auth_err}\n"); traceback.print_exc(file=original_stderr); exit(1)
# ==============================================================================
# --- Helper Functions ---
# ==============================================================================
def build_drive_service_impersonated(impersonate_email):
    if not impersonate_email: print("  ERROR: Impersonation email not provided."); return None, "N/A"
    try: creds = Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES).with_subject(impersonate_email); service = build('drive', 'v3', credentials=creds, cache_discovery=False); return service, impersonate_email
    except Exception as e: print(f"  FATAL ERROR building Drive service (impersonating {impersonate_email}): {e}"); traceback.print_exc(); return None, impersonate_email

def build_gmail_service(impersonate_email):
    if not impersonate_email: print("  ERROR: Impersonation email not provided."); return None
    try: creds = Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES).with_subject(impersonate_email); service = build('gmail', 'v1', credentials=creds, cache_discovery=False); return service
    except Exception as e: print(f"  FATAL ERROR building Gmail service for {impersonate_email}: {e}"); traceback.print_exc(); return None

def get_user_status(admin_service, user_email):
    if not admin_service:
        print(f"  Skipping user status check for {user_email}: Admin service not available.")
        return None
    print(f"  Checking status for user: {user_email}...")
    try:
        user_data = admin_service.users().get(userKey=user_email, fields="suspended").execute()
        suspended = user_data.get('suspended', False)
        print(f"    User {user_email} is {'suspended' if suspended else 'active'}.")
        return suspended
    except HttpError as error:
        print(f"    ERROR getting user status for {user_email}: {error}")
        if error.resp.status == 404:
            print(f"    User {user_email} not found.")
        return None
    except Exception as e:
        print(f"    UNEXPECTED ERROR getting user status for {user_email}: {e}")
        traceback.print_exc()
        return None

def update_user_status(admin_service, user_email, suspend_user):
    if not admin_service:
        print(f"  Skipping user status update for {user_email}: Admin service not available.")
        return False
    action = "suspending" if suspend_user else "activating"
    if DRY_RUN_ADMIN_OPS:
        print(f"  [DRY RUN] Would attempt to {action} user {user_email}.")
        return True
    print(f"  Attempting to {action} user {user_email}...")
    try:
        admin_service.users().update(userKey=user_email, body={'suspended': suspend_user}).execute()
        print(f"    Successfully {action}d user {user_email}.")
        return True
    except HttpError as error:
        print(f"    ERROR {action} user {user_email}: {error}")
        return False
    except Exception as e:
        print(f"    UNEXPECTED ERROR {action} user {user_email}: {e}")
        traceback.print_exc()
        return False

def add_user_to_group(admin_service, user_email, group_key):
    if not admin_service:
        print(f"  Skipping add {user_email} to group: Admin service not available.")
        return False
    if not group_key or group_key.strip() == '' or group_key == 'x':
        print(f"  Skipping add {user_email} to group: No valid group key provided ('{group_key}').")
        return True
    if DRY_RUN_ADMIN_OPS:
        print(f"  [DRY RUN] Would add user {user_email} to group {group_key}.")
        return True
    print(f"  Attempting to add user {user_email} to group {group_key}...")
    member_body = {'email': user_email, 'role': 'MEMBER'}
    try:
        admin_service.members().insert(groupKey=group_key, body=member_body).execute()
        print(f"    Successfully added {user_email} to group {group_key}.")
        return True
    except HttpError as error:
        if error.resp.status == 409:
            print(f"    User {user_email} is already a member of group {group_key}.")
            return True
        print(f"    ERROR adding {user_email} to group {group_key}: {error}")
        return False
    except Exception as e:
        print(f"    UNEXPECTED ERROR adding {user_email} to group {group_key}: {e}")
        traceback.print_exc()
        return False

def remove_user_from_group(admin_service, user_email, group_key):
    if not admin_service:
        print(f"  Skipping remove {user_email} from group: Admin service not available.")
        return False
    if not group_key or group_key.strip() == '' or group_key == 'x':
        print(f"  Skipping remove {user_email} from group: No valid group key provided ('{group_key}').")
        return True
    if DRY_RUN_ADMIN_OPS:
        print(f"  [DRY RUN] Would remove user {user_email} from group {group_key}.")
        return True
    print(f"  Attempting to remove user {user_email} from group {group_key}...")
    try:
        admin_service.members().delete(groupKey=group_key, memberKey=user_email).execute()
        print(f"    Successfully removed {user_email} from group {group_key}.")
        return True
    except HttpError as error:
        if error.resp.status == 404:
            print(f"    User {user_email} not found in group {group_key}.")
            return True
        print(f"    ERROR removing {user_email} from group {group_key}: {error}")
        return False
    except Exception as e:
        print(f"    UNEXPECTED ERROR removing {user_email} from group {group_key}: {e}")
        traceback.print_exc()
        return False

def sanitize_filename(filename):
    if not isinstance(filename, str): filename = str(filename)
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1F]', '_', filename)
    sanitized = re.sub(r'[\s_]+', '_', sanitized); sanitized = sanitized.strip('. _'); MAX_LEN = 180
    if len(sanitized) > MAX_LEN: sanitized = sanitized[:MAX_LEN]
    sanitized = sanitized.strip('. _'); reserved_names = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}
    name_part, _ = os.path.splitext(sanitized)
    if name_part.upper() in reserved_names: sanitized = "_" + sanitized
    if not sanitized: sanitized = "_unnamed_file"
    return sanitized

# --- Email Archiving (archive_emails_to_mbox, archive_user_data_mbox_only) ---
# These functions are unchanged from your provided code. I'm omitting them for brevity
# to focus on the changed parts, but they are assumed to be present in the final script.
# --- START OF UNCHANGED EMAIL FUNCTIONS (ASSUMED PRESENT) ---
def archive_emails_to_mbox(gmail_service_user, user_email, mbox_file_path):
    message_ids_to_process = []
    page_token = None
    total_message_ids_listed = 0
    permanently_failed_ids_final_list = set()

    log_summary(f"Email Archive: Starting email ID retrieval for {user_email}...")
    print(f"  Starting email ID retrieval for {user_email}...")
    try:
        request = gmail_service_user.users().messages().list(userId='me', includeSpamTrash=True, q="is:anywhere", pageToken=page_token)
        while request is not None:
            response = request.execute()
            retrieved_stubs = response.get('messages', [])
            if retrieved_stubs:
                message_ids_to_process.extend([stub['id'] for stub in retrieved_stubs])
                total_message_ids_listed += len(retrieved_stubs)
                print(f"    Retrieved {total_message_ids_listed} message IDs so far...", end='\r')
            page_token = response.get('nextPageToken')
            if page_token: request = gmail_service_user.users().messages().list_next(previous_request=request, previous_response=response)
            else: request = None
        log_summary(f"Email Archive: Found {total_message_ids_listed} total message IDs for {user_email}.")
        print(f"\n  Found {total_message_ids_listed} total message IDs for {user_email}.")

        if not message_ids_to_process:
            log_summary(f"Email Archive: No messages found for {user_email}.")
            print(f"  No messages found for {user_email}.")
            os.makedirs(os.path.dirname(mbox_file_path), exist_ok=True)
            with open(mbox_file_path, 'wb') as mbox_f: pass
            print(f"  Created empty mbox file at {mbox_file_path}")
            return True, 0, total_message_ids_listed, []

        os.makedirs(os.path.dirname(mbox_file_path), exist_ok=True)
        with open(mbox_file_path, 'ab') as mbox_file:
            final_written_count = 0; retry_needed_ids_map = {}
            def write_raw_email_to_mbox(raw_email_b64, msg_id_for_log="UnknownID"):
                nonlocal final_written_count
                if not raw_email_b64: print(f"\n    Warning: No raw email content for {msg_id_for_log}. Skip."); return False
                try:
                    email_bytes = base64.urlsafe_b64decode(raw_email_b64)
                    from_sender = "MAILER-DAEMON"; date_str = formatdate(timeval=None, localtime=False, usegmt=True)
                    try:
                        parsed_msg = message_from_bytes(email_bytes)
                        if parsed_msg['From']: from_sender = str(parsed_msg['From']).replace('\n',' ').replace('\r','')
                        if parsed_msg['Date']:
                            dt_obj = parsedate_to_datetime(str(parsed_msg['Date']))
                            if dt_obj.tzinfo is None or dt_obj.tzinfo.utcoffset(dt_obj) is None: dt_obj = dt_obj.replace(tzinfo=timezone.utc)
                            date_str = formatdate(dt_obj.timestamp(), localtime=False, usegmt=True)
                    except Exception: pass # Stick to defaults if parsing headers fails
                    from_line = f"From {from_sender} {date_str}\n".encode(LOG_FILE_ENCODING)
                    mbox_file.write(from_line); mbox_file.write(email_bytes); mbox_file.write(b"\n\n")
                    final_written_count += 1; return True
                except (TypeError, ValueError) as de: print(f"\n    Warn: Base64 decode err for {msg_id_for_log}: {de}. Skip.")
                except Exception as e: print(f"\n    Warn: MBOX write err for {msg_id_for_log}: {e}. Skip.")
                return False

            def batch_callback_stream(request_id, response, exception):
                nonlocal retry_needed_ids_map, permanently_failed_ids_final_list
                msg_id = request_id
                if msg_id in permanently_failed_ids_final_list: return
                if exception:
                    if isinstance(exception, HttpError):
                        is_retryable = False
                        if (exception.resp.status == 429 or \
                           (exception.resp.status >= 500 and exception.resp.status < 600)):
                            is_retryable = True
                        elif exception.resp.status == 403:
                            try:
                                error_content = exception.content.decode('utf-8','ignore').lower()
                                if "quota exceeded" in error_content or "rate limit" in error_content or "backenderror" in error_content:
                                    is_retryable = True
                            except: pass
                        elif exception.resp.status == 404: # Optional: Retry 404s cautiously in batch
                            current_retries_for_404 = retry_needed_ids_map.get(msg_id + "_404_batch_retry", 0) # Use a distinct counter for 404 batch retries
                            if current_retries_for_404 < 1: # Allow only one batch retry for a 404
                                is_retryable = True
                                retry_needed_ids_map[msg_id + "_404_batch_retry"] = current_retries_for_404 + 1
                                print(f"\n    Batch Warn: Retrying 404 for {msg_id} (1st batch retry attempt for this 404).")
                            else:
                                print(f"\n    Batch Info: Not retrying 404 for {msg_id} further in batch after 1 attempt.")
                        
                        if is_retryable:
                            retry_needed_ids_map[msg_id] = retry_needed_ids_map.get(msg_id, 0) + 1
                            if retry_needed_ids_map[msg_id] <= 3: 
                                print(f"\n    Batch Warn: Retryable err ({exception.resp.status}) for {msg_id}. Will retry in batch (Attempt {retry_needed_ids_map[msg_id]}/3).")
                            else: 
                                print(f"\n    Batch Err: Max batch retries for {msg_id} ({exception.resp.status}). Will try sequential if configured, or skip.")
                        else: 
                            print(f"\n    Batch Err: Non-retryable API err {exception.resp.status} for {msg_id}. Skip perm: {getattr(exception, 'reason', '')}")
                            retry_needed_ids_map.pop(msg_id, None)
                            permanently_failed_ids_final_list.add(msg_id)
                    else: 
                        print(f"\n    Batch Err: Unexpected err for {msg_id}: {exception}. Skip perm.")
                        retry_needed_ids_map.pop(msg_id, None)
                        permanently_failed_ids_final_list.add(msg_id)
                else: # Success from batch
                    if write_raw_email_to_mbox(response.get('raw'), msg_id):
                        retry_needed_ids_map.pop(msg_id, None) 
                        permanently_failed_ids_final_list.discard(msg_id)
                    else: # Write failed, keep for retry
                        retry_needed_ids_map[msg_id] = retry_needed_ids_map.get(msg_id, 0) + 1

            log_summary(f"Email Archive: Starting initial batch fetch & write for {len(message_ids_to_process)} emails...")
            print(f"  Starting initial batch fetch & write (Batch Size: 50)...")
            batch_size = 50
            for i in range(0, len(message_ids_to_process), batch_size):
                current_batch_ids = message_ids_to_process[i:i+batch_size]
                batch = gmail_service_user.new_batch_http_request(callback=batch_callback_stream)
                for msg_id in current_batch_ids:
                    if msg_id not in permanently_failed_ids_final_list: 
                        batch.add(gmail_service_user.users().messages().get(userId='me', id=msg_id, format='raw', fields='raw,id'), request_id=msg_id)
                if len(batch._requests)>0: 
                    print(f"      Executing initial batch {i//batch_size + 1} (Written: {final_written_count})...", end='\r')
                    try: batch.execute()
                    except Exception as e: print(f"\n  ERROR/Exception during initial batch.execute(): {e}.") 
                time.sleep(0.5 + random.uniform(0, 0.5))
            print("\n  Initial batch fetch & write pass complete."); log_summary(f"Email Archive: Initial batch pass done. Written: {final_written_count}. Pending retry: {len(retry_needed_ids_map)}")

            max_retry_passes = 2; current_retry_pass = 0
            while current_retry_pass < max_retry_passes and retry_needed_ids_map:
                current_retry_pass += 1
                ids_for_this_pass = [mid for mid in list(retry_needed_ids_map.keys()) if mid not in permanently_failed_ids_final_list]
                if not ids_for_this_pass: break
                log_summary(f"Email Archive: Batch retry pass {current_retry_pass}/{max_retry_passes} for {len(ids_for_this_pass)} msgs.")
                print(f"\n  --- Batch Retry Pass {current_retry_pass}/{max_retry_passes} for {len(ids_for_this_pass)} msgs ---")
                for i in range(0, len(ids_for_this_pass), batch_size):
                    current_batch_ids = ids_for_this_pass[i:i+batch_size]
                    retry_batch = gmail_service_user.new_batch_http_request(callback=batch_callback_stream)
                    for msg_id in current_batch_ids:
                        if msg_id in retry_needed_ids_map and msg_id not in permanently_failed_ids_final_list: 
                            retry_batch.add(gmail_service_user.users().messages().get(userId='me', id=msg_id, format='raw', fields='raw,id'), request_id=msg_id)
                    if len(retry_batch._requests)>0: 
                        print(f"      Executing retry batch {i//batch_size + 1} (Written: {final_written_count})...", end='\r')
                        try: retry_batch.execute()
                        except Exception as e: print(f"\n  ERROR/Exception during retry batch.execute(): {e}.")
                    time.sleep(1.0 + current_retry_pass + random.uniform(0,1))
                print(f"\n  Batch Retry Pass {current_retry_pass} done. Written: {final_written_count}. Pending: {len(retry_needed_ids_map)}")
                log_summary(f"Email Archive: Batch Retry pass {current_retry_pass} done. Written: {final_written_count}. Pending: {len(retry_needed_ids_map)}")

            ids_for_seq_pass = [mid for mid in list(retry_needed_ids_map.keys()) if mid not in permanently_failed_ids_final_list]
            if ids_for_seq_pass:
                log_summary(f"Email Archive: Sequential fetch for {len(ids_for_seq_pass)} remaining msgs.")
                print(f"\n  --- FINAL Sequential Attempt for {len(ids_for_seq_pass)} failures ---"); seq_success = 0; seq_fail = 0; seq_delay = 2
                for i, msg_id in enumerate(ids_for_seq_pass):
                    if msg_id in permanently_failed_ids_final_list: continue
                    print(f"      Sequential attempt {i+1}/{len(ids_for_seq_pass)} for {msg_id} (Total Written: {final_written_count})...", end='\r')
                    try:
                        msg_resp = gmail_service_user.users().messages().get(userId='me', id=msg_id, format='raw', fields='raw,id').execute()
                        if write_raw_email_to_mbox(msg_resp.get('raw'), msg_id): 
                            seq_success +=1; retry_needed_ids_map.pop(msg_id, None); permanently_failed_ids_final_list.discard(msg_id)
                        else: # Write failed
                            seq_fail += 1; permanently_failed_ids_final_list.add(msg_id); retry_needed_ids_map.pop(msg_id, None)
                    except HttpError as final_err:
                        print(f"\n        ERROR (Sequential): Failed final fetch for {msg_id}: Status {final_err.resp.status}. Reason: {getattr(final_err, 'reason', '')}. Skipping.")
                        seq_fail += 1; permanently_failed_ids_final_list.add(msg_id); retry_needed_ids_map.pop(msg_id, None)
                    except Exception as fe:
                        print(f"\n        ERROR (Sequential) for {msg_id}: {fe}. Skip perm.")
                        seq_fail += 1; permanently_failed_ids_final_list.add(msg_id); retry_needed_ids_map.pop(msg_id, None)
                    finally:
                        time.sleep(seq_delay + random.uniform(0, 0.5))
                print(f"\n  Sequential Attempt done. Succeeded: {seq_success}, Failed: {seq_fail}."); log_summary(f"Email Archive: Sequential fetch done. Succeeded: {seq_success}, Failed: {seq_fail}.")

            if permanently_failed_ids_final_list:
                log_summary(f"Email Archive: Warning - {len(permanently_failed_ids_final_list)} messages ultimately failed and were not archived.")
                print(f"\n  Warning: {len(permanently_failed_ids_final_list)} messages ultimately failed fetch/write.")

            log_summary(f"Email Archive: MBOX processing complete. Total emails written: {final_written_count}.")
            print(f"\n  Finished MBOX processing. Total emails written: {final_written_count} / {total_message_ids_listed} listed.")
            return True, final_written_count, total_message_ids_listed, list(permanently_failed_ids_final_list)
    except HttpError as error:
         log_summary(f"Email Archive: API error: {error}")
         print(f"\n  ERROR API during email archiving for {user_email}: {error}"); traceback.print_exc()
         return False, 0, total_message_ids_listed, list(permanently_failed_ids_final_list)
    except Exception as e:
        log_summary(f"Email Archive: Unexpected error: {e}")
        print(f"\n  ERROR Unexpected during email archiving for {user_email}: {e}"); traceback.print_exc()
        return False, 0, total_message_ids_listed, list(permanently_failed_ids_final_list)

def archive_user_data_mbox_only(gmail_service_user, user_email, temp_user_dir):
    log_summary(f"Email MBOX: Starting MBOX creation for {user_email}.")
    print(f"  --- Starting MBOX creation for {user_email} ---")
    print(f"  Temporary MBOX storage directory: {temp_user_dir}")

    safe_user_email = sanitize_filename(user_email)
    mbox_filename = f"{safe_user_email}{MBOX_FILE_SUFFIX}"
    mbox_path = os.path.join(temp_user_dir, mbox_filename)
    
    total_listed_for_mbox = 0 
    failed_ids_from_mbox = [] 

    try:
        log_summary(f"Email MBOX: Archiving emails to {os.path.basename(mbox_path)}...")
        print(f"  Archiving emails to {mbox_path}...")
        mbox_success, mbox_written_count, total_listed_for_mbox, failed_ids_from_mbox = \
            archive_emails_to_mbox(gmail_service_user, user_email, mbox_path)

        if not mbox_success:
             log_summary(f"Email MBOX: MBOX creation function reported failure.")
             print(f"  Email archiving function reported failure for {user_email}.")
             return None, 0, total_listed_for_mbox, failed_ids_from_mbox

        log_summary(f"Email MBOX: MBOX function completed (Messages written: {mbox_written_count} / {total_listed_for_mbox} listed).")
        print(f"  Email archiving function completed (Messages written: {mbox_written_count} / {total_listed_for_mbox} listed).")

        if mbox_written_count == 0:
             log_summary(f"Email MBOX: No messages written (either no emails or all failed/skipped).")
             if os.path.exists(mbox_path) and os.path.getsize(mbox_path) == 0: 
                 return "NO_DATA", 0, total_listed_for_mbox, failed_ids_from_mbox
             else: 
                 return mbox_path, 0, total_listed_for_mbox, failed_ids_from_mbox
        
        return mbox_path, mbox_written_count, total_listed_for_mbox, failed_ids_from_mbox

    except Exception as ex:
        log_summary(f"Email MBOX: ERROR during MBOX creation wrapper: {ex}") 
        print(f"\n  ERROR during MBOX creation wrapper for {user_email}: {ex}") 
        if DETAILED_CONSOLE_LOGGING or not DRY_RUN: 
            traceback.print_exc() 
        return None, 0, total_listed_for_mbox, failed_ids_from_mbox
# --- END OF UNCHANGED EMAIL FUNCTIONS ---
        
# --- MODIFIED: Create MBOX-only Archive ZIP ---
def create_mbox_only_archive_zip(temp_user_dir, user_email_sanitized, mbox_file_path):
    zip_filename = f"{user_email_sanitized}{ZIP_FILE_SUFFIX}" # e.g., user_archive.zip
    final_zip_path = os.path.join(temp_user_dir, zip_filename)
    log_summary(f"MBOX Archive ZIP: Creating MBOX-only zip: {zip_filename}...")
    print(f"  Creating MBOX-only archive zip: {final_zip_path}...")
    try:
        with zipfile.ZipFile(final_zip_path, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as zipf:
            if mbox_file_path and mbox_file_path != "NO_DATA" and os.path.exists(mbox_file_path) and os.path.getsize(mbox_file_path) > 0 :
                arcname_mbox = os.path.basename(mbox_file_path)
                log_summary(f"MBOX Archive ZIP: Adding MBOX '{arcname_mbox}' to zip.")
                print(f"    Adding MBOX: {arcname_mbox}...")
                zipf.write(mbox_file_path, arcname=arcname_mbox)
            elif mbox_file_path == "NO_DATA":
                log_summary(f"MBOX Archive ZIP: No MBOX data to add to zip.")
                # Create an empty zip if there's no MBOX, so the process doesn't break
                # Or return None if an empty zip is not desired. For now, creates an empty zip.
                print("    No MBOX data; zip will be empty or contain only MBOX if one was (unexpectedly) created empty.")
            else:
                log_summary(f"MBOX Archive ZIP: MBOX file not added (Path: {mbox_file_path}). Zip may be empty.")

        log_summary(f"MBOX Archive ZIP: Zip file '{zip_filename}' created successfully.")
        print(f"  MBOX-only archive zip created: {final_zip_path}")
        return final_zip_path
    except Exception as ze:
        log_summary(f"MBOX Archive ZIP: FAILED to create zip '{zip_filename}': {ze}")
        print(f"  ERROR creating MBOX-only zip {final_zip_path}: {ze}")
        if os.path.exists(final_zip_path):
            try: os.remove(final_zip_path); log_summary(f"MBOX Archive ZIP: Partially created zip '{final_zip_path}' removed.")
            except OSError as ose: log_summary(f"MBOX Archive ZIP: Error removing partially created zip '{final_zip_path}': {ose}")
        return None

# --- MODIFIED: Upload to Shared Drive (added mimetype parameter) ---
def upload_to_shared_drive(drive_service_sa_to_use, file_path_to_upload, user_email_for_desc, target_folder_id_in_sd, mimetype_to_use='application/octet-stream'):
    if not file_path_to_upload or not os.path.exists(file_path_to_upload):
        log_summary(f"Upload: File not found: {file_path_to_upload}. Skipping upload.")
        print(f"  ERROR: File not found: {file_path_to_upload}"); return None
    if not target_folder_id_in_sd:
        log_summary(f"Upload: Target Folder ID missing. Skipping upload.")
        print(f"  ERROR: Target Folder ID is missing for upload."); return None
    if "dry_run_folder_id" in str(target_folder_id_in_sd) and not DRY_RUN_UPLOAD :
        log_summary(f"Upload: Attempting live upload to dry-run folder ID ({target_folder_id_in_sd}). Skipping.")
        print(f"  ERROR: Attempting live upload to a dry-run folder ID ({target_folder_id_in_sd}). Skipping upload."); return None
    
    file_name_to_upload = os.path.basename(file_path_to_upload)
    upload_type_msg = "MBOX Zip" if file_name_to_upload.endswith(ZIP_FILE_SUFFIX) else "Log File"

    if DRY_RUN_UPLOAD:
        log_summary(f"Upload ({upload_type_msg}): [DRY RUN] Would upload '{file_name_to_upload}' ({mimetype_to_use}) to target folder {target_folder_id_in_sd}.")
        print(f"  [DRY RUN] Would upload '{file_name_to_upload}' to target folder ID: {target_folder_id_in_sd}"); return f"dry_run_upload_id_{random.randint(1000,9999)}"
    
    try:
        file_size = os.path.getsize(file_path_to_upload)
        log_summary(f"Upload ({upload_type_msg}): Starting upload of '{file_name_to_upload}' ({file_size / 1024 / 1024:.2f} MB, type: {mimetype_to_use}) to folder {target_folder_id_in_sd}.")
        print(f"  Uploading '{file_name_to_upload}' ({file_size / 1024 / 1024:.2f} MB, type: {mimetype_to_use}) to target folder ID: {target_folder_id_in_sd} (using SA: {sa_email_address})...")
    except OSError as e:
        log_summary(f"Upload ({upload_type_msg}): Cannot get size of file {file_path_to_upload}: {e}. Skipping.")
        print(f"  ERROR: Cannot get size of file {file_path_to_upload}: {e}. Skipping upload."); return None

    metadata = {'name': file_name_to_upload, 'parents': [target_folder_id_in_sd], 
                'description': f'{upload_type_msg} for user {user_email_for_desc} created on {datetime.now().isoformat()}'}
    
    retries = 3; delay = 5;
    for attempt in range(retries):
         media_file_handle = None
         try:
            media_file_handle = open(file_path_to_upload, 'rb')
            media = MediaIoBaseUpload(media_file_handle, mimetype=mimetype_to_use, resumable=True, chunksize=10*1024*1024)
            request = drive_service_sa_to_use.files().create(body=metadata, media_body=media, supportsAllDrives=True, fields='id, name, webViewLink')
            print(f"    Upload Attempt {attempt + 1}/{retries}..."); response = None
            while response is None:
                try:
                    status, response = request.next_chunk()
                    if status: print(f"    Upload progress: {int(status.progress() * 100)}%    ", end='\r')
                except HttpError as chunk_error:
                    if chunk_error.resp.status in [404, 410]: print(f"\n    Resumable upload session expired ({chunk_error.resp.status}). Restarting attempt."); break
                    is_retryable_chunk_err = (chunk_error.resp.status == 429 or (chunk_error.resp.status >= 500 and chunk_error.resp.status < 600))
                    if not is_retryable_chunk_err and chunk_error.resp.status == 403:
                        try:
                            error_content = chunk_error.content.decode('utf-8','ignore').lower()
                            if "quota exceeded" in error_content or "rate limit" in error_content: is_retryable_chunk_err = True
                        except: pass
                    if is_retryable_chunk_err : print(f"\n    Retryable error during upload chunk ({chunk_error.resp.status}). Retrying attempt..."); break
                    else: print(f"\n    Non-retryable error during upload chunk: {chunk_error.resp.status}. Aborting."); raise chunk_error
            if response:
                uploaded_file_details = response; file_id = uploaded_file_details.get('id')
                log_summary(f"Upload ({upload_type_msg}): Success! File ID: {file_id}, Name: '{uploaded_file_details.get('name')}'")
                print(f"\n  File uploaded successfully: Name='{uploaded_file_details.get('name')}', ID='{file_id}', Link='{uploaded_file_details.get('webViewLink')}'")
                return file_id
            if attempt < retries -1 and response is None: # Chunk loop broke, and not last attempt
                current_delay = delay * (2 ** attempt) + random.uniform(0,1)
                print(f"    Upload attempt {attempt + 1} did not complete fully (chunk error likely). Retrying in {current_delay:.2f}s...")
                time.sleep(current_delay)
                continue # To next attempt in outer loop
            elif response is None and attempt == retries -1: # Chunk loop broke on final attempt
                log_summary(f"Upload ({upload_type_msg}): FAILED for '{file_name_to_upload}' after {attempt + 1} attempts (next_chunk loop did not complete).")
                return None
         except HttpError as error:
            status_code = getattr(error.resp, 'status', 'N/A'); reason_text = getattr(error, 'reason', 'N/A')
            print(f"\n    Upload attempt {attempt + 1} failed with API Error: Status {status_code} Reason: {reason_text}")
            is_retryable_outer = (status_code in [404, 410] or status_code == 429 or (status_code >= 500 and status_code < 600)) # 404/410 might be if resumable session is truly gone
            if not is_retryable_outer and status_code == 403:
                try:
                    error_content = error.content.decode('utf-8','ignore').lower()
                    if "quota exceeded" in error_content or "rate limit" in error_content: is_retryable_outer = True
                except: pass
            if is_retryable_outer and attempt < retries - 1:
                 current_delay = delay * (2 ** attempt) + random.uniform(0, 1); print(f"      Retrying in {current_delay:.2f}s...")
                 time.sleep(current_delay); continue
            else:
                log_summary(f"Upload ({upload_type_msg}): FAILED for '{file_name_to_upload}' after {attempt + 1} attempts. Error: {status_code} {reason_text}")
                print(f"      Non-retryable API Error or final attempt failed. Upload aborted for {file_name_to_upload}."); return None
         except Exception as e:
              print(f"\n    Upload attempt {attempt + 1} failed with unexpected error: {e}"); traceback.print_exc()
              if attempt < retries - 1:
                   current_delay = delay * (2 ** attempt) + random.uniform(0, 1); print(f"      Retrying in {current_delay:.2f}s...")
                   time.sleep(current_delay); continue
              else:
                   log_summary(f"Upload ({upload_type_msg}): FAILED for '{file_name_to_upload}' after {attempt + 1} attempts. Unexpected error: {e}")
                   print(f"      Final attempt failed. Upload aborted for {file_name_to_upload}."); return None
         finally:
              if media_file_handle and not media_file_handle.closed: media_file_handle.close()
    log_summary(f"Upload ({upload_type_msg}): FAILED for '{file_name_to_upload}' after all {retries} attempts.")
    print(f"  ERROR: Upload failed for '{file_name_to_upload}' after {retries} attempts."); return None

# --- Permission Management Functions ---
# Unchanged, omitting for brevity (assumed present)
def add_user_permission(drive_service_to_use, sd_id, email, role):
    op = f"Grant '{role}' to {email} on SD {sd_id}";
    if DRY_RUN_PERMISSIONS: log_summary(f"Perms: [DRY RUN] Would {op}."); return f"dry_run_perm_{random.randint(1000,9999)}"
    log_summary(f"Perms: Attempting {op} (SA: {sa_email_address})."); print(f"    Attempting {op}...")
    body = {'type': 'user', 'role': role, 'emailAddress': email}
    try: p = drive_service_to_use.permissions().create(fileId=sd_id,body=body,supportsAllDrives=True,sendNotificationEmail=False,fields='id,role').execute(); p_id=p.get('id'); r=p.get('role'); log_summary(f"Perms: OK. User: {email}, Role: {r}, ID: {p_id}"); print(f"      OK. User: {email}, Role: {r}, ID: {p_id}"); return p_id
    except Exception as e: log_summary(f"Perms: ERROR adding for {email}: {e}"); print(f"      ERROR adding for {email}: {e}"); return None

def remove_user_permission(drive_service_to_use, sd_id, perm_id, email_log):
    op = f"Remove perm ID {perm_id} ({email_log}) from SD {sd_id}";
    if not perm_id or "dry_run_perm" in str(perm_id):
        if DRY_RUN_PERMISSIONS: log_summary(f"Perms: [DRY RUN] Would {op} (placeholder ID)."); return True
        else: log_summary(f"Perms: Skip remove for {email_log}: Invalid ID '{perm_id}'."); return False
    if DRY_RUN_PERMISSIONS and "dry_run_perm" not in str(perm_id): log_summary(f"Perms: [DRY RUN] Would {op} (real ID)."); return True
    log_summary(f"Perms: Attempting {op} (SA: {sa_email_address})."); print(f"    Attempting {op}...")
    try: drive_service_to_use.permissions().delete(fileId=sd_id,permissionId=perm_id,supportsAllDrives=True).execute(); log_summary(f"Perms: OK removed perm ID {perm_id} for {email_log}."); print(f"      OK removed perm ID {perm_id}."); return True
    except HttpError as e:
        log_summary(f"Perms: ERROR removing perm ID {perm_id}: {e}"); print(f"      ERROR removing perm ID {perm_id}: {e}")
        if e.resp.status == 404: log_summary(f"Perms: Perm ID {perm_id} not found (already removed?). OK."); return True
        return False
    except Exception as e: log_summary(f"Perms: UNEXPECTED ERROR removing perm ID {perm_id}: {e}"); print(f"      UNEXPECTED ERROR removing perm ID {perm_id}: {e}"); return False


# --- Sheet Interaction Functions ---
# get_sheet_data is unchanged
def get_sheet_data(ss_id, sheet_name_val):
    try: range_name = f"'{sheet_name_val}'!A1:Z"; result = sheets_service.spreadsheets().values().get(spreadsheetId=ss_id, range=range_name).execute(); values = result.get('values',[]); original_stdout.write(f"  Read {len(values)} rows from '{sheet_name_val}'.\n"); return values
    except Exception as e: original_stdout.write(f"ERROR reading sheet '{sheet_name_val}': {e}\n"); return None

# batch_update_sheet now has a small print statement if not DRY_RUN for visibility of individual updates
def batch_update_sheet(ss_id, updates):
    if not updates: return True
    if DRY_RUN: original_stdout.write(f"  [DRY RUN] Would update sheet with {len(updates)} changes.\n"); return True
    try:
        # original_stdout.write(f"  Attempting to update sheet with {len(updates)} changes...\n") # More verbose if needed
        body={'valueInputOption':'USER_ENTERED','data':updates}
        sheets_service.spreadsheets().values().batchUpdate(spreadsheetId=ss_id,body=body).execute()
        # original_stdout.write(f"  Sheet update successful for {len(updates)} changes.\n")
        return True
    except Exception as e: original_stdout.write(f"  ERROR batch updating sheet: {e}\n"); return False

# --- Drive Ops (find/create folder, list/copy items) ---
# These functions (find_drive_folder, create_folder, list_drive_items_for_copy, copy_drive_file, copy_mydrive_files_to_folder)
# are unchanged from your provided code. I'm omitting them for brevity.
# --- START OF UNCHANGED DRIVE OPS FUNCTIONS (ASSUMED PRESENT) ---
def find_drive_folder(drive_svc, actor, name, parent_id):
    safe_name = name.replace("'", "\\'") 
    query = f"name = '{safe_name}' and mimeType = '{FOLDER_MIME_TYPE}' and '{parent_id}' in parents and trashed = false"
    try:
        params = {
            'q': query,
            'supportsAllDrives': True,
            'fields': 'files(id,name,driveId,parents)',
            'pageSize': 2 
        }
        is_sd_context = False
        effective_drive_id = None
        if parent_id == SHARED_DRIVE_ID:
            is_sd_context = True
            effective_drive_id = SHARED_DRIVE_ID
        else:
            try:
                parent_metadata = drive_svc.files().get(fileId=parent_id, fields='id,driveId', supportsAllDrives=True).execute()
                if parent_metadata.get('driveId'):
                    is_sd_context = True
                    effective_drive_id = parent_metadata.get('driveId')
            except HttpError as he:
                if he.resp.status == 404: print(f"    Warning (find_drive_folder): Parent folder {parent_id} not found by {actor}. Query will proceed without explicit driveId.")
                else: print(f"    Error (find_drive_folder) getting metadata for parent {parent_id}: {he}")
            except Exception as e_meta: print(f"    Unexpected Error (find_drive_folder) getting metadata for parent {parent_id}: {e_meta}")

        if is_sd_context and effective_drive_id:
            params['corpora'] = 'drive'
            params['driveId'] = effective_drive_id
            params['includeItemsFromAllDrives'] = True
            
        res = drive_svc.files().list(**params).execute()
        folders = res.get('files', [])
        if folders:
            print(f"    Found folder '{folders[0]['name']}' (ID: {folders[0]['id']}) in parent '{parent_id}' by {actor}.")
            return folders[0]
        return None
    except Exception as e:
        print(f"    ERROR (find_drive_folder) finding folder '{name}' in {parent_id} (as {actor}): {e}")
        traceback.print_exc()
        return None

def create_folder(drive_svc, actor, name, parent_id):
    meta = {'name':name,'mimeType':FOLDER_MIME_TYPE,'parents':[parent_id]}
    if DRY_RUN_FOLDER_CREATION: print(f"    [DRY RUN] Create folder '{name}' in {parent_id}."); return {'id':f'dry_run_fid_{random.randint(1000,9999)}','name':name}
    try: f=drive_svc.files().create(body=meta,fields='id,name',supportsAllDrives=True).execute(); print(f"    OK created folder '{f.get('name')}' (ID: {f.get('id')}) in {parent_id} (as {actor})"); return f
    except Exception as e: print(f"    ERROR creating folder '{name}' in {parent_id} (as {actor}): {e}"); return None

def list_drive_items_for_copy(drive_svc, email_log):
    items=[];tok=None;count=0;query=f"'me' in owners and trashed=false"; print(f"    Listing Drive items for {email_log}..."); retries=0
    while True:
        try:
            params={'q':query,'spaces':'drive','fields':"nextPageToken,files(id,name,mimeType,parents,capabilities/canCopy,ownedByMe,driveId,shortcutDetails,webViewLink)",'pageToken':tok,'pageSize':200,'supportsAllDrives':True,'includeItemsFromAllDrives':True,'corpora':'user'}
            res=drive_svc.files().list(**params).execute(); batch=res.get('files',[]); items.extend(batch); count+=len(batch); print(f"      Fetched {count} items...", end='\r'); tok=res.get('nextPageToken')
            if not tok: break
            time.sleep(0.3); retries=0
        except HttpError as he:
            print(f"\n      ERROR listing Drive items: {he}")
            if he.resp.status in [403,429,500,503] and retries<3: retries+=1; st=(2**retries)+random.random(); print(f"        Retry list in {st:.2f}s..."); time.sleep(st); continue
            else: print(f"        Aborting list for {email_log}."); return None
        except Exception as e: print(f"\n      UNEXPECTED ERROR listing Drive items: {e}"); return None
    print(f"\n    Finished list for {email_log}. Found {len(items)} items."); return items

def copy_drive_file(drive_service_impersonated_to_use, effective_email_log, file_data_to_copy, new_parent_id_for_copy):
    file_id = file_data_to_copy['id']; file_name = file_data_to_copy['name']
    file_link = file_data_to_copy.get('webViewLink', 'N/A')
    log_prefix = f"      Copying (as {effective_email_log}):"

    if DRY_RUN_COPY:
        print(f"{log_prefix} [DRY RUN] Would copy '{file_name}' (ID: {file_id}, Link: {file_link}) to parent {new_parent_id_for_copy}.")
        return {'id': f'dry_run_copied_id_{random.randint(1000,9999)}', 'name': file_name, 'webViewLink': 'dry_run_link'}

    print(f"{log_prefix} File='{file_name}' (ID: {file_id}, Link: {file_link}) -> Target Parent ID: {new_parent_id_for_copy}")
    copy_metadata = {'name': file_name, 'parents': [new_parent_id_for_copy]}

    for attempt in range(DRIVE_COPY_MAX_RETRIES + 1):
        try:
            copied_file_response = drive_service_impersonated_to_use.files().copy(
                fileId=file_id, body=copy_metadata, fields='id, name, webViewLink', supportsAllDrives=True
            ).execute()
            copied_file_id = copied_file_response.get('id'); copied_file_name = copied_file_response.get('name')
            copied_file_link_new = copied_file_response.get('webViewLink', 'N/A')
            print(f"        -> Attempt {attempt + 1}: Successfully copied to New ID='{copied_file_id}' (Name='{copied_file_name}', Link: {copied_file_link_new})")
            return copied_file_response
        except HttpError as error:
            print(f"        -> Attempt {attempt + 1}: ERROR copying file '{file_name}' (ID: {file_id}): {error}")
            is_retryable = False; error_content_str = ""
            if hasattr(error, 'content') and error.content:
                try: error_content_str = error.content.decode('utf-8').lower()
                except: pass 

            if error.resp.status == 403 and ("userratelimitexceeded" in error_content_str or \
                                            "quotaexceeded" in error_content_str or \
                                            "backenderror" in error_content_str or \
                                            " দৈনিক সীমা অতিক্রম হয়েছে" in error_content_str): is_retryable = True
            elif error.resp.status == 429: is_retryable = True
            elif error.resp.status >= 500 and error.resp.status < 600: is_retryable = True

            if is_retryable and attempt < DRIVE_COPY_MAX_RETRIES:
                sleep_time = (DRIVE_COPY_RETRY_BASE_DELAY ** attempt) + random.uniform(0, 1)
                print(f"          Retryable error ({error.resp.status}). Retrying in {sleep_time:.2f} seconds... (Attempt {attempt + 2}/{DRIVE_COPY_MAX_RETRIES + 1})")
                time.sleep(sleep_time); continue
            else:
                if error.resp.status == 403 and not is_retryable: print(f"          Permission Denied (403). Reason: {getattr(error, 'reason', 'N/A')}")
                elif "storage quota" in error_content_str: print(f"          Storage Quota Exceeded on destination.")
                elif error.resp.status == 404: print(f"          Source file {file_id} or target parent {new_parent_id_for_copy} not found.")
                else: print(f"          Error details: {error.content if hasattr(error, 'content') else 'N/A'}")
                return None
        except Exception as e:
            print(f"        -> Attempt {attempt + 1}: UNEXPECTED ERROR copying file '{file_name}' (ID: {file_id}): {e}"); traceback.print_exc()
            if attempt < DRIVE_COPY_MAX_RETRIES:
                sleep_time = (DRIVE_COPY_RETRY_BASE_DELAY ** attempt) + random.uniform(0, 1)
                print(f"          Unexpected error. Retrying in {sleep_time:.2f} seconds... (Attempt {attempt + 2}/{DRIVE_COPY_MAX_RETRIES + 1})")
                time.sleep(sleep_time); continue
            else: return None
    return None

def copy_mydrive_files_to_folder(user_email, drive_svc_imp, eff_email, target_pid):
    log_summary(f"MyDrive Copy: Starting for {user_email} to target {target_pid}."); print(f"  --- MyDrive Copy for {user_email} to {target_pid} (as {eff_email}) ---")
    if DRY_RUN_COPY: print("  DRY RUN for File Copies")
    res = {"total_items_listed":0,"files_to_copy_count":0,"folders_skipped":0,"shortcuts_skipped":0,"sites_skipped":0,"already_in_sd_skipped":0,"cannot_copy_capability_skipped":0,"files_copied_successfully":0,"files_failed_copy":0,"failed_copy_details":[],"success":False,"status_message":"Init"}
    if not target_pid or ("dry_run_folder_id" in str(target_pid) and not DRY_RUN_COPY): res["status_message"]=f"Skip: Invalid/DryRun Target PID {target_pid}"; log_summary(res["status_message"]); return res
    try:
        all_items = list_drive_items_for_copy(drive_svc_imp, eff_email)
        if all_items is None: raise ValueError("Failed list items for copy.")
        res["total_items_listed"]=len(all_items); log_summary(f"MyDrive Copy: Listed {res['total_items_listed']} items.")
        to_copy=[]; print("    Filtering items for copy...");
        for item in all_items:
            if item.get('driveId'): res["already_in_sd_skipped"]+=1; continue
            mt=item['mimeType']
            if mt==SHORTCUT_MIME_TYPE: res["shortcuts_skipped"]+=1; continue
            if mt==SITE_MIME_TYPE: res["sites_skipped"]+=1; continue
            if mt==FOLDER_MIME_TYPE: res["folders_skipped"]+=1; continue
            if not item.get('capabilities',{}).get('canCopy',False): res["cannot_copy_capability_skipped"]+=1; continue
            to_copy.append(item)
        res["files_to_copy_count"]=len(to_copy); log_summary(f"MyDrive Copy: {res['files_to_copy_count']} files to copy. Skipped: Fld={res['folders_skipped']}, SC={res['shortcuts_skipped']}, Site={res['sites_skipped']}, SD={res['already_in_sd_skipped']}, NoCopy={res['cannot_copy_capability_skipped']}.")
        print(f"    Filtered: {res['files_to_copy_count']} files to copy.")
        if res["folders_skipped"] > 0: print(f"      - Folders skipped (flat copy target): {res['folders_skipped']}")
        if res["shortcuts_skipped"] > 0: print(f"      - Shortcuts skipped: {res['shortcuts_skipped']}")
        if res["sites_skipped"] > 0: print(f"      - Sites skipped: {res['sites_skipped']}")
        if res["already_in_sd_skipped"] > 0: print(f"      - Items already in a Shared Drive skipped: {res['already_in_sd_skipped']}")
        if res["cannot_copy_capability_skipped"] > 0: print(f"      - Files with no 'canCopy' capability skipped: {res['cannot_copy_capability_skipped']}")

        if not to_copy: res["status_message"]="OK (No files to copy)"; res["success"]=True; return res
        log_summary(f"MyDrive Copy: Starting copy of {res['files_to_copy_count']} files."); print(f"    Starting copy of {res['files_to_copy_count']} files to {target_pid}...")
        for item_data in to_copy:
            copied = copy_drive_file(drive_svc_imp, eff_email, item_data, target_pid)
            if copied: res["files_copied_successfully"]+=1
            else: res["files_failed_copy"]+=1; res["failed_copy_details"].append({'name':item_data.get('name'),'id':item_data.get('id'),'link':item_data.get('webViewLink','N/A')})
            time.sleep(COPY_API_DELAY)
        if res["files_failed_copy"]==0: res["success"]=True; res["status_message"]=f"OK (Copied {res['files_copied_successfully']}/{res['files_to_copy_count']} files)"
        elif res["files_copied_successfully"]>0: res["success"]=True; res["status_message"]=f"Partial (Copied {res['files_copied_successfully']}/{res['files_to_copy_count']}; Failed: {res['files_failed_copy']})"
        else: res["success"]=False; res["status_message"]=f"Failed (0 copied; Failed: {res['files_failed_copy']})"
        log_summary(f"MyDrive Copy: Result: {res['status_message']}.")
    except Exception as e: log_summary(f"MyDrive Copy: FATAL ERROR: {e}"); print(f"  FATAL MyDrive Copy ERROR: {e}"); traceback.print_exc(); res["error"]=str(e); res["status_message"]=f"Copy Failed: Error ({type(e).__name__})"; res["success"]=False
    print(f"  --- MyDrive Copy Summary ---"); print(f"    Copied: {res['files_copied_successfully']}, Failed: {res['files_failed_copy']}"); print(f"    Status: {res['status_message']}"); print(f"  --- End MyDrive Copy ---")
    return res
# --- END OF UNCHANGED DRIVE OPS FUNCTIONS ---

# ==============================================================================
# --- Main Processing Loop (MODIFIED FOR NEW FOLDER STRUCTURE, LOG UPLOADS, IMMEDIATE SHEET UPDATE) ---
# ==============================================================================
# ==============================================================================
# --- Main Processing Loop (MODIFIED FOR PER-USER EXECUTION TIME IN SHEET LOG) ---
# ==============================================================================
# ==============================================================================
# --- Main Processing Loop (Corrected Log Closure for Uploads) ---
# ==============================================================================
def process_users_combined():
    global rowcol_to_a1 # Assuming rowcol_to_a1 is initialized globally
    if rowcol_to_a1 is None:
        original_stdout.write("FATAL ERROR: rowcol_to_a1 function not available.\n")
        return

    original_stdout.write("\n=== Starting Combined User Processing ===\n")

    try:
        original_stdout.write("Reading sheet data...\n")
        sheet_data = get_sheet_data(SPREADSHEET_ID, SHEET_NAME)
        if sheet_data is None: original_stdout.write("Failed to read sheet data. Aborting.\n"); return
        if not sheet_data or len(sheet_data) < 2: original_stdout.write("Spreadsheet empty or no header/data rows.\n"); return

        header = sheet_data[0]; rows_to_process = sheet_data[1:]
        try:
            email_col_idx = header.index("Email"); dept_col_idx = header.index("Department Name")
            status_col_idx = header.index("Status"); log_col_idx = header.index("Log")
        except ValueError as ve:
            original_stdout.write(f"FATAL ERROR: Missing required columns. Ensure 'Email', 'Department Name', 'Status', 'Log' headers exist. Error: {ve}. Header found: {header}\n"); return
        original_stdout.write(f"Found {len(rows_to_process)} user rows. Col Indices: Email={email_col_idx+1}, Department={dept_col_idx+1}, Status={status_col_idx+1}, Log={log_col_idx+1}\n")
    except Exception as e:
        original_stdout.write(f"ERROR setting up sheet processing: {e}\n"); traceback.print_exc(file=original_stderr); return

    for idx, row_data in enumerate(rows_to_process):
        row_num_on_sheet = idx + 2
        user_email, department_name_from_sheet, actual_department_name_for_drive = "", "", ""
        user_email_sanitized, overall_status_sheet, sheet_log_str = "_unknown_", "Pending", ""

        # These are reset for each user
        detailed_log_path_for_user, summary_log_path_for_user, temp_user_dir = None, None, None
        temp_drive_perm_id, user_activated_flag, added_to_group_flag, original_suspension = None, False, False, False
        drive_svc_imp, eff_email_ops, gmail_svc_user = None, None, None
        user_sd_base_folder_id, mydrive_target_subfolder_id = None, None

        user_start_time = datetime.now()

        mbox_archived_count, email_total_listed = 0, 0
        mydrive_eligible_files, mydrive_copied_count = 0, 0
        email_archive_ok, mydrive_copy_ok = False, False
        mbox_zip_id, uploaded_detailed_log_id, uploaded_summary_log_id = None, None, None
        mbox_path_for_zip = None
        failed_email_ids, failed_drive_files = [], []
        copy_res_dict = {}

        try:
            if len(row_data) <= email_col_idx:
                original_stdout.write(f"Row {row_num_on_sheet}: Skipped (Row Format Error - too short to read email).\n")
                overall_status_sheet="Skipped (RowFormat)"; sheet_log_str="Err:RowFormat"
                raise Exception("RowFormatError_PreLogging_Email")

            user_email = row_data[email_col_idx].strip().lower()
            if len(row_data) > dept_col_idx: department_name_from_sheet = row_data[dept_col_idx].strip()

            user_email_sanitized = sanitize_filename(user_email)
            temp_user_dir = os.path.join(TEMP_PROCESSING_DIR_BASE, user_email_sanitized)
            os.makedirs(temp_user_dir, exist_ok=True)

            # Use specific variables for this user's log paths
            detailed_log_path_for_user, summary_log_path_for_user = setup_user_logging(user_email_sanitized, temp_user_dir)
            if not detailed_log_path_for_user: # Check if setup_user_logging succeeded
                overall_status_sheet="Failure (LogInit)"; sheet_log_str="Err:LogInit"
                raise Exception("LoggingInitializationFailed")

            log_summary(f"Processing User: {user_email} (Sheet Row: {row_num_on_sheet}), Department from sheet: '{department_name_from_sheet}'")
            log_summary(f"Run Start Time: {user_start_time.strftime('%Y-%m-%d %H:%M:%S')}")

            if not user_email or '@' not in user_email:
                 log_summary(f"Error: Invalid email '{user_email}'. Skipping.")
                 overall_status_sheet="Skipped (InvalidEmail)"; raise Exception("InvalidEmailFormat")

            if not department_name_from_sheet: actual_department_name_for_drive = "Departmentless"
            else: actual_department_name_for_drive = department_name_from_sheet
            if not actual_department_name_for_drive: actual_department_name_for_drive = "Departmentless"
            log_summary(f"Using department name for Drive folder: '{actual_department_name_for_drive}'.")

            print(f"\n--- Processing Row {row_num_on_sheet}: {user_email}, Target Department Folder Name: {actual_department_name_for_drive} ---")
            overall_status_sheet = "In Progress"
            initial_status_upd = [{'range':f"'{SHEET_NAME}'!{rowcol_to_a1(row_num_on_sheet, status_col_idx+1)}", 'values':[[overall_status_sheet]]}]
            if not batch_update_sheet(SPREADSHEET_ID, initial_status_upd):
                 log_summary("Warning: Failed to set sheet status to 'In Progress'.")

            archived_data_root_folder_id, department_folder_id, year_folder_id = None, None, None
            log_summary(f"Verifying SD folder structure: SD_Root -> '{ARCHIVED_DATA_ROOT_FOLDER_NAME}' -> '{actual_department_name_for_drive}' -> CurrentYear -> '{user_email_sanitized}'")

            archived_data_root_folder_obj = find_drive_folder(drive_service_sa, sa_email_address, ARCHIVED_DATA_ROOT_FOLDER_NAME, SHARED_DRIVE_ID)
            if not archived_data_root_folder_obj: raise Exception(f"Root archive folder '{ARCHIVED_DATA_ROOT_FOLDER_NAME}' NOT FOUND. Must exist.")
            archived_data_root_folder_id = archived_data_root_folder_obj['id']

            department_folder_obj = find_drive_folder(drive_service_sa, sa_email_address, actual_department_name_for_drive, archived_data_root_folder_id)
            if not department_folder_obj: raise Exception(f"Department folder '{actual_department_name_for_drive}' NOT FOUND in '{ARCHIVED_DATA_ROOT_FOLDER_NAME}'. Must exist.")
            department_folder_id = department_folder_obj['id']

            current_year_str = str(datetime.now().year)
            year_folder_obj = find_drive_folder(drive_service_sa, sa_email_address, current_year_str, department_folder_id)
            if not year_folder_obj: year_folder_obj = create_folder(drive_service_sa, sa_email_address, current_year_str, department_folder_id)
            if not year_folder_obj: raise Exception(f"Failed to find/create Year folder '{current_year_str}'.")
            year_folder_id = year_folder_obj['id']

            user_sd_folder_name = user_email_sanitized
            user_sd_final_folder_obj = find_drive_folder(drive_service_sa, sa_email_address, user_sd_folder_name, year_folder_id)
            if not user_sd_final_folder_obj: user_sd_final_folder_obj = create_folder(drive_service_sa, sa_email_address, user_sd_folder_name, year_folder_id)
            if not user_sd_final_folder_obj: raise Exception(f"Failed to find/create User folder '{user_sd_folder_name}'.")
            user_sd_base_folder_id = user_sd_final_folder_obj['id']
            log_summary(f"User SD base folder for uploads/MyDrive copy: '{user_sd_folder_name}' (ID: {user_sd_base_folder_id}) established.")

            log_summary("Building impersonated services...")
            gmail_svc_user = build_gmail_service(user_email)
            drive_svc_imp, eff_email_ops = build_drive_service_impersonated(user_email)
            if not gmail_svc_user: log_summary(f"Error: Failed to build Gmail service for {user_email}. Email archiving will be skipped.")
            if not drive_svc_imp: log_summary(f"Error: Failed to build Drive service for {user_email}. MyDrive copy will be skipped.")

            if gmail_svc_user and user_sd_base_folder_id:
                try:
                    log_summary("Email MBOX: Starting...");
                    mbox_path_for_zip, mbox_archived_count, email_total_listed, failed_email_ids = \
                        archive_user_data_mbox_only(gmail_svc_user, user_email, temp_user_dir)
                    if mbox_path_for_zip=="NO_DATA": email_archive_ok=True; mbox_archived_count=0; log_summary("Email MBOX: No data.")
                    elif mbox_path_for_zip and os.path.exists(mbox_path_for_zip): email_archive_ok=True; log_summary(f"Email MBOX: OK ({mbox_archived_count}/{email_total_listed}).")
                    else: log_summary("Email MBOX: FAIL.")
                    if failed_email_ids: log_summary(f"Email MBOX: {len(failed_email_ids)} emails failed.")
                except Exception as ex: log_summary(f"Email MBOX: Unexpected error: {ex}"); traceback.print_exc()

            if drive_svc_imp and user_sd_base_folder_id:
                try:
                    log_summary("MyDrive Copy: Initiating...")
                    if admin_service_global:
                        susp_stat = get_user_status(admin_service_global, user_email)
                        if susp_stat is True:
                            original_suspension = True; log_summary(f"MyDrive Copy: User suspended. Activating...")
                            if update_user_status(admin_service_global,user_email,False): user_activated_flag=True; log_summary(f"MyDrive Copy: Activated. Wait {USER_ACTIVATION_DELAY}s."); time.sleep(USER_ACTIVATION_DELAY)
                            else: raise Exception("ActivationFailDrive: Could not activate user for MyDrive copy.")
                        if TARGET_GROUP_KEY and TARGET_GROUP_KEY.strip()!='' and TARGET_GROUP_KEY != 'x':
                            log_summary(f"MyDrive Copy: Add to group {TARGET_GROUP_KEY}...")
                            if add_user_to_group(admin_service_global,user_email,TARGET_GROUP_KEY): added_to_group_flag=True; log_summary(f"MyDrive Copy: In group. Wait {GROUP_MEMBERSHIP_DELAY}s."); time.sleep(GROUP_MEMBERSHIP_DELAY)
                            else: log_summary(f"MyDrive Copy: Warn - Fail add to group.")

                    log_summary(f"MyDrive Copy: Grant temp '{TEMPORARY_ROLE}' perm...");
                    temp_drive_perm_id = add_user_permission(drive_service_sa,SHARED_DRIVE_ID,user_email,TEMPORARY_ROLE)
                    if not temp_drive_perm_id and not DRY_RUN_PERMISSIONS: raise Exception("PermGrantFailDrive: Failed to grant temporary Drive permission.")
                    elif not temp_drive_perm_id and DRY_RUN_PERMISSIONS: temp_drive_perm_id = f"dry_run_perm_{random.randint(1000,9999)}"
                    elif temp_drive_perm_id and not DRY_RUN_PERMISSIONS: log_summary(f"MyDrive Copy: Perm granted. Wait {PERMISSION_PROPAGATION_DELAY}s..."); time.sleep(PERMISSION_PROPAGATION_DELAY)

                    mydrive_subfolder_obj = find_drive_folder(drive_svc_imp,eff_email_ops,MYDRIVE_COPY_SUBFOLDER_NAME,user_sd_base_folder_id)
                    if not mydrive_subfolder_obj: mydrive_subfolder_obj = create_folder(drive_svc_imp,eff_email_ops,MYDRIVE_COPY_SUBFOLDER_NAME,user_sd_base_folder_id)
                    if not mydrive_subfolder_obj: raise Exception(f"SubfolderFailDrive: Failed to create/find MyDrive subfolder '{MYDRIVE_COPY_SUBFOLDER_NAME}'.")
                    mydrive_target_subfolder_id = mydrive_subfolder_obj['id']

                    copy_res_dict = copy_mydrive_files_to_folder(user_email,drive_svc_imp,eff_email_ops,mydrive_target_subfolder_id)
                    mydrive_copy_ok = copy_res_dict.get("success",False)
                    mydrive_copied_count = copy_res_dict.get("files_copied_successfully",0)
                    mydrive_eligible_files = copy_res_dict.get("files_to_copy_count",0)
                    failed_drive_files = copy_res_dict.get("failed_copy_details",[])
                except Exception as drive_ex: log_summary(f"MyDrive Copy: Unexpected error: {drive_ex}"); traceback.print_exc()
            
            # Determine Overall Status (pre-log upload)
            # This status might be refined after log uploads
            current_all_uploads_ok_estimate = mbox_zip_id # Placeholder, will be refined after uploads
            if mbox_path_for_zip == "NO_DATA" and not mbox_zip_id:
                 current_all_uploads_ok_estimate = True # True for mbox part, logs pending

            if email_archive_ok and mydrive_copy_ok and current_all_uploads_ok_estimate: overall_status_sheet = "Success"
            elif (email_archive_ok or mydrive_copy_ok):
                 if current_all_uploads_ok_estimate: overall_status_sheet = "Partial Success (Data Ops)"
                 else: overall_status_sheet = "Partial Success (Uploads May Be Incomplete)"
            else:
                 overall_status_sheet = "Failure"
            log_summary(f"Mid-process status (before log uploads): {overall_status_sheet}")


        except Exception as user_ex:
             if overall_status_sheet=="In Progress" or overall_status_sheet=="Pending": # If error happened before status was set further
                overall_status_sheet = "Failure (OuterError)"
                if "NOT FOUND" in str(user_ex) or "Failed to find/create" in str(user_ex):
                    overall_status_sheet = "Failure (FolderSetup)"
             
             # Log the critical error to the user's log files (if they were set up)
             if detailed_log_path_for_user: # Check if logging was set up
                 log_summary(f"CRITICAL ERROR processing {user_email}: {user_ex}")
                 # The Tee object will write to detailed_log_file_handler and original_stderr
                 print(f"  CRITICAL ERROR for {user_email} (Dept: {actual_department_name_for_drive}): {user_ex}\n", file=sys.stderr)
                 if DETAILED_CONSOLE_LOGGING or not DRY_RUN: traceback.print_exc(file=sys.stderr)
             else: # Logging not set up, print to original streams
                 original_stdout.write(f"  CRITICAL ERROR for {user_email} (Dept: {actual_department_name_for_drive}) PRE-LOGGING: {user_ex}\n")
                 traceback.print_exc(file=original_stderr)

             if not sheet_log_str: sheet_log_str=f"Error: {type(user_ex).__name__} - {str(user_ex)[:500]}"

        finally:
            user_process_end_time = datetime.now()
            user_duration = user_process_end_time - user_start_time
            user_duration_seconds = user_duration.total_seconds()
            if user_duration_seconds < 60:
                user_time_str = f"{user_duration_seconds:.2f} sec"
            else:
                user_time_str = f"{user_duration_seconds / 60:.2f} min"

            # --- LOGGING FINALIZATION AND CLOSURE (BEFORE UPLOAD ATTEMPTS) ---
            if detailed_log_path_for_user: # Check if logging was successfully set up
                log_summary(f"Run End Time: {user_process_end_time.strftime('%Y-%m-%d %H:%M:%S')}")
                log_summary(f"Total time for user: {user_duration}")
                log_summary(f"Final Counts - Emails Archived: {mbox_archived_count}/{email_total_listed if email_archive_ok else (email_total_listed if email_total_listed>0 else 'N/A')}")
                if failed_email_ids: log_summary(f"  Failed Email IDs ({len(failed_email_ids)}): {', '.join(failed_email_ids[:10])}{'...' if len(failed_email_ids)>10 else ''}")
                log_summary(f"Final Counts - MyDrive Files Copied: {mydrive_copied_count}/{mydrive_eligible_files if mydrive_eligible_files>0 else('N/A' if not drive_svc_imp else'0')}")
                if failed_drive_files: log_summary(f"  Failed MyDrive Files ({len(failed_drive_files)}): {len(failed_drive_files)} items (see detailed log for list)")
                
                # Indicate pending uploads in the log files themselves
                log_summary(f"Log Upload Status - Detailed Log: {'PENDING' if os.path.exists(detailed_log_path_for_user) else 'SKIPPED (No file)'}")
                log_summary(f"Log Upload Status - Summary Log: {'PENDING' if os.path.exists(summary_log_path_for_user) else 'SKIPPED (No file)'}")
                log_summary(f"MBOX ZIP Upload Status: {'PENDING' if mbox_path_for_zip and mbox_path_for_zip != 'NO_DATA' else ('NO MBOX DATA' if mbox_path_for_zip=='NO_DATA' else 'SKIPPED')}")
                
                close_user_logging() # This now correctly flushes and closes handlers
                original_stdout.write(f"  User log files closed for {user_email_sanitized}. Preparing for upload.\n")
            else:
                original_stdout.write(f"  User log files were not initialized for {user_email_sanitized}, skipping log-specific finalization.\n")


            # --- LOG FILE UPLOADS (This section now runs AFTER logs are closed) ---
            logs_upload_sd_folder_id = None
            if detailed_log_path_for_user and summary_log_path_for_user and user_sd_base_folder_id: # Use the specific user paths
                original_stdout.write(f"  Attempting to upload log files for {user_email}...\n")
                
                logs_subfolder_obj = find_drive_folder(drive_service_sa, sa_email_address, LOGS_SUBFOLDER_NAME, user_sd_base_folder_id)
                if not logs_subfolder_obj:
                    original_stdout.write(f"    '{LOGS_SUBFOLDER_NAME}' subfolder not found in {user_sd_base_folder_id}. Creating it...\n")
                    logs_subfolder_obj = create_folder(drive_service_sa, sa_email_address, LOGS_SUBFOLDER_NAME, user_sd_base_folder_id)
                
                if logs_subfolder_obj and logs_subfolder_obj.get('id'):
                    logs_upload_sd_folder_id = logs_subfolder_obj['id']
                    original_stdout.write(f"    Logs subfolder for uploads: '{LOGS_SUBFOLDER_NAME}' (ID: {logs_upload_sd_folder_id})\n")
                    
                    if os.path.exists(detailed_log_path_for_user):
                        original_stdout.write(f"    Uploading detailed log: {os.path.basename(detailed_log_path_for_user)}\n")
                        uploaded_detailed_log_id = upload_to_shared_drive(drive_service_sa, detailed_log_path_for_user, user_email, logs_upload_sd_folder_id, mimetype_to_use='text/plain')
                        if uploaded_detailed_log_id: original_stdout.write(f"    Detailed log uploaded. ID: {uploaded_detailed_log_id}\n")
                        else: original_stdout.write("    FAILED to upload detailed log.\n")
                    else: original_stdout.write(f"    Detailed log path not found for upload: {detailed_log_path_for_user}\n")
                    
                    if os.path.exists(summary_log_path_for_user):
                        original_stdout.write(f"    Uploading summary log: {os.path.basename(summary_log_path_for_user)}\n")
                        uploaded_summary_log_id = upload_to_shared_drive(drive_service_sa, summary_log_path_for_user, user_email, logs_upload_sd_folder_id, mimetype_to_use='text/plain')
                        if uploaded_summary_log_id: original_stdout.write(f"    Summary log uploaded. ID: {uploaded_summary_log_id}\n")
                        else: original_stdout.write("    FAILED to upload summary log.\n")
                    else: original_stdout.write(f"    Summary log path not found for upload: {summary_log_path_for_user} (Upload skipped).\n")
                else:
                    original_stdout.write(f"    Could not find/create '{LOGS_SUBFOLDER_NAME}' subfolder. Log file uploads skipped.\n")
            else:
                original_stdout.write(f"  Skipping individual log uploads for {user_email} (log paths were '{detailed_log_path_for_user}', '{summary_log_path_for_user}' or target SD folder ID '{user_sd_base_folder_id}' not set).\n")

            # --- MBOX-only ZIP CREATION AND UPLOAD ---
            mbox_zip_path_local = None # Renamed to avoid conflict with mbox_path_for_zip (source)
            if temp_user_dir and user_sd_base_folder_id:
                original_stdout.write(f"  Attempting to create MBOX-only zip for {user_email}...\n")
                mbox_zip_path_local = create_mbox_only_archive_zip(temp_user_dir, user_email_sanitized, mbox_path_for_zip) # mbox_path_for_zip is the source .mbox
                if mbox_zip_path_local: # Check if zip creation was successful
                    original_stdout.write(f"    MBOX Zip created: {os.path.basename(mbox_zip_path_local)}\n")
                    mbox_zip_id = upload_to_shared_drive(drive_service_sa, mbox_zip_path_local, user_email, user_sd_base_folder_id, mimetype_to_use='application/zip')
                    if mbox_zip_id: original_stdout.write(f"    MBOX Zip Uploaded. ID: {mbox_zip_id}\n")
                    else: original_stdout.write(f"    MBOX Zip UPLOAD FAILED for {os.path.basename(mbox_zip_path_local)}. Kept in {temp_user_dir}\n")
                else: original_stdout.write("    MBOX Zip: Failed to create. No upload.\n")
            else: original_stdout.write(f"  MBOX Archive ZIP: Skipped for {user_email} (temp_dir or base_sd_folder_id not set).\n")

            # Re-evaluate overall_status_sheet based on actual upload results
            final_all_uploads_ok = mbox_zip_id and uploaded_detailed_log_id and uploaded_summary_log_id
            if mbox_path_for_zip == "NO_DATA" and not mbox_zip_id: # Mbox was empty, no zip made/uploaded
                 final_all_uploads_ok = uploaded_detailed_log_id and uploaded_summary_log_id

            if email_archive_ok and mydrive_copy_ok and final_all_uploads_ok: overall_status_sheet = "Success"
            elif (email_archive_ok or mydrive_copy_ok): # Some data ops were ok
                 if final_all_uploads_ok: overall_status_sheet = "Partial Success (Data Ops)"
                 else: overall_status_sheet = "Partial Success (Uploads Incomplete)"
            elif final_all_uploads_ok : # No data ops, but logs uploaded (e.g. empty user)
                 overall_status_sheet = "Success (No Data, Logs OK)"
            # If overall_status_sheet was already "Failure (OuterError)" or "Failure (FolderSetup)", it remains.
            elif "Failure" not in overall_status_sheet: # Avoid overwriting specific failure reasons
                 overall_status_sheet = "Failure"


            # Construct final sheet log string
            email_log_part = f"Emails: {mbox_archived_count}/{email_total_listed if email_archive_ok else (email_total_listed if email_total_listed > 0 else 'N/A')}"
            if not email_archive_ok and gmail_svc_user and email_total_listed > 0 and mbox_archived_count < email_total_listed : email_log_part += " (Issues)"
            drive_log_part = f"MyDrive: {mydrive_copied_count}/{mydrive_eligible_files if mydrive_eligible_files > 0 else ('N/A' if not drive_svc_imp else '0')}"
            if not mydrive_copy_ok and drive_svc_imp and mydrive_eligible_files > 0 and mydrive_copied_count < mydrive_eligible_files: drive_log_part += " (Issues)"

            sheet_log_lines = [email_log_part, drive_log_part]
            sites_skipped = copy_res_dict.get("sites_skipped", 0) if copy_res_dict else 0
            if sites_skipped > 0: sheet_log_lines.append(f"Sites Skipped: {sites_skipped}")

            sheet_log_lines.append(f"Det.Log Up: {'OK' if uploaded_detailed_log_id else 'FAIL/SKIP'}")
            sheet_log_lines.append(f"Sum.Log Up: {'OK' if uploaded_summary_log_id else 'FAIL/SKIP'}")
            sheet_log_lines.append(f"MBOX Zip Up: {'OK' if mbox_zip_id else ('NoMbox' if mbox_path_for_zip == 'NO_DATA' else 'FAIL/SKIP')}")
            sheet_log_lines.append(f"User Time: {user_time_str}")

            final_sheet_log_str = " | ".join(s for s in sheet_log_lines if s)
            if sheet_log_str and "Error:" in sheet_log_str:
                final_sheet_log_str = sheet_log_str + " | " + final_sheet_log_str

            if len(final_sheet_log_str) >= MAX_CELL_LENGTH:
                final_sheet_log_str = final_sheet_log_str[:MAX_CELL_LENGTH-20] + "...(trunc)"

            # Final admin ops cleanup
            if temp_drive_perm_id:
                original_stdout.write(f"  Finalizing {user_email}: Revoking temp Drive perm ID {temp_drive_perm_id}...\n")
                remove_user_permission(drive_service_sa, SHARED_DRIVE_ID, temp_drive_perm_id, user_email)
            if admin_service_global:
                if TARGET_GROUP_KEY and added_to_group_flag:
                    original_stdout.write(f"  Finalizing {user_email}: Removing from group {TARGET_GROUP_KEY}...\n")
                    remove_user_from_group(admin_service_global, user_email, TARGET_GROUP_KEY)
                if user_activated_flag:
                    original_stdout.write(f"  Finalizing {user_email}: Re-suspending user...\n")
                    if not update_user_status(admin_service_global, user_email, True): original_stdout.write(f"  CRITICAL WARNING - FAILED TO RE-SUSPEND {user_email}!\n")

            if temp_user_dir and os.path.exists(temp_user_dir):
                original_stdout.write(f"  Finalizing {user_email}: Cleaning up temporary processing directory: {temp_user_dir}\n")
                try: shutil.rmtree(temp_user_dir); original_stdout.write(f"    Temp dir removed for {user_email}.\n")
                except OSError as e: original_stdout.write(f"    Warning: Failed to remove temp dir for {user_email} ({temp_user_dir}): {e}\n")

            # IMMEDIATE SHEET UPDATE FOR THIS USER
            status_range = f"'{SHEET_NAME}'!{rowcol_to_a1(row_num_on_sheet, status_col_idx+1)}"
            log_range = f"'{SHEET_NAME}'!{rowcol_to_a1(row_num_on_sheet, log_col_idx+1)}"
            current_user_sheet_updates = [
                {'range':status_range,'values':[[overall_status_sheet]]},
                {'range':log_range,'values':[[final_sheet_log_str]]}
            ]
            original_stdout.write(f"  Updating sheet for {user_email} (Row {row_num_on_sheet}): Status='{overall_status_sheet}', Log='{final_sheet_log_str[:100].replace(chr(10),' ')}...'...\n")
            if not batch_update_sheet(SPREADSHEET_ID, current_user_sheet_updates):
                 original_stdout.write(f"  WARNING: Failed to update sheet immediately for user {user_email}.\n")

            original_stdout.write(f"--- Finished Row {row_num_on_sheet}: {user_email} (Dept: {actual_department_name_for_drive}). Final Sheet Status: {overall_status_sheet} ---\n")
            time.sleep(0.5)

    original_stdout.write("\n=== Combined User Processing Finished ===\n")

# ==============================================================================
# --- Main Execution Block ---
# ==============================================================================
if __name__ == "__main__":
    script_overall_start_time = time.time() # Record overall script start time for console output

    original_stdout.write("--- Combined Email Archiver & MyDrive Copier Script ---\n")
    original_stdout.write(f"Timestamp: {datetime.now().isoformat()}\n")
    # ... (rest of the __main__ block from the previous version is unchanged here) ...
    # This includes:
    # - Dry run info print
    # - Config print
    # - Config validation
    # - Temp dir creation
    # - Calling process_users_combined()
    # - Printing total script execution time to console
    original_stdout.write(f"OPERATION MODE: {'DRY RUN' if DRY_RUN else 'LIVE RUN'}\n")
    if DRY_RUN:
        original_stdout.write("  Dry Run Details:\n")
        original_stdout.write(f"    - Permissions: {'DRY RUN' if DRY_RUN_PERMISSIONS else 'LIVE'}\n")
        original_stdout.write(f"    - Admin Ops: {'DRY RUN' if DRY_RUN_ADMIN_OPS else 'LIVE'}\n")
        original_stdout.write(f"    - Uploads (MBOX Zip & Logs): {'DRY RUN' if DRY_RUN_UPLOAD else 'LIVE'}\n")
        original_stdout.write(f"    - MyDrive Copies: {'DRY RUN' if DRY_RUN_COPY else 'LIVE'}\n")
        original_stdout.write(f"    - Folder Creation: {'DRY RUN' if DRY_RUN_FOLDER_CREATION else 'LIVE'}\n")
    original_stdout.write(f"Console Logging for Detailed User Ops: {'ENABLED' if DETAILED_CONSOLE_LOGGING else 'DISABLED (File Only)'}\n")
    original_stdout.write(f"Service Account: {SERVICE_ACCOUNT_FILE} ({sa_email_address})\n")
    original_stdout.write(f"Spreadsheet ID: {SPREADSHEET_ID}, Sheet Name: '{SHEET_NAME}'\n")
    original_stdout.write(f"Target Shared Drive ID: {SHARED_DRIVE_ID}\n")
    original_stdout.write(f"Target Root Archive Folder Name (must exist in SD): '{ARCHIVED_DATA_ROOT_FOLDER_NAME}'\n")
    original_stdout.write(f"Logs Subfolder Name in User's Archive: '{LOGS_SUBFOLDER_NAME}'\n")
    original_stdout.write(f"MyDrive Copy Subfolder Name: '{MYDRIVE_COPY_SUBFOLDER_NAME}'\n")
    original_stdout.write(f"Base Temp Directory: {TEMP_PROCESSING_DIR_BASE}\n")
    if ADMIN_USER_EMAIL and ADMIN_USER_EMAIL != 'x' and ADMIN_USER_EMAIL.strip() != '': original_stdout.write(f"Admin User for Impersonation: {ADMIN_USER_EMAIL}\n")
    else: original_stdout.write("Admin User for Impersonation: NOT CONFIGURRED or placeholder 'x' (Admin ops will be skipped or fail)\n")
    if TARGET_GROUP_KEY and TARGET_GROUP_KEY != 'x' and TARGET_GROUP_KEY.strip() != '': original_stdout.write(f"Target Group: {TARGET_GROUP_KEY}\n")
    else: original_stdout.write("Target Group: NOT CONFIGURED or placeholder 'x' (Group ops will be skipped)\n")
    original_stdout.write("-" * 70 + "\n")
    
    config_valid = True
    if SERVICE_ACCOUNT_FILE == 'x.json' or not os.path.exists(SERVICE_ACCOUNT_FILE): original_stdout.write("FATAL ERROR: SERVICE_ACCOUNT_FILE missing/placeholder.\n"); config_valid = False
    if SPREADSHEET_ID == 'x': original_stdout.write("FATAL ERROR: SPREADSHEET_ID missing/placeholder.\n"); config_valid = False
    if SHARED_DRIVE_ID == 'x': original_stdout.write("FATAL ERROR: SHARED_DRIVE_ID missing/placeholder.\n"); config_valid = False
    if not ARCHIVED_DATA_ROOT_FOLDER_NAME: original_stdout.write("FATAL ERROR: ARCHIVED_DATA_ROOT_FOLDER_NAME empty.\n"); config_valid = False
    if not config_valid: original_stdout.write("FATAL: Config errors prevent script execution.\n"); exit(1)

    if not os.path.exists(TEMP_PROCESSING_DIR_BASE):
        try: os.makedirs(TEMP_PROCESSING_DIR_BASE); original_stdout.write(f"Created base temp directory: {TEMP_PROCESSING_DIR_BASE}\n")
        except OSError as e: original_stdout.write(f"FATAL ERROR: Could not create base temp dir {TEMP_PROCESSING_DIR_BASE}: {e}\n"); exit(1)
    
    if drive_service_sa and sheets_service:
        # MODIFIED: Call process_users_combined without the start time argument
        process_users_combined()
        script_overall_end_time = time.time() # MODIFIED: Renamed from script_end_time for clarity
        total_script_duration_seconds = script_overall_end_time - script_overall_start_time
        original_stdout.write(f"\nTotal script execution time: {total_script_duration_seconds / 60:.2f} minutes ({total_script_duration_seconds:.2f} seconds).\n")
    else: original_stdout.write("\nScript aborted due to base service initialization failure.\n")
    original_stdout.write("--- Script End ---\n")