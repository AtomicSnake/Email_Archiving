import mailbox
import sys
import email.header # Needed for potentially decoding subjects

def decode_subject(header_value):
    """Decodes an email subject header, handling potential encoding."""
    if header_value is None:
        return "(No Subject)"
    try:
        decoded_parts = email.header.decode_header(header_value)
        subject_parts = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                # If encoding is None, try common encodings or default to latin-1
                if encoding is None:
                    try:
                        subject_parts.append(part.decode('utf-8'))
                    except UnicodeDecodeError:
                        try:
                            subject_parts.append(part.decode('latin-1'))
                        except UnicodeDecodeError:
                            subject_parts.append(part.decode('ascii', errors='replace')) # Fallback
                else:
                    try:
                        subject_parts.append(part.decode(encoding))
                    except (UnicodeDecodeError, LookupError): # Handle bad encoding names
                         subject_parts.append(part.decode('latin-1', errors='replace')) # Fallback
            elif isinstance(part, str):
                subject_parts.append(part)
        return "".join(subject_parts)
    except Exception as e:
        # Fallback if any decoding error occurs
        print(f"Warning: Could not decode subject: {header_value}. Error: {e}", file=sys.stderr)
        # Try a simple string representation or return a placeholder
        try:
            return str(header_value)
        except:
            return "(Subject Decoding Error)"


def get_message_data(mbox_path):
    """Extracts Message-IDs and Subjects from an mbox file."""
    # Store data as { 'message_id': 'subject' }
    message_data = {}
    try:
        mbox_obj = mailbox.mbox(mbox_path, factory=None, create=False)
        print(f"Processing {mbox_path}...", file=sys.stderr)
        count = 0
        missing_id_count = 0
        duplicate_id_count = 0 # Count overwritten entries

        for message in mbox_obj:
            count += 1
            if count % 1000 == 0:
                 print(f"  ...processed {count} messages.", file=sys.stderr)

            msg_id_raw = message.get('Message-ID')

            if msg_id_raw:
                msg_id = msg_id_raw.strip().strip('<>')
                subject_raw = message.get('Subject')
                subject = decode_subject(subject_raw) # Use decoder function

                if msg_id in message_data:
                    duplicate_id_count += 1
                    # Overwriting - the last message with this ID wins.
                    # You could add logic here to handle duplicates differently if needed.
                message_data[msg_id] = subject
            else:
                missing_id_count += 1

        if missing_id_count > 0:
             print(f"Warning: {missing_id_count} message(s) without Message-ID found in {mbox_path}", file=sys.stderr)
        if duplicate_id_count > 0:
             print(f"Warning: {duplicate_id_count} duplicate Message-ID(s) found and overwritten in {mbox_path}", file=sys.stderr)

        print(f"Finished {mbox_path}. Found {len(message_data)} unique Message-IDs.", file=sys.stderr)
        return message_data
    except Exception as e:
        print(f"Error reading {mbox_path}: {e}", file=sys.stderr)
        return None
    finally:
        if 'mbox_obj' in locals() and hasattr(mbox_obj, 'close'):
             mbox_obj.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <file1.mbox> <file2.mbox>")
        print(f"Description: Compares two mbox files and prints Message-IDs and Subjects unique to each file.")
        sys.exit(1)

    file1_path = sys.argv[1]
    file2_path = sys.argv[2]

    print(f"Reading message data from {file1_path}...")
    data1 = get_message_data(file1_path)
    print(f"\nReading message data from {file2_path}...")
    data2 = get_message_data(file2_path)

    if data1 is None or data2 is None:
        print("\nAborting comparison due to errors reading one or both files.", file=sys.stderr)
        sys.exit(1)

    # --- Perform the comparison using Message-IDs (the dictionary keys) ---
    ids1 = set(data1.keys())
    ids2 = set(data2.keys())

    unique_ids_file1 = ids1 - ids2
    unique_ids_file2 = ids2 - ids1
    common_ids = ids1 & ids2

    print(f"\n--- Comparison Results ---")
    print(f"Total unique Message-IDs in {file1_path}: {len(ids1)}")
    print(f"Total unique Message-IDs in {file2_path}: {len(ids2)}")
    print(f"Messages unique to {file1_path}: {len(unique_ids_file1)}")
    print(f"Messages unique to {file2_path}: {len(unique_ids_file2)}")
    print(f"Messages common to both files: {len(common_ids)}")

    # --- Output the unique Message-IDs and their Subjects ---

    # Output items unique to file 1
    if unique_ids_file1:
        print(f"\n--- Messages unique to {file1_path} ---")
        # Sort by Message-ID for consistent output
        for msg_id in sorted(list(unique_ids_file1)):
            subject = data1.get(msg_id, "(Subject not found - error?)") # Look up subject in data1
            print(f"{msg_id} | Subject: {subject}")
    else:
        print(f"\n--- No messages found unique to {file1_path} ---")


    # Output items unique to file 2
    if unique_ids_file2:
        print(f"\n--- Messages unique to {file2_path} ---")
        # Sort by Message-ID for consistent output
        for msg_id in sorted(list(unique_ids_file2)):
            subject = data2.get(msg_id, "(Subject not found - error?)") # Look up subject in data2
            print(f"{msg_id} | Subject: {subject}")
    else:
        print(f"\n--- No messages found unique to {file2_path} ---")

    print("\nComparison finished.")