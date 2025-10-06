import sys
import email
from email import policy
import re

def extract_boundary_from_header(content_type_header):
    """
    Extracts the boundary value from a Content-Type header,
    safely handling both quoted and unquoted formats.
    """
    match = re.search(r'boundary=("[^"]+"|[^;\s]+)', content_type_header, re.IGNORECASE)
    if match:
        boundary = match.group(1)
        if boundary.startswith('"') and boundary.endswith('"'):
            boundary = boundary[1:-1]  # Remove quotes
        return boundary
    return None

def fix_content_type_header(raw_str, boundary):
    """
    Prepends the correctly formatted Content-Type header with no quotes or line wrapping.
    """
    header = f'Content-Type: multipart/mixed;boundary={boundary}\n\n'
    return header + raw_str

def extract_signed_body_only(part, boundary):
    """
    Extracts just the multipart/mixed section up to and including the closing boundary,
    avoiding any extra parts like attachments or public keys.
    """
    payload = part.get_payload()

    if isinstance(payload, list):
        raw_parts = []
        # Use a policy that disables header folding/wrapping so long header
        # lines (like Content-Type with many parameters) are not split.
        no_wrap_policy = policy.default.clone(max_line_length=None)
        for p in payload:
            part_str = p.as_string(policy=no_wrap_policy)
            raw_parts.append(f'--{boundary}\n{part_str}')
        raw_parts.append(f'--{boundary}--\n')
        return '\n'.join(raw_parts)
    else:
        print("❌ Unexpected payload structure in signed part.")
        return None

def extract_pgp_parts(filename):
    with open(filename, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    # Locate the multipart/signed part
    signed_part = None
    if msg.get_content_type() == 'multipart/signed':
        signed_part = msg
    else:
        for part in msg.walk():
            if part.get_content_type() == 'multipart/signed':
                signed_part = part
                break

    if not signed_part:
        print("❌ Could not find multipart/signed MIME part.")
        return False

    # Extract signed data and signature parts
    try:
        signed_data = signed_part.get_payload(0)
        signature_part = signed_part.get_payload(1)
    except Exception:
        print("❌ Could not extract signed and signature parts.")
        return False

    if not signature_part or signature_part.get_content_type() != 'application/pgp-signature':
        print("❌ Could not find PGP signature part.")
        return False

    # Get boundary string from Content-Type header
    content_type_header = signed_data.get('Content-Type', '')
    boundary = extract_boundary_from_header(content_type_header)
    if not boundary:
        print("❌ Could not extract boundary from Content-Type header.")
        return False

    # Extract only signed body up to closing boundary
    raw_signed_body = extract_signed_body_only(signed_data, boundary)
    if not raw_signed_body:
        print("❌ Failed to extract clean multipart body.")
        return False

    # Prepend exact Content-Type line to match what was signed
    final_message = fix_content_type_header(raw_signed_body, boundary)

    # Decode and extract the signature
    signature = signature_part.get_payload(decode=True).decode('utf-8')

    # Ensure output directory exists
    import os
    os.makedirs('extractedSignatureData', exist_ok=True)

    # Create if does not exist
    if not os.path.exists('extractedSignatureData'):
        os.makedirs('extractedSignatureData')

    # Save files
    with open('extractedSignatureData/message.txt', 'w', encoding='utf-8') as f:
        f.write(final_message)

    with open('extractedSignatureData/signature.asc', 'w', encoding='utf-8') as f:
        f.write(signature)

    print("\n\033[92m✅ Extraction of signed message and signature complete.\033[0m\n")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extract_pgp_signature.py <email_file.eml>")
        sys.exit(1)

    input_file = sys.argv[1]
    success = extract_pgp_parts(input_file)
    if not success:
        sys.exit(1)
