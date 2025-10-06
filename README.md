# ProtonMail Email Signature Verification Script

## Overview

Have you received a signed email from a ProtonMail user and been unable to verify the signature? This is because more than just the visible body is signed. Hidden parts of the email are included in the signature.

This script enables you to verify the signature by:
- Taking the downloaded email file.
- Extracting the correct parts of the email (including hidden sections).
- Running the `gpg --verify` command on the properly extracted data using the signature.

## Usage

1. **Download the signed email** from your email client (e.g., Gmail).  
    *Make sure to download the original or raw email file (including all headers and attachments - typically a `.eml` file), not just copy and pasting the visible message body.*

2. **Ensure you have the sender's public key** imported into your GPG keyring.

3. **Make the script executable** (if needed):
    ```bash
    chmod +x verifyProtonSig.sh
    ```

4. **Run the script** with the downloaded email file as input:
    ```bash
    ./verifyProtonSig.sh path/to/email.eml
    ```

The script will:
- Parse the email file.
- Extract all necessary components for signature verification.
- Use GPG to verify the signature.

## Notes

- This script has only been tested on messages sent from ProtonMail to Gmail.
- Make sure you have the sender's public key in your GPG keyring before running the script.

## Requirements

- Python (version 3.6.0 or higher)
- GPG installed and accessible from the command line
- The sender's public key imported into your GPG keyring

## Disclaimer

This script is provided as-is and may require adjustments for emails from other providers or formats.