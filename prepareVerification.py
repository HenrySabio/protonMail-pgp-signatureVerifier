#!/usr/bin/env python3
import sys
import re

def die(msg):
    print(f"❌ {msg}")
    sys.exit(1)

def find_header_block(raw: bytes):
    """
    Split raw message into (headers_bytes, rest_bytes) at the first blank line.
    Detects either CRLF or LF as the separator.
    """
    sep = b"\r\n\r\n"
    idx = raw.find(sep)
    if idx != -1:
        return raw[:idx], raw[idx+len(sep):], b"\r\n"
    # fallback to LF
    sep = b"\n\n"
    idx = raw.find(sep)
    if idx == -1:
        die("Could not find end of top-level header block.")
    return raw[:idx], raw[idx+len(sep):], b"\n"

def get_top_level_boundary(top_headers: bytes):
    """
    Parse the *raw* top-level headers to get the multipart/signed boundary token.
    We do not normalize quoting; we only need the token (without quotes)
    to find boundary delimiter lines in the body.
    """
    # join folded lines for Content-Type parsing (RFC allows folding)
    # We do minimal unfolding: lines starting with space/tab are continuations.
    lines = top_headers.splitlines()
    unfolded = []
    for line in lines:
        if unfolded and (line.startswith(b" ") or line.startswith(b"\t")):
            unfolded[-1] += line
        else:
            unfolded.append(line)

    # find Content-Type header (case-insensitive)
    ct = None
    for l in unfolded:
        if l.lower().startswith(b"content-type:"):
            ct = l[len(b"content-type:"):].strip()
            break
    if not ct:
        die("Top-level Content-Type header not found.")

    # must be multipart/signed
    if b"multipart/signed" not in ct.lower():
        die("Top-level message is not multipart/signed.")

    # extract boundary parameter value (quoted or not)
    m = re.search(br'boundary=(?P<q>")?(?P<val>[^";\s]+)(?P=q)?', ct, flags=re.IGNORECASE)
    if not m:
        die("Could not find boundary parameter on multipart/signed.")
    boundary_token = m.group('val')  # bytes, no quotes
    return boundary_token

def iter_signed_boundaries(body: bytes, boundary: bytes):
    """
    Yield (start_index, end_index, is_closing) for each boundary delimiter line:
      --boundary[OWS]CRLF        (part boundary)
      --boundary--[OWS]CRLF      (closing boundary)
    We search in multiline mode anchored to start-of-line.
    """
    # Allow optional whitespace after delimiter before EOL.
    # Match either LF or CRLF line endings. Use (?m) for ^ and $ over multiple lines.
    pattern = re.compile(
        br'(?m)^(--' + re.escape(boundary) + br'(?P<closing>--)?)[ \t]*\r?\n'
    )
    for m in pattern.finditer(body):
        start = m.start()
        end   = m.end()
        is_closing = (m.group('closing') is not None)
        yield start, end, is_closing

def split_multipart_signed_parts(body: bytes, boundary: bytes):
    """
    For a multipart/signed body:
      preamble, then:
        --boundary CRLF
          <part1 headers + body>
        --boundary CRLF
          <part2 headers + body>
        --boundary-- CRLF
      epilogue
    Return (part1_bytes, part2_bytes) each including their own headers+body,
    but NOT including any boundary delimiter lines.
    """
    # Find all boundaries
    bmarks = list(iter_signed_boundaries(body, boundary))
    if len(bmarks) < 2:
        die("Did not find enough boundary delimiters inside multipart/signed body.")

    # We expect at least:
    #   #0: first part delimiter
    #   #1: second part delimiter
    #   last: closing delimiter (with --)
    # Extract the segments between:
    #   part1 = [end of bmarks[0] : start of bmarks[1]]
    #   part2 = [end of bmarks[1] : start of closing]
    # Find closing index
    closing_idx = None
    for i, (_s, _e, is_closing) in enumerate(bmarks):
        if is_closing:
            closing_idx = i
            break
    if closing_idx is None:
        die("Closing boundary not found (no -- after boundary).")

    if closing_idx < 2:
        die("Not enough parts before the closing boundary (need 2 parts).")

    # Compute slices
    first_delim_start, first_delim_end, _ = bmarks[0]
    second_delim_start, second_delim_end, _ = bmarks[1]
    closing_start, _closing_end, _ = bmarks[closing_idx]

    part1 = body[first_delim_end:second_delim_start]
    part2 = body[second_delim_end:closing_start]

    # Trim leading lone CRLF/LF if present (after boundary lines there is normally no blank line,
    # but some generators might add one spuriously). We only trim a single empty line safely.
    for p_name, p in (("part1", part1), ("part2", part2)):
        if p.startswith(b"\r\n"):
            p = p[2:]
        elif p.startswith(b"\n"):
            p = p[1:]
        if p_name == "part1":
            part1 = p
        else:
            part2 = p

    return part1, part2

def strip_headers(part_bytes: bytes):
    """
    Split a MIME part into (headers_bytes, body_bytes) using the first blank line.
    Return (headers, body). If no blank line, body is empty.
    Preserves the original line endings.
    """
    # Try CRLF first
    sep = b"\r\n\r\n"
    idx = part_bytes.find(sep)
    if idx != -1:
        return part_bytes[:idx], part_bytes[idx+len(sep):]
    # Then LF
    sep = b"\n\n"
    idx = part_bytes.find(sep)
    if idx == -1:
        # no header/body split, assume no headers
        return b"", part_bytes
    return part_bytes[:idx], part_bytes[idx+len(sep):]

def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_pgp_signature_rawsafe.py <email_file.eml>")
        sys.exit(1)

    path = sys.argv[1]
    try:
        raw = open(path, "rb").read()
    except Exception as e:
        die(f"Failed to read file: {e}")

    # 1) Split top-level headers and body; detect EOL style
    top_headers, top_body, _eol = find_header_block(raw)

    # 2) Extract top-level multipart/signed boundary token (no normalization)
    boundary = get_top_level_boundary(top_headers)

    # 3) Extract the two parts (between boundary delimiters) as raw bytes
    part1, part2 = split_multipart_signed_parts(top_body, boundary)

    # 4) part1 is the SIGNED ENTITY (headers+body) EXACTLY as sent — save as message.txt
    # NOTE: No modifications, no reserialization, no added/removed quotes/spaces.
    # 5) part2 is the signature container; strip its headers so only the ASCII armored block remains.
    _sig_headers, sig_body = strip_headers(part2)

    # Ensure output
    import os
    outdir = "extractedSignatureData"
    os.makedirs(outdir, exist_ok=True)

    def trim_trailing_newline(b: bytes) -> bytes:
        if b.endswith(b"\r\n"):
            return b[:-2]
        elif b.endswith(b"\n"):
            return b[:-1]
        return b

    part1 = trim_trailing_newline(part1)
    sig_body = trim_trailing_newline(sig_body)

    with open(f"{outdir}/message.txt", "wb") as f:
        f.write(part1)

    with open(f"{outdir}/signature.asc", "wb") as f:
        f.write(sig_body)

    print("\n\033[92m✅ Extraction complete (raw-safe, no reformatting).\033[0m\n")
    print(f"• Data:      {outdir}/message.txt")
    print(f"• Signature: {outdir}/signature.asc")

if __name__ == "__main__":
    main()
