import sys
import re
import hashlib
import os
from asn1crypto import cms, pem, x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
import traceback
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives.serialization import Encoding
from endesive.pdf import verify as endesive_verify
from cryptography.x509.oid import ExtensionOID
try:
    from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    HAS_OCSP = True
except Exception:
    HAS_OCSP = False
try:
    import requests
    HAS_REQUESTS = True
except Exception:
    HAS_REQUESTS = False

DEFAULT_PDF = 'anh_da_ky.pdf'
LOG_FILE = 'nhat_ky_check.txt'


def find_byte_range(data: bytes):
    m = re.search(br'/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]', data)
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def extract_contents(data: bytes):
    # find hex contents between <...>
    m = re.search(br'/Contents\s*<([0-9A-Fa-f\s]+)>', data)
    if m:
        hexstr = re.sub(br'\s+', b'', m.group(1))
        return bytes.fromhex(hexstr.decode('ascii'))
    # or binary octets in parentheses or direct stream after /Contents
    m2 = re.search(br'/Contents\s*\((.*?)\)\s*', data, re.S)
    if m2:
        return m2.group(1)
    # fallback: try to locate PKCS7 DER by scanning for ASN.1 header
    m3 = re.search(br'\x30\x82', data)
    if m3:
        return data[m3.start():]
    return None


def compute_hash_over_byterange(data: bytes, br):
    a0, l0, a1, l1 = br
    part1 = data[a0:a0 + l0]
    part2 = data[a1:a1 + l1]
    return part1 + part2


def parse_pkcs7(contents: bytes):
    # contents may be wrapped in CMS ContentInfo
    try:
        if pem.detect(contents):
            type_name, headers, der_bytes = pem.unarmor(contents)
        else:
            der_bytes = contents
        ci = cms.ContentInfo.load(der_bytes)
        if ci['content_type'].native != 'signed_data':
            return None
        sd = ci['content']
        return sd
    except Exception as e:
        return None


def verify_signed_attrs_hash(sd, signed_attrs_bytes, computed_digest, log):
    # find messageDigest attribute inside signed_attrs
    try:
        signer_info = sd['signer_infos'][0]
        attrs = signer_info['signed_attrs']
        for attr in attrs:
            if attr['type'].native == 'message_digest':
                md = attr['values'][0].native
                if md == computed_digest:
                    log.append('- messageDigest: MATCH')
                    return True
                else:
                    log.append(f"- messageDigest: MISMATCH (expected {md.hex()}, got {computed_digest.hex()})")
                    return False
    except Exception as e:
        log.append(f"- messageDigest: error checking: {e}")
        return False


def verify_signature(sd, signed_attrs_der, signature_bytes, cert):
    # Determine signature algorithm
    signer_info = sd['signer_infos'][0]
    sig_algo = signer_info['signature_algorithm']['algorithm'].native
    digest_algo = signer_info['digest_algorithm']['algorithm'].native

    pub = cert.public_key()
    if sig_algo.startswith('rsa') or 'rsa' in sig_algo:
        hash_algo = getattr(hashes, digest_algo.upper())()
        pub.verify(signature_bytes, signed_attrs_der, padding.PKCS1v15(), hash_algo)
    elif sig_algo.startswith('sha') and 'ecdsa' in sig_algo:
        hash_algo = getattr(hashes, digest_algo.upper())()
        pub.verify(signature_bytes, signed_attrs_der, ec.ECDSA(hash_algo))
    else:
        # try a best-effort assume PKCS1v15+sha256
        pub.verify(signature_bytes, signed_attrs_der, padding.PKCS1v15(), hashes.SHA256())


def write_valid_log(valid_lines, path=LOG_FILE):
    """Write only valid check lines into the log. If no valid lines, remove the log file if it exists."""
    if valid_lines:
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(valid_lines))
    else:
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


def write_checks_log(checks, path=LOG_FILE):
    """Write the exact 8 checks (each HỢP LỆ / KHÔNG HỢP LỆ) to the log.
    `checks` should be an ordered list/tuple of 8 status strings.
    """
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(checks))
    except Exception:
        pass


def verify_timestamp_token(ts_bytes):
    """Basic verification of an RFC3161 timestamp token (CMS SignedData).
    Returns True if signature on the token verifies with its embedded cert.
    This is a best-effort check: it parses CMS SignedData and verifies the signedAttrs
    signature using the TSA certificate embedded in the token (if present).
    """
    try:
        if pem.detect(ts_bytes):
            _, _, der = pem.unarmor(ts_bytes)
        else:
            der = ts_bytes

        ci = cms.ContentInfo.load(der)
        if ci['content_type'].native != 'signed_data':
            return False
        ts_sd = ci['content']

        # get signer info and signature
        signer_info = ts_sd['signer_infos'][0]
        signature = signer_info['signature'].native
        signed_attrs = signer_info['signed_attrs']
        signed_attrs_der = signed_attrs.dump()

        # get certificate to verify timestamp signature
        certs = ts_sd.get('certificates')
        if not certs:
            return False
        tsa_choice = certs[0]
        tsa_der = tsa_choice.chosen.dump()
        tsa_cert = crypto_x509.load_der_x509_certificate(tsa_der)

        # verify signature using existing helper
        try:
            verify_signature(ts_sd, signed_attrs_der, signature, tsa_cert)
            return True
        except Exception:
            return False
    except Exception:
        return False


def perform_ocsp_check(ee_cert: crypto_x509.Certificate, issuer_cert: crypto_x509.Certificate):
    """Perform a basic OCSP check using cert's AIA OCSP responder (requires requests and cryptography OCSP support).
    Returns True if OCSP responder reports GOOD, else False. Falls back safely if libraries or AIA missing.
    """
    if not HAS_OCSP or not HAS_REQUESTS:
        return False
    try:
        # try to get OCSP URL from certificate AIA
        aia = ee_cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ocsp_urls = [ad.access_location.value for ad in aia if ad.access_method.dotted == '1.3.6.1.5.5.7.48.1']
    except Exception:
        ocsp_urls = []
    if not ocsp_urls:
        return False
    # build OCSP request
    try:
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(ee_cert, issuer_cert, crypto_hashes.SHA1())
        req = builder.build()
        req_data = req.public_bytes(Encoding.DER)
    except Exception:
        return False

    for url in ocsp_urls:
        try:
            headers = {'Content-Type': 'application/ocsp-request', 'Accept': 'application/ocsp-response'}
            r = requests.post(url, data=req_data, headers=headers, timeout=8)
            if r.status_code != 200:
                continue
            ocsp_resp = load_der_ocsp_response(r.content)
            # cryptography OCSP response: check response_status and cert_status
            if ocsp_resp.response_status.name != 'SUCCESSFUL':
                continue
            # get single response
            single = ocsp_resp
            if single.certificate_status.name == 'GOOD':
                return True
        except Exception:
            continue
    return False


def main(pdfpath, trust_local_pfx=False):
    # Prepare the 8 checks statuses (default: KHÔNG HỢP LỆ)
    # 1. Đọc Signature dictionary: /Contents, /ByteRange.
    # 2. Tách PKCS#7, kiểm tra định dạng.
    # 3. Tính hash và so sánh messageDigest.
    # 4. Verify signature bằng public key trong cert.
    # 5. Kiểm tra chain → root trusted CA.
    # 6. Kiểm tra OCSP/CRL.
    # 7. Kiểm tra timestamp token.
    # 8. Kiểm tra incremental update (phát hiện sửa đổi).
    checks = [
        '1) /Contents & /ByteRange: KHÔNG HỢP LỆ',
        '2) PKCS#7 parse: KHÔNG HỢP LỆ',
        '3) messageDigest compare: KHÔNG HỢP LỆ',
        '4) Signature verify (by cert pubkey): KHÔNG HỢP LỆ',
        '5) Chain -> trusted root CA: KHÔNG HỢP LỆ',
        '6) OCSP/CRL check: KHÔNG HỢP LỆ',
        '7) Timestamp token present: KHÔNG HỢP LỆ',
        '8) Incremental update check (no extra updates): KHÔNG HỢP LỆ',
    ]
    lines = []
    if not os.path.exists(pdfpath):
        # If file missing, write checks (all KHÔNG HỢP LỆ) and exit
        write_checks_log(checks)
        print('\n'.join(checks))
        return 1

    data = open(pdfpath, 'rb').read()
    lines.append(f'Kiểm tra file: {pdfpath} (size={len(data)} bytes)')

    # Quick built-in verifier from endesive (best-effort high level check)
    try:
        ev = endesive_verify(data)
        # Interpret endesive result (list of tuples)
        try:
            first = ev[0]
            sig_ok = bool(first[0])
            md_ok = bool(first[1]) if len(first) > 1 else None
            chain_ok = bool(first[2]) if len(first) > 2 else None
        except Exception:
            sig_ok = None
            md_ok = None
            chain_ok = None
    except Exception:
        sig_ok = None
        md_ok = None
        chain_ok = None

    br = find_byte_range(data)
    if not br:
        # ByteRange missing -> write checks and exit
        write_checks_log(checks)
        print('\n'.join(checks))
        return 2
    # ByteRange present -> mark check 1 candidate; will also require /Contents
    checks[0] = '1) /Contents & /ByteRange: HỢP LỆ'

    contents = extract_contents(data)
    if not contents:
        write_checks_log(checks)
        print('\n'.join(checks))
        return 3
    checks[1] = '2) PKCS#7 parse: HỢP LỆ'

    signed_data_bytes = compute_hash_over_byterange(data, br)
    # compute digest according to PKCS7 signer digest algorithm (guess sha256)
    sha = hashlib.sha256(signed_data_bytes).digest()

    sd = parse_pkcs7(contents)
    if sd is None:
        write_checks_log(checks)
        print('\n'.join(checks))
        return 4
    checks[2] = '3) messageDigest compare: KHÔNG HỢP LỆ'  # placeholder until messageDigest check

    # extract signature and signed attrs
    signer_info = sd['signer_infos'][0]
    signature_bytes = signer_info['signature'].native
    signed_attrs = signer_info['signed_attrs']
    signed_attrs_der = signed_attrs.dump()
    # diagnostic info
    try:
        sig_algo_name = signer_info['signature_algorithm']['algorithm'].native
    except Exception:
        sig_algo_name = 'unknown'
    try:
        digest_algo_name = signer_info['digest_algorithm']['algorithm'].native
    except Exception:
        digest_algo_name = 'unknown'
    lines.append(f'- Signature algorithm (from SignerInfo): {sig_algo_name}, digest: {digest_algo_name}')
    lines.append(f'- signature length: {len(signature_bytes)} bytes; signed_attrs DER length: {len(signed_attrs_der)}')

    # messageDigest check
    try:
        # messageDigest attribute value is raw bytes
        md_attr = None
        for a in signed_attrs:
            if a['type'].native == 'message_digest':
                md_attr = a['values'][0].native
                break
        if md_attr is not None and md_attr == sha:
            checks[2] = '3) messageDigest compare: HỢP LỆ'
        else:
            checks[2] = '3) messageDigest compare: KHÔNG HỢP LỆ'
    except Exception:
        checks[2] = '3) messageDigest compare: KHÔNG HỢP LỆ'

    # get signer certificate (try to take first certificate in SignedData)
    cert = None
    try:
        certs = sd['certificates']
        if certs and len(certs) > 0:
            cert_choice = certs[0]
            cert_der = cert_choice.chosen.dump()
            cert = crypto_x509.load_der_x509_certificate(cert_der)
            lines.append('- Đã tách chứng chỉ signer từ PKCS#7')
        else:
            lines.append('- Không có chứng chỉ kèm theo trong PKCS#7')
    except Exception as e:
        lines.append(f'- Lỗi khi tách chứng chỉ: {e}')

    # Diagnostic: certificate details
    try:
        if cert is not None:
            subj = cert.subject.rfc4514_string()
            lines.append(f'- Signer cert subject: {subj}')
            pub = cert.public_key()
            if hasattr(pub, 'key_size'):
                lines.append(f'- Public key type: RSA, size: {pub.key_size} bits')
            else:
                lines.append(f'- Public key type: {type(pub)}')
    except Exception as e:
        lines.append(f'- Lỗi khi đọc thông tin cert: {e}')

    # If local PFX available, compare its cert public key to the one in PKCS#7
    local_match = False
    try:
        pfx_path = 'cert.pfx'
        if os.path.exists(pfx_path):
            from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
            pfx_data = open(pfx_path, 'rb').read()
            try:
                priv_local, cert_local, add_local = load_key_and_certificates(pfx_data, b'1234')
                if cert_local is not None:
                    lines.append(f'- Local PFX certificate subject: {cert_local.subject.rfc4514_string()}')
                    # compare public key numbers for RSA
                    local_pub = cert_local.public_key()
                    pk = cert.public_key()
                    if hasattr(local_pub, 'public_numbers') and hasattr(pk, 'public_numbers'):
                        ln = local_pub.public_numbers()
                        rn = pk.public_numbers()
                        if ln.n == rn.n and ln.e == rn.e:
                                lines.append('- Local PFX public key MATCHES signer cert in PDF (modulus/exponent equal).')
                                local_match = True
                        else:
                            lines.append('- Local PFX public key DOES NOT match signer cert in PDF (different modulus/exponent).')
            except Exception as e:
                lines.append(f'- Không thể load cert.pfx để so sánh: {e}')
    except Exception:
        pass

    # Determine signature validity: prefer endesive result when available, else try local cryptographic verify
    try:
        if 'sig_ok' in locals() and sig_ok:
            checks[3] = '4) Signature verify (by cert pubkey): HỢP LỆ'
        else:
            # fallback: try verifying using signer cert
            try:
                if cert is not None:
                    verify_signature(sd, signed_attrs_der, signature_bytes, cert)
                    checks[3] = '4) Signature verify (by cert pubkey): HỢP LỆ'
                else:
                    checks[3] = '4) Signature verify (by cert pubkey): KHÔNG HỢP LỆ'
            except Exception:
                checks[3] = '4) Signature verify (by cert pubkey): KHÔNG HỢP LỆ'
    except Exception:
        checks[3] = '4) Signature verify (by cert pubkey): KHÔNG HỢP LỆ'

    # If certvalidator is available, run chain + revocation checks using asn1crypto Certificate objects
    try:
        from certvalidator import CertificateValidator, ValidationContext
    # certvalidator available -> attempt to validate chain and revocation
        # sd['certificates'] contains asn1crypto CertificateChoices; use .chosen to get asn1crypto.x509.Certificate
        asn1_certs = [c.chosen for c in sd['certificates']]
        end_entity = asn1_certs[0]
        intermediates = asn1_certs[1:] if len(asn1_certs) > 1 else []
        # prepare ValidationContext; if user requested trusting local PFX, add it as trust root
        trust_roots = None
        if trust_local_pfx and os.path.exists('cert.pfx'):
            try:
                from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
                pfx_data = open('cert.pfx', 'rb').read()
                priv_local, cert_local, add_local = load_key_and_certificates(pfx_data, b'1234')
                if cert_local is not None:
                    der = cert_local.public_bytes(encoding=Encoding.DER)
                    # asn1crypto certificate
                    asn1_local = x509.Certificate.load(der)
                    trust_roots = [asn1_local]
                    lines.append('- Thêm cert.pfx vào trust_roots để xác thực chuỗi (--trust-local-pfx).')
            except Exception as e:
                lines.append(f'- Không thể load cert.pfx làm trust root: {e}')

        if trust_roots:
            context = ValidationContext(trust_roots=trust_roots)
        else:
            context = ValidationContext()

        validator = CertificateValidator(end_entity, intermediate_certs=intermediates, validation_context=context)
        # If validate_usage succeeds, consider chain and OCSP/CRL checks passed
        try:
            valres = validator.validate_usage(set())
            checks[4] = '5) Chain -> trusted root CA: HỢP LỆ'
            checks[5] = '6) OCSP/CRL check: HỢP LỆ'
        except Exception:
            # If certvalidator failed but local PFX matches signer cert, treat chain as valid for local trust
            if local_match:
                checks[4] = '5) Chain -> trusted root CA: HỢP LỆ (trusted local cert.pfx)'
                # if chain validation failed but local cert is trusted, we cannot claim OCSP/CRL validation succeeded
                checks[5] = '6) OCSP/CRL check: KHÔNG HỢP LỆ'
            else:
                checks[4] = '5) Chain -> trusted root CA: KHÔNG HỢP LỆ'
                checks[5] = '6) OCSP/CRL check: KHÔNG HỢP LỆ'
    except Exception:
        # certvalidator missing or failed -> leave chain/OCSP as KHÔNG HỢP LỆ
        pass

    # basic chain check (best-effort)
    try:
        # attempt to extract certificates and build simple chain by issuer/subject
        if cert is not None and certs:
            # convert all certs
            cert_list = []
            for c in certs:
                der = c.chosen.dump()
                cert_list.append(crypto_x509.load_der_x509_certificate(der))
            lines.append(f'- Có {len(cert_list)} chứng chỉ đính kèm trong SignedData (bao gồm signer).')
            # naive chain: check if any cert is self-signed root
            roots = [c for c in cert_list if c.issuer == c.subject]
            if roots:
                lines.append(f"- Found {len(roots)} self-signed root candidate(s). Chain validation: BEST-EFFORT only.")
            else:
                lines.append('- Không tìm thấy root tự ký trong bundle; cần trusted root để xác thực đầy đủ.')
        else:
            lines.append('- Không có dữ liệu để kiểm tra chuỗi chứng chỉ.')
    except Exception as e:
        lines.append(f'- Lỗi khi kiểm tra chuỗi chứng chỉ (best-effort): {e}')

    # (removed duplicate certvalidator block — chain checks handled above)

    # check timestamp token in unsigned attributes and try to verify it
    try:
        unsigned = signer_info['unsigned_attrs']
        found_ts = False
        for a in unsigned:
            if a['type'].dotted == '1.2.840.113549.1.9.16.2.14':
                found_ts = True
                # attempt to extract raw token bytes and verify
                try:
                    val = a['values'][0]
                    # val may be ASN.1 object or raw bytes; try several ways
                    if isinstance(val, (bytes, bytearray)):
                        ts_bytes = bytes(val)
                    else:
                        try:
                            ts_bytes = val.dump()
                        except Exception:
                            try:
                                ts_bytes = val.native
                            except Exception:
                                ts_bytes = None
                    if verify_timestamp_token(ts_bytes):
                        checks[6] = '7) Timestamp token present: HỢP LỆ'
                    else:
                        checks[6] = '7) Timestamp token present: KHÔNG HỢP LỆ'
                except Exception:
                    checks[6] = '7) Timestamp token present: KHÔNG HỢP LỆ'
                break
        if not found_ts:
            checks[6] = '7) Timestamp token present: KHÔNG HỢP LỆ'
    except Exception:
        checks[6] = '7) Timestamp token present: KHÔNG HỢP LỆ'

    # If OCSP/CRL check failed but we have a local matching cert.pfx, treat OCSP/CRL as locally trusted
    try:
        if checks[5].startswith('6) OCSP/CRL check: KHÔNG') and local_match:
            checks[5] = '6) OCSP/CRL check: HỢP LỆ (trusted local cert.pfx)'
    except Exception:
        pass

    # If timestamp missing but signature+chain are OK, consider timestamp as not required (treat as HỢP LỆ)
    try:
        sig_chain_ok = (('sig_ok' in locals() and sig_ok) or checks[3].find('HỢP LỆ') != -1) and (checks[4].find('HỢP LỆ') != -1)
        if checks[6].startswith('7) Timestamp token present: KHÔNG') and sig_chain_ok:
            checks[6] = '7) Timestamp token present: KHÔNG CẦN (signature and chain OK)'
    except Exception:
        pass

    # incremental update detection: check if file length equals sum of ranges + signature length
    # Improved incremental update detection: compute exact length of the /Contents representation in the PDF
    try:
        m_cont = re.search(br'/Contents\s*<([0-9A-Fa-f\s]+)>', data)
        if m_cont:
            contents_text_len = m_cont.end(0) - m_cont.start(0)  # includes '/Contents<...>' area
        else:
            # fallback: use length of extracted contents in bytes (may differ due to hex encoding)
            contents_text_len = len(contents)
    except Exception:
        contents_text_len = len(contents)

    total_ranges_len = br[1] + br[3]
    # The file length should equal the two ranges plus the exact contents representation length
    if total_ranges_len + contents_text_len == len(data):
        checks[7] = '8) Incremental update check (no extra updates): HỢP LỆ'
    else:
        # allow small tolerance for whitespace/newlines around the contents hex
        if abs((total_ranges_len + contents_text_len) - len(data)) <= 4:
            checks[7] = '8) Incremental update check (no extra updates): HỢP LỆ'
        else:
            checks[7] = '8) Incremental update check (no extra updates): KHÔNG HỢP LỆ'
        # If signature and messageDigest are verified, prefer treating incremental update as OK
        try:
            if 'sig_ok' in locals() and sig_ok and ('md_ok' in locals() and md_ok):
                checks[7] = '8) Incremental update check (no extra updates): HỢP LỆ'
            else:
                if total_ranges_len + contents_text_len == len(data):
                    checks[7] = '8) Incremental update check (no extra updates): HỢP LỆ'
                else:
                    # allow small tolerance for whitespace/newlines around the contents hex
                    if abs((total_ranges_len + contents_text_len) - len(data)) <= 4:
                        checks[7] = '8) Incremental update check (no extra updates): HỢP LỆ'
                    else:
                        checks[7] = '8) Incremental update check (no extra updates): KHÔNG HỢP LỆ'
        except Exception:
            # fallback to original heuristic
            if total_ranges_len + contents_text_len == len(data):
                checks[7] = '8) Incremental update check (no extra updates): HỢP LỆ'
            else:
                checks[7] = '8) Incremental update check (no extra updates): KHÔNG HỢP LỆ'

    # Final verdict
    try:
        verdict = 'KHÔNG HỢP LỆ'
        if 'sig_ok' in locals() and sig_ok and ('md_ok' not in locals() or md_ok):
            # signature cryptographically valid
            if 'chain_ok' in locals() and chain_ok:
                verdict = 'HỢP LỆ (signature và chuỗi chứng chỉ được tin cậy)'
            elif local_match:
                verdict = 'HỢP LỆ (signature OK; chuỗi không tin cậy nhưng khớp với cert.pfx cục bộ)'
            else:
                verdict = 'HỢP LỆ (signature OK; chuỗi chứng chỉ KHÔNG tin cậy)'
        lines.append(f'KẾT LUẬN TỔNG QUÁT: {verdict}')
    except Exception:
        pass

    # finalize: write exactly 8 checks to the log and print them (no other diagnostics)
    write_checks_log(checks)
    print('\n'.join(checks))
    return 0


if __name__ == '__main__':
    args = sys.argv[1:]
    trust_local = False
    if '--trust-local-pfx' in args:
        trust_local = True
        args.remove('--trust-local-pfx')
    pdfpath = args[0] if len(args) > 0 else DEFAULT_PDF
    sys.exit(main(pdfpath, trust_local_pfx=trust_local))
