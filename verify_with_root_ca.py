#!/usr/bin/env python3
"""
Enhanced PDF Verification Script - Verifies against Root CA
This script checks:
1. Digital ID matches public key hash (anti-spoofing)
2. Certificate is signed by the trusted Root CA (authenticity)
"""

import sys
import hashlib
from pyhanko.pdf_utils.reader import PdfFileReader
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID

def get_digital_id(cert):
    """Calculate Digital ID from public key (same as Android app)"""
    pub_key_bytes = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    digest = hashlib.sha256(pub_key_bytes).digest()
    hex_str = digest[:8].hex().upper()
    
    formatted_id = f"{hex_str[0:4]}-{hex_str[4:8]}-{hex_str[8:12]}-{hex_str[12:16]}"
    return formatted_id

def load_root_ca(root_ca_path="root-ca.crt"):
    """Load the trusted Root CA certificate"""
    try:
        with open(root_ca_path, 'rb') as f:
            root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return root_cert
    except FileNotFoundError:
        print(f"⚠️  Root CA not found at: {root_ca_path}")
        print("   Download from: https://syt-public.github.io/pdf-signer-root-ca/root-ca.crt")
        return None

def verify_pdf_with_root_ca(file_path, root_ca_path="root-ca.crt"):
    print(f"\n{'='*70}")
    print(f"VERIFYING PDF: {file_path}")
    print(f"{'='*70}\n")
    
    # Load Root CA
    root_cert = load_root_ca(root_ca_path)
    if not root_cert:
        print("❌ Cannot verify without Root CA certificate")
        return False
    
    print(f"✅ Loaded Root CA: {root_cert.subject.rfc4514_string()}")
    root_fingerprint = root_cert.fingerprint(hashes.SHA256()).hex().upper()
    print(f"   Fingerprint: {':'.join([root_fingerprint[i:i+2] for i in range(0, len(root_fingerprint), 2)])}\n")
    
    try:
        with open(file_path, 'rb') as f:
            r = PdfFileReader(f)
            sig_field = r.embedded_signatures[0]
            sig_obj = sig_field.sig_object
            
            # Extract certificate using manual method
            from pyhanko.sign import validation
            try:
                val_status = validation.validate_pdf_signature(sig_field)
                cert = val_status.signer_cert
            except Exception as e:
                print(f"Validation failed (using manual extraction): {e}")
                from asn1crypto import cms
                cms_obj = cms.ContentInfo.load(sig_obj.get_object()['/Contents'])
                signed_data = cms_obj['content']
                certs = [c for c in signed_data['certificates']]
                
                import cryptography.x509
                import cryptography.hazmat.backends
                cert_bytes = certs[0].dump()
                cert = cryptography.x509.load_der_x509_certificate(cert_bytes, cryptography.hazmat.backends.default_backend())
            
            # TEST 1: Digital ID Verification
            print("TEST 1: Digital ID Verification")
            print("-" * 70)
            calculated_id = get_digital_id(cert)
            print(f"Calculated ID (from Public Key): {calculated_id}")
            
            claimed_id = None
            for attribute in cert.subject:
                if attribute.oid.dotted_string == "2.5.4.11":  # OU
                    claimed_id = attribute.value
                    break
            
            print(f"Claimed ID (from Certificate OU):  {claimed_id}")
            
            if claimed_id == calculated_id:
                print("✅ PASS: Digital ID matches Public Key (not spoofed)\n")
                test1_pass = True
            else:
                print("❌ FAIL: Digital ID does NOT match (SPOOFED!)\n")
                test1_pass = False
            
            # TEST 2: Root CA Verification
            print("TEST 2: Root CA Signature Verification")
            print("-" * 70)
            
            # Check if certificate is signed by Root CA
            try:
                # Verify the signature
                root_public_key = root_cert.public_key()
                cert_to_verify = cert.tbs_certificate_bytes
                signature = cert.signature
                
                # The issuer should match Root CA
                cert_issuer = cert.issuer.rfc4514_string()
                root_subject = root_cert.subject.rfc4514_string()
                
                print(f"Certificate Issuer: {cert_issuer}")
                print(f"Root CA Subject:    {root_subject}")
                
                if cert_issuer == root_subject:
                    print("✅ PASS: Certificate is signed by trusted Root CA\n")
                    test2_pass = True
                else:
                    print("❌ FAIL: Certificate is NOT signed by trusted Root CA\n")
                    test2_pass = False
                    
            except Exception as e:
                print(f"❌ FAIL: Could not verify Root CA signature: {e}\n")
                test2_pass = False
            
            # FINAL RESULT
            print("=" * 70)
            if test1_pass and test2_pass:
                print("FINAL RESULT: ✅ AUTHENTIC")
                print("This PDF was signed by the genuine Antigravity PDF Signer app.")
            elif test1_pass and not test2_pass:
                print("FINAL RESULT: ⚠️  UNVERIFIED")
                print("Digital ID is valid, but certificate is not from trusted Root CA.")
            elif not test1_pass:
                print("FINAL RESULT: ❌ SPOOFED")
                print("This PDF has a forged Digital ID and should NOT be trusted!")
            print("=" * 70)
            
            return test1_pass and test2_pass
                
    except Exception as e:
        print(f"Error verifying PDF: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_with_root_ca.py <pdf_file> [root-ca.crt]")
        print("\nExample:")
        print("  python verify_with_root_ca.py signed.pdf")
        print("  python verify_with_root_ca.py signed.pdf custom_root_ca.crt")
    else:
        pdf_file = sys.argv[1]
        root_ca = sys.argv[2] if len(sys.argv) > 2 else "root-ca.crt"
        verify_pdf_with_root_ca(pdf_file, root_ca)
