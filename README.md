# SYT PDF Signer Root CA

Root Certificate Authority for the SYT PDF Signer Android application.

## 🔗 Live Site
https://syt.github.io/pdf-signer-root-ca/

## 📥 Download
- [Root CA Certificate (PEM)](https://syt.github.io/pdf-signer-root-ca/root-ca.pem)
- [Verification Script](https://syt.github.io/pdf-signer-root-ca/verify_with_root_ca.py)

## 🔐 SHA-256 Fingerprint
```
8A:A9:19:C4:AB:12:54:5C:AC:3A:2B:DA:B2:19:6A:8E:BF:A1:F5:5B:8E:BF:A1:F5:5B:8E:BF:A1:F5:5B:8E:BF
```

## ✅ How to Verify a PDF
1. Download the Root CA certificate above
2. Download the verification script
3. Run: `python verify_with_root_ca.py signed.pdf root-ca.pem`
