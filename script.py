#!/usr/bin/env python3
import argparse
import base64
from datetime import datetime, timezone
from lxml import etree

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7SignatureBuilder, PKCS7Options

# ------------------------
# CLI
# ------------------------
parser = argparse.ArgumentParser(description="Generate PKCS#7 or XML/XAdES signatures")
parser.add_argument("--mode", choices=["pkcs7", "xml"], required=True)
parser.add_argument("--input", required=True)
parser.add_argument("--cert", required=True)
parser.add_argument("--key", required=True)
parser.add_argument("--password", help="Private key password if encrypted")
parser.add_argument("--out-signature", required=True)
parser.add_argument("--detached", action="store_true", help="For PKCS#7: detached signature")
parser.add_argument("--signing-time", help="Fixed SigningTime (e.g., 2025-11-20T23:01:46Z)")
args = parser.parse_args()

password = args.password.encode() if args.password else None

# ------------------------
# Load key and certificate
# ------------------------
with open(args.key, "rb") as f:
    key_bytes = f.read()
private_key = load_pem_private_key(key_bytes, password=password)

with open(args.cert, "rb") as f:
    cert_bytes = f.read()
cert = load_pem_x509_certificate(cert_bytes)
cert_der_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()

# ------------------------
# Helpers
# ------------------------
def c14n(el):
    """Exclusive c14n without comments."""
    return etree.tostring(el, method="c14n", exclusive=True, with_comments=False)

# ------------------------
# PKCS#7 signing
# ------------------------
def sign_pkcs7(input_path, output_path, detached):
    with open(input_path, "rb") as f:
        data = f.read()
    builder = PKCS7SignatureBuilder().set_data(data).add_signer(cert, private_key, hashes.SHA256())
    options = [PKCS7Options.DetachedSignature] if detached else []
    sig = builder.sign(encoding=Encoding.PEM, options=options)
    with open(output_path, "wb") as f:
        f.write(sig)
    print(f"PKCS#7 signature written to: {output_path}")

# ------------------------
# XML/XAdES signing
# ------------------------
def sign_xml(input_path, output_path, fixed_signing_time=None):
    NS_DS = "http://www.w3.org/2000/09/xmldsig#"
    NS_XADES = "http://uri.etsi.org/01903/v1.3.2#"
    NS_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"
    NSMAP = {None: NS_DS, "xades": NS_XADES}

    parser = etree.XMLParser(remove_blank_text=False)
    tree = etree.parse(input_path, parser)
    root = tree.getroot()

    # Build SignedProperties
    signed_props = etree.Element(f"{{{NS_XADES}}}SignedProperties", Id="SignedProperties", nsmap=NSMAP)
    ssp = etree.SubElement(signed_props, f"{{{NS_XADES}}}SignedSignatureProperties")
    signing_time_text = fixed_signing_time or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    etree.SubElement(ssp, f"{{{NS_XADES}}}SigningTime").text = signing_time_text

    sc = etree.SubElement(ssp, f"{{{NS_XADES}}}SigningCertificate")
    cert_el = etree.SubElement(sc, f"{{{NS_XADES}}}Cert")
    cert_digest = etree.SubElement(cert_el, f"{{{NS_XADES}}}CertDigest")
    etree.SubElement(cert_digest, f"{{{NS_DS}}}DigestMethod", Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
    h_cert = hashes.Hash(hashes.SHA256())
    h_cert.update(cert.public_bytes(serialization.Encoding.DER))
    etree.SubElement(cert_digest, f"{{{NS_DS}}}DigestValue").text = base64.b64encode(h_cert.finalize()).decode()
    issuer_serial = etree.SubElement(cert_el, f"{{{NS_XADES}}}IssuerSerial")
    etree.SubElement(issuer_serial, f"{{{NS_DS}}}X509IssuerName").text = cert.issuer.rfc4514_string()
    etree.SubElement(issuer_serial, f"{{{NS_DS}}}X509SerialNumber").text = str(cert.serial_number)

    # Build Signature
    signature_el = etree.Element(f"{{{NS_DS}}}Signature", Id="Signature-3427863444", nsmap=NSMAP)
    signed_info = etree.SubElement(signature_el, f"{{{NS_DS}}}SignedInfo")
    etree.SubElement(signed_info, f"{{{NS_DS}}}CanonicalizationMethod",
                     Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
    etree.SubElement(signed_info, f"{{{NS_DS}}}SignatureMethod",
                     Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

    # Reference to whole doc
    ref1 = etree.SubElement(signed_info, f"{{{NS_DS}}}Reference", URI="")
    t1 = etree.SubElement(ref1, f"{{{NS_DS}}}Transforms")
    etree.SubElement(t1, f"{{{NS_DS}}}Transform", Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    etree.SubElement(t1, f"{{{NS_DS}}}Transform", Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
    etree.SubElement(ref1, f"{{{NS_DS}}}DigestMethod", Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
    dv1 = etree.SubElement(ref1, f"{{{NS_DS}}}DigestValue")

    # Reference to SignedProperties
    ref2 = etree.SubElement(signed_info, f"{{{NS_DS}}}Reference",
                            URI="#SignedProperties", Type="http://uri.etsi.org/01903#SignedProperties")
    t2 = etree.SubElement(ref2, f"{{{NS_DS}}}Transforms")
    inc_t = etree.SubElement(t2, f"{{{NS_DS}}}Transform", Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
    etree.SubElement(inc_t, f"{{{NS_EXC}}}InclusiveNamespaces", PrefixList="xades")
    etree.SubElement(ref2, f"{{{NS_DS}}}DigestMethod", Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
    dv2 = etree.SubElement(ref2, f"{{{NS_DS}}}DigestValue")

    sigval_el = etree.SubElement(signature_el, f"{{{NS_DS}}}SignatureValue")

    ki = etree.SubElement(signature_el, f"{{{NS_DS}}}KeyInfo")
    x509 = etree.SubElement(ki, f"{{{NS_DS}}}X509Data")
    etree.SubElement(x509, f"{{{NS_DS}}}X509Certificate").text = cert_der_b64

    obj = etree.SubElement(signature_el, f"{{{NS_DS}}}Object")
    qp = etree.SubElement(obj, f"{{{NS_XADES}}}QualifyingProperties", Target="#Signature-3427863444")
    qp.append(signed_props)

    # Append Signature
    root.append(signature_el)

    # Compute digest for URI=""
    doc_clone = etree.fromstring(etree.tostring(root))
    sig_clone = doc_clone.find(f".//{{{NS_DS}}}Signature")
    if sig_clone is not None:
        sig_parent = sig_clone.getparent()
        if sig_parent is not None:
            sig_parent.remove(sig_clone)
    h1 = hashes.Hash(hashes.SHA256())
    h1.update(c14n(doc_clone))
    dv1.text = base64.b64encode(h1.finalize()).decode()

    # Compute digest for SignedProperties
    sp_node = signature_el.find(f".//{{{NS_XADES}}}SignedProperties")
    h2 = hashes.Hash(hashes.SHA256())
    h2.update(c14n(sp_node))
    dv2.text = base64.b64encode(h2.finalize()).decode()

    # Sign SignedInfo
    si_c14n = c14n(signed_info)
    sig_bytes = private_key.sign(si_c14n, padding.PKCS1v15(), hashes.SHA256())
    sigval_el.text = base64.b64encode(sig_bytes).decode()

    tree.write(output_path, xml_declaration=True, encoding="utf-8")
    print(f"Signed XML written to: {output_path}")

# ------------------------

# ------------------------
# Dispatch
# ------------------------
if args.mode == "pkcs7":
    sign_pkcs7(args.input, args.out_signature, args.detached)
elif args.mode == "xml":
    fixed_time = args.signing_time if args.signing_time else None
    sign_xml(args.input, args.out_signature, fixed_signing_time=fixed_time)
