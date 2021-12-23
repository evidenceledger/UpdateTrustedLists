from binascii import Error
import json
import base64

from devtools import debug

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from cryptojwt.jwk.ec import ECKey

def base64UrlEncode(x: bytes) -> str:
    x = base64.b64encode(x, altchars=b'-_')
    x = x.decode("ascii")
    return x

## Open and read the PEM file
with open("TestAzKeyVaultdiciembre2021.pem") as f:
    pem = f.read()

# Convert the PEM to a Certificate object
cert_obj = load_pem_x509_certificate(bytes(pem, "utf8"))

# Calculate the SHA-256 fingerprint of the certificate to calculate the KID
fingerprint = cert_obj.fingerprint(hashes.SHA256())
fg_b64 = base64UrlEncode(fingerprint)

# The KID is the base64Url encoding of the most significant 8 bytes of the fingerprint
kid_bytes = fingerprint[:8]
kid_b64 = base64UrlEncode(kid_bytes)

# Get the public key and check that it is EC
pub_key = cert_obj.public_key()
if not isinstance(pub_key, ec.EllipticCurvePublicKey):
    raise Error("Not an Elliptic curve public key")

# Convert the key to JWK format as python dict
ec_key = ECKey(pub_key=pub_key)
pub_key = ec_key.public_key()
key_dict = ec_key.to_dict()

# Add missing fields
key_dict["use"] = "sig"
key_dict["kid"] = kid_b64
key_dict["x5t#S256"] = fg_b64

# Create the structure needed for the Trusted List
jwk_key = {
    "co": "ES",
    "kid": kid_b64,
    "jwk": key_dict
}

# Print the structure so it can be inserted
print(json.dumps(jwk_key, indent=2, ensure_ascii=False))
