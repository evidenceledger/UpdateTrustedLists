# Download and prepare the production trusted list for the EU DCC

# From standard python library
from itertools import count
import json
import base64
from pathlib import Path
from shutil import copy2
from filecmp import cmp

# Requests
import requests

# PyJWT
import jwt

# Typer
import typer

# Create the main application
app = typer.Typer()

# The Swedish URLs to get the EU TrustList and associated Value Sets
URL_Trust_List_SE = "https://dgcg.covidbevis.se/tp/trust-list"
URL_Value_Set_IDs_SE = "https://dgcg.covidbevis.se/tp/valuesets"
Trust_list_Issuer_SE = "https://dgcg.covidbevis.se/tp"

# Default file name to save raw Trusted List as JWT
raw_EU_Trusted_List = "raw_eu_tl.jws"

# Default file name for the decoded Trusted List files
processed_EU_Trusted_List = "eu_jwk_keys.json"

# File to store Values sets
vsFileName = "value-sets.json"

# The URL with the Trustlist from UK
URL_Trust_List_UK = "https://covid-status.service.nhsx.nhs.uk/pubkeys/keys.json"
processed_UK_Trusted_List = "uk_jwk_keys.json"


# Download the trusted list of UK
@app.command()
def download_uk(out_fileName: str = processed_UK_Trusted_List):
    '''Download the Trusted List from UK'''

    typer.echo(f"Saving UK Trusted List to {out_fileName}")

    r = requests.get(URL_Trust_List_UK)
    r.raise_for_status()

    # Retrieve the TL
    tl = r.text

    # Save the JSON list
    with open(out_fileName, "w") as f:
        f.write(tl)


# Download the EU trusted list AS-IS, for later processing
@app.command()
def download(out_fileName: str = raw_EU_Trusted_List):
    '''Download the EU Trusted List from Sweden'''

    typer.echo(f"Saving raw EU Trusted List to {out_fileName}")

    r = requests.get(URL_Trust_List_SE)
    r.raise_for_status()

    # Retrieve the TL as a JWS
    dsc_tl_jws = r.text

    # Save the JWS for further reference
    with open(out_fileName, "w") as f:
        f.write(dsc_tl_jws)

from cryptography.x509 import load_pem_x509_certificate

def key_from_PEM():
    '''Get the public key from a PEM x509 certificate'''
    with open("sweden.pem", "rb") as f:
        cert_str = f.read()
    cert_obj = load_pem_x509_certificate(cert_str)
    public_key = cert_obj.public_key()
    return public_key

def verify(input_fileName: str = raw_EU_Trusted_List):
    '''Verify silently the raw file EU Trusted List downloaded from Sweden'''
    typer.echo("Verifying")

    with open(input_fileName, "r") as f:
        jwtTL = f.read()
    
    # Decode the components, without verifying the signature (for the moment)
    jws_components = jwtTL.split(".")
    if len(jws_components) != 3:
        raise Exception("Malformed JWS received")

    # Decode the header
    header = jws_components[0] + "=="
    header = base64.b64decode(header)
    header = json.loads(header)

    # Decode the payload
    p = jws_components[1] + "=="
    p = base64.b64decode(p)
    p = json.loads(p)

    # Try to decode with all possible verifications
    options = dict(
        verify_iss = True,
        verify_exp = True,
        verify_aud = False, # The jwt does not contain an 'aud' claim
        verify_iat = True,
        require = ["iss", "id", "exp", "iat"],
    )

    decoded = jwt.decode(jwtTL, key=key_from_PEM(), algorithms=["ES256"], issuer=Trust_list_Issuer_SE, options=options)

    dsc_trust_list = decoded["dsc_trust_list"]

    total_num_keys = 0
    num_ec_keys = 0
    num_rsa_keys = 0
    num_unkwnown_keys = 0

    for co in dsc_trust_list:
        country_orgs = set()
        country_rsa_keys = 0
        entry = dsc_trust_list[co]
        keys = entry["keys"]
        total_num_keys += len(keys)
        for key in keys:
            kty = key["kty"]
            if kty == "EC":
                num_ec_keys += 1
            elif kty == "RSA":
                num_rsa_keys += 1
                country_rsa_keys += 1
            else:
                num_unkwnown_keys += 1
            
            pem = key["x5c"][0]
            pem = f"-----BEGIN CERTIFICATE-----\n{pem}\n-----END CERTIFICATE-----"
            cert_obj = load_pem_x509_certificate(bytes(pem, "utf8"))
            rdns = cert_obj.subject.rdns
            for elem in rdns:
                if elem.rfc4514_string().startswith("O="):
                    country_orgs.add(elem.rfc4514_string())

@app.command()
def diagnostics(input_fileName: str = raw_EU_Trusted_List):
    '''Verify the raw file EU Trusted List downloaded from Sweden'''
    typer.echo("Verifying")

    with open(input_fileName, "r") as f:
        jwtTL = f.read()
    
    # Decode the components, without verifying the signature (for the moment)
    jws_components = jwtTL.split(".")
    if len(jws_components) != 3:
        raise Exception("Malformed JWS received")

    # Decode the header
    header = jws_components[0] + "=="
    header = base64.b64decode(header)
    header = json.loads(header)


    # Decode the payload
    p = jws_components[1] + "=="
    p = base64.b64decode(p)
    p = json.loads(p)

    # Try to decode with all possible verifications
    options = dict(
        verify_iss = True,
        verify_exp = True,
        verify_aud = False, # The jwt does not contain an 'aud' claim
        verify_iat = True,
        require = ["iss", "id", "exp", "iat"],
    )

    signature_expired = False
    try:
        decoded = jwt.decode(jwtTL, key=key_from_PEM(), algorithms=["ES256"], issuer=Trust_list_Issuer_SE, options=options)
    except jwt.exceptions.ExpiredSignatureError:
        signature_expired = True
        # Try to decode again without signature verification, to get the payload
        options = dict(
            verify_iss = True,
            verify_exp = False,
            verify_aud = False,
            verify_iat = True,
            require = ["iss", "id", "exp", "iat"],
        )
        decoded = jwt.decode(jwtTL, key=key_from_PEM(), algorithms=["ES256"], issuer=Trust_list_Issuer_SE, options=options)

    dsc_trust_list = decoded["dsc_trust_list"]

    # Print diagnostics about the list
    typer.echo(f"Size of JWT: {len(jwtTL)}")
    if signature_expired:
        typer.echo("Signature is expired")
        
    typer.echo(f'Algorithm: {header["alg"]}')
    typer.echo(f'Type of JWT: {header["typ"]}')

    typer.echo(f'Identifier of list: {decoded["id"]}')

    typer.echo(f'iss: {decoded["iss"]}')
    typer.echo(f'iat: {decoded["iat"]}')
    typer.echo(f'exp: {decoded["exp"]}')

    typer.echo(f"Number of countries: {len(dsc_trust_list)}")

    total_num_keys = 0
    num_ec_keys = 0
    num_rsa_keys = 0
    num_unkwnown_keys = 0

    for co in dsc_trust_list:
        country_orgs = set()
        country_rsa_keys = 0
        entry = dsc_trust_list[co]
        keys = entry["keys"]
        total_num_keys += len(keys)
        for key in keys:
            kty = key["kty"]
            if kty == "EC":
                num_ec_keys += 1
            elif kty == "RSA":
                num_rsa_keys += 1
                country_rsa_keys += 1
            else:
                num_unkwnown_keys += 1
            
            if key.get("use") == "enc":
                print(f"Warning, key usage is incorrect: {key}")

            pem = key["x5c"][0]
            pem = f"-----BEGIN CERTIFICATE-----\n{pem}\n-----END CERTIFICATE-----"
            cert_obj = load_pem_x509_certificate(bytes(pem, "utf8"))
            rdns = cert_obj.subject.rdns
            for elem in rdns:
                if elem.rfc4514_string().startswith("O="):
                    country_orgs.add(elem.rfc4514_string())
        typer.echo(f"Country {co}, keys: {len(keys)}, Orgs: {len(country_orgs)}")
        typer.echo(f"      Orgs: {country_orgs}")
        if country_rsa_keys > 0:
            typer.echo(f"      RSA Keys: {country_rsa_keys}")

    typer.echo(f"Total number of keys: {total_num_keys}")
    typer.echo(f"   EC: {num_ec_keys}")
    typer.echo(f"   RSA: {num_rsa_keys}")
    typer.echo(f"   OTHER: {num_unkwnown_keys}")



@app.command()
def decode(in_fileName: str = raw_EU_Trusted_List, out_fileName: str = processed_EU_Trusted_List):
    '''Convert raw EU Trust List to final format'''
    typer.echo("Decoding")

    with open(in_fileName, "r") as f:
        jwtTL = f.read()

    # Decode the payload, without verifying the signature (for the moment)
    jws_components = jwtTL.split(".")
    if len(jws_components) != 3:
        raise Exception("Malformed JWS received")
    payload = jws_components[1] + "=="
    payload = base64.b64decode(payload)

    dsc_tl = json.loads(payload)

    dsc_trust_list = dsc_tl['dsc_trust_list']

    new_dsc_tl = {}

    for co in dsc_trust_list:
        entry = dsc_trust_list[co]
        keys = entry["keys"]
        for key in keys:
            kid = key["kid"]

            del key["x5c"]

            new_dsc_tl[kid] = {
                "co": co,
                "kid": kid,
                "jwk": key
            }

    new_dsc_tl_json = json.dumps(new_dsc_tl, ensure_ascii=False, check_circular=False, indent=2)
    with open(out_fileName, "w") as f:
        f.write(new_dsc_tl_json)


map_id_to_file = {
    "country-2-codes": "country-2-codes",
    "covid-19-lab-test-manufacturer-and-name": "test-manf",
    "covid-19-lab-test-type": "test-type",
    "vaccines-covid-19-names": "vaccine-medicinal-product",
    "disease-agent-targeted": "disease-agent-targeted",
    "covid-19-lab-result": "test-result",
    "vaccines-covid-19-auth-holders": "vaccine-mah-manf",
    "sct-vaccines-covid-19": "vaccine-prophylaxis"
}

# Download the set of value set ids
def getValuesets():
    '''Download Value Sets from Sweden'''

    r = requests.get(URL_Value_Set_IDs_SE)
    r.raise_for_status()

    # Retrieve the TL as a JWS
    json_data = r.json()
    
    return json_data

# Download a given value set
def getValueSet(valueSet: str):
    '''Download a given Value Set'''

    vs_url = f"https://dgcg.covidbevis.se/tp/valuesets/{valueSet}"

    r = requests.get(vs_url)
    r.raise_for_status()

    # Retrieve the TL as a JWS
    json_data = r.json()

    return json_data

# Download All Valuesets
@app.command()
def getAllValueSets():
    '''Download all value sets'''
    typer.echo("Downloading Value Sets")


    all_value_sets = {}

    value_set_ids = getValuesets()

    for id in value_set_ids:

        file_name = map_id_to_file[id]+ ".json"
        value_set = getValueSet(file_name)

        all_value_sets[file_name] = value_set

    # Convert to JSNO format
    vs_json = json.dumps(all_value_sets, ensure_ascii=False, indent=3)

    # Save the JWS for further reference
    with open(vsFileName, "w") as f:
        f.write(vs_json)



def update_file_if_new(source_file: Path, target_dir: Path):

    target_file = target_dir / source_file

    # Check if files exist
    if not source_file.exists():
        print(f"Old file {source_file} does not exist. Doing nothing")
        return
    if not target_dir.exists():
        print(f"Target dir {target_dir} does not exist. Doing nothing")
        return

    if not target_file.exists():
        print(f"New file {target_file} does not exist, copying")
        copy2(source_file, target_file)
        return

    if cmp(source_file, target_file):
        # Files are the same. Do nothing
        print(f"{source_file} files are equal, skipping")
    else:
        # Files are different. Update target
        print(f"{source_file} files are different, copying")
        copy2(source_file, target_file)

def update_web_app(json_path, public_path):
    '''Update trusted lists and value sets in the web app'''
    typer.echo("Updating the web app")

    # Update EU trusted list in JSON path
    update_file_if_new(Path(processed_EU_Trusted_List), json_path)

    # Update EU trusted list in PUBLIC path
    update_file_if_new(Path(processed_EU_Trusted_List), public_path)

    # Update UK trusted list
    update_file_if_new(Path(processed_UK_Trusted_List), json_path)

    # Update Value Sets
    update_file_if_new(Path(vsFileName), json_path)

@app.command()
def update_verificacovid():
    '''Update trusted lists and value sets in the web app'''
    typer.echo("Updating the web app")

    json_path = Path("../VerificaCOVID/src/json/")
    public_path = Path("../VerificaCOVID/src/public/")

    update_web_app(json_path, public_path)

@app.command()
def update_mycovidcredential():
    '''Update trusted lists and value sets in the web app'''
    typer.echo("Updating the web app")

    json_path = Path("../MyCovidCredential/src/json/")
    public_path = Path("../MyCovidCredential/src/public/")

    update_web_app(json_path, public_path)


@app.command()
def download_and_update_all():
    '''Download and update all lists in web app'''
    typer.echo("Downloading all Trusted Lists and values Sets")

    # Download EU Trusted List
    download()
    verify()
    decode()

    # Download UK Trusted List
    download_uk()

    # Download Value Sets
    getAllValueSets()

    # Update the web app
    update_web_app()


# Run the CLI commands
if __name__ == "__main__":
    app()