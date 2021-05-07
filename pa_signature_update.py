"""
Description: 
    Download latest malware/spyware signatures from Dell SecureWorks
    Upload new signatures to Panorama, and 

Requires:
    requests
    xmltodict
        to install: pip install -r requirements.txt

Author:
    Ryan Gillespie rgillespie@compunet.biz


Tested:
    Tested on macos 10.15.7
    Python: 3.9.0
    Panorama v9.0.1, v10.?

Example usage:
    Run 'python pa_signature_update.py --setup' to initialize secrets.
    use 'python pa_signature_update.py --help' for argument list.
    Normal operation requires no arguments

Cautions:


Legal:
    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""

import os, sys, shutil, smtplib, ssl, keyring, argparse, logging
from getpass import getpass

import sw_download as swrx
import api_lib_pa as pa_api

############ EDIT BELOW ####################################################################
pa_ip = "10.254.254.5"
device_groups = ["dg-name1", "dg-name2"]
email_from = "me@domain.com"
email_recipient = "you@domain.com"
email_subject = "pa-swrx signature auto-updater"
log_file_name = "./logs/pa_signature_update.log"
# Setup passwords/secrets by running 'python pa_signature_update.py --setup'
############ EDIT ABOVE ####################################################################
from_xpath = "/config/devices/entry/vsys/entry/threats/spyware"
to_xpath = "/config/devices/entry/device-group/entry[@name='DG_NAME']/threats/spyware"


def output(message):
    print(f"\n{message}")
    logging.info(message)


def error_check(response, operation):
    if response.status_code != 200 or "error" in response.text:
        message = f"""\n\n{operation} Failed."
        "Response Code: {response.status_code}"
        "Response: {response.text}\n\n"""

        # Log and email error, exit program.
        output(message)
        send_mail(message)
        sys.exit(0)


def send_mail(message):
    # Create SSL Context
    context = ssl.create_default_context()

    # Prepare variables
    email_password = keyring.get_password("pa-secureworks", "email_password")
    message = f"Subject: {email_subject}\n\n\n{message}\n\n\n"

    # Create Connection
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(email_from, email_password)
            server.sendmail(email_from, email_recipient, message)
    except: 
        message = "\n\nFAILED sending email, please check email settings.\n\n"
        logging.error(message)
        print(message)


def set_secrets():
    # Prompt user and set all the secrets
    client_id = input("Paste SecureWorks client_id: ")
    client_secret = input("Paste SecureWorks client_secret: ")
    pa_username = input("Panorama Username: ")
    pa_password = getpass("Panorama Password: ")
    email_password = getpass("Email Password: ")

    keyring.set_password("pa-secureworks", "client_id", client_id)
    keyring.set_password("pa-secureworks", "client_secret", client_secret)
    keyring.set_password("pa-secureworks", "pa_username", pa_username)
    keyring.set_password("pa-secureworks", "pa_password", pa_password)
    keyring.set_password("pa-secureworks", "email_password", email_password)
    

def get_secrets():
    # Grab all the existing secrets, returns None if they don't exist
    secrets = {}
    secrets["client_id"] = keyring.get_password("pa-secureworks", "client_id")
    secrets["client_secret"] = keyring.get_password("pa-secureworks", "client_secret")
    secrets["pa_username"] = keyring.get_password("pa-secureworks", "pa_username")
    secrets["pa_password"] = keyring.get_password("pa-secureworks", "pa_password")
    secrets["email_password"] = keyring.get_password("pa-secureworks", "email_password")
    
    return secrets


def delete_secrets():
    # Prompt user then delete secrets
    answer = ""
    while answer not in ("yes", "no"):
        print("This will delete ALL credentials used by this script from the OS Keychain/Credential Manager.")
        answer = input("ARE YOU SURE? (yes/no): ")

    if answer == "yes":
        try:
            keyring.delete_password("pa-secureworks", "client_id")
            keyring.delete_password("pa-secureworks", "client_secret")
            keyring.delete_password("pa-secureworks", "pa_username")
            keyring.delete_password("pa-secureworks", "pa_password")
            keyring.delete_password("pa-secureworks", "email_password")
            print("\nAll secrets used by pa-secureworks have been removed from the OS Keychain/Credential Manager.\n")

        except Exception as e:
            print("\nError deleting secrets, they may have already been deleted. Check with '-g'.\n")
    else:
        print("\nNo secrets were deleted.\n")


def sig_update(client_id, client_secret, pa_username, pa_password, email_password):
    #Log into Panorama
    pa = pa_api.api_lib_pa(pa_ip, pa_username, pa_password, "panorama")
    
    # Download the file
    sig_file = swrx.sw_download(client_id, client_secret)

    # Create Commit Lock
    output("Creating commit lock on Panorama, please wait....")
    response = pa.commit_lock('add')
    error_check(response, "Commit Lock Add")

    # Import Named Configuration .xml via Palo Alto API
    with open("sigs/" + sig_file) as fin:
        output(f"Uploading new Signature File: {sig_file}, please wait....")
        response = pa.import_named_configuration(fin)
        error_check(response, "Import Named Configuration")
    output("Signature File Uploaded.")

    # Load Config Partial to device groups
    for group in device_groups:
        output(f"Loading new configuration to {group}, please wait....")
        to_xpath_specific = to_xpath.replace('DG_NAME', group)
        response = pa.load_config_partial(from_xpath, to_xpath_specific, sig_file)
        error_check(response, "Load Config Partial")

    # Check if -n was used or not
    if args.nocommit:
        output("Removing commit lock on Panorama, please wait....")
        response = pa.commit_lock('remove')
        error_check(response, "Commit Lock Remove")
        message = ("No-commit argument used. Config loaded successfully, check Panorama and commit/push manually to update.")
    else:
        # Commit changes
        output("Committing changes in Panorama, please wait....")
        response = pa.commit("pa-swrx-signatures")
        error_check(response, "Commit")

        # Push to devices
        for group in device_groups:        
            output(f"Pushing to {group}, please wait....")
            response = pa.push(group)
            error_check(response, f"Push config to {group}")
        
        message = f"Success!, Panorama has updated spyware signatures with: {sig_file}"
    
    # Update with status and send email
    output(message)
    send_mail(message)

    # Remove temp 'sigs' directory
    shutil.rmtree("./sigs")


if __name__ == "__main__":

    # Logging
    os.makedirs("./logs", exist_ok=True)
    logging.basicConfig(level=logging.INFO, filename=log_file_name, format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')

    # Check for arguments
    parser = argparse.ArgumentParser(description="Use --setup to initaliize the secrets.")
    parser.add_argument("-s", "--setup", help="Set the secrets and passwords to be used.", action='store_true')
    parser.add_argument("-g", "--getsecrets", help="Get the secrets and passwords that will be used.", action="store_true")
    parser.add_argument("-d", "--download", help="Download the latest signature update ONLY, will not touch the PA.", action="store_true")
    parser.add_argument("-xx", "--delete", help="Delete all secrets from the OS Keychain/Credential Store.", action="store_true")
    parser.add_argument("-nc", "--nocommit", help="Load config, but do not commit or push the configuration changes.", action="store_true")
    args = parser.parse_args()

    # Gather Secrets
    secrets = get_secrets() 

    # Run based on arguments given
    if args.setup:
        set_secrets()

    elif args.getsecrets:
        secrets = get_secrets()
        print()
        for secret, value in secrets.items():
            print(f"{secret} = {value}")
        print()

    elif args.download:
        # Check that secrets exist before running
        if None in {**secrets}:
            print("\nError, unable to find secrets, please run with --setup to configure these variables.\n")
            sys.exit(0)
        swrx.sw_download(secrets["client_id"], secrets["client_secret"])

    elif args.delete:
        delete_secrets()

    else:
        # Check that secrets exist before running
        if None in {**secrets}:
            print("\nError, unable to find secrets, please run with --setup to configure these variables.\n")
            sys.exit(0)
        else:
            # Run the update procedure
            sig_update(**secrets)