import os, sys, shutil, smtplib, ssl, keyring, argparse, logging
from getpass import getpass

import sw_download as swrx
import api_lib_pa as pa_api

############ EDIT BELOW ####################################################################
pa_ip = "10.254.254.5"
email_from = ""
email_recipient = ""
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

    # Delong Load Config Partial
    output("Loading new configuration to Delong, please wait....")
    to_xpath_delong = to_xpath.replace('DG_NAME', 'Delong')
    response = pa.load_config_partial(from_xpath, to_xpath_delong, sig_file)
    error_check(response, "Load Config Partial")

    # Phoenix Load Config Partial
    output("Loading new configuration to Phoenix, please wait....")
    to_xpath_phoenix = to_xpath.replace('DG_NAME', 'Phoenix')
    response = pa.load_config_partial(from_xpath, to_xpath_phoenix, sig_file)
    error_check(response, "Load Config Partial")

    # Commit changes
    output("Committing changes in Panorama, please wait....")
    response = pa.commit("pa-swrx-signatures")
    error_check(response, "Commit")

    message = f"Success!, Panorama has updated spyware signatures with: {sig_file}"
    output(message)

    # Send mail update
    send_mail(message)

    # Remove temp 'sigs' directory
    shutil.rmtree("./sigs")

if __name__ == "__main__":

    # Logging
    os.makedirs("./logs", exist_ok=True)
    logging.basicConfig(level=logging.INFO, filename=log_file_name, format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')

    # Check for --setup or -s
    parser = argparse.ArgumentParser(description="Use --setup to initaliize the secrets.")
    parser.add_argument("-s", "--setup", help="Set the secrets and passwords to be used.", action='store_true')
    parser.add_argument("-g", "--get", help="Get the secrets and passwords that will be used.", action="store_true")
    parser.add_argument("-d", "--download", help="Download the latest signature update ONLY, will not touch the PA.", action="store_true")
    parser.add_argument("-xx", "--delete", help="Delete all secrets from the OS Keychain/Credential Store.", action="store_true")
    args = parser.parse_args()

    # Gather Secrets
    secrets = get_secrets() # Returns None if not found

    # Run based on args sent
    if args.setup:
        set_secrets()
    elif args.get:
        secrets = get_secrets()
        print()
        for secret, value in secrets.items():
            print(f"{secret} = {value}")
        print()
    elif args.download:
        swrx.sw_download(secrets["client_id"], secrets["client_secret"])
    elif args.delete:
        delete_secrets()
    else:
        # Main 
        if None in {**secrets}:
            print("\nError, unable to find secrets, please run with --setup to configure these variables.\n")
            sys.exit(0)
        else:
            # Run update
            sig_update(**secrets)