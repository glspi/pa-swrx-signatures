import os, sys, shutil, smtplib, ssl, keyring, argparse, logging
from getpass import getpass

import sw_download as swrx
import api_lib_pa as pa_api

############################################################################################
pa_ip = "10.254.254.5"
email_from = "rgillespie@gmail.com"
email_recipient = "rgillespie@compunet.biz"
log_file_name = "./logs/pa_signature_update.log"
from_xpath = "/config/devices/entry/vsys/entry/threats/spyware"
to_xpath = "/config/devices/entry/device-group/entry[@name='DG_NAME']/threats/spyware"
############################################################################################


def error_check(pa, response, operation):
    if response.status_code != 200 or "error" in response.text:
        print(f"\n\n{operation} Failed.")
        print(f"Response Code: {response.status_code}")
        print(f"Response: {response.text}\n\n")

        print("\nRemoving commit lock on Panorama, please Wait....")
        response = pa.commit_lock('remove')
        sys.exit(0)


def send_mail(message, email_password):
    # Create SSL Context
    context = ssl.create_default_context()
    message = "\n" + message + "\n"
    # Create Connection
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(email_from, email_password)
        server.sendmail(email_from, email_recipient, message)


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

    client_id = keyring.get_password("pa-secureworks", "client_id")
    client_secret = keyring.get_password("pa-secureworks", "client_secret")
    pa_username = keyring.get_password("pa-secureworks", "pa_username")
    pa_password = keyring.get_password("pa-secureworks", "pa_password")
    email_password = keyring.get_password("pa-secureworks", "email_password")
    
    print()
    print(f"client_id = {client_id }")
    print(f"client_secret = {client_secret}")
    print(f"pa_username = {pa_username}")
    print(f"pa_password = {pa_password}")
    print(f"email_password = {email_password}")
    print()


def sig_update(client_id, client_secret, pa_username, pa_password, email_password):
    #Log into Panorama
    pa = pa_api.api_lib_pa(pa_ip, pa_username, pa_password, "panorama")

    # Create temp 'sigs' directory
    os.makedirs("./sigs", exist_ok=True)
    
    # Download the file
    sig_file = swrx.sw_download(client_id, client_secret)

    # Create Commit Lock
    message = "Creating commit lock on Panorama"
    print(f"\n{message}, please wait....")
    logging.info(message)
    response = pa.commit_lock('add')
    error_check(pa, response, "Commit Lock Add")

    # Import Named Configuration .xml via Palo Alto API
    with open("sigs/" + sig_file) as fin:
        message = f"Uploading new Signature File: {sig_file}"
        print(f"\n{message}, please wait....")
        logging.info(message)
        response = pa.import_named_configuration(fin)
    error_check(pa, response, "Importing Configuration")
    message = "Signature File Uploaded."
    print(f"\n{message}")
    logging.info(message)

    # Delong Load Config Partial
    message = "Loading new configuration to Delong"
    print(f"\n{message}, please wait....")
    logging.info(message)
    to_xpath_delong = to_xpath.replace('DG_NAME', 'Delong')
    response = pa.load_config_partial(from_xpath, to_xpath_delong, sig_file)
    error_check(pa, response, "Loading Configuration")

    # Phoenix Load Config Partial
    message = "Loading new configuration to Phoenix"
    print(f"\n{message}, please wait....")
    logging.info(message)
    to_xpath_phoenix = to_xpath.replace('DG_NAME', 'Phoenix')
    response = pa.load_config_partial(from_xpath, to_xpath_phoenix, sig_file)
    error_check(pa, response, "Loading Configuration")

    # Commit changes
    message = "Committing changes in Panorama"
    print(f"\n{message}, please Wait....")
    logging.info(message)
    response = pa.commit("pa-swrx-signatures")
    error_check(pa, response, "Commit")

    message = f"Success!, Panorama updated with: {sig_file}"
    print(f"\n{message}\n")
    logging.info(message)
    send_mail(message, email_password)

    # Remove temp 'sigs' directory
    shutil.rmtree("./sigs")

if __name__ == "__main__":

    # Check for --setup or -s
    parser = argparse.ArgumentParser(description="Use --setup to initaliize the secrets.")
    parser.add_argument("-s", "--setup", help="Set the secrets and passwords to be used.", action='store_true')
    parser.add_argument("-g", "--get", help="Get the secrets and passwords that will be used.", action="store_true")
    args = parser.parse_args()

    # IF XML, do not connect to PA/Pan
    if args.setup:
        set_secrets()
    elif args.get:
        get_secrets()
    else:
        # Main 
        client_id = keyring.get_password("pa-secureworks", "client_id")
        client_secret = keyring.get_password("pa-secureworks", "client_secret")
        pa_username = keyring.get_password("pa-secureworks", "pa_username")
        pa_password = keyring.get_password("pa-secureworks", "pa_password")
        email_password = keyring.get_password("pa-secureworks", "email_password")

        if None in (client_id, client_secret, pa_username, pa_password):
            print("\nError, unable to find secrets, please run with --setup to set these variables.\n")
            sys.exit(0)
        else:
            # Logging
            os.makedirs("./logs", exist_ok=True)
            logging.basicConfig(level=logging.INFO, filename=log_file_name, format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')
            # Run update
            sig_update(client_id, client_secret, pa_username, pa_password, email_password)