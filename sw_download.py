from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
import requests
import os
import json
import tarfile
import logging

def output(message, log):
    print(f"\n{message}")
    log.info(message)

def sw_download(client_id, client_secret):
    log = logging.getLogger(__name__)
    # Create temp 'sigs' directory
    os.makedirs("./sigs", exist_ok=True)
    filename = "./sigs/cm.tgz"

    client = BackendApplicationClient(client_id=client_id)
    oauth_client = OAuth2Session(client=client)
    token = oauth_client.fetch_token(token_url='https://api.ctpx.secureworks.com/auth/api/v2/auth/token', client_id=client_id,
                                    client_secret=client_secret)

    r = oauth_client.get('https://api.ctpx.secureworks.com/intel-requester/')
    data = json.loads(r.content)

    # list available counter measures
    output(f"Available counter measures: {[x['name'] for x in data]}", log)

    # Select the one you want to download
    counter_measure = 'ti-ruleset/PaloAltoNGFW_pan-malware_latest.tgz'

    download_link = list(filter(lambda x: x['name'] == counter_measure, data))[0]

    output(f"Downloading: {counter_measure}.", log)

    # Download it to a local file
    r = requests.get(download_link['link'], allow_redirects=True)
    open(filename, 'wb').write(r.content)

    output(f"Downloaded: {counter_measure} to {filename}", log)

    output(f"Extracting {filename}", log)

    # Extract and list the file contents
    tar = tarfile.open(filename)
    tar.extractall(path="./sigs/")
    output(tar.list(), log)
    tar.close()
    output(f"Extracted {filename}.", log)

    # Do custom things with the rulesets beyond here

    for sig_file in os.listdir("./sigs"):
        if sig_file.endswith(".xml"):
            return sig_file


if __name__ == "__main__":
    client_id = input("client_id: ")
    client_secret = (input("client_secret: "))
    
    sw_download(client_id, client_secret)
