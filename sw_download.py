from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
import requests
import os
import json
import tarfile

def sw_download(client_id, client_secret):
    client = BackendApplicationClient(client_id=client_id)
    oauth_client = OAuth2Session(client=client)
    token = oauth_client.fetch_token(token_url='https://api.ctpx.secureworks.com/auth/api/v2/auth/token', client_id=client_id,
                                    client_secret=client_secret)

    r = oauth_client.get('https://api.ctpx.secureworks.com/intel-requester/')
    data = json.loads(r.content)

    # list available counter measures
    print("Available counter measures: {}".format([x['name'] for x in data]))

    # Select the one you want to download
    counter_measure = 'ti-ruleset/PaloAltoNGFW_pan-malware_latest.tgz'

    download_link = list(filter(lambda x: x['name'] == counter_measure, data))[0]

    print("Downloading: {}".format(counter_measure))

    # Download it to a local file
    r = requests.get(download_link['link'], allow_redirects=True)
    open('sigs/cm.tgz', 'wb').write(r.content)

    print("Downloaded: {} to cm.tgz".format(counter_measure))

    print("Extracting cm.tgz")

    # Extract and list the file contents
    tar = tarfile.open("sigs/cm.tgz")
    tar.extractall(path="./sigs/")
    print(tar.list())
    tar.close()
    print("Extracted cm.tgz")

    # Do custom things with the rulesets beyond here

    for filename in os.listdir("./sigs"):
        if filename.endswith(".xml"):
            return filename


if __name__ == "__main__":
    client_id = ""
    client_secret = ""
    
    sw_download(client_id, client_secret)
