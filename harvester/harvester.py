#!/usr/bin/python3
from email_helper import analyze_email_message
import pickle
import os.path
import json
from apiclient import errors
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# If modifying these scopes, delete the file token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def load_credentials():
    creds = None
    # The file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=8888)
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    return creds

def analyze_emails(credentials, cache_message_ids_pickle_file):
    cached_data_store = retrieve_cache_messages(cache_message_ids_pickle_file)
    service = build('gmail', 'v1', credentials=credentials)
    results = service.users().messages().list(userId='me').execute()
    print("Retrieved %s emails from Google Mailbox - manuka.bee.harvester.1@gmail.com" % str(len(results['messages'])))
    for message in results['messages']:
        if message['id'] not in cached_data_store['ids']:
            message = service.users().messages().get(userId='me', id=message['id']).execute()
            # try:
            ioi = analyze_email_message(message)
            
            if ioi:
                sha256_hash = ioi.sha256_hash
                if sha256_hash not in cached_data_store['hashes']:
                    cached_data_store['hashes'][sha256_hash] = [message['id']]
                else:
                    # print("Message[\"%s\"] is found to contain duplicated content" % message['id'])
                    ioi.add_duplicates(cached_data_store['hashes'][sha256_hash])
                    cached_data_store['hashes'][sha256_hash].append(message['id'])
                # send to backend for processing
                print(ioi.toJSON())
            cached_data_store['ids'].append(message['id'])
    cache_messages(cache_message_ids_pickle_file, cached_data_store)

def cache_messages(pickle_file, cached_data_store):
    with open(pickle_file, 'wb') as output_pickle_file:
            pickle.dump(cached_data_store, output_pickle_file)
    print("Cached %s messages" %(str(len(cached_data_store['ids']))))

def retrieve_cache_messages(pickle_file):
    if os.path.exists(pickle_file):
        with open(pickle_file, 'rb') as output_pickle_file:
            cached_data_store = pickle.load(output_pickle_file)
            if cached_data_store is not None:
                print("Retrieved cached %s cached messages" %(str(len(cached_data_store['ids']))))
                return cached_data_store
    print("Retrieved cached 0 cached messages")
    return {'ids':[], 'hashes':{}}

def dump_obj(obj_to_dump):
    print(json.dumps(obj_to_dump,indent=4))

if __name__ == '__main__':
    credentials = load_credentials()
    analyze_emails(credentials, 'cached_message_ids.pickle')    
