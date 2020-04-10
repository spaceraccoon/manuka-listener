#!/usr/bin/python3
from email_helper import is_intelligence, analyze_intelligence_source
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
    analyzed_message_ids = retrieve_cache_message_ids(cache_message_ids_pickle_file)
    service = build('gmail', 'v1', credentials=credentials)
    results = service.users().messages().list(userId='me').execute()
    for message in results['messages']:
        if message['id'] not in analyzed_message_ids:
            message = service.users().messages().get(userId='me', id=message['id'],format='raw').execute()
            if is_intelligence(message['snippet']):
                ioi = analyze_intelligence_source(message)
                print(ioi.toJSON())
                # send to backend
                analyzed_message_ids.append(message['id'])
    cache_message_ids(cache_message_ids_pickle_file, analyzed_message_ids)

def cache_message_ids(pickle_file, ids):
    with open(pickle_file, 'wb') as output_pickle_file:
            pickle.dump(ids, output_pickle_file)
    print("Cached %s message IDs" %(str(len(ids))))

def retrieve_cache_message_ids(pickle_file):
    ids = []
    if os.path.exists(pickle_file):
        with open(pickle_file, 'rb') as output_pickle_file:
            ids = pickle.load(output_pickle_file)
    print("Retrieved cached %s message IDs" %(str(len(ids))))
    return ids

def dump_obj(obj_to_dump):
    print(json.dumps(obj_to_dump,indent=4))

if __name__ == '__main__':
    credentials = load_credentials()
    analyze_emails(credentials, 'cached_message_ids.pickle')    
