

import base64
import email
import re
from IndicatorOfInterest import IndicatorOfInterest
from utility_helper import extract_email_header
from datetime import datetime

intelligence_indicators = {
    'LINKEDIN': {
        'attempted_network_connection': {
        'subject': ['please add me to your LinkedIn network'],
        'content': ['I\'d like to join your LinkedIn network.'],
        'from': ['invitations@linkedin.com']
        }, 
        'successful_network_connection': {
            'subject': ['start a conversation with your new connection'],
            'content': ['has accepted your invitation. Let\'s start a conversation'],
            'from': ['invitations@linkedin.com']
        }, 
        'network_appearance': {
            'subject': ['You appeared in', 'searches this week'],
            'content': ['You appeared in', 'searches this week'],
            'from': ['notifications-noreply@linkedin.com']
        }
    },
    'FACEBOOK': {
        'attempted_network_connection': {
        'subject': ['wants to be friends on Facebook'],
        'content': ['wants to be friends with you on Facebook.', 'Confirm request Facebook', 'Confirm request See all requests'],
        'from': ['notification@facebookmail.com']
        }
    },
    'TWITTER': {
        'attempted_network_connection': {
        'subject': ['please add me to your LinkedIn network'],
        'content': ['I\'d like to join your LinkedIn network.'],
        'from': ['invitations@linkedin.com']
        }, 
        'successful_network_connection': {
            'subject': ['start a conversation with your new connection'],
            'content': ['has accepted your invitation. Let\'s start a conversation'],
            'from': ['invitations@linkedin.com']
        }, 
        'network_appearance': {
            'subject': ['You appeared in', 'searches this week'],
            'content': ['You appeared in', 'searches this week'],
            'from': ['notifications-noreply@linkedin.com']
        }
    },
    'INSTAGRAM': {
        'attempted_network_connection': {
        'subject': ['please add me to your LinkedIn network'],
        'content': ['I\'d like to join your LinkedIn network.'],
        'from': ['invitations@linkedin.com']
        }, 
        'successful_network_connection': {
            'subject': ['start a conversation with your new connection'],
            'content': ['has accepted your invitation. Let\'s start a conversation'],
            'from': ['invitations@linkedin.com']
        }, 
        'network_appearance': {
            'subject': ['You appeared in', 'searches this week'],
            'content': ['You appeared in', 'searches this week'],
            'from': ['notifications-noreply@linkedin.com']
        }
    }
}


def extract_relevant_headers(message):
    sender_email = extract_email(extract_email_header(message['payload']['headers'],'From'))
    target_email = extract_email(extract_email_header(message['payload']['headers'],'To'))
    datetime_str = extract_email_header(message['payload']['headers'],'Date')
    subject = extract_email_header(message['payload']['headers'],'Subject')
    snippet = message['snippet']
    return (sender_email, target_email, datetime_str, subject, snippet)

def extract_timestamp_epoch(line, platform):
# Known Issue: parsing of timezone at the end of the string
    if platform == 'LINKEDIN':
        # "Sun, 12 Apr 2020 11:11:54 +0000 (UTC)"
        datetime_obj = datetime.strptime(line, '%a, %d %b %Y %H:%M:%S +0000 (UTC)')
    if platform == 'FACEBOOK':
        # Sat, 11 Apr 2020 21:10:44 -0700
        datetime_obj = datetime.strptime(line, '%a, %d %b %Y %H:%M:%S -0700')
    return datetime_obj.timestamp()

def extract_email(line):
    return re.findall("([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", line)[0]

# Based on the sender's email and the subject
# determine which source the email is from
def analyze_email_message(message):
    sender_email, target_email, datetime_str, subject, snippet = extract_relevant_headers(message)
    for platform in intelligence_indicators:
        events = intelligence_indicators[platform].keys()
        for event in events:
            subject_check = True
            from_check = True
            for subject_content in intelligence_indicators[platform][event]['subject']:
                if subject_content not in subject:
                    subject_check = False
            if sender_email not in intelligence_indicators[platform][event]['from']:
                from_check = False
            if subject_check and from_check:
                datetime = extract_timestamp_epoch(datetime_str, platform)
                return IndicatorOfInterest(message['id'],target_email,platform,event,snippet,datetime)