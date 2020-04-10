

import base64
import email
import re
from IndicatorOfInterest import IndicatorOfInterest
from datetime import datetime

intel_sources = ['LINKEDIN', 'TWITTER', 'FACEBOOK', 'INSTAGRAM']
linkedin_event_types_keywords = {
        'attempted_network_connection': {
        'subject': ['please add me to your LinkedIn network'],
        'content': ['like to join your LinkedIn network']
    }, 'successful_network_connection': {
        'subject': ['start a conversation with your new connection'],
        'content': ['connections, experience, and more']
    }, 'network_appearance': {
        'subject': ['You appeared in', 'searches this week'],
        'content': ['You appeared in', 'searches this week']
    }
}
email_mime_payload_delimiter = '---------- Forwarded message ---------'


# Message body is considered an intelligence if the snippet tells us that its a forwarded message from a social media platform
def is_intelligence(snippet):
    snippet = snippet.upper()
    if 'LINKEDIN' in snippet and 'FORWARDED MESSAGE' in snippet:
        return True
    return False

def extract_intelligence_source(snippet):
    snippet = snippet.upper()
    for intel_source in intel_sources:
        if intel_source in snippet:
            return intel_source

def extract_timestamp_epoch(line):
    datetime_obj = datetime.strptime(line, 'Date: %a, %b %d, %Y at %I:%M %p')
    return datetime_obj.timestamp()

def determine_event_type(subject, content):
    for index, (event_type, data_identifier) in enumerate(linkedin_event_types_keywords.items()):
        continue_with_next_event_type = False
        for subject_data_identifier in data_identifier['subject']:
            if subject_data_identifier not in subject:
                continue_with_next_event_type = True
                break
        if continue_with_next_event_type: 
            continue
        for content_data_identifier in data_identifier['content']:
            if content_data_identifier not in content:
                continue_with_next_event_type = True
                break
        if not continue_with_next_event_type:
            return event_type

def extract_email(line):
    return re.findall("([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", line)[0]

def analyze_intelligence_source(message):
    msg_str = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
    mime_msg = str(email.message_from_string(str(msg_str)))
    parsed_payload = []
    target = ''
    event_type = ''
    notification_epoch_timestamp = 0.0
    source = extract_intelligence_source(message['snippet'])
    if extract_intelligence_source(message['snippet']) == intel_sources[0]:
        # LinkedIn Specific Content Extraction
        content = mime_msg.split(email_mime_payload_delimiter)[1].split('\\r\\n')
        # First 8 lines of the message is enough for us as parsed email payload
        parsed_payload.extend(content[1:5])
        parsed_payload.extend(content[7:8])
        # Extract the email (target)
        target = extract_email(parsed_payload[3])
        # Extract timestamp (epoch)
        notification_epoch_timestamp = extract_timestamp_epoch(parsed_payload[1])
        # Determine the type of IOI event
        event_type = determine_event_type(parsed_payload[2],parsed_payload[4])
    if extract_intelligence_source(message['snippet']) == intel_sources[1]:
        # intel_sources = ['LINKEDIN', 'TWITTER', 'FACEBOOK', 'INSTAGRAM']
        # Twitter Specific Content Extraction
        pass
    if extract_intelligence_source(message['snippet']) == intel_sources[2]:
        # Facebook Specific Content Extraction
        pass
    if extract_intelligence_source(message['snippet']) == intel_sources[3]:
        # Instagram Specific Content Extraction
        pass
    return IndicatorOfInterest(target, source, event_type, parsed_payload, notification_epoch_timestamp)