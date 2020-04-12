# Target: Email
# Source: LinkedIn
# Event Type: attempted_network_connection, successful_network_connection, network_appearance
# Payload: parsed_email_content

import enum, json, hashlib

class IndicatorOfInterestEventType(enum.Enum):
    attempted_network_connection = 'attempted_network_connection'
    successful_network_connection = 'successful_network_connection'
    network_appearance = 'network_appearance'

class IndicatorOfInterest:

    def get_hash(self):
        # only selected attribute are used to determine if the email content is the same
        message = self.target + ":" + self.source + ":" + self.event_type + ":" + self.payload
        return hashlib.sha256(bytes(message, 'utf-8')).hexdigest()

    def __init__(self, message_id, target, source, event_type, payload, notification_epoch_timestamp):
        self.message_id = message_id
        self.target = target
        self.source = source
        self.event_type = event_type
        self.payload = payload
        self.sha256_hash = self.get_hash()
        self.duplicates = []
        self.notification_epoch_timestamp = notification_epoch_timestamp

    def add_duplicates(self, duplicate_list):
        self.duplicates.extend(duplicate_list)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)