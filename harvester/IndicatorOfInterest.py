# Target: Email
# Source: LinkedIn
# Event Type: attempted_network_connection, successful_network_connection, network_appearance
# Payload: parsed_email_content

import enum, json

class IndicatorOfInterestEventType(enum.Enum):
    attempted_network_connection = 'attempted_network_connection'
    successful_network_connection = 'successful_network_connection'
    network_appearance = 'network_appearance'

class IndicatorOfInterest:
    def __init__(self, target, source, event_type, payload, notification_epoch_timestamp):
        self.target = target
        self.source = source
        self.event_type = event_type
        self.payload = payload
        self.notification_epoch_timestamp = notification_epoch_timestamp

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)