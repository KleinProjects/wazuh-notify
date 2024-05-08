#!/usr/bin/env python3

# This script is free software.
#
#           Copyright (C) 2024, Rudi Klein.
#           All rights reserved.
#
#           This program is free software; you can redistribute it
#           and/or modify it under the terms of the GNU General Public
#           License (version 2) as published by the FSF - Free Software
#           Foundation.
#
# This script is executed by the active response script (wazuh-active-response.py), which is triggered by rules firing.
#
# Discord is a voice, video and text communication service used by over a hundred million people to hang out and talk
# with their friends and communities. It allows for receiving message using webhooks.
# For more information: https://discord.com.


import json

import requests

from wazuh_notifier_module import get_arguments
from wazuh_notifier_module import get_env
from wazuh_notifier_module import get_yaml_config
from wazuh_notifier_module import set_environment
from wazuh_notifier_module import set_time
from wazuh_notifier_module import threat_priority_mapping

# Setup the environment

# Get time value
now_message, now_logging = set_time()

# Get .env values
discord_webhook, ntfy_webhook = get_env()

# Get path values
wazuh_path, ar_path, config_path = set_environment()


# the POST builders for the targets. Prepares https and sends the request.

def discord_command(url, sender, destination, priority, message, tags, click):
    x_message = (now_message +
                 "\n\n" + message + "\n\n" +
                 "Priority: " + priority + "\n" +
                 "Tags: " + tags + "\n\n" + click
                 )
    data = {"username": sender, "embeds": [{"description": x_message, "title": destination}]}

    requests.post(url, json=data)


def ntfy_command(url, sender, destination, priority, message, tags, click):
    header = ""
    if sender != "": header = header + '"Title"' + ": " + '"' + sender + '"' + ", "
    if tags != "": header = header + '"Tags"' + ": " + '"' + tags + '"' + ", "
    if click != "": header = header + '"Click"' + ": " + '"' + click + '"' + ", "
    if priority != "": header = header + '"Priority"' + ": " + '"' + priority + '"'
    header = json.loads("{" + header + "}")
    x_message = now_message + "\n\n" + message

    # todo POST the request **** NEEDS future TRY ****
    requests.post(url + destination, data=x_message, headers=header)


# Get the YAML config if any
config: dict = get_yaml_config()

# Get the command line arguments
if get_arguments() is None:
    url, sender, destination, message, priority, tags, click = "", "", "", "", "", "", ""
else:
    url, sender, destination, priority, message, tags, click = get_arguments()

# Get the threat level from the event (message)
threat_level = message[message.find('Threat level:') + 13:message.find('Threat level:') + 15].replace(" ", "")

# Get the mapping between threat level (event) and priority (Discord/ntfy)
threat_priority = threat_priority_mapping(threat_level, config.get('np_1'), config.get('np_2'),
                                          config.get('np_3'), config.get('np_4'), config.get('np_5'))

# Finally, execute the POST request
# discord_command(discord_webhook, sender, destination, priority, message, tags, click)
