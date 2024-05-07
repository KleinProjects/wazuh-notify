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

import os
from os.path import join, dirname

import requests
from dotenv import load_dotenv

from wazuh_notifier_module import get_arguments as ga
from wazuh_notifier_module import get_yaml_config as yc
from wazuh_notifier_module import set_basic_defaults as bd
from wazuh_notifier_module import set_environment as se
from wazuh_notifier_module import set_time as st
from wazuh_notifier_module import threat_priority_mapping as tpm

# Get path values
wazuh_path, ar_path, config_path = se()


# Get time value
now_message, now_logging = st()

# Retrieve webhook from .env

# Catching some path errors.
try:
    dotenv_path = join(dirname(__file__), '.env')
    load_dotenv(dotenv_path)
    if not os.path.isfile(dotenv_path):
        raise Exception(dotenv_path, "file not found")

    discord_webhook = os.getenv("DISCORD_WEBHOOK")

except Exception as err:
    # output error, and return with an error code
    print(str(Exception(err.args)))
    exit(err)

# the POST builder. Prepares https and sends the request.


def discord_command(n_server, n_sender, n_destination, n_priority, n_message, n_tags, n_click):
    x_message = (now_message +
                 "\n\n" + n_message + "\n\n" +
                 "Priority: " + n_priority + "\n" +
                 "Tags: " + n_tags + "\n\n" + n_click
                 )
    n_data = {"username": n_sender, "embeds": [{"description": x_message, "title": n_destination}]}

    requests.post(n_server, json=n_data)


# Remove 1st argument from the list of command line arguments
# argument_list: list = sys.argv[1:]

# Short options
options: str = "u:s:p:m:t:c:hv"

# Long options
long_options: list = ["server=", "sender=", "destination=", "priority=", "message=", "tags=", "click=", "help", "view"]

# Defining who I am
notifier = "discord"

# Retrieve the hard-coded basic defaults.

(d_server, d_sender, d_destination, d_priority, d_message, d_tags, d_click, d_notifier_priority_1,
 d_notifier_priority_2, d_notifier_priority_3, d_notifier_priority_4, d_notifier_priority_5) = bd(notifier)

# Use the values from the config yaml if available. Overrides the basic defaults (get_yaml_config).

yc_args = [notifier, d_server, d_sender, d_destination, d_priority, d_message, d_tags, d_click, d_notifier_priority_1,
           d_notifier_priority_2, d_notifier_priority_3, d_notifier_priority_4, d_notifier_priority_5]

(server, sender, destination, priority, message, tags, click, notifier_priority_1, notifier_priority_2,
 notifier_priority_3, notifier_priority_4, notifier_priority_5) = yc(*yc_args)

#   Get params during execution. Params found here, override minimal defaults and/or config settings.

if ga(notifier, options, long_options) is None:
    pass
    # sender, destination, priority, message, tags, click = "", "", "", "", "", ""
else:
    sender, destination, priority, message, tags, click = ga(notifier, options, long_options)

# Get the threat level from the message and map it to priority

threat_level = message[message.find('Threat level:') + 13:message.find('Threat level:') + 15].replace(" ", "")

# Get the mapping between threat level (event) and priority (Discord/ntfy)

# noinspection PyRedeclaration
priority = tpm(threat_level, notifier_priority_1, notifier_priority_2, notifier_priority_3,
               notifier_priority_4, notifier_priority_5)

# Finally, execute the POST request
discord_command(discord_webhook, sender, destination, priority, message, tags, click)
