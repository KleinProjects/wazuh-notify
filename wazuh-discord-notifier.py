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

import getopt
import os
import sys
from os.path import join, dirname

import requests
from dotenv import load_dotenv

from wazuh_notifier_lib import import_config as ic
from wazuh_notifier_lib import set_env as se
from wazuh_notifier_lib import set_time as st
from wazuh_notifier_lib import view_config as vc

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

    result = requests.post(n_server, json=n_data)


# Remove 1st argument from the list of command line arguments
argument_list: list = sys.argv[1:]

# Short options
options: str = "u:s:p:m:t:c:hv"

# Long options
long_options: list = ["server=", "sender=", "destination=", "priority=", "message=", "tags=", "click=", "help", "view"]

# Setting some basic defaults.
d_sender: str = "Security message"
d_destination: str = "WAZUH (IDS)"
d_priority: str = "5"
d_message: str = "Test message"
d_tags: str = "informational, testing, hard-code"
d_click: str = "https://google.com"

# Use the values from the config yaml if available. Overrides the basic defaults.
server = discord_webhook
sender = d_sender if (ic("discord_sender") is None) else ic("discord_sender")
destination = d_destination if (ic("discord_destination") is None) else ic("discord_destination")
priority = d_priority if (ic("discord_priority") is None) else ic("discord_priority")
message = d_message if (ic("discord_message") is None) else ic("discord_message")
tags = d_tags if (ic("discord_tags") is None) else ic("discord_tags")
click = d_click if (ic("discord_click") is None) else ic("discord_click")

help_text: str = """
 -u, --server        is the webhook URL of the Discord server. It is stored in .env.
 -s, --sender        is the sender of the message, either an app name or a person. 
                     The default is "Security message".
 -d, --destination   is the destination (actually the originator) of the message, either an app name or a person. 
                     Default is "Wazuh (IDS)"
 -p, --priority      is the priority of the message, ranging from 1 (highest), to 5 (lowest). 
                     Default is 5.
 -m, --message       is the text of the message to be sent. 
                     Default is "Test message", but may include --tags and/or --click.
 -t, --tags          is an arbitrary strings of tags (keywords), seperated by a "," (comma). 
                     Default is "informational, testing, hard-coded".
 -c, --click         is a link (URL) that can be followed by tapping/clicking inside the message. 
                     Default is https://google.com.
 -h, --help          Shows this help message.
 -v, --view          Show yaml configuration.
"""

#   Get params during execution. Params found here, override minimal defaults and/or config settings.
try:
    # Parsing argument
    arguments, values = getopt.getopt(argument_list, options, long_options)

    # checking each argument
    for current_argument, current_value in arguments:

        if current_argument in ("-h", "--help"):
            print(help_text)
            exit()

        elif current_argument in ("-v", "--view"):
            vc()
            exit()

        elif current_argument in ("-s", "--sender"):
            sender = current_value

        elif current_argument in ("-d", "--destination"):
            destination = current_value

        elif current_argument in ("-p", "--priority"):
            priority = current_value

        elif current_argument in ("-m", "--message"):
            message = current_value

        elif current_argument in ("-t", "--tags"):
            tags = current_value

        elif current_argument in ("-c", "--click"):
            click = current_value

except getopt.error as err:
    # output error, and return with an error code
    print(str(err))

# Finally, execute the POST request
discord_command(discord_webhook, sender, destination, priority, message, tags, click)
