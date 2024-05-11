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


import requests

from wazuh_notifier_module import color_mapping
from wazuh_notifier_module import get_arguments
from wazuh_notifier_module import get_config
from wazuh_notifier_module import get_env
from wazuh_notifier_module import set_environment
from wazuh_notifier_module import set_time

# Get path values
wazuh_path, ar_path, config_path, notifier_path = set_environment()

# Get time value
now_message, now_logging = set_time()

# Get some paths.
discord_url, ntfy_url = get_env()

# Get the yaml config
config: dict = get_config()

# the POST builder. Prepares https and sends the request.


def discord_command(n_url, n_sender, n_destination, n_priority, n_message, n_tags, n_click):
    color = color_mapping(n_priority)

    x_message = (now_message +
                 "\n\n" + n_message + "\n\n" +
                 "Priority: " + n_priority + "\n" +
                 "Tags: " + n_tags + "\n\n" + n_click
                 )
    n_data = {"username": n_sender, "embeds": [{"color": color, "description": x_message, "title": n_destination}]}

    requests.post(n_url, json=n_data)


# Remove 1st argument from the list of command line arguments
# argument_list: list = sys.argv[1:]

notifier = "discord"

url, sender, destination, priority, message, tags, click = get_arguments()


# Finally, execute the POST request
discord_command(discord_url, sender, destination, priority, message, tags, click)
