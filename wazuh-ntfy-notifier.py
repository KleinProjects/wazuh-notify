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
# ntfy (pronounced notify) is a simple HTTP-based pub-sub notification service.
# It allows you to send notifications to your phone or desktop via scripts from any computer, and/or using a REST API.
# It's infinitely flexible, and 100% free software. For more information: https://ntfy.sh.

import json
import sys

import requests

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

# the POST builder


def ntfy_command(n_server, n_sender, n_destination, n_priority, n_message, n_tags, n_click):
    n_header = ""
    if n_sender != "": n_header = n_header + '"Title"' + ": " + '"' + n_sender + '"' + ", "
    if n_tags != "": n_header = n_header + '"Tags"' + ": " + '"' + n_tags + '"' + ", "
    if n_click != "": n_header = n_header + '"Click"' + ": " + '"' + n_click + '"' + ", "
    if n_priority != "": n_header = n_header + '"Priority"' + ": " + '"' + n_priority + '"'
    n_header = json.loads("{" + n_header + "}")
    x_message = now_message + "\n\n" + n_message

# todo POST the request **** NEEDS future TRY ****
    requests.post(n_server + n_destination, data=x_message, headers=n_header)


# Remove 1st argument from the list of command line arguments
argument_list = sys.argv[1:]

# Short options
options: str = "u:s:d:p:m:t:c:hv"

# Long options
long_options: list = ["server=", "sender=", "destination=", "priority=", "message=", "tags=", "click", "help", "view"]

# Defining who I am
notifier = "ntfy"

# Retrieve the hard-coded basic defaults.
(d_server, d_sender, d_destination, d_priority, d_message, d_tags, d_click, d_notifier_priority_1,
 d_notifier_priority_2, d_notifier_priority_3, d_notifier_priority_4, d_notifier_priority_5) = bd(notifier)

# Use the values from the config yaml if available. Overrides the basic defaults.
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
ntfy_command(server, sender, destination, priority, message, tags, click)

