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
# This script is executed by the active response script (custom-active-response.py), which is triggered by rules firing.
#
# ntfy (pronounced notify) is a simple HTTP-based pub-sub notification service.
# It allows you to send notifications to your phone or desktop via scripts from any computer, and/or using a REST API.
# It's infinitely flexible, and 100% free software. For more information: https://ntfy.sh.

import json
import requests
import getopt
import sys

from wazuh_notifier_lib import set_env as se
from wazuh_notifier_lib import set_time as st
from wazuh_notifier_lib import import_config as ic
from wazuh_notifier_lib import view_config as vc

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

# Setting some minimal defaults in case the yaml config isn't available
d_server: str = "https://ntfy.sh/"
d_sender: str = "Security message"
d_destination: str = "phil_alerts"
d_priority: str = "5"
d_message: str = "Test message"
d_tags: str = "informational, testing, hard-coded"
d_click: str = "https://google.com"

# Use the values from the config yaml if available. Overrides the minimal defaults.
server = d_server if (ic("ntfy_server") is None) else ic("ntfy_server")
sender = d_sender if (ic("ntfy_sender") is None) else ic("ntfy_sender")
destination = d_destination if (ic("ntfy_destination") is None) else ic("ntfy_destination")
priority = d_priority if (ic("ntfy_priority") is None) else ic("ntfy_priority")
message = d_message if (ic("ntfy_message") is None) else ic("ntfy_message")
tags = d_tags if (ic("ntfy_tags") is None) else ic("ntfy_tags")
click = d_click if (ic("ntfy_click") is None) else ic("ntfy_click")

help_text: str = """
 -u, --server        is the URL of the NTFY server, ending with a "/". Default is https://ntfy.sh/.
 -s, --sender        is the sender of the message, either an app name or a person. Default is "Wazuh (IDS)".
 -d, --destination   is the NTFY subscription, to send the message to. Default is none.
 -p, --priority      is the priority of the message, ranging from 1 (highest), to 5 (lowest). Default is 5.
 -m, --message       is the text of the message to be sent. Default is "Test message".
 -t, --tags          is an arbitrary strings of tags (keywords), seperated by a "," (comma). Default is "informational, testing, hard-coded".
 -c, --click         is a link (URL) that can be followed by tapping/clicking inside the message. Default is https://google.com.
 -h, --help          shows this help message. Must have no value argument.
 -v, --view          show config.
"""

#   Get params during execution. Params found here, override minimal defaults and/or config settings.
try:
    # Parsing argument
    arguments, values = getopt.getopt(argument_list, options, long_options)

    # Checking each argument
    for current_argument, current_value in arguments:

        if current_argument in ("-h", "--help"):
            print(help_text)
            exit()

        elif current_argument in ("-v", "--view"):
            vc()
            exit()

        elif current_argument in ("-u", "--server"):
            server = current_value

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
ntfy_command(server, sender, destination, priority, message, tags, click)

