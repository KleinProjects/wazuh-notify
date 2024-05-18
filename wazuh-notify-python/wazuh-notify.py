#!/usr/bin/env python3

# This script is adapted version of the Python active response script sample, provided by Wazuh, in the documentation:
# https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
# It is provided under the below copyright statement:
#
#           Copyright (C) 2015-2022, Wazuh Inc.
#           All rights reserved.
#
#           This program is free software; you can redistribute it
#           and/or modify it under the terms of the GNU General Public
#           License (version 2) as published by the FSF - Free Software
#           Foundation.
#
# This adapted version is free software. Rudi Klein, april 2024

import json
import sys

import requests

from wazuh_notify_module import build_notification
from wazuh_notify_module import construct_basic_message
from wazuh_notify_module import exclusions_check
from wazuh_notify_module import get_arguments
from wazuh_notify_module import get_config
from wazuh_notify_module import get_env
from wazuh_notify_module import load_message
from wazuh_notify_module import logger
from wazuh_notify_module import set_environment
from wazuh_notify_module import threat_mapping


def main(argv):
    # Load the YAML config
    config: dict = get_config()

    # Path variables assignments
    wazuh_path, ar_path, config_path = set_environment()

    # Get the arguments used with running the script
    arg_url, arg_sender, arg_destination, arg_message, arg_priority, arg_tags, arg_click = get_arguments()

    # Check if we are in test mode (test_mode setting in config yaml). If so, load test event instead of live event.
    if config.get("test_mode"):
        logger(config, "In test mode: using test message wazuh-notify-test-event.json")

        with (open('wazuh-notify-test-event.json') as event_file):
            data: dict = json.loads(event_file.read())

    else:
        logger(config, "In live mode: using live message")
        data = load_message()

    # Extract the 'alert' section of the (JSON) event
    alert = data["parameters"]["alert"]

    # Check the config for any exclusion rules
    fire_notification = exclusions_check(config, alert)

    if not fire_notification:
        logger(config, "Event excluded, no notification sent. Exiting")
        exit()

    # Include a specific control sequence for Discord bold text
    if "discord" in config["targets"]:
        accent: str = "**"
    else:
        accent: str = ""

    # Create the notification text to be sent.
    notification: str = construct_basic_message(accent, alert)
    logger(config, "Notification constructed")

    # todo Not used?
    # Get the mapping from event threat level to priority (Discord/ntfy), color (Discord) and mention_flag (Discord)
    priority, color, mention = threat_mapping(config, alert['rule']['level'],
                                              alert['rule']['firedtimes'])

    result = ""
    # Prepare the messaging platform specific request and execute
    if "discord" in config["targets"]:
        caller = "discord"
        discord_url, _, _ = get_env()
        payload = build_notification(caller, config, notification, alert, priority, color, mention)
        result = requests.post(discord_url, json=payload)
        exit(result)

    if "ntfy" in config["targets"]:
        caller = "ntfy"
        ntfy_url, _, _ = get_env()
        payload = build_notification(caller, config, notification, alert, priority, color, mention)
        result = requests.post(ntfy_url, json=payload)
        exit(result)

    if "slack" in config["targets"]:
        caller = "slack"
        slack_url, _, _ = get_env()
        payload = build_notification(caller, config, notification, alert, priority, color, mention)
        result = requests.post(slack_url, json=payload)
        exit(result)


if __name__ == "__main__":
    main(sys.argv)
