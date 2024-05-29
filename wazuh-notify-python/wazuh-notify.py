#!/usr/bin/env python3

#           This program is free software; you can redistribute it
#           and/or modify it under the terms of the GNU General Public
#           License (version 2) as published by the FSF - Free Software
#           Foundation.
#
#           Rudi Klein, May 2024


import requests

from wazuh_notify_module import *


def main():
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    me = frame(0).f_code.co_name
    him = frame(1).f_code.co_name

    # Load the TOML config.
    config: dict = get_config()

    logger(0, config, me, him, "############ Processing event ###############################")

    # Get the arguments used with running the script.
    arguments = get_arguments()

    # Check for test mode. Use test data if true.
    event_data = check_test_mode(config)

    # Extract the 'alert' section of the (JSON) event.
    alert = event_data["parameters"]["alert"]
    logger(2, config, me, him, "Extracting data from the event")

    # Check the config for any exclusion rules and abort when excluded.
    exclusions_check(config, alert)

    # Get the mapping from event threat level to priority, color and mention_flag.
    priority, color, mention = threat_mapping(config, alert['rule']['level'], alert['rule']['firedtimes'])

    # If the target argument was used with the script, we'll use that instead of the configuration parameter.
    config["targets"] = arguments['targets'] if arguments['targets'] != "" else config["targets"]

    # Prepare the messaging platform specific notification and execute if configured.

    # Discord notification handler
    if "discord" in config["targets"]:
        payload_json, discord_url = handle_discord_notification(config=config, arguments=arguments, alert=alert,
                                                                color=color, priority=priority, mention=mention)
        # POST the notification through requests.
        discord_result = requests.post(url=discord_url, json=payload_json)
        logger(1, config, me, him, "Discord notification constructed and sent: " + str(discord_result))

    # ntfy.sh notification handler
    if "ntfy" in config["targets"]:
        payload_data, payload_headers, ntfy_url = handle_ntfy_notification(config=config, arguments=arguments,
                                                                           alert=alert, priority=priority)
        # POST the notification through requests.
        ntfy_result = requests.post(url=ntfy_url, data=payload_data, headers=payload_headers)
        logger(1, config, me, him, "Ntfy notification constructed and sent: " + str(ntfy_result))

    # Slack notification handler
    if "slack" in config["targets"]:
        payload_json, slack_url = handle_slack_notification(config=config, arguments=arguments, alert=alert,
                                                            color=color, priority=priority, mention=mention)

        slack_result = requests.post(url=slack_url, headers={'Content-Type': 'application/json'}, json=payload_json)
        logger(1, config, me, him, "Slack notification constructed and sent: " + str(slack_result))

    # The end of processing
    logger(0, config, me, him, "############ Event processed ################################")
    exit(0)


if "__main__" == __name__:
    main()
