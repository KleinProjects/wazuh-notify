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

    # Check for test mode. Use test data if true
    data = check_test_mode(config)

    # Extract the 'alert' section of the (JSON) event
    alert = data["parameters"]["alert"]
    logger(2, config, me, him, "Extracting data from the event")

    # Check the config for any exclusion rules and abort when excluded.
    exclusions_check(config, alert)

    # Get the mapping from event threat level to priority, color and mention_flag.
    priority, color, mention = threat_mapping(config, alert['rule']['level'], alert['rule']['firedtimes'])

    # If the target argument was used with the script, we'll use that instead of the configuration parameter.
    config["targets"] = arguments['targets'] if arguments['targets'] != "" else config["targets"]

    # Prepare the messaging platform specific notification and execute if configured.
    if "discord" in config["targets"]:
        # Show me some ID! Stop resisting!
        caller = "discord"
        me = frame(0).f_code.co_name
        him = frame(1).f_code.co_name

        # Load the url/webhook from the configuration.
        discord_url, _, _ = get_env()
        discord_url = arguments['url'] if arguments['url'] else discord_url

        # Build the basic message content.
        message_body: str = construct_message_body(caller, config, arguments, alert)

        # Common preparation of the notification.
        notification_body, click, sender = prepare_payload(caller, config, arguments, message_body, alert, priority)

        # Build the payload(s) for the POST request.
        _, _, payload_json = build_discord_notification(caller, config, notification_body, color, mention, sender)

        # Build the notification to be sent.
        build_discord_notification(caller, config, notification_body, color, mention, sender)

        # POST the notification through requests.
        discord_result = requests.post(discord_url, json=payload_json)
        logger(1, config, me, him, caller + " notification constructed and sent: " + str(discord_result))

    if "ntfy" in config["targets"]:
        # Show me some ID! Stop resisting!
        caller = "ntfy"
        me = frame(0).f_code.co_name
        him = frame(1).f_code.co_name

        # Load the url/webhook from the configuration.
        _, ntfy_url, _ = get_env()
        ntfy_url = arguments['url'] if arguments['url'] else ntfy_url

        # Build the basic message content.
        message_body: str = construct_message_body(caller, config, arguments, alert)

        # Common preparation of the notification.
        notification_body, click, sender = prepare_payload(caller, config, arguments, message_body, alert, priority)

        # Build the payload(s) for the POST request.
        payload_headers, payload_data, _ = build_ntfy_notification(caller, config, notification_body, color, mention,
                                                                   sender)

        # Build the notification to be sent.
        build_ntfy_notification(caller, config, notification_body, priority, click, sender)

        # POST the notification through requests.
        ntfy_result = requests.post(ntfy_url, data=payload_data, headers=payload_headers)
        logger(1, config, me, him, caller + " notification constructed and sent: " + str(ntfy_result))

    # if "slack" in config["targets"]:
    # # Show me some ID! Stop resisting!
    # caller = "slack"
    # me = frame(0).f_code.co_name
    # him = frame(1).f_code.co_name
    #
    # # Load the url/webhook from the configuration.
    # _, _, slack_url = get_env()
    # slack_url = arguments['url'] if arguments['url'] else slack_url
    #
    # # Build the basic message content.
    # message_body: str = construct_message_body(caller, config, arguments, data)
    #
    # # Common preparation of the notification.
    # notification_body, click, sender = prepare_payload(caller, config, arguments, message_body, alert,
    #                                                    priority)
    # # Build the payload(s) for the POST request.
    # _, _, payload_json = build_slack_notification(caller, config, notification_body, priority, color, mention,
    #                                               click, sender)
    #
    # # Build the notification to be sent.
    # build_slack_notification(caller, config, notification_body, priority, click, sender)
    #
    # result = requests.post(slack_url, headers={'Content-Type': 'application/json'}, json=payload_json)
    #
    # logger(1, config, me, him, caller + " notification constructed and sent: " + str(result))

    logger(0, config, me, him, "############ Event processed ################################")
    exit(0)


if "__main__" == __name__:
    main()
