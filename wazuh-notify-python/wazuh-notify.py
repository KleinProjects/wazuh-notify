#!/usr/bin/env python3

#           This program is free software; you can redistribute it
#           and/or modify it under the terms of the GNU General Public
#           License (version 2) as published by the FSF - Free Software
#           Foundation.
#
#           Rudi Klein, april 2024


import requests

from wazuh_notify_module import *


def main():
    me = frame(0).f_code.co_name
    him = frame(1).f_code.co_name

    # Load the YAML config.

    config: dict = get_config()

    logger(0, config, me, him, "############ Processing event ###############################")
    logger(2, config, me, him, "Loading yaml configuration")

    # Get the arguments used with running the script.

    arguments = get_arguments()

    # Check if we are in test mode (test_mode setting in config yaml). If so, load test event instead of live event.
    if config.get('python', 'test_mode'):

        logger(1, config, me, him, "Running in test mode: using test message wazuh-notify-test-event.json")

        # Load the test event data.

        home_path, _, _ = set_environment()
        with (open(home_path + '/etc/wazuh-notify-test-event.json') as event_file):
            data: dict = json.loads(event_file.read())

    else:

        # We are running live. Load the data from the Wazuh process.

        logger(2, config, me, him, "Running in live mode: using live message")
        data = load_message()

    # Extract the 'alert' section of the (JSON) event

    alert = data["parameters"]["alert"]
    logger(2, config, me, him, "Extracting data from the event")

    # Check the config for any exclusion rules

    fire_notification = exclusions_check(config, alert)
    logger(1, config, me, him, "Checking if we are outside of the exclusion rules: " + str(fire_notification))

    if not fire_notification:

        # The event was excluded by the exclusion rules in the configuration.

        logger(1, config, me, him, "Event excluded, no notification sent. Exiting")
        exit()
    else:

        # The event was not excluded by the exclusion rules in the configuration. Keep processing.

        logger(2, config, me, him, "Event NOT excluded, notification will be sent")

    # Get the mapping from event threat level to priority, color and mention_flag.

    priority, color, mention = threat_mapping(config, alert['rule']['level'], alert['rule']['firedtimes'])

    logger(2, config, me, him, "Threat mapping done: " +
           "prio:" + str(priority) + " color:" + str(color) + " mention:" + mention)

    # If the target argument was used with the script, we'll use that instead of the configuration parameter.

    config["targets"] = arguments['targets'] if arguments['targets'] != "" else config["targets"]

    # Prepare the messaging platform specific request and execute

    if "discord" in config["targets"]:
        caller = "discord"

        # Load the url/webhook from the configuration.

        discord_url, _, _ = get_env()

        discord_url = arguments['url'] if arguments['url'] else discord_url

        # Build the basic notification message content.

        notification: str = construct_basic_message(config, arguments, caller, alert)
        logger(2, config, me, him, caller + " basic message constructed")

        # Build the payload(s) for the POST request.

        _, _, payload_json = build_notification(caller,
                                                config,
                                                arguments,
                                                notification,
                                                alert,
                                                priority,
                                                color,
                                                mention
                                                )

        # POST the notification through requests.

        result = requests.post(discord_url, json=payload_json)

        logger(1, config, me, him, caller + " notification constructed and HTTPS request done: " + str(result))

    if "ntfy" in config["targets"]:
        caller = "ntfy"

        # Load the url/webhook from the configuration.

        _, ntfy_url, _ = get_env()

        # Build the basic notification message content.

        notification: str = construct_basic_message(config, arguments, caller, alert)

        logger(2, config, me, him, caller + " basic message constructed")

        # Build the payload(s) for the POST request.
        payload_headers, payload_data, _ = build_notification(caller,
                                                              config,
                                                              arguments,
                                                              notification,
                                                              alert,
                                                              priority,
                                                              color,
                                                              mention
                                                              )

        # POST the notification through requests.

        result = requests.post(ntfy_url, data=payload_data, headers=payload_headers)
        logger(1, config, me, him, caller + " notification constructed and request done: " + str(result))

    if "slack" in config["targets"]:
        caller = "slack"

        # Load the url/webhook from the configuration.

        _, _, slack_url = get_env()

        # Build the basic notification message content.

        notification: str = construct_basic_message(config, arguments, caller, alert)

        logger(2, config, me, him, caller + " basic message constructed")

        # Build the payload(s) for the POST request.

        _, _, payload_json = build_notification(caller,
                                                config,
                                                arguments,
                                                notification,
                                                alert,
                                                priority,
                                                color,
                                                mention
                                                )

        # POST the notification through requests.

        result = requests.post(slack_url, headers={'Content-Type': 'application/json'}, json=payload_json)

        logger(1, config, me, him, caller + " notification constructed and request done: " + str(result))

    logger(0, config, me, him, "############ Event processed ################################")
    exit(0)


if __name__ == "__main__":
    main()
