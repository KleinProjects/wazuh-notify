#!/usr/bin/env python3

#           This program is free software; you can redistribute it
#           and/or modify it under the terms of the GNU General Public
#           License (version 2) as published by the FSF - Free Software
#           Foundation.
#
#           Rudi Klein, May 2024


import requests
from requests import Response

from wazuh_notify_module import *


def main():
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    me: str = frame(0).f_code.co_name
    him: str = frame(1).f_code.co_name
    config: dict = get_config()

    # Write header line in logfile
    logger(level=99, config=config, me=me, him=him, message='')

    # Load the TOML config.
    logger(level=0, config=config, me=me, him=him, message='############# [Processing event] #########################')

    # Get the arguments used with running the script.
    arguments: dict = get_arguments()

    # Check for test mode. Use test data if true.
    event_data: dict = check_test_mode(config)

    alert: dict = event_data['parameters']['alert']
    logger(level=2, config=config, me=me, him=him, message='Extracting data from the event')

    # Check the config for any exclusion rules and abort when excluded.
    if not exclusions_check(config, alert):
        logger(level=1, config=config, me=me, him=him, message='Event excluded, no notification sent. Exiting')
        exit()
    logger(level=2, config=config, me=me, him=him, message='Event NOT excluded, notification will be sent')

    # Get the mapping from event threat level to priority, color and mention_flag.
    priority, color, mention = threat_mapping(config, alert['rule']['level'], alert['rule']['firedtimes'])

    config['targets'] = arguments['targets'] if arguments['targets'] != '' else config['targets']

    # Discord notification handler
    if 'discord' in config['targets']:
        payload_json, discord_url = handle_discord_notification(config=config, arguments=arguments, alert=alert,
                                                                color=color, priority=priority, mention=mention)
        discord_result: Response = requests.post(url=discord_url, json=payload_json)
        logger(level=1, config=config, me=me, him=him,
               message=f'Discord notification constructed and sent: %s' % discord_result)
    # ntfy.sh notification handler
    if 'ntfy' in config['targets']:
        payload_data, payload_headers, ntfy_url = handle_ntfy_notification(config=config, arguments=arguments,
                                                                           alert=alert, priority=priority)
        ntfy_result: Response = requests.post(url=ntfy_url, data=payload_data, headers=payload_headers)
        logger(level=1, config=config, me=me, him=him,
               message=f'Ntfy notification constructed and sent: %s' % ntfy_result)
    # Slack notification handler
    if 'slack' in config['targets']:
        payload_json, slack_url = handle_slack_notification(config=config, arguments=arguments, alert=alert,
                                                            color=color, priority=priority, mention=mention)
        slack_result: Response = requests.post(url=slack_url, json=payload_json)
        logger(1, config, me, him, f'Slack notification constructed and sent: %s' % slack_result)

    logger(0, config, me, him, '############# [Event processed] #########################')
    exit(0)


if __name__ == '__main__':
    main()
