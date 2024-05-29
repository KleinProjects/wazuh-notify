#!/usr/bin/env python3

import getopt
import json
import os
import sys
import time
from os.path import join, dirname
from sys import _getframe as frame

import tomli
from dotenv import load_dotenv


# Define paths: wazuh_path = wazuh root directory
#               log_path = wazuh-notify.log path,
#               config_path = wazuh-notify-config.yaml


##############################################################################################
#                   General process environment handlers                                     #
##############################################################################################


def set_environment() -> tuple:
    set_wazuh_path = os.path.abspath(os.path.join(__file__, "../.."))
    # set_wazuh_path = os.path.abspath(os.path.join(__file__, "../../.."))
    set_log_path = '{0}/logs/wazuh-notify.log'.format(set_wazuh_path)
    set_config_path = '{0}/etc/wazuh-notify-config.toml'.format(set_wazuh_path)

    return set_wazuh_path, set_log_path, set_config_path


# Set paths for use in this module
wazuh_path, log_path, config_path = set_environment()


# Set structured timestamps for notifications.
def set_time_format() -> tuple:
    now_message = time.strftime('%A, %d %b %Y %H:%M:%S')
    now_logging = time.strftime('%Y-%m-%d %H:%M:%S')
    now_time = time.strftime('%H:%M')
    now_weekday = time.strftime('%A')

    return now_message, now_logging, now_weekday, now_time


# Logger: print to console and/or log to file
def logger(level, config, me, him, message) -> None:
    _, now_logging, _, _ = set_time_format()

    logger_wazuh_path, logger_log_path, _ = set_environment()

    # When logging from main(), the destination function is called "<module>". For cosmetic reasons rename to "main".
    him: str = 'main' if him == '<module>' else him
    log_line: str = f'{now_logging} | {level} | {me: <27} | {him: <27} | {message}'

    # Compare the extended_print log level in the configuration to the log level of the message.
    if config.get('python').get('extended_print', 0) >= level:
        print(log_line)
    try:
        # Compare the extended_logging level in the configuration to the log level of the message.
        if config.get('python').get('extended_logging', 0) >= level:
            with open(logger_log_path, mode="a") as log_file:
                log_file.write(log_line + "\n")
    except (FileNotFoundError, PermissionError, OSError):
        # Special message to console when logging to file fails and console logging might not be set.
        log_line: str = f'{now_logging} | {level} | {me: <27} | {him: <17} | error opening log file: {logger_log_path}'
        print(log_line)


# Get the content of the .env file (url's and/or webhooks).
def get_env() -> tuple:
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    me: str = frame(0).f_code.co_name
    him: str = frame(1).f_code.co_name

    # Write the configuration to a dictionary.
    config: dict = get_config()
    logger(2, config, me, him, "Configuration retrieved to dictionary")

    # Check if the secrets .env file is available.
    try:
        dotenv_path = join(dirname(__file__), '.env')
        load_dotenv(dotenv_path)
        if not os.path.isfile(dotenv_path):
            logger(0, config, me, him, dotenv_path + " not found")
            raise Exception(dotenv_path, "file not found")

        # Retrieve URLs from .env
        discord_url = os.getenv("DISCORD_URL")
        logger(2, config, me, him, "DISCORD_URL: " + discord_url)
        ntfy_url = os.getenv("NTFY_URL")
        logger(2, config, me, him, "NTFY_URL: " + ntfy_url)
        slack_url = os.getenv("SLACK_URL")
        logger(2, config, me, him, "SLACK_URL: " + slack_url)

    except Exception as err:
        # output error, and return with an error code
        logger(0, config, me, him, 'Error reading ' + str(err))
        exit(err)
    logger(2, config, me, him, dotenv_path + " loaded")

    return discord_url, ntfy_url, slack_url


# Read and process configuration settings from wazuh-notify-config.yaml and create dictionary.
def get_config() -> dict:
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    me: str = frame(0).f_code.co_name
    him: str = frame(1).f_code.co_name
    this_config_path: str = ""
    config: dict = {}

    try:
        _, _, this_config_path = set_environment()
        with open(this_config_path, 'rb') as ntfier_config:
            config: dict = tomli.load(ntfier_config)
    except (FileNotFoundError, PermissionError, OSError):
        logger(2, config, me, him, "Error accessing configuration file: " + this_config_path)
    logger(2, config, me, him, "Reading TOML configuration file: " + this_config_path)

    config['targets']: str = config.get('general').get('targets', 'discord, slack, ntfy')
    config['full_alert']: bool = config.get('general').get('full_alert', False)
    config['excluded_rules']: str = config.get('general').get('excluded_rules', '')
    config['excluded_agents']: str = config.get('general').get('excluded_agents', '')
    config['priority_map']: dict = config.get('priority_map', [])
    config['sender']: str = config.get('general').get('sender', 'Wazuh (IDS)')
    config['click']: str = config.get('general').get('click', 'https://wazuh.com')
    config['md_e']: str = config.get('general').get('markdown_emphasis', '')
    config['excluded_days']: list = config.get('python').get('excluded_days', '')
    config['excluded_hours']: list = config.get('python').get('excluded_hours', '')
    config['test_mode']: bool = config.get('python').get('test_mode', False)
    config['extended_logging']: int = config.get('python').get('extended_logging', 0)
    config['extended_print']: int = config.get('python').get('extended_print', 0)

    return config


# Show configuration settings from wazuh-notify-config.yaml
def view_config() -> None:
    _, _, this_config_path, _ = set_environment()

    try:
        with open(this_config_path, 'r') as ntfier_config:
            print(ntfier_config.read())
    except (FileNotFoundError, PermissionError, OSError):
        print(this_config_path + " does not exist or is not accessible")
        return


# Get script arguments during execution. Params found here override config settings.
def get_arguments() -> dict:
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    me: str = frame(0).f_code.co_name
    him: str = frame(1).f_code.co_name

    # Retrieve the configuration information
    config: dict = get_config()
    logger(2, config, me, him, "Configuration retrieved to dictionary")

    # Short options
    options: str = "u:s:p:m:t:c:hv"

    # Long options
    long_options: list = ["url=",
                          "sender=",
                          "targets=",
                          "priority=",
                          "message=",
                          "tags=",
                          "click=",
                          "help",
                          "view"
                          ]

    help_text: str = """
         -u, --url           is the url for the server, ending with a "/". 
         -s, --sender        is the sender of the message, either an app name or a person. 
         -d, --targets       is the list of platforms to send a message to (slack, ntfy, discord) 
         -p, --priority      is the priority of the message, ranging from 1 (lowest), to 5 (highest). 
         -m, --message       is the text of the message to be sent.
         -t, --tags          is an arbitrary strings of tags (keywords), seperated by a "," (comma). 
         -c, --click         is a link (URL) that can be followed by tapping/clicking inside the message. 
         -h, --help          shows this help message. Must have no value argument.
         -v, --view          show config.

    """

    # Initialize some variables.
    url: str = ""
    sender: str = ""
    targets: str = ""
    message: str = ""
    priority: int = 0
    tags: str = ""
    click: str = ""

    # Fetch the arguments from the command line, skipping the first argument (name of the script).
    argument_list: list = sys.argv[1:]
    logger(2, config, me, him, "Found arguments:" + str(argument_list))

    if not argument_list:
        logger(1, config, me, him, 'No argument list found (no arguments provided with script execution')

        # Store defaults for the non-existing arguments in the arguments dictionary to avoid None errors.
        arguments: dict = {'url': url,
                           'sender': sender,
                           'targets': targets,
                           'message': message,
                           'priority': priority,
                           'tags': tags,
                           'click': click}
        return arguments
    else:
        try:
            # Parsing arguments
            p_arguments, values = getopt.getopt(argument_list, options, long_options)
            logger(2, config, me, him, "Parsing arguments")

            # Check each argument. Arguments that are present will override the defaults.
            for current_argument, current_value in p_arguments:
                if current_argument in ("-h", "--help"):
                    print(help_text)
                    exit()
                elif current_argument in ("-v", "--view"):
                    view_config()
                    exit()
                elif current_argument in ("-u", "--url"):
                    url: str = current_value
                elif current_argument in ("-s", "--sender"):
                    sender: str = current_value
                elif current_argument in ("-d", "--targets"):
                    targets: str = current_value
                elif current_argument in ("-p", "--priority"):
                    priority: int = int(current_value)
                elif current_argument in ("-m", "--message"):
                    message: str = current_value
                elif current_argument in ("-t", "--tags"):
                    tags: str = current_value
                elif current_argument in ("-c", "--click"):
                    click: str = current_value
        except getopt.error as err:

            # Output error, and return error code
            logger(0, config, me, him, "Error during argument parsing:" + str(err))
        logger(2, config, me, him, "Arguments returned as dictionary")

        # Store the arguments in the arguments dictionary.
        arguments: dict = {'url': url, 'sender': sender, 'targets': targets, 'message': message,
                           'priority': priority, 'tags': tags, 'click': click}
        return arguments


##############################################################################################
#                   Wazuh event handling                                                     #
##############################################################################################


# Receive and load message from Wazuh
def load_message() -> dict:
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    me: str = frame(0).f_code.co_name
    him: str = frame(1).f_code.co_name
    config: dict = get_config()

    # get alert from stdin
    logger(2, config, me, him, "Loading event message from STDIN")

    input_str: str = ""
    for line in sys.stdin:
        input_str: str = line
        break

    data: json = json.loads(input_str)

    if data.get("command") == "add":
        logger(1, config, me, him, "Relevant event data found")
        return data
    else:
        # Event came in, but wasn't processed.
        logger(0, config, me, him, "Event data not found")
        sys.exit(1)


# Check if we are in test mode (test_mode setting in config yaml). If so, load test event instead of live event.
def check_test_mode(config) -> dict:
    me: str = frame(0).f_code.co_name
    him: str = frame(1).f_code.co_name

    if config.get('python').get('test_mode'):
        logger(1, config, me, him, "Running in test mode: using test message wazuh-notify-test-event.json")
        # Load the test event data.
        home_path, _, _ = set_environment()
        with (open(home_path + '/etc/wazuh-notify-test-event.json') as event_file):
            data: dict = json.loads(event_file.read())
    else:
        # We are running live. Load the data from the Wazuh process.
        logger(2, config, me, him, "Running in live mode: using live message")
        data: dict = load_message()

    return data


# Check if there are reasons not to process this event. Check exclusions for rules, agents, days and hours.
def exclusions_check(config, alert) -> None:
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    me: str = frame(0).f_code.co_name
    him: str = frame(1).f_code.co_name

    # Set some environment
    now_message, now_logging, now_weekday, now_time = set_time_format()
    logger(2, config, me, him, "Setting pretty datetime formats for notifications and logging.")

    # Check the exclusion records from the configuration yaml.
    logger(1, config, me, him, "Checking if we are outside of the exclusion rules: ")
    ex_hours: tuple = config.get('python').get('excluded_hours')

    # Start hour may not be later than end hours. End hour may not exceed 00:00 midnight to avoid day jump.
    ex_hours: tuple = [ex_hours[0], "23:59"] if (ex_hours[1] >= '23:59' or ex_hours[1] < ex_hours[0]) else ex_hours

    # Get some more exclusion records from the config.
    ex_days: str = config.get('python').get('excluded_days')
    ex_agents: str = config.get('general').get("excluded_agents")
    ex_rules: str = config.get('general').get("excluded_rules")

    # Check agent and rule from within the event.
    ev_agent = alert['agent']['id']
    ev_rule = alert['rule']['id']

    # Let's assume all lights are green, until proven otherwise.
    ex_hours_eval, ex_weekday_eval, ev_rule_eval, ev_agent_eval = True, True, True, True

    # Evaluate the conditions for sending a notification. Any False will cause the notification to be discarded.
    if (now_time > ex_hours[0]) and (now_time < ex_hours[1]):
        logger(2, config, me, him, "excluded: event inside exclusion time frame")
        ex_hours_eval = False
    elif now_weekday in ex_days:
        logger(2, config, me, him, "excluded: event inside excluded weekdays")
        ex_weekday_eval = False
    elif ev_rule in ex_rules:
        logger(2, config, me, him, "excluded: event id inside exclusion list")
        ev_rule_eval = False
    elif ev_agent in ex_agents:
        logger(2, config, me, him, "excluded: event agent inside exclusion list")
        ev_rule_eval = False

    notification_eval = True if (ex_hours_eval and ex_weekday_eval and ev_rule_eval and ev_agent_eval) else False
    logger(1, config, me, him, "Exclusion rules evaluated. Process event is " + str(notification_eval))

    if not notification_eval:
        # The event was excluded by the exclusion rules in the configuration.
        logger(1, config, me, him, "Event excluded, no notification sent. Exiting")
        exit()
    else:
        # The event was not excluded by the exclusion rules in the configuration. Keep processing.
        logger(2, config, me, him, "Event NOT excluded, notification will be sent")

    return


# Map the event threat level to the appropriate 5-level priority scale and color for use in the notification platforms.
def threat_mapping(config, threat_level, fired_times):
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    me: str = frame(0).f_code.co_name
    him: str = frame(1).f_code.co_name

    # Map threat level to priority. Enters Homeland Security :-).
    p_map = config.get('priority_map')
    logger(2, config, me, him, "Threat mapping: priority mapped to: " + str(p_map))

    for i in range(len(p_map)):
        logger(2, config, me, him, "Threat mapping: list loop counter: " + str(i))
        logger(2, config, me, him, "Threat mapping: threat level found: " + str(threat_level))

        if threat_level in p_map[i]["threat_map"]:
            color_mapping = p_map[i]["color"]
            priority_mapping = 5 - i
            logger(2, config, me, him, "Threat mapping: priority: " + str(priority_mapping))
            logger(2, config, me, him, "Threat mapping: color: " + str(color_mapping))

            if fired_times >= p_map[i]["notify_threshold"]:
                logger(2, config, me, him, "The notification_threshold prevents this message from sending")
                exit(0)

            if fired_times >= p_map[i]["mention_threshold"]:
                # When this flag is set, Discord!! recipients get a stronger message (DM).
                mention_flag = "@here"
                logger(2, config, me, him, "Threat mapping: mention flag: " + str(mention_flag))
            else:
                mention_flag = ""
            logger(2, config, me, him, "Threat level mapped as: " + "priority:" + str(priority_mapping) +
                   " color: " + str(color_mapping) + " mention: " + str(mention_flag))

            return priority_mapping, color_mapping, mention_flag

    logger(0, config, me, him, "Threat level mapping failed! Returning garbage (99, 99, 99)")
    return 99, 99, "99"


##############################################################################################
#                   Common notification preparation                                          #
##############################################################################################


# Construct the message that will be sent to the notifier platforms.
def construct_message_body(caller, config, arguments, alert) -> str:
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    me: str = frame(0).f_code.co_name
    him: str = frame(1).f_code.co_name

    logger(2, config, me, him, caller + ": Constructing message body")

    # Include a specific control sequence for markdown bold parameter names.
    # todo To be fixed
    md_map = config.get('markdown_emphasis', '')
    md_e = md_map[caller]
    logger(2, config, me, him, caller + "Emphasis string used: " + md_e)

    # If the --message (-m) argument was fulfilled, use this message to be sent.
    if arguments['message']:
        message_body = arguments['message']
    else:
        _, timestamp, _, _ = set_time_format()
        message_body: str = \
            (
                    md_e + "Timestamp:" + md_e + " " + timestamp + "\n" +
                    md_e + "Agent:" + md_e + " " + alert["agent"]["name"] + " (" + alert["agent"]["id"] + ")" + "\n" +
                    md_e + "Rule id:" + md_e + " " + alert["rule"]["id"] + "\n" +
                    md_e + "Rule:" + md_e + " " + alert["rule"]["description"] + "\n" +
                    md_e + "Description:" + md_e + " " + alert["full_log"] + "\n" +
                    md_e + "Threat level:" + md_e + " " + str(alert["rule"]["level"]) + "\n" +
                    md_e + "Times fired:" + md_e + " " + str(alert["rule"]["firedtimes"]) + "\n"
            )
    logger(2, config, me, him, caller + " basic message constructed. Returning: " + message_body)
    return message_body


# Construct the notification (message + additional information) that will be sent to the notifier platforms.
def prepare_payload(caller, config, arguments, message_body, alert, priority):
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    me: str = frame(0).f_code.co_name
    him: str = frame(1).f_code.co_name

    logger(2, config, me, him, "Payload being constructed.")

    md_map = config.get('markdown_emphasis', '')
    md_e = md_map[caller]
    logger(2, config, me, him, caller + "Emphasis string used: " + md_e)

    priority: str = str(priority)
    tags = (str(alert['rule']['groups']).replace("[", "")
            .replace("]", "")
            .replace("'", "")
            .replace(",", ", ")
            )
    logger(2, config, me, him, caller + " full event formatted.")

    full_event: str = str(json.dumps(alert, indent=4)
                          .replace('"', '')
                          .replace('{', '')
                          .replace('}', '')
                          .replace('[', '')
                          .replace(']', '')
                          .replace(',', ' ')
                          )
    # Fill some of the variables with argument values if available.

    priority = arguments['priority'] if arguments['priority'] else priority
    tags = arguments['tags'] if arguments['tags'] else tags
    sender: str = config.get('general').get('sender', 'Wazuh (IDS)')
    sender = arguments['sender'] if arguments['sender'] else sender
    click: str = config.get('general').get('click', 'https://wazuh.com')
    click = arguments['click'] if arguments['click'] else click

    # Add the full alert data to the notification.
    if caller in config["full_alert"]:
        logger(2, config, me, him, caller + "Full alert data will be attached.")
        # Add the full alert data to the notification body
        notification_body: str = ("\n\n" + message_body + "\n" +
                                  md_e + "__Full event__" + md_e + "\n" + "```\n" + full_event + "```")
    else:
        notification_body: str = message_body

    # Add priority & tags to the notification body
    notification_body = (notification_body + "\n\n" + md_e + "Priority:" + md_e + " " + str(priority) + "\n" +
                         md_e + "Tags:" + md_e + " " + tags + "\n\n" + click)
    logger(2, config, me, him, caller + " adding priority and tags")

    config["targets"] = arguments['targets'] if arguments['targets'] != "" else config["targets"]

    return notification_body, click, sender


##############################################################################################
#                    Platform specific notification creation and handling                    #
##############################################################################################


# Build the notification for this specific platform.
def build_discord_notification(config, notification_body, color, mention, sender):
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    me: str = frame(0).f_code.co_name
    him: str = frame(1).f_code.co_name
    logger(2, config, me, him, "Discord payload created")

    payload_json = {"username": sender,
                    "content": mention,
                    "embeds": [{"description": notification_body,
                                "color": color,
                                "title": sender}]}
    logger(2, config, me, him, "Discord notification built")
    return "", "", payload_json


# Build the notification for this specific platform.
def build_ntfy_notification(config, notification_body, priority, click, sender):
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    me: str = frame(0).f_code.co_name
    him: str = frame(1).f_code.co_name
    logger(2, config, me, him, "Ntfy payloads created")

    payload_data = notification_body
    payload_headers = {"Markdown": "yes",
                       "Title": sender,
                       "Priority": str(priority),
                       "Click": click}
    logger(2, config, me, him, "Ntfy notification built")
    return payload_headers, payload_data, ""


# Build the notification for this specific platform.
def build_slack_notification(config, notification_body, color, mention, sender):
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    me: str = frame(0).f_code.co_name
    him: str = frame(1).f_code.co_name
    logger(2, config, me, him, "Slack payload created")

    payload_json = {"username": sender,
                    "content": mention,
                    "embeds": [{"description": notification_body,
                                "color": color,
                                "title": sender}]}
    logger(2, config, me, him, "Slack notification built")
    return "", "", payload_json


# Handle the complete notification generation for this specific platform.
def handle_discord_notification(config, arguments, alert, color, priority, mention):
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    me: str = frame(0).f_code.co_name
    him: str = frame(1).f_code.co_name

    logger(1, config, me, him, "Process discord notification: start")

    # Load the url/webhook from the configuration.
    discord_url, _, _ = get_env()
    discord_url = arguments['url'] if arguments['url'] else discord_url

    # Build the basic message content.
    message_body: str = construct_message_body(caller='discord', config=config, arguments=arguments, alert=alert)

    # Common preparation of the notification.
    notification_body, click, sender = prepare_payload(caller='discord', config=config, arguments=arguments,
                                                       message_body=message_body, alert=alert, priority=priority)

    # Build the payload(s) for the POST request.
    _, _, payload_json = build_discord_notification(config=config, notification_body=notification_body, color=color,
                                                    mention=mention, sender=sender)

    logger(1, config, me, him, "Process discord notification: done")
    return payload_json, discord_url


# Handle the complete notification generation for this specific platform.
def handle_ntfy_notification(config, arguments, alert, priority):
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    me: str = frame(0).f_code.co_name
    him: str = frame(1).f_code.co_name

    logger(1, config, me, him, "Process ntfy notification: start")

    # Load the url/webhook from the configuration.
    _, ntfy_url, _ = get_env()
    ntfy_url = arguments['url'] if arguments['url'] else ntfy_url

    # Build the basic message content.
    message_body: str = construct_message_body(caller='ntfy', config=config, arguments=arguments, alert=alert)

    # Special blank line after the title of the message.
    message_body = "&nbsp;\n" + message_body

    # Common preparation of the notification.
    notification_body, click, sender = prepare_payload(caller='ntfy', config=config, arguments=arguments,
                                                       message_body=message_body, alert=alert, priority=priority)

    # Build the payload(s) for the POST request.
    payload_headers, payload_data, _ = build_ntfy_notification(config=config, notification_body=notification_body,
                                                               priority=priority, click=click, sender=sender)

    logger(1, config, me, him, "Process ntfy notification: done")
    return payload_data, payload_headers, ntfy_url


# Handle the complete notification generation for this specific platform.
def handle_slack_notification(config, arguments, alert, color, priority, mention):
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    me: str = frame(0).f_code.co_name
    him: str = frame(1).f_code.co_name

    logger(1, config, me, him, "Process slack notification: start")

    # Load the url/webhook from the configuration.
    _, _, slack_url = get_env()
    slack_url = arguments['url'] if arguments['url'] else slack_url

    # Build the basic message content.
    message_body: str = construct_message_body(caller='slack', config=config, arguments=arguments, alert=alert)

    # Common preparation of the notification.
    notification_body, click, sender = prepare_payload(caller='slack', config=config, arguments=arguments,
                                                       message_body=message_body, alert=alert, priority=priority)

    # Build the payload(s) for the POST request.
    _, _, payload_json = build_slack_notification(config=config, notification_body=notification_body, color=color,
                                                  mention=mention, sender=sender)

    logger(1, config, me, him, "Process slack notification: done")
    return payload_json, slack_url
