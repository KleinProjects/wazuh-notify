#!/usr/bin/env python3

import getopt
import json
import os
import sys
import time
from os.path import join, dirname
from sys import _getframe as frame

import yaml
from dotenv import load_dotenv


# Define paths: wazuh_path = wazuh root directory
#               log_path = wazuh-notify.log path,
#               config_path = wazuh-notify-config.yaml

def set_environment() -> tuple:

    set_wazuh_path = os.path.abspath(os.path.join(__file__, "../../.."))
    set_log_path = '{0}/logs/wazuh-notify.log'.format(set_wazuh_path)
    set_config_path = '{0}/etc/wazuh-notify-config.yaml'.format(set_wazuh_path)

    return set_wazuh_path, set_log_path, set_config_path


# Set paths for use in this module

wazuh_path, log_path, config_path = set_environment()


# Set structured timestamps for notifications.

def set_time_format():

    now_message = time.strftime('%A, %d %b %Y %H:%M:%S')
    now_logging = time.strftime('%Y-%m-%d %H:%M:%S')
    now_time = time.strftime('%H:%M')
    now_weekday = time.strftime('%A')

    return now_message, now_logging, now_weekday, now_time


# Logger: print to console and/or log to file

def logger(level, config, me, him, message):
    _, now_logging, _, _ = set_time_format()
    
    logger_wazuh_path = os.path.abspath(os.path.join(__file__, "../../.."))
    logger_log_path = '{0}/logs/wazuh-notify.log'.format(logger_wazuh_path)

    # When logging from main(), the destination function is called "<module>". For cosmetic reasons rename to "main".
    
    him = 'main' if him == '<module>' else him

    log_line = f'{now_logging} | {level} | {me: <23} | {him: <15} | {message}'

    # Compare the extended_print log level in the configuration to the log level of the message.

    if config.get('extended_print') >= level:
        print(log_line)

    try:
        # Compare the extended_logging level in the configuration to the log level of the message.

        if config.get("extended_logging") >= level:
            with open(logger_log_path, mode="a") as log_file:
                log_file.write(log_line + "\n")

    except (FileNotFoundError, PermissionError, OSError):

        # Special message to console when logging to file fails and console logging might not be set.

        log_line = f'{now_logging} | {level} | {me: <23} | {him: <15} | error opening log file: {logger_log_path}'
        print(log_line)


# Get the content of the .env file (url's and/or webhooks).

def get_env():
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.

    me = frame(0).f_code.co_name
    him = frame(1).f_code.co_name

    # Write the configuration to a dictionary.
    
    config: dict = get_config()

    # Check if the secrets .env file is available.
    
    try:
        dotenv_path = join(dirname(__file__), '.env')
        load_dotenv(dotenv_path)
        if not os.path.isfile(dotenv_path):
            logger(0, config, me, him, dotenv_path + " not found")
            raise Exception(dotenv_path, "file not found")

        # Retrieve URLs from .env

        discord_url = os.getenv("DISCORD_URL")
        ntfy_url = os.getenv("NTFY_URL")
        slack_url = os.getenv("SLACK_URL")

    except Exception as err:

        # output error, and return with an error code

        logger(0, config, me, him, 'Error reading ' + str(err))
        exit(err)

    logger(2, config, me, him, dotenv_path + " loaded")

    return discord_url, ntfy_url, slack_url


# Read and process configuration settings from wazuh-notify-config.yaml and create dictionary.

def get_config():
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    
    me = frame(0).f_code.co_name
    him = frame(1).f_code.co_name

    this_config_path: str = ""
    config: dict = {}

    try:
        _, _, this_config_path = set_environment()

        with open(this_config_path, 'r') as ntfier_config:
            config: dict = yaml.safe_load(ntfier_config)

    except (FileNotFoundError, PermissionError, OSError):
        logger(2, config, me, him, "Error accessing configuration file: " + this_config_path)

    logger(2, config, me, him, "Reading configuration file: " + this_config_path)

    config['targets'] = config.get('targets', 'discord, ntfy, slack')
    config['full_alert'] = config.get('full_alert', '')
    config['excluded_rules'] = config.get('excluded_rules', '')
    config['excluded_agents'] = config.get('excluded_agents', '')
    config['priority_map'] = config.get('priority_map', [])
    config['sender'] = config.get('sender', 'Wazuh (IDS)')
    config['click'] = config.get('click', 'https://wazuh.org')
    config['md_e'] = config.get('markdown_emphasis', '')

    config['excluded_days'] = config.get('excluded_days', '')
    config['excluded_hours'] = config.get('excluded_hours', '')
    config['test_mode'] = config.get('test_mode', False)
    config['extended_logging'] = config.get('extended_logging', True)
    config['extended_print'] = config.get('extended_print', True)

    return config


# Show configuration settings from wazuh-notify-config.yaml

def view_config():

    _, _, this_config_path, _ = set_environment()

    try:
        with open(this_config_path, 'r') as ntfier_config:
            print(ntfier_config.read())
    except (FileNotFoundError, PermissionError, OSError):
        print(this_config_path + " does not exist or is not accessible")
        return


# Get script arguments during execution. Params found here override config settings.

def get_arguments():
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.

    me = frame(0).f_code.co_name
    him = frame(1).f_code.co_name

    # Retrieve the configuration information

    config: dict = get_config()

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

            logger(2, config, me, him, "Parsing arguments")

            # Parsing arguments

            p_arguments, values = getopt.getopt(argument_list, options, long_options)

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


# Receive and load message from Wazuh

def load_message():
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    
    me = frame(0).f_code.co_name
    him = frame(1).f_code.co_name

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


# Check if there are reasons not to process this event. Check exclusions for rules, agents, days and hours.

def exclusions_check(config, alert):
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    
    me = frame(0).f_code.co_name
    him = frame(1).f_code.co_name

    # Set some environment

    now_message, now_logging, now_weekday, now_time = set_time_format()

    # Check the exclusion records from the configuration yaml.

    ex_hours: tuple = config.get('excluded_hours')

    # Start hour may not be later than end hours. End hour may not exceed 00:00 midnight to avoid day jump.

    ex_hours = [ex_hours[0], "23:59"] if (ex_hours[1] >= '23:59' or ex_hours[1] < ex_hours[0]) else ex_hours

    # Get some more exclusion records from the config.

    ex_days = config.get('excluded_days')
    ex_agents = config.get("excluded_agents")
    ex_rules = config.get("excluded_rules")

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

    logger(1, config, me, him, "Exclusion rules evaluated. Final decision: " + str(notification_eval))

    return notification_eval


# Map the event threat level to the appropriate 5-level priority scale and color for use in the notification platforms.

def threat_mapping(config, threat_level, fired_times):
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    
    me = frame(0).f_code.co_name
    him = frame(1).f_code.co_name

    # Map threat level to priority. Enters Homeland Security :-).

    p_map = config.get('priority_map')

    logger(2, config, me, him, "Prio map: " + str(p_map))

    for i in range(len(p_map)):

        logger(2, config, me, him, "Loop: " + str(i))
        logger(2, config, me, him, "Level: " + str(threat_level))

        if threat_level in p_map[i]["threat_map"]:

            color_mapping = p_map[i]["color"]
            priority_mapping = 5 - i

            logger(2, config, me, him, "Prio: " + str(priority_mapping))
            logger(2, config, me, him, "Color: " + str(color_mapping))

            if fired_times >= p_map[i]["mention_threshold"]:

                # When this flag is set, Discord recipients get a stronger message (DM).

                mention_flag = "@here"

            else:

                mention_flag = ""

            logger(2, config, me, him, "Threat level mapped as: " +
                   "prio:" + str(priority_mapping) + " color: " + str(color_mapping) + " mention: " + mention_flag)

            return priority_mapping, color_mapping, mention_flag

    logger(0, config, me, him, "Threat level mapping failed! Returning garbage (99, 99, 99)")

    return 99, 99, "99"


# Construct the message that will be sent to the notifier platforms.

def construct_basic_message(config, arguments, caller: str, data: dict) -> str:
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    
    me = frame(0).f_code.co_name
    him = frame(1).f_code.co_name

    # Include a specific control sequence for markdown bold parameter names.

    md_map = config.get('markdown_emphasis')
    md_e = md_map[caller]

    # If the --message (-m) argument was fulfilled, use this message to be sent.
    
    if arguments['message']:

        basic_msg = arguments['message']

    else:

        _, timestamp, _, _ = set_time_format()
        basic_msg: str = \
            (
                    md_e + "Timestamp:" + md_e + " " + timestamp + "\n" +
                    md_e + "Agent:" + md_e + " " + data["agent"]["name"] + " (" + data["agent"]["id"] + ")" + "\n" +
                    md_e + "Rule id:" + md_e + " " + data["rule"]["id"] + "\n" +
                    md_e + "Rule:" + md_e + " " + data["rule"]["description"] + "\n" +
                    md_e + "Description:" + md_e + " " + data["full_log"] + "\n" +
                    md_e + "Threat level:" + md_e + " " + str(data["rule"]["level"]) + "\n" +
                    md_e + "Times fired:" + md_e + " " + str(data["rule"]["firedtimes"]) + "\n")

        if caller == "ntfy":
            # todo Check this out
            basic_msg = "&nbsp;\n" + basic_msg

    logger(2, config, me, him, caller + " basic message constructed.")

    return basic_msg


# Construct the notification (message + additional information) that will be sent to the notifier platforms.

def build_notification(caller, config, arguments, notification, alert, priority, color, mention):
    # The 'me' variable sets the called function (current function), the 'him' the calling function. Used for logging.
    
    me = frame(0).f_code.co_name
    him = frame(1).f_code.co_name

    logger(2, config, me, him, caller + " notification being constructed.")

    md_map = config.get('markdown_emphasis')
    md_e = md_map[caller]

    click: str = config.get('click')
    sender: str = config.get('sender')
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
    # todo Redundant?

    click = arguments['click'] if arguments['click'] else click
    priority = arguments['priority'] if arguments['priority'] else priority
    sender = arguments['sender'] if arguments['sender'] else sender
    tags = arguments['tags'] if arguments['tags'] else tags

    # Add the full alert data to the notification.

    if caller in config["full_alert"]:
        logger(2, config, me, him, caller + "Full alert data will be sent.")

        notification: str = ("\n\n" + notification + "\n" +
                             md_e + "__Full event__" + md_e + "\n" + "```\n" + full_event + "```")

    # Add Priority & tags to the notification

    logger(2, config, me, him, caller + " adding priority and tags")

    notification = (notification + "\n\n" + md_e + "Priority:" + md_e + " " + str(priority) + "\n" +
                    md_e + "Tags:" + md_e + " " + tags + "\n\n" + click)

    config["targets"] = arguments['targets'] if arguments['targets'] != "" else config["targets"]

    # Prepare the messaging platform specific notification and execute

    if caller == "discord":

        logger(2, config, me, him, caller + " payload created")
        payload_json = {"username": sender,
                        "content": mention,
                        "embeds": [{"description": notification,
                                    "color": color,
                                    "title": sender}]}

        logger(2, config, me, him, caller + " notification built")

        return "", "", payload_json

    if caller == "ntfy":
        logger(2, config, me, him, caller + " payloads created")

        payload_data = notification
        payload_headers = {"Markdown": "yes",
                           "Title": sender,
                           "Priority": str(priority),
                           "Click": click}

        logger(2, config, me, him, caller + " notification built")

        return payload_headers, payload_data, ""

    if caller == "slack":
        logger(2, config, me, him, caller + " payloads created")

        # todo Need some investigation.

        payload_json = {"text": notification}
        # payload_json = {"username": sender,
        #                 "content": mention,
        #                 "embeds": [{"description": notification,
        #                             "color": color,
        #                             "title": sender}]}

        logger(2, config, me, him, caller + " notification built")

        return "", "", payload_json
