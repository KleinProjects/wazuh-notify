#!/usr/bin/env python3

import datetime
import getopt
import json
import os
import sys
import time
from os.path import join, dirname
from pathlib import PureWindowsPath, PurePosixPath

import yaml
from dotenv import load_dotenv


# Define paths: wazuh_path = wazuh root directory
#               ar_path = active-responses.log path,
#               config_path = wazuh-notify-config.yaml
#
def set_environment() -> tuple:
    # todo fix reference when running manually/in process

    set_wazuh_path = "/home/rudi/pycharm"
    # set_wazuh_path = os.path.abspath(os.path.join(__file__, "../../.."))
    set_ar_path = '{0}/logs/wazuh-notifier.log'.format(set_wazuh_path)
    set_config_path = '{0}/etc/wazuh-notify-config.yaml'.format(set_wazuh_path)

    return set_wazuh_path, set_ar_path, set_config_path


# Set paths for use in this module
wazuh_path, ar_path, config_path = set_environment()


# Set structured timestamps for logging and notifications.


def set_time_format():
    now_message = time.strftime('%A, %d %b %Y %H:%M:%S')
    now_logging = time.strftime('%Y/%m/%d %H:%M:%S')
    now_time = time.strftime('%H:%M')
    now_weekday = time.strftime('%A')
    return now_message, now_logging, now_weekday, now_time


# Logger
def logger(config, message):
    # todo fix logging

    _, log_path, _ = set_environment()

    if config.get('extended_print', True):
        print(time.strftime('%Y/%m/%d %H:%M:%S'), "|", message)

    if config.get("extended_logging"):
        with open(ar_path, mode="a") as log_file:
            ar_name_posix = str(PurePosixPath(PureWindowsPath(log_path[log_path.find("active-response"):])))
            log_file.write(
                str(datetime.datetime.now().strftime(
                    '%Y/%m/%d %H:%M:%S')) + " " + ar_name_posix + ": " + message + "\n")
    else:
        pass


# Get the content of the .env file


def get_env():
    config: dict = get_config()

    try:
        dotenv_path = join(dirname(__file__), '.env')
        load_dotenv(dotenv_path)
        if not os.path.isfile(dotenv_path):
            logger(config, ".env not found")
            raise Exception(dotenv_path, "file not found")

        # Retrieve url from .env
        discord_url = os.getenv("DISCORD_URL")
        ntfy_url = os.getenv("NTFY_URL")
        slack_url = os.getenv("SLACK_URL")

    except Exception as err:
        # output error, and return with an error code
        logger(config, str(Exception(err.args)))
        exit(err)

    return discord_url, ntfy_url, slack_url


# Process configuration settings from wazuh-notify-config.yaml


def get_config():
    # DO NOT USE logger() IN THIS FUNCTION. IT WILL CREATE A RECURSION LOOP!

    this_config_path: str = ""

    try:
        _, _, this_config_path = set_environment()

        with open(this_config_path, 'r') as ntfier_config:
            config: dict = yaml.safe_load(ntfier_config)
    except (FileNotFoundError, PermissionError, OSError):
        print(time.strftime('%Y/%m/%d %H:%M:%S') + " | " + this_config_path + " missing")

    print(time.strftime('%Y/%m/%d %H:%M:%S') + " | " + "reading config: " + this_config_path)
    config['targets'] = config.get('targets', 'ntfy, discord')
    config['excluded_rules'] = config.get('excluded_rules', '')
    config['excluded_agents'] = config.get('excluded_agents', '')
    config['excluded_days'] = config.get('excluded_days', '')
    config['excluded_hours'] = config.get('excluded_hours', '')
    config['test_mode'] = config.get('test_mode', True)
    config['extended_logging'] = config.get('extended_logging', True)
    config['extended_print'] = config.get('extended_print', True)

    config['sender'] = 'Wazuh (IDS)'
    config['click'] = 'https://wazuh.org'

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

    # Get params during execution. Params found here override config settings.


def get_arguments():
    config: dict = get_config()
    # Short options
    options: str = "u:s:p:m:t:c:hv"

    # Long options
    long_options: list = ["url=", "sender=", "destination=", "priority=", "message=", "tags=", "click=", "help",
                          "view"]

    help_text: str = """
         -u, --url           is the url for the server, ending with a "/". 
         -s, --sender        is the sender of the message, either an app name or a person. 
         -d, --destination   is the NTFY subscription or Discord title, to send the message to. 
         -p, --priority      is the priority of the message, ranging from 1 (lowest), to 5 (highest). 
         -m, --message       is the text of the message to be sent.
         -t, --tags          is an arbitrary strings of tags (keywords), seperated by a "," (comma). 
         -c, --click         is a link (URL) that can be followed by tapping/clicking inside the message. 
         -h, --help          shows this help message. Must have no value argument.
         -v, --view          show config.

    """
    url: str
    sender: str
    destination: str
    message: str
    priority: int
    tags: str
    click: str

    url, sender, destination, message, priority, tags, click = "", "", "", "", 0, "", ""

    argument_list: list = sys.argv[1:]

    if not argument_list:
        logger(config, 'No argument list found (no arguments provided with script execution')
        return url, sender, destination, message, priority, tags, click

    else:

        try:

            logger(config, "Parsing arguments")

            # Parsing arguments
            arguments, values = getopt.getopt(argument_list, options, long_options)

            # checking each argument
            for current_argument, current_value in arguments:

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

                elif current_argument in ("-d", "--destination"):
                    destination: str = current_value

                elif current_argument in ("-p", "--priority"):
                    priority: int = int(current_value)

                elif current_argument in ("-m", "--message"):
                    message: str = current_value

                elif current_argument in ("-t", "--tags"):
                    tags: str = current_value

                elif current_argument in ("-c", "--click"):
                    click: str = current_value

        except getopt.error as err:
            # output error, and return with an error code

            logger(config, str(err))

        return url, sender, destination, message, priority, tags, click


# Receive and load message from Wazuh


def load_message():
    config: dict = get_config()

    # get alert from stdin

    logger(config, "Loading event message from STDIN")

    input_str: str = ""
    for line in sys.stdin:
        input_str: str = line
        break

    data: json = json.loads(input_str)

    if data.get("command") == "add":
        logger(config, "Relevant event data found")
        return data
    else:
        # todo fix error message
        sys.exit(1)


# Check if there are reasons not to process this event (as per config yaml)


def exclusions_check(config, alert):
    # Set some environment
    now_message, now_logging, now_weekday, now_time = set_time_format()

    # Check the exclusion records from the configuration yaml
    ex_hours: tuple = config.get('excluded_hours')

    # Start hour may not be later than end hours. End hour may not exceed 00:00 midnight to avoid day jump
    ex_hours = [ex_hours[0], "23:59"] if (ex_hours[1] >= '23:59' or ex_hours[1] < ex_hours[0]) else ex_hours

    # Get some more exclusion records from the config
    ex_days = config.get('excluded_days')
    ex_agents = config.get("excluded_agents")
    ex_rules = config.get("excluded_rules")

    # Check agent and rule from within the event
    ev_agent = alert['agent']['id']
    ev_rule = alert['rule']['id']

    # Let's assume all lights are green
    ex_hours_eval, ex_weekday_eval, ev_rule_eval, ev_agent_eval = True, True, True, True

    # Evaluate the conditions for sending a notification. Any False will cause the notification to be discarded.
    if (now_time > ex_hours[0]) and (now_time < ex_hours[1]):
        logger(config, "excluded: event inside exclusion time frame")
        ex_hours_eval = False
    elif now_weekday in ex_days:
        logger(config, "excluded: event inside excluded weekdays")
        ex_weekday_eval = False
    elif ev_rule in ex_rules:
        logger(config, "excluded: event id inside exclusion list")
        ev_rule_eval = False
    elif ev_agent in ex_agents:
        logger(config, "excluded: event agent inside exclusion list")
        ev_rule_eval = False

    notification_eval = ex_hours_eval and ex_weekday_eval and ev_rule_eval and ev_agent

    return notification_eval


# Map the event threat level to the appropriate 5-level priority scale and color for use in the notification platforms.


def threat_mapping(config, threat_level, fired_times):
    # Map threat level v/s priority

    p_map = config.get('priority_map')

    for i in range(len(p_map)):

        if threat_level in p_map[i]["threat_map"]:
            color_mapping = p_map[i]["color"]
            priority_mapping = 5 - i
            if fired_times >= p_map[i]["mention_threshold"]:
                mention_flag = "@here"
            else:
                mention_flag = ""
            return priority_mapping, color_mapping, mention_flag
        else:
            return 0, 0, 0


# Construct the message that will be sent to the notifier platforms


def construct_basic_message(accent: str, data: dict) -> str:
    # Adding the BOLD text string for Discord use

    basic_msg: str = (accent +
                      "Agent:" + " " + accent + data["agent"]["name"] + " (" + data["agent"][
                          "id"] + ")" + "\n" + accent +
                      "Rule id: " + accent + data["rule"]["id"] + "\n" + accent +
                      "Rule: " + accent + data["rule"]["description"] + "\n" + accent +
                      "Description: " + accent + data["full_log"] + "\n" + accent +
                      "Threat level: " + accent + str(data["rule"]["level"]) + "\n" + accent +
                      "Times fired: " + accent + str(data["rule"]["firedtimes"]) + "\n")

    return basic_msg


def build_notification(caller, config, notification, alert, priority, color, mention):
    click: str = config.get('click')
    sender: str = config.get('sender')
    priority: str = str(priority)
    tags = (str(alert['rule']['groups']).replace("[", "")
            .replace("]", "")
            .replace("'", "")
            .replace(",", ", ")
            )
    full_event: str = str(json.dumps(alert, indent=4)
                          .replace('"', '')
                          .replace('{', '')
                          .replace('}', '')
                          .replace('[', '')
                          .replace(']', '')
                          .replace(',', ' ')
                          )
    # Add the full alert data to the notification
    if caller in config["full_message"]:
        notification: str = ("\n\n" + notification + "\n" +
                             "**" + "__Full event__" + "**" + "\n" + "```\n" + full_event + "```")

    # Add Priority & tags to the notification
    notification = (notification + "\n\n" + "Priority: " + priority + "\n" +
                    "Tags: " + tags + "\n\n" + click)

    # Prepare the messaging platform specific notification and execute
    if "discord" in config["targets"]:
        url, _, _ = get_env()

        payload = {"username": "sender",
                   "content": mention,
                   "embeds": [{"description": notification,
                               "color": color,
                               "title": sender}]}
        return payload

    if "ntfy" in config["targets"]:
        caller = "ntfy"
        ntfy_url, _, _ = get_env()

        payload = {"username": "sender",
                   "content": mention,
                   "embeds": [{"description": notification,
                               "color": color,
                               "title": sender}]}
        return payload

    if "slack" in config["targets"]:
        caller = "slack"
        slack_url, _, _ = get_env()

        payload = {"username": "sender",
                   "content": mention,
                   "embeds": [{"description": notification,
                               "color": color,
                               "title": sender}]}
        return payload
