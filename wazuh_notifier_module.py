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


def set_environment() -> tuple:
    # todo fix reference when running manually/in process

    set_wazuh_path = "/home/rudi/pycharm"
    # set_wazuh_path = os.path.abspath(os.path.join(__file__, "../../.."))
    set_ar_path = '{0}/logs/active-responses.log'.format(set_wazuh_path)
    set_config_path = '{0}/etc/wazuh-notify-config.yaml'.format(set_wazuh_path)
    set_notifier_path = '{0}/active-response/bin'.format(set_wazuh_path)

    return set_wazuh_path, set_ar_path, set_config_path, set_notifier_path


# Define paths: wazuh_path = wazuh root directory
#               ar_path = active-responses.log path,
#               config_path = wazuh-notifier-wazuh-notify-config.yaml

wazuh_path, ar_path, config_path, notifier_path = set_environment()


# Debug writer
def write_debug_file(ar_name, msg):
    with open(ar_path, mode="a") as log_file:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):])))
        log_file.write(
            str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name_posix + ": " + msg + "\n")


def get_env():
    try:
        dotenv_path = join(dirname(__file__), '.env')
        load_dotenv(dotenv_path)
        if not os.path.isfile(dotenv_path):
            raise Exception(dotenv_path, "file not found")

        # Retrieve url from .env
        discord_url = os.getenv("DISCORD_URL")
        ntfy_url = os.getenv("NTFY_URL")

    except Exception as err:
        # output error, and return with an error code
        print(str(Exception(err.args)))
        exit(err)

    return discord_url, ntfy_url


# Set structured timestamp for logging and discord/ntfy message.


def set_time():
    now_message = time.strftime('%a, %d %b %Y %H:%M:%S')
    now_logging = time.strftime('%Y/%m/%d %H:%M:%S')
    return now_message, now_logging


# Import configuration settings from wazuh-notify-config.yaml


def import_config():
    try:
        _, _, this_config_path, _ = set_environment()

        with open(this_config_path, 'r') as ntfier_config:
            config: dict = yaml.safe_load(ntfier_config)
            return config
    except (FileNotFoundError, PermissionError, OSError):
        return None


# Process configuration settings from wazuh-notify-config.yaml


def get_config():
    config = import_config()

    config['np_5'] = config.get('np_1', [15, 14, 13, 12])
    config['np_4'] = config.get('np_2', [11, 10, 9])
    config['np_3'] = config.get('np_3', [8, 7, 6])
    config['np_2'] = config.get('np_4', [5, 4])
    config['np_1'] = config.get('np_5', [3, 2, 1, 0])
    config['targets'] = config.get('targets', 'ntfy, discord')
    config['excluded_rules'] = config.get('excluded_rules', '')
    config['excluded_agents'] = config.get('excluded_agents', '')
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


# Logging the Wazuh active Response request


def ar_log():
    now = set_time()
    _, this_ar_path, _, _ = set_environment()
    msg = '{0} {1} {2}'.format(now, os.path.realpath(__file__), 'Post JSON Alert')
    f = open(this_ar_path, 'a')
    f.write(msg + '\n')
    f.close()


def threat_mapping(threat_level, np_1, np_2, np_3, np_4, np_5):
    # Map threat level v/s priority

    if threat_level in np_1:
        priority_mapping = "1"
    elif threat_level in np_2:
        priority_mapping = "2"
    elif threat_level in np_3:
        priority_mapping = "3"
    elif threat_level in np_4:
        priority_mapping = "4"
    elif threat_level in np_5:
        priority_mapping = "5"
    else:
        priority_mapping = "3"

    return priority_mapping


def color_mapping(priority):
    # Map priority to color

    if priority == 1:
        priority_color = 0x339900
    elif priority == 2:
        priority_color = 0x99cc33
    elif priority == 3:
        priority_color = 0xffcc00
    elif priority == 4:
        priority_color = 0xff9966
    elif priority == 5:
        priority_color = 0xcc3300
    else:
        priority_color = 0xffcc00

    return priority_color


def get_arguments():
    # Get params during execution. Params found here, override minimal defaults and/or config settings.

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
        return url, sender, destination, message, priority, tags, click

    else:

        try:
            # Parsing argument
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
                    priority: int = current_value

                elif current_argument in ("-m", "--message"):
                    message: str = current_value

                elif current_argument in ("-t", "--tags"):
                    tags: str = current_value

                elif current_argument in ("-c", "--click"):
                    click: str = current_value

        except getopt.error as err:
            # output error, and return with an error code
            print(str(err))

        return url, sender, destination, message, priority, tags, click


def load_message(argv):
    # get alert from stdin
    input_str: str = ""
    for line in sys.stdin:
        input_str: str = line
        break

    data: json = json.loads(input_str)

    if data.get("command") == "add":
        return data
    else:
        # todo fix error message
        sys.exit(1)


def parameters_deconstruct(argv, event_keys):
    config: dict = get_config()

    a_id: str = str(event_keys["agent"]["id"])
    a_name: str = str(event_keys["agent"]["name"])
    e_id: str = str(event_keys["rule"]["id"])
    e_description: str = str(event_keys["rule"]["description"])
    e_level: str = str(event_keys["rule"]["level"])
    e_fired_times: str = str(event_keys["rule"]["firedtimes"])
    e_full_event: str = str(json.dumps(event_keys, indent=4).replace('"', '')
                            .replace('{', '')
                            .replace('}', '')
                            .replace('[', '')
                            .replace(']', '')
                            )

    if e_id not in config["excluded_rules"] or a_id not in config["excluded_agents"]:
        parameters: dict = dict(a_id=a_id, a_name=a_name, e_id=e_id, e_description=e_description, e_level=e_level,
                                e_fired_times=e_fired_times, e_full_event=e_full_event)
        return parameters


def construct_basic_message(argv, accent: str, a_id: str, a_name: str, e_id: str, e_description: str, e_level: str,
                            e_fired_times: str) -> str:
    # Adding the BOLD text string to the Discord message. Ntfy has a different message format.

    basic_message: str = ("--message " + '"' +
                          accent + "Agent: " + accent + a_name + " (" + a_id + ")" + "\n" +
                          accent + "Event id: " + accent + e_id + "\n" +
                          accent + "Description: " + accent + e_description + "\n" +
                          accent + "Threat level: " + accent + e_level + "\n" +
                          # Watch this last addition to the string. It should include the closing quote for the
                          # basic_message string. It must be closed by -> '"'. This will be done outside this function
                          # in order to enable another specific addition (event_full_message) in the calling procedure.
                          accent + "Times fired: " + accent + e_fired_times + "\n")

    return basic_message
