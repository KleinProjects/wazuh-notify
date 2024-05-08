import getopt
import os
import sys
import time
from os.path import join, dirname

import yaml
from dotenv import load_dotenv


def get_env():
    try:
        dotenv_path = join(dirname(__file__), '.env')
        load_dotenv(dotenv_path)
        if not os.path.isfile(dotenv_path):
            raise Exception(dotenv_path, "file not found")

        # Retrieve url from .env
        discord_url = os.getenv("DISCORD_url")
        ntfy_url = os.getenv("NTFY_url")

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


# Define paths: wazuh_path = wazuh root directory
#               ar_path = active-responses.log path,
#               config_path = wazuh-notifier-config.yaml

def set_environment():
    # todo fix reference when running manually/in process

    wazuh_path = "/var/ossec"
    # wazuh_path = os.path.abspath(os.path.join(__file__, "../../.."))
    ar_path = '{0}/logs/active-responses.log'.format(wazuh_path)
    config_path = 'wazuh-notifier-config.yaml'.format(wazuh_path)

    return wazuh_path, ar_path, config_path


# Import configuration settings from wazuh-notifier-config.yaml


def import_config():
    try:
        _, _, config_path = set_environment()

        with open(config_path, 'r') as ntfier_config:
            config: dict = yaml.safe_load(ntfier_config)
            return config
    except (FileNotFoundError, PermissionError, OSError):
        return None


# Show configuration settings from wazuh-notifier-config.yaml


def view_config():
    _, _, config_path = set_environment()

    try:
        with open(config_path, 'r') as ntfier_config:
            print(ntfier_config.read())
    except (FileNotFoundError, PermissionError, OSError):
        print(config_path + " does not exist or is not accessible")
        return


# Logging the Wazuh active Response request


def ar_log():
    now = set_time()
    _, ar_path, _ = set_environment()
    msg = '{0} {1} {2}'.format(now, os.path.realpath(__file__), 'Post JSON Alert')
    f = open(ar_path, 'a')
    f.write(msg + '\n')
    f.close()


def threat_priority_mapping(threat_level, np_1, np_2, np_3, np_4, np_5):
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


def get_yaml_config():
    config = import_config()

    config['np_1'] = "3, 3, 3" if (config.get("notifier_priority_1") is None) else config.get("notifier_priority_1")
    config['np_2'] = "4, 5" if (config.get("notifier_priority_2") is None) else config.get("notifier_priority_2")
    config['np_3'] = "6, 7" if (config.get("notifier_priority_3") is None) else config.get("notifier_priority_3")
    config['np_4'] = "8, 9" if (config.get("notifier_priority_4") is None) else config.get("notifier_priority_4")
    config['np_5'] = "10, 11, 12" if (config.get("notifier_priority_5") is None) else config.get("notifier_priority_5")
    config['targets'] = "ntfy, discord" if (config.get("targets") is None) else config.get("targets")
    config['excluded_rules'] = "" if (config.get("excluded_rules") is None) else config.get("excluded_rules")
    config['excluded_agents'] = "" if (config.get("excluded_agents") is None) else config.get("excluded_agents")
    config['sender'] = "Wazuh (IDS)" if (config.get("sender") is None) else config.get("sender")
    config['click'] = "https://wazuh.org" if (config.get("click") is None) else config.get("click")

    return config


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

    url, sender, destination, message, priority, tags, click = "", "", "", "", "", "", ""

    argument_list: list = sys.argv[1:]

    if not argument_list:
        pass

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
                    url = current_value

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

        return url, sender, destination, message, priority, tags, click
