import getopt
import os
import sys
import time

import yaml


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
    config_path = '{0}/etc/wazuh-notifier-config.yaml'.format(wazuh_path)

    return wazuh_path, ar_path, config_path


# Import configuration settings from wazuh-notifier-config.yaml


def import_config(key):
    try:
        _, _, config_path = set_environment()

        with open(config_path, 'r') as ntfier_config:
            config: dict = yaml.safe_load(ntfier_config)
            value: str = config.get(key)
            return value
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


def set_basic_defaults(notifier):
    # Setting some minimal defaults in case the yaml config isn't available
    notifier: str = notifier.lower()

    sender: str = "Security message"
    destination: str = "Test"
    priority: str = "1"
    message: str = "Test message"
    tags: str = "informational, testing, hard-coded"
    click: str = "https://google.com"

    if notifier == "ntfy":
        # NTFY defaults.
        server: str = "https://ntfy.sh/"

    elif notifier == "discord":

        # Discord defaults.
        server: str = ""

    else:
        server: str = "Unknown notifier specified. Must be ntfy or discord."

    # Mapping event threat level to 5 value priority level.

    np_5 = "12, 11, 10"
    np_4 = "9, 8"
    np_3 = "7, 6"
    np_2 = "5, 4"
    np_1 = "3, 2, 1"

    return (server, sender, destination, priority, message, tags, click,
            np_1, np_2, np_3, np_4, np_5)


def get_yaml_config(notifier: str, y_server: str, y_sender: str, y_destination: str, y_priority: str, y_message: str,
                    y_tags: str, y_click: str, y_np_1: str, y_np_2: str, y_np_3: str, y_np_4: str, y_np_5: str):
    notifier: str = notifier.lower()
    server = y_server if (import_config(notifier + "_server") is None) else import_config(notifier + "_server")
    sender = y_sender if (import_config(notifier + "_sender") is None) else import_config(notifier + "_sender")
    destination = y_destination if (import_config(notifier + "_destination") is None) else \
        import_config(notifier + "_destination")
    priority = y_priority if (import_config(notifier + "_priority") is None) else import_config(notifier + "_priority")
    message = y_message if (import_config(notifier + "_message") is None) else import_config(notifier + "_message")
    tags = y_tags if (import_config(notifier + "_tags") is None) else import_config(notifier + "_tags")
    click = y_click if (import_config(notifier + "_click") is None) else import_config(notifier + "_click")

    np_1 = y_np_1 if (import_config("np1") is None) else import_config("np1")
    np_2 = y_np_2 if (import_config("np2") is None) else import_config("np2")
    np_3 = y_np_3 if (import_config("np3") is None) else import_config("np3")
    np_4 = y_np_4 if (import_config("np4") is None) else import_config("np4")
    np_5 = y_np_5 if (import_config("np5") is None) else import_config("np5")

    return (server, sender, destination, priority, message, tags, click,
            np_1, np_2, np_3, np_4, np_5)


def call_for_help(notifier):
    notifier: str = notifier.lower()

    if notifier == "ntfy":
        # NTFY help.

        help_text: str = """
         -u, --server        is the URL of the NTFY server, ending with a "/". 
                             Default is https://ntfy.sh/.
         -s, --sender        is the sender of the message, either an app name or a person. 
                             Default is "Wazuh (IDS)".
         -d, --destination   is the NTFY subscription, to send the message to. 
                             Default is none.
         -p, --priority      is the priority of the message, ranging from 1 (lowest), to 5 (highest). 
                             Default is 5.
         -m, --message       is the text of the message to be sent.
                             Default is "Test message".
         -t, --tags          is an arbitrary strings of tags (keywords), seperated by a "," (comma). 
                             Default is "informational, testing, hard-coded".
         -c, --click         is a link (URL) that can be followed by tapping/clicking inside the message. 
                             Default is https://google.com.
         -h, --help          shows this help message. Must have no value argument.
         -v, --view          show config.
        """

    elif notifier == "discord":

        # Discord help.

        help_text: str = """
             -u, --server        is the webhook URL of the Discord server. It is stored in .env.
             -s, --sender        is the sender of the message, either an app name or a person. 
                                 The default is "Security message".
             -d, --destination   is the destination (actually the originator) of the message, either an app name or a person. 
                                 Default is "Wazuh (IDS)"
             -p, --priority      is the priority of the message, ranging from 1 (highest), to 5 (lowest). 
                                 Default is 5.
             -m, --message       is the text of the message to be sent. 
                                 Default is "Test message", but may include --tags and/or --click.
             -t, --tags          is an arbitrary strings of tags (keywords), seperated by a "," (comma). 
                                 Default is "informational, testing, hard-coded".
             -c, --click         is a link (URL) that can be followed by tapping/clicking inside the message. 
                                 Default is https://google.com.
             -h, --help          Shows this help message.
             -v, --view          Show yaml configuration.
            """
    else:
        help_text: str = """
        No help available. Assuming the wrong notifier asked for help.
        """

    return help_text


def get_arguments(notifier, options, long_options):
    # Get params during execution. Params found here, override minimal defaults and/or config settings.

    help_text = call_for_help(notifier)

    sender, destination, message, priority, tags, click = "", "", "", "", "", ""
    notifier: str = notifier.lower()

    if notifier == "discord":

        pass
    else:
        argument_list: list = sys.argv[1:]
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

            return sender, destination, priority, tags, click
