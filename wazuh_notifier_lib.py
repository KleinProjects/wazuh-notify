import os
import time
import yaml
from dotenv import load_dotenv


# Set structured timestamp.


def set_time():
    now_message = time.strftime('%a, %d %b %Y %H:%M:%S')
    now_logging = time.strftime('%Y/%m/%d %H:%M:%S')
    return now_message, now_logging

# Define paths


def set_env():

    wazuh_path = os.path.abspath(os.path.join(__file__, "../../.."))
    ar_path = '{0}/logs/active-responses.log'.format(wazuh_path)
    config_path = 'wazuh-notifier-config.yaml'.format(wazuh_path)

    return wazuh_path, ar_path, config_path


def import_config(key):
    try:
        _, _, config_path = set_env()

        with open(config_path, 'r') as ntfier_config:
            config: dict = yaml.safe_load(ntfier_config)
            value: str = config.get(key)
            return value
    except (FileNotFoundError, PermissionError, OSError):
        return None


# Showing yaml config

def view_config():

    _, _, config_path = set_env()

    try:
        with open(config_path, 'r') as ntfier_config:
            print(ntfier_config.read())
    except (FileNotFoundError, PermissionError, OSError):
        print(config_path + " does not exist or is not accessible")
        return


# Logging the Wazuh active Response request


def ar_log():
    now = set_time()
    _, ar_path, _ = set_env()
    msg = '{0} {1} {2}'.format(now, os.path.realpath(__file__), 'Post JSON Alert')
    f = open(ar_path, 'a')
    f.write(msg + '\n')
    f.close()

