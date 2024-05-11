#!/usr/bin/env python3

# This script is adapted version of the Python active response script sample, provided by Wazuh, in the documentation:
# https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
# It is provided under the below copyright statement:
#
#           Copyright (C) 2015-2022, Wazuh Inc.
#           All rights reserved.
#
#           This program is free software; you can redistribute it
#           and/or modify it under the terms of the GNU General Public
#           License (version 2) as published by the FSF - Free Software
#           Foundation.
#
# This adapted version is free software. Rudi Klein, april 2024

import os
import sys

from wazuh_notifier_module import construct_basic_message
from wazuh_notifier_module import get_config
from wazuh_notifier_module import parameters_deconstruct
from wazuh_notifier_module import set_environment
from wazuh_notifier_module import threat_mapping

# Path variable assignments

wazuh_path, ar_path, config_path, notifier_path = set_environment()


def main(argv):

    # validate json and get command

    # data = load_message(argv)
    # This example event can be used for troubleshooting. Comment out the line above and uncomment the line below.
    data: dict = {"version": 1, "origin": {"name": "worker01", "module": "wazuh-execd"}, "command": "add",
                  "parameters": {"extra_args": [], "alert": {"timestamp": "2021-02-01T20:58:44.830+0000",
                                                             "rule": {"level": 15,
                                                                      "description": "Shellshock attack detected",
                                                                      "id": "31168", "mitre": {"id": ["T1068", "T1190"],
                                                                                               "tactic": [
                                                                                                   "Privilege Escalation",
                                                                                                   "Initial Access"],
                                                                                               "technique": [
                                                                                                   "Exploitation for Privilege Escalation",
                                                                                                   "Exploit Public-Facing Application"]},
                                                                      "info": "CVE-2014-6271https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271",
                                                                      "firedtimes": 2, "mail": "true",
                                                                      "groups": ["web", "accesslog", "attack"],
                                                                      "pci_dss": ["11.4"], "gdpr": ["IV_35.7.d"],
                                                                      "nist_800_53": ["SI.4"],
                                                                      "tsc": ["CC6.1", "CC6.8", "CC7.2", "CC7.3"]},
                                                             "agent": {"id": "000", "name": "wazuh-server"},
                                                             "manager": {"name": "wazuh-server"},
                                                             "id": "1612213124.6448363",
                                                             "full_log": "192.168.0.223 - - [01/Feb/2021:20:58:43 +0000] \"GET / HTTP/1.1\" 200 612 \"-\" \"() { :; }; /bin/cat /etc/passwd\"",
                                                             "decoder": {"name": "web-accesslog"},
                                                             "data": {"protocol": "GET", "srcip": "192.168.0.223",
                                                                      "id": "200", "url": "/"},
                                                             "location": "/var/log/nginx/access.log"},
                                 "program": "/var/ossec/active-response/bin/firewall-drop"}}

    alert = data["parameters"]["alert"]

    # Get the threat level from the event (message)
    threat_level = data["parameters"]["alert"]["rule"]["level"]

    parameters: dict = parameters_deconstruct(argv, alert)

    # Get the YAML config if any
    config: dict = get_config()

    # Get the mapping between threat level (event) and priority (Discord/ntfy)
    threat_priority = threat_mapping(threat_level, config.get('np_1'), config.get('np_2'),
                                     config.get('np_3'), config.get('np_4'), config.get('np_5'))

    if "discord" in config["targets"]:
        accent: str = "**"
    elif "ntfy" in config["targets"]:
        accent: str = ""
    else:
        accent: str = ""

    notifier_message: str = construct_basic_message(argv, accent,
                                                    parameters.get('a_id', '000'),
                                                    parameters.get('a_name', 'agent not found'),
                                                    parameters.get('e_id', '9999'),
                                                    parameters.get('e_description', 'Event not found'),
                                                    parameters.get('e_level', '9999'),
                                                    parameters.get('e_fired_times', '3')
                                                    )

    if "discord" in config["targets"]:

        discord_notifier: str = '{0}/active-response/bin/wazuh-discord-notifier.py'.format(wazuh_path)
        discord_exec: str = "python3 " + discord_notifier + " "

        discord_message: str = notifier_message

        if "discord" in config["full_message"]:
            discord_message: str = (discord_message + "\n" + accent + "__Full event__" +
                                    accent + parameters['e_full_event'] + '"')
        else:
            discord_message: str = discord_message + '"'

        discord_command: str = discord_exec + discord_message
        os.system(discord_command)

    if "ntfy" in config["targets"]:

        ntfy_notifier: str = '{0}/active-response/bin/wazuh-ntfy-notifier.py'.format(wazuh_path)
        ntfy_exec: str = "python3 " + ntfy_notifier + " "
        ntfy_message: str = notifier_message

        # If the full message flag is set, the full message PLUS the closing parenthesis will be added
        if "ntfy" in config["full_message"]:
            ntfy_message: str = ntfy_message + "\n" + "Full event" + parameters['e_full_event'] + '"'

        else:
            ntfy_message: str = ntfy_message + '"'

        ntfy_command: str = ntfy_exec + ntfy_message
        os.system(ntfy_command)


if __name__ == "__main__":
    main(sys.argv)
