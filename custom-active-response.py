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
# This version has changes in
# 1) the first lines of code with the assignments, and
# 2) the Start Custom Action Add section
# This adapted version is free software. Rudi Klein, april 2024

import datetime
import json
import os
import sys
from pathlib import PureWindowsPath, PurePosixPath

from wazuh_notifier_lib import import_config as ic
from wazuh_notifier_lib import set_env as se

wazuh_path, ar_path, config_path = se()

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1


class Message:

    def __init__(self):
        self.alert = ""
        self.command = 0


def write_debug_file(ar_name, msg):
    with open(ar_path, mode="a") as log_file:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):])))
        log_file.write(
            str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name_posix + ": " + msg + "\n")


def setup_and_check_message(argv):
    # get alert from stdin
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        Message.command = OS_INVALID
        return Message

    Message.alert = data

    command = data.get("command")

    if command == "add":
        Message.command = ADD_COMMAND
    elif command == "delete":
        Message.command = DELETE_COMMAND
    else:
        Message.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + command)

    return Message


def send_keys_and_check_message(argv, keys):
    # build and send message with keys
    keys_msg = json.dumps(
        {"version": 1, "origin": {"name": argv[0], "module": "active-response"}, "command": "check_keys",
         "parameters": {"keys": keys}})

    write_debug_file(argv[0], keys_msg)

    print(keys_msg)
    sys.stdout.flush()

    # read the response of previous message
    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return Message

    action = data.get("command")

    if "continue" == action:
        ret = CONTINUE_COMMAND
    elif "abort" == action:
        ret = ABORT_COMMAND
    else:
        ret = OS_INVALID
        write_debug_file(argv[0], "Invalid value of 'command'")

    return ret


def parameters_deconstruct(event_keys):
    a_id: str = str(event_keys["agent"]["id"])
    a_name: str = str(event_keys["agent"]["name"])
    e_level: str = str(event_keys["rule"]["level"])
    e_description: str = str(event_keys["rule"]["description"])
    e_id: str = str(event_keys["rule"]["id"])
    e_fired_times: str = str(event_keys["rule"]["firedtimes"])

    return a_id, a_name, e_id, e_description, e_level, e_fired_times


def construct_message(caller: str, a_id: str, a_name: str, e_id: str, e_description: str, e_level: str,
                      e_fired_times: str):
    discord_accent = ""
    if caller == "discord":
        discord_accent = "**"

    message_params: str = ("--message " + '"' +
                           discord_accent + "Agent: " + discord_accent + a_name + " (" + a_id + ")" + "\n" +
                           discord_accent + "Event id: " + discord_accent + e_id + "\n" +
                           discord_accent + "Description: " + discord_accent + e_description + "\n" +
                           discord_accent + "Threat level: " + discord_accent + e_level + "\n" +
                           discord_accent + "Times fired: " + discord_accent + e_fired_times + "\n" + '"')

    return message_params


def main(argv):
    write_debug_file(argv[0], "Started")

    # validate json and get command
    msg = setup_and_check_message(argv)

    if msg.command < 0:
        sys.exit(OS_INVALID)

    if msg.command == ADD_COMMAND:

        """ Start Custom Key
        At this point, it is necessary to select the keys from the alert and add them into the keys array.
        """

        alert = msg.alert["parameters"]["alert"]
        keys = [alert["rule"]]

        agent_id, agent_name, event_level, event_description, event_id, event_fired_times = parameters_deconstruct(
            alert)

        action = send_keys_and_check_message(argv, keys)

        # if necessary, abort execution
        if action != CONTINUE_COMMAND:

            if action == ABORT_COMMAND:
                write_debug_file(argv[0], "Aborted")
                sys.exit(OS_SUCCESS)
            else:
                write_debug_file(argv[0], "Invalid command")
                sys.exit(OS_INVALID)

        """ Start Custom Action Add """

        if str(ic("discord_enabled")) == "1":
            caller = "discord"
            discord_notifier = '{0}/active-response/bin/wazuh-discord-notifier.py'.format(wazuh_path)
            discord_exec = "python3 " + discord_notifier + " "
            write_debug_file(argv[0], "Start Discord notifier")
            discord_params = construct_message(caller, agent_id, agent_name, event_level, event_description, event_id,
                                               event_fired_times)
            discord_command = discord_exec + discord_params
            os.system(discord_command)

        if str(ic("ntfy_enabled")) == "1":
            caller = "ntfy"
            ntfy_notifier = '{0}/active-response/bin/wazuh-ntfy-notifier.py'.format(wazuh_path)
            ntfy_exec = "python3 " + ntfy_notifier + " "
            write_debug_file(argv[0], "Start NTFY notifier")
            ntfy_params = construct_message(caller, agent_id, agent_name, event_level, event_description, event_id,
                                            event_fired_times)
            ntfier_command = ntfy_exec + ntfy_params
            os.system(ntfier_command)

        """ End Custom Action Add """

    elif msg.command == DELETE_COMMAND:

        """ Start Custom Action Delete """

        pass

        """ End Custom Action Delete """

    else:
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")

    sys.exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)
