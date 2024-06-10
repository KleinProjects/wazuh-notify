# Wazuh notify
*version 1.0*

## Introduction

Wazuh notifier enables the Wazuh manager to be notified when Wazuh selected events occur, using 3 messaging platforms:
[ntfy.sh](https://ntfy.sh), [Discord](https://discord.com) and [Slack](https://slack.com).

There are 2 implementations of Wazuh notify. One written in Golang, the other in Python. Both implementations have
similar functionality, but the Python version is slightly more configurable for testing purposes.

Wazuh notify is a stateless implementation and only notifies: triggered by specific rules, agents, or threat levels.

Wazuh notify is executed by configuring the **ossec.conf** and adding an **active response configuration**.

### Please refer to https://docs.notifier.kleinsense.nl/wazuh-notifier.html for the full documentation.
