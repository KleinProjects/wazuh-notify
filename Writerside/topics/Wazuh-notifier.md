# Wazuh notify
*version 1.0*

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
    - [Step 1: download](#step-1-download)
    - [Step 2: copy files](#step-2-copy-files)
        - [Python](#python_1)
        - [Golang](#golang_1)
    - [Step 3: copy the TOML file](#step-3-copy-the-toml-configuration-file)
    - [Step 4: create .env file](#step-4-create-env-file)
- [Wazuh configuration](#wazuh-configuration)
    - [Golang](#golang_2)
    - [Python](#python_2)
    - [Note](#note)
- [The TOML configuration file](#the-toml-configuration)
- [Setting up the platforms](#setting-up-the-platforms-receiving-the-notifications)

## Introduction

Wazuh notifier enables the Wazuh manager to be notified when Wazuh selected events occur, using 3 messaging platforms:
[ntfy.sh](https://ntfy.sh), [Discord](https://discord.com) and [Slack](https://slack.com).

There are 2 implementations of Wazuh notify. One written in Golang, the other in Python. Both implementations have
similar functionality, but the Python version is slightly more configurable for testing purposes.

Wazuh notify is a stateless implementation and only notifies: triggered by specific rules, agents, or threat levels.

Wazuh notify is executed by configuring the **ossec.conf** and adding an **active response configuration**.

## Installation

### Step 1: download

Download the files from https://github.com/kleinprojects/wazuh-notify to your server.

### Step 2: copy files

#### _Python_ {id="python_1"}

Copy the 2 Python scripts to the /var/ossec/active-response/bin/ folder

``` 
$ sudo cp <download folder>/wazuh-*.py /var/ossec/active-response/bin/
```

Set the correct ownership {id="set-the-correct-ownership_1"}

```
$ sudo chown root:wazuh /var/ossec/active-response/bin/wazuh-notify.py
$ sudo chown root:wazuh /var/ossec/active-response/bin/wazuh_notify_module.py
```

Set the correct permissions {id="set-the-correct-permissions_1"}

```
$ sudo chmod uog+rx /var/ossec/active-response/bin/wazuh-notify.py
$ sudo chmod uog+rx /var/ossec/active-response/bin/wazuh_notify_module.py
```

#### _Golang_ {id="golang_1"}

Copy the Go executable to the /var/ossec/active-response/bin/ folder

``` 
$ sudo cp <download folder>/wazuh-notify /var/ossec/active-response/bin/
```

Set the correct ownership {id="set-the-correct-ownership_2"}

```
$ sudo chown root:wazuh /var/ossec/active-response/bin/wazuh-notify
```

Set the correct permissions {id="set-the-correct-permissions_2"}

```
$ sudo chmod uog+rx /var/ossec/active-response/bin/wazuh-notify
```

### Step 3: copy the TOML configuration file

Copy the TOML file to /var/ossec/etc/

```
$ sudo cp <download folder>/wazuh-notify-config.toml /var/ossec/etc/
```

Set the correct ownership {id="set-the-correct-ownership_3"}

```
$ sudo chown root:wazuh /var/ossec/etc/wazuh-notify-config.toml
```

Set the correct permissions {id="set-the-correct-permissions_3"}

```
$ sudo chmod uog+r /var/ossec/etc/wazuh-notify-config.toml
```

### Step 4: create .env file

Create an .env file in /var/ossec/etc/

```
$ sudo touch /var/ossec/etc/.env
```

Set the correct ownership {id="set-the-correct-ownership_4"}

```
$ sudo chown root:wazuh /var/ossec/etc/wazuh-notify-config.toml
```

Set the correct permissions {id="set-the-correct-permissions_4"}

```
$ sudo chmod uog+r /var/ossec/etc/wazuh-notify-config.toml
```

## Wazuh configuration

#### _Golang_ {id="golang_2"}

Modify the /var/ossec/etc/ossec.conf configuration file and add the following:<br/>

*Command section*

```
<command>
<name>wazuh-notify-go</name>
<executable>wazuh-notify</executable>
<timeout_allowed>yes</timeout_allowed>
</command>
```

*Active response section*

```
<active-response>
<command>wazuh-notify-go</command>
<location>server</location>
<level></level>
<rules_id></rules_id>
</active-response>
```

#### _Python_ {id="python_2"}

*Command section*

```
<command>
<name>wazuh-notify-py</name>
<executable>wazuh-notify.py</executable>
<timeout_allowed>yes</timeout_allowed>
</command>
```

*Active response section*

```
<active-response>
<command>wazuh-notify-py</command>
<location>server</location>
<level></level>
<rules_id></rules_id>
</active-response>
```

#### NOTE: <format color="OrangeRed">!</format>
The ```<name>``` in the ```<command>``` section needs to be the same as the ```<command>``` in
the ```<active-response>``` section.
The ```<command>``` section describes the program that is executed. The ```<active-response>``` section describes the
trigger that runs the ```<command>```.

Add the rules you want to be informed about between the ```<rules_id></rules_id>```, with the rules id's separated by
comma's.  
Example: ```<rules_id>5402, 3461, 8777</rules_id>```.

Please refer to
the [Wazuh online documentation](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)
for more information.

## The TOML configuration

This is the toml configuration file for wazuh-notify (for both the Python and Golang version).

The targets setting defines the platforms where notifications will be sent to.
Platforms in this comma-separated string will receive notifications, if and when they are set up. 
Refer to [setting up the platforms](#setting-up-the-platforms-receiving-the-notifications).

```
targets: "slack, ntfy, discord"
```

Platforms in this comma-separated string will receive the full event information.

```
full_alert: "" 
```

Exclude_rules and excluded_agents will disable notification for these particular events or agents that are enabled in
the ossec.conf active response definition.
These settings provide an easier way to disable event notifications from firing. No need to restart Wazuh-manager.

Enter rule numbers as a string with comma-separated values.
Enter numeric agent id's as a string with comma-separated values.

```
excluded_rules: "99999, 00000"
excluded_agents: "99999"
```

[The threat levels used in Wazuh](https://documentation.wazuh.com/current/user-manual/ruleset/rules-classification.html) 
(0-15) are mapped to notification priority levels (1-5), and their respective colors (Discord only).
The Wazuh threat level scale runs from 0-15, where 15 is the most severe threat. It corresponds to the 
[HSAS](https://en.wikipedia.org/wiki/Homeland_Security_Advisory_System) threat scale that runs from 5-1, whereby 1 is 
the highest threat level. The configuration allows for customized mapping: in some use cases the mapping could be different.

The mention threshold defines when Discord users receive a DM, next to the common messages they receive in their channel.
Often these common channels are muted and DM's will draw more attention. 1 means that for every notification a DM will be sent.
A mention threshold of 5 means that for every 5th occurrence of this specific event, a DM will be sent also.

The notify threshold is somewhat similar to the mention threshold. A notify threshold of 1 will send each notification, 
a notify threshold of 4 will only send each 4th notification triggered by a specific event. This will reduce high amounts
of notifications for the same event. The fired_times value in the message will show the actual number of the times this 
specific event was generated.

Enter a threat_map as a list of integers,  
color as a hex RGB color values,
mention/notify_threshold as integers.
```
[[priority_map]]                # Priority 1 on the HSAS scale
threat_map = [15, 14, 13, 12]   # Wazuh threat levels -> priority 2
color = 0xec3e40                # Red, SEVERE on the HSAS scale
mention_threshold = 1           
notify_threshold = 1

[[priority_map]]                # Priority 2 on the HSAS scale
threat_map = [11, 10, 9]        # Wazuh threat levels -> priority 2
color = 0xff9b2b                # Orange, HIGH on the HSAS scale
mention_threshold = 1
notify_threshold = 1

[[priority_map]]                # Priority 3 on the HSAS scale
threat_map = [8, 7, 6]          # Wazuh threat levels -> priority 3
color = 0xf5d800                # Yellow, ELEVATED on the HSAS scale
mention_threshold = 5
notify_threshold = 5

[[priority_map]]                # Priority 4 on the HSAS scale
threat_map = [5, 4]             # Wazuh threat levels -> priority 4
color = 0x377fc7                # Blue, GUARDED on the HSAS scale
mention_threshold = 20
notify_threshold = 5

[[priority_map]]                # Priority 5 on the HSAS scale
threat_map = [3, 2, 1, 0]       # Wazuh threat levels -> priority 5
color = 0x01a465                # Green, LOW on the HSAS scale
mention_threshold = 20
notify_threshold = 1
```

The next settings are used to add information to the messages.
```Sender``` translate to the ``` username ``` field in Discord and Slack and to the ```title``` field in ntfy.sh. 
The ```click``` parameter adds an arbitrary URL to the message.

```
sender: "Wazuh (IDS)"
click: "https://documentation.wazuh.com/"
```

### From here on the settings are ONLY used by the Python version of wazuh-notify.

Below settings provide for a window that enable/disables events from firing the notifiers.

Enter ```excluded_days``` as a string with comma separated values. Be aware of your regional settings.

```
excluded_days: "" 
```

Enter ```excluded_hours``` as a tuple of string values.

```
excluded_hours: [ "23:59", "00:00" ]
```

The following parameters define the markdown characters used to emphasise the parameter names in the notification
messages (Markdown style). This is a dictionary notation.

```
markdown_emphasis:
slack: "*"
ntfy: "**"
discord: "**"
```

The next settings are used for testing purposes.

```Test mode``` will add an example event (```wazuh-notify-test-event.json```) instead of the message received through Wazuh.
This enables customization for testing of a particular event.

```
test_mode: False
```

Setting the ```extended_logging``` and ```extended_print``` parameters provides more logging to the wazuh-notifier log
and console. The possible values are:

0-> limited logging   
1-> basic logging   
2-> verbose logging

```
extended_logging: 2
extended_print: 0
```

### Setting up the platforms receiving the notifications

Each of the 3 platforms make use of webhooks or similar API's. In order to have the right information in the ```.env```
file, please refer to the platform's documentation.

[Slack](https://api.slack.com/) API documentation

[ntfy.sh](https://docs.ntfy.sh/subscribe/api/) API documentation

[ntfy.sh](https://docs.ntfy.sh/examples/) examples

[Discord](https://discord.com/developers/docs/intro) developers documentation