# Wazuh notify

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
- [Configuration](#configuration)
- [The YAML configuration](#the-yaml-configuration)


## Introduction

Wazuh notifier enables the Wazuh manager to be notified when selected events occur, using 3 messaging platforms:
ntfy.sh, Discord and Slack.  

There are 2 implementations of Wazuh notify. One written in Golang and the other in Python. Both implementations have
similar functionality, but the Python version is slightly more configurable.

Wazuh notify is a stateless implementation and only notifies, triggered by selected rules, agents, or threat levels.

Wazuh notify is triggered by configuring the **ossec.conf** and adding an **active response configuration.**

## Installation

### Step 1: download

Download the files from https://github.com/kleinprojects/wazuh-notify to your server.

### Step 2: copy files

#### _Python_ {id="python_1"}

##### Copy the 2 Python scripts to the /var/ossec/active-response/bin/ folder

``` 
$ sudo cp <download folder>/wazuh-*.py /var/ossec/active-response/bin/
```

##### Set the correct ownership {id="set-the-correct-ownership_1"}

```
$ sudo chown root:wazuh /var/ossec/active-response/bin/wazuh-notify.py
$ sudo chown root:wazuh /var/ossec/active-response/bin/wazuh_notify_module.py
```

##### Set the correct permissions {id="set-the-correct-permissions_1"}

```
$ sudo chmod uog+rx /var/ossec/active-response/bin/wazuh-notify.py
$ sudo chmod uog+rx /var/ossec/active-response/bin/wazuh_notify_module.py
```

#### _Golang_ {id="golang_1"}

##### Copy the Go executable to the /var/ossec/active-response/bin/ folder

``` 
$ sudo cp <download folder>/wazuh-notify /var/ossec/active-response/bin/
```

##### the correct ownership {id="set-the-correct-ownership_2"}

```
$ sudo chown root:wazuh /var/ossec/active-response/bin/wazuh-notify
```

##### Set the correct permissions {id="set-the-correct-permissions_2"}

```
$ sudo chmod uog+rx /var/ossec/active-response/bin/wazuh-notify
```

### Step 3

##### Copy the YAML file to /var/ossec/etc/

```
$ sudo cp <download folder>/wazuh-notify-config.yaml /var/ossec/etc/
```

##### Set the correct ownership {id="set-the-correct-ownership_3"}

```
$ sudo chown root:wazuh /var/ossec/etc/wazuh-notify-config.yaml
```

##### Set the correct permissions {id="set-the-correct-permissions_3"}

```
$ sudo chmod uog+r /var/ossec/etc/wazuh-notify-config.yaml
```

### Step 4

##### Create an .env file in /var/ossec/etc/

```
$ sudo touch /var/ossec/etc/.env
```

#### Set the correct ownership {id="set-the-correct-ownership_4"}

```
$ sudo chown root:wazuh /var/ossec/etc/wazuh-notify-config.yaml
```

#### Set the correct permissions {id="set-the-correct-permissions_4"}

```
$ sudo chmod uog+r /var/ossec/etc/wazuh-notify-config.yaml
```

## Configuration

#### Golang {id="golang_2"}

Modify the /var/ossec/etc/ossec.conf configuration file and add the following<br/>

Command section

```
<command>
<name>wazuh-notify-go</name>
<executable>wazuh-notify</executable>
<timeout_allowed>yes</timeout_allowed>
</command>
```

Active response section

```
<active-response>
<command>wazuh-notify-go</command>
<location>server</location>
<level></level>
<rules_id></rules_id>
</active-response>
```

#### Python {id="python_2"}

Command section

```
<command>
<name>wazuh-notify-py</name>
<executable>wazuh-notify.py</executable>
<timeout_allowed>yes</timeout_allowed>
</command>
```

Active response section

```
<active-response>
<command>wazuh-notify-py</command>
<location>server</location>
<level></level>
<rules_id></rules_id>
</active-response>
```

### NOTE: 

The ```<name>``` in the ```<command>``` section needs to be the same as the ```<command>``` in
the ```<active-response>``` section.
The ```<command>``` section describes the program that is executed. The ```<active-response>``` section describes the
trigger that runs the ```<command>```.

Add the rules you want to be informed about between the ```<rules_id></rules_id>```, with the rules id's separated by
comma's.
Example: ```<rules_id>5402, 3461, 8777</rules_id><br/>```
(Please refer to the Wazuh online documentation for more information [^Wazuh docs])

[^Wazuh docs]: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html

## The YAML configuration

This is the yaml config file for wazuh-active-response (for both the Python and Go version)

The targets setting defines the platforms where notifications will be sent to.
Platforms in this comma-separated string will receive notifications.

```
targets: "slack, ntfy, discord"
```

Platforms in this comma-separated string will receive the full event information.

```
full_message: "" 
```

Exclude_rules and excluded_agents will disable notification for these particular events or agents that are enabled in
the ossec.conf active response definition.
These settings provide an easier way to disable events from firing. No need to restart Wazuh-manager.

Enter rule numbers as a string with comma-separated values.
Enter numeric agent id's as a string with comma-separated values.

```
excluded_rules: "99999, 00000"
excluded_agents: "99999"
```

There is a mapping from Wazuh threat levels (0-15) to priorities (1-5) in notifications.
https://documentation.wazuh.com/current/user-manual/ruleset/rules-classification.html
Enter the values for the threat_map as lists of integers, mention_thresholds as integers and colors as Hex integers.
The mention_threshold, relates to the number of times a rule has been fired. When the times fired is equal to or greater
than the mention_threshold, the recipient will receive a Discord mention in addition to the normal message.
This is a list notation.

```
priority_map:
- threat_map: [ 15,14,13,12 ]
mention_threshold: 1
color: 0xcc3300
- threat_map: [ 11,10,9 ]
mention_threshold: 1
color: 0xff9966
- threat_map: [ 8,7,6 ]
mention_threshold: 5
color: 0xffcc00
- threat_map: [ 5,4 ]
mention_threshold: 20
color: 0x99cc33
- threat_map: [ 3,2,1,0 ]
mention_threshold: 20
color: 0x339900
```

The next 2 settings are used to add information to the messages.
Sender translate to the ``` username ``` field in Discord and to the ```title``` field in ntfy.sh. It is not used for
Slack. 
Click adds an arbitrary URL to the message.

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

Enter ```excluded_hours``` as a tuple of string values. Be aware of your regional settings.

```
excluded_hours: [ "23:59", "00:00" ]
```

The following parameters define the markdown characters used to emphasise the parameter names in the notification
messages (Markdown style)
This is a dictionary (object) notation.

```
markdown_emphasis:
slack: "*"
ntfy: "**"
discord: "**"
```

The next settings are used for testing purposes.

Test mode will add an example event (wazuh-notify-test-event.json) instead of the message received through Wazuh.
This enables testing for particular events when the test event is customized.

```
test_mode: False
```

Setting this parameter provides more logging to the wazuh-notifier log. Possible values are
0 (almost no logging),
1 (basic logging) and
2 (verbose logging)

```
extended_logging: 2
```

Enabling this parameter provides extended logging to the console (see extended logging).

```
extended_print: 0
```
