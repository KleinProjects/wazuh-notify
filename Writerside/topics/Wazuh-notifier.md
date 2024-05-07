# Wazuh notifier

Wazuh notifier enables the Wazuh manager to be notified when selected events occur.

## Contents

The main script is a custom active response Python script: wazuh-active-response.py.<br/>
The actual sending of the messages is done by 2 notifier Python scripts:<br/>
**Discord notifier**: wazuh-discord-notifier.py, and **NTFY.sh notifier**: wazuh-ntfy-notifier.py<br/>
A YAML configuration: wazuh-notifier-config.yaml, and a Python module: wazuh_notifier_lib.py

Wazuh notifier is a stateless implementation and only notifies, using the Discord and/or NTFY.sh messaging services.

The Wazuh notifier is triggered by configuring the **ossec.conf** and adding an **active response configuration.**

## Installation ##

### Step 1 ###

Download the files from https://github.com/RudiKlein/wazuh-notifier to your server.

### Step 2 ###

Copy the 4 Python files to the /var/ossec/active-response/bin/ folder

``` 
$ cp <downloaded notifier files>/wazuh-*.py /var/ossec/active-response/bin/
```

Set the correct ownership

```
$ chown root:wazuh /var/ossec/active-response/bin/wazuh-*.py
```

Set the correct permissions

```
$ chmod uog+rx /var/ossec/active-response/bin/wazuh-*.py
```

### Step 3 ###

Copy the YAML file to /var/ossec/etc/

```
$ cp <downloaded notifier files>/wazuh-notifier-config.yaml /var/ossec/etc/
```

Set the correct ownership

```
$ chown root:wazuh /var/ossec/etc/wazuh-notifier-config.yaml
```

Set the correct permissions

```
$ chmod uog+r /var/ossec/etc/wazuh-notifier-config.yaml
```

### Step 4 ###

Modify the /var/ossec/etc/ossec.conf configuration file and add the following<br/>

```
  <command>
    <name>wazuh-active-response</name>
    <executable>wazuh-active-response.py</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>
```

```
  <active-response>
    <command>wazuh-active-response</command>
    <location>server</location>
    <level></level>
    <rules_id></rules_id>
  </active-response>
```

Add the rules you want to be informed about between the <rules_id></rules_id>, with the rules id's separated by comma's.
Example: <rules_id>5402, 3461, 8777</rules_id><br/>
(Please refer to the Wazuh online documentation for more information [^Wazuh docs])

[^Wazuh docs]: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html

## The Active Response module ##

The wazuh-active-response.py acts as the interface between Wazuh and the messaging notifiers for Discord and ntfy.
It is based on the example active response Python script in the [^Wazuh docs].

## The Discord notifier ##

## The ntfy.sh notifier ##

## The YAML configuration ##

**Enable/disable the notifiers**<br/>

```
discord_enabled: 1 (0 if not set in the yaml configuration)
ntfy_enabled: 1  (0 if not set in the yaml configuration)
```

**Exclude rules that are enabled in the ossec.conf active response definition.**<br/>
This prevents the need to alter the ossec.conf for temporary rule disabling and stopping/starting wazuh-manager.
Additionally, agents can also be excluded from notifications.

```
excluded_rules: "5401, 5402, 5403"
excluded_agents: "999"
```

Default settings for the ntfy notifier. This overrules the hardcoded defaults.

```
ntfy_server: "https://ntfy.sh/"
ntfy_sender: "Wazuh (IDS)"
ntfy_destination: "__KleinTest"
ntfy_priority: "5"
ntfy_message: "Test message"
ntfy_tags: "information, testing, yaml"
ntfy_click: "https://google.com"
```

Default settings for the ntfy notifier. This overrules the hardcoded defaults.

```
discord_server: "not used. The webhook (server) is a secret stored in .env"
discord_sender: "Security message"
discord_destination: "WAZUH (IDS)"
discord_priority: "5"
discord_message: "Test message"
discord_tags: "informational, testing, yaml"
discord_click: "https://google.com"

# 1 to send the full event data with the message. 0 only sends the message with basic details
discord_full_message: "0"
```

