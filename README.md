Wazuh notifier

Wazuh notifier enables the Wazuh user to be notified when selected events occur.
It combines a customized custom-ar Python script (
ref: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)
with two notifier Python scripts: a Discord notifier and a NTFY.sh notifier.

It is a Stateless implementation and only notifies, using any or both of the messaging services.

The ossec.conf configuration needs to include the following command and active-response configuration:
<ossec_config>
<command>
<name>linux-custom-ar</name>
<executable>custom-ar.py</executable>
<timeout_allowed>yes</timeout_allowed>
</command>

  <active-response>
    <disabled>no</disabled>
    <command>linux-custom-ar</command>
    <location>local</location>
    <rules_id>503</rules_id>
    <timeout>60</timeout>
  </active-response>
</ossec_config>
