# Splunk-UF-SIEM 
Splunk Universal Forwarder using Sysmon event logs in an Active Directory environment.

## Objective

The objective of this project is to create an Active Directory environment using virtual machines in VirtualBox, 
implement Splunk Universal Forwarder on domain endpoints that send Sysmon event log data to a Splunk server on the domain, 
thus generating telemetry data within the Security Information and Event Management (SIEM) system. 
This lab is designed to simulate real-world attack scenarios and to understand how to detect and protect from different attack vectors and monitor for Indicators of Compromise (IoCs).

### Skills Learned

- Hands-on experience with complex and interconnected virtualization.
- Configuration of detailed Sysmon event logs.
- Active Directory setup and management.
- Ability to install and configure Splunk Universal Forwarder on domain endpoints.
- Proficiency in analyzing event logs and identifying Indicators of Compromise.
- Enhanced comprehension of network vulnerabilities and security protocols.

### Tools Used

- Active Directory to create domain, domain registered endpoints, servers and users.
- Sysmon to create event logs that contain more in-depth analysis than standard Windows Event Viewer.
- Splunk Universal Forwarder to send event log data to Splunk server on domain.
- Crowbar used on Kali Linux machine to simulate brute force attack on domain user account.
- Splunk Enterprise used to analyze telemetry data generated from attack simulation.



##
# Project References and Resources

Splunk server iso download 

    https://www.splunk.com/en_us/download/splunk-enterprise/thank-you-enterprise.html 

 
Sysmon download 

    https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon 

 
Sysmon config 

    https://github.com/olafhartong/sysmon-modular 

    https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml 


Read this for any info on Splunk!

    https://docs.splunk.com/Documentation 


 Crowbar install and config

    https://github.com/galkan/crowbar 

 
