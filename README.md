# Splunk-UF-SIEM [WORK IN PROGRESS]
Splunk Universal Forwarder using Sysmon event logs in an Active Directory environment.

## Objective

The objective of this project is to create an Active Directory environment using virtual machines in VirtualBox, 
implement Splunk universal forwarder on domain endpoints that send Sysmon event log data to a Splunk server on the domain, 
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
- Splunk Universal Forwarder to sent event log data to Splunk server on domain.
- Crowbar used on Kali Linux machine to simulate brute force attack on domain user account.
- Splunk Enterprise used to analyze telemetry data generated from attack simulation.0


## Steps
Step 1:
Creating the domain using Active Directory on domain controller server.

The Network depicted in this project simulates that of a small company domain, running an active directory (AD) on a domain controller (DC) server, another server running splunk, and a windows 10 host machine. The network also consists of a switch and a router connecting to the internet.

A kali linux machine is being used to attack the network, simulating outside threats and attackers.

The DC server and Windows 10 machine will have Splunk Universal Forwarder installed and Sysmon configured to send event log data to the server running splunk, which will generate telemetry on the Splunk Enterprise instance with the received event logs.

![Network Topology](https://github.com/user-attachments/assets/701da123-ab56-43aa-afea-2254cd00d8f7)

