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
Create Network using Virtual Machines in VirtualBox.

The Network depicted in this project simulates that of a small company domain, running an Active Directory (AD) on a Domain Controller (DC) server (Windows Server 2022), another server (Ubuntu) running the Splunk Enterprise instance, and a Windows 10 host machine. The network also consists of a switch and a router connecting to the internet.

A Kali Linux machine is being used to attack the network, simulating outside threats and attackers.

The DC server and Windows 10 machine will have Splunk Universal Forwarder installed and Sysmon configured to send event log data to the server running splunk, which will generate telemetry on the Splunk Enterprise instance with the received event logs.

![Network Topology](https://github.com/user-attachments/assets/701da123-ab56-43aa-afea-2254cd00d8f7)



Step 2:
Splunk server configuration.

By downloading Splunk Enterprise for Ubuntu and installing it on the Ubuntu server, this server will act as the Splunk recieving indexer within the domain's SIEM, collecting log data from the network's universal forwarders and generating telemetry of network activity for later analysis.

Splunk server static IP config: 
- Splunk server ip = 192.168.10.10/24 
- Nameserver = 8.8.8.8 (Google) 
- Route set to network gateway

![Splunk server ip config](https://github.com/user-attachments/assets/969c36e4-9e0d-447b-972f-5be14423d822)


This command ensures that any time the splunk server starts up or reboots, the splunk module installed on the server will run as the user "splunk". Meaning that all that is needed to access splunk on the network connected device (Win10-PC) is to ensure that the splunk server is running. 

![Splunk auto start command](https://github.com/user-attachments/assets/ed3f49c1-48c9-449d-913c-0b8cf2403c44)



Step 3:
Splunk Universal Forwarder installation and Sysmon configuration.

Downloaded Splunk Universal Forwarder on each of the network endpoints, DC server and Win10-PC, and installed it as an "on-premises Splunk Enterprise Instance".

![Splunk install](https://github.com/user-attachments/assets/ef963081-09c3-4776-b8e7-5d6cfcb1d1d5)

In the installation phase, this is where the network's Splunk server will be set as the receiving indexer for each endpoint running Universal Forwarder.

![Splunk recieving indexer](https://github.com/user-attachments/assets/7ba2c9d5-f21c-4f28-91d0-50517307edf2)

Sysmon can be downloaded as a part of Microsoft's "Sysinternals" suite. This will act as an extension of the Windows Event Viewer logs that will be sent to the Splunk indexer. 

In this project i researched and found a suitable and customisable Sysmon configuration authored by Olaf Hartong on Github.
"This is a Microsoft Sysinternals Sysmon configuration repository, set up modular for easier maintenance and generation of specific configs."
(https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml)

On each network endpoint, run Sysmon.exe with with powershell using the downloaded configuration file.

![Sysmon powershell](https://github.com/user-attachments/assets/8026a704-d832-4159-bf8d-ba895351cd5b)

Create a configuration to determine what data will be sent to the splunk server via the Universal Forwarder. Configuration will be created in C:\Program Files\SplunkUniversalForwarder\etc\system\local directory. 

![Sysmon config file](https://github.com/user-attachments/assets/1c57454c-8a5c-4ef1-b2c1-6eebb78039c5)

Note: index = endpoint, will log any events that fall under the configured categories under the index "endpoint" on the splunk server. The splunk server must have an index named "endpoint" in order to receive these events. 

Note: Any updates made to this config file, will require a restart of the universal forwarder service to have an effect. To do so, the splunkforwarder service can be found in services app on the endpoints: 
![Splunk forwarder service](https://github.com/user-attachments/assets/593a61f2-922b-4f49-bb24-a504736865a7)



Step 4:
