# Splunk-UF-SIEM [WORK IN PROGRESS]
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


## Steps
### Step 1: Create Network using Virtual Machines in VirtualBox
##
The network depicted in this project simulates that of a small company domain, running an Active Directory (AD) on a Domain Controller (DC) server (Windows Server 2022), another server (Ubuntu) running the Splunk Enterprise instance, and a Windows 10 host machine. The network also consists of a switch and a router connecting to the internet.

A Kali Linux machine is being used to attack the network, simulating outside threats and attackers.

The DC server and Windows 10 machine will have Splunk Universal Forwarder installed and Sysmon configured to send event log data to the server running Splunk, which will generate telemetry on the Splunk Enterprise instance with the received event logs.

  ![Network Topology](https://github.com/user-attachments/assets/701da123-ab56-43aa-afea-2254cd00d8f7)


##
### Step 2: Splunk server configuration
##
By downloading Splunk Enterprise for Ubuntu and installing it on the Ubuntu server, this server will act as the Splunk receiving indexer within the domain's SIEM, collecting log data from the network's universal forwarders and generating telemetry of network activity for later analysis.

Splunk server static IP config: 
- Splunk server ip = 192.168.10.10/24 
- Nameserver = 8.8.8.8 (Google) 
- Route set to network gateway

  ![Splunk server ip config](https://github.com/user-attachments/assets/969c36e4-9e0d-447b-972f-5be14423d822)


This command ensures that any time the Splunk server starts up or reboots, the Splunk module installed on the server will run as the user "splunk". Meaning that all that is needed to access Splunk on the network connected device (Win10-PC) is to ensure that the Splunk server is running. 

  ![Splunk auto start command](https://github.com/user-attachments/assets/ed3f49c1-48c9-449d-913c-0b8cf2403c44)


##
### Step 3: Splunk Universal Forwarder installation and Sysmon configuration
##
Downloaded Splunk Universal Forwarder on each of the network endpoints, DC server and Win10-PC, and installed it as an "on-premises Splunk Enterprise Instance".

  ![Splunk install](https://github.com/user-attachments/assets/ef963081-09c3-4776-b8e7-5d6cfcb1d1d5)

In the installation phase, this is where the network's Splunk server will be set as the receiving indexer for each endpoint running Universal Forwarder.

  ![Splunk recieving indexer](https://github.com/user-attachments/assets/7ba2c9d5-f21c-4f28-91d0-50517307edf2)

Sysmon can be downloaded as a part of Microsoft's "Sysinternals" suite. This will act as an extension of the Windows Event Viewer logs that will be sent to the Splunk indexer. 

In this project i researched and found a suitable and customizable Sysmon configuration authored by Olaf Hartong on GitHub.
"This is a Microsoft Sysinternals Sysmon configuration repository, set up modular for easier maintenance and generation of specific configs."
(https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml)

On each network endpoint, run Sysmon.exe with PowerShell using the downloaded configuration file.

  ![Sysmon powershell](https://github.com/user-attachments/assets/8026a704-d832-4159-bf8d-ba895351cd5b)

Create a configuration to determine what data will be sent to the Splunk server via the Universal Forwarder. Configuration will be created in C:\Program Files\SplunkUniversalForwarder\etc\system\local directory. 

  ![Sysmon config file](https://github.com/user-attachments/assets/1c57454c-8a5c-4ef1-b2c1-6eebb78039c5)

    NOTE: index = endpoint, will log any events that fall under the configured categories under the index "endpoint" on the Splunk server. The Splunk server must have an index named "endpoint" in order to receive these events. 

    NOTE: Any updates made to this config file, will require a restart of the universal forwarder service to have an effect. To do so, the Splunk forwarder service can be found in services app on the endpoints: 

  ![Splunk forwarder service](https://github.com/user-attachments/assets/593a61f2-922b-4f49-bb24-a504736865a7)


##
### Step 4: Splunk Indexer setup
##
Create the "endpoint" index on Splunk.

  ![Splunk endpoint index](https://github.com/user-attachments/assets/dfb2f2e1-f111-49e4-a8be-29f8bf690ef8)

Now that the endpoint index is created, enable the Splunk server to receive the endpoint data. 

Within the "Forwarding and receiving" tab on Splunk, under "receive data" section, select "Configure receiving", then select "New receiving port". Port left as default of 9997.

  ![Index reciever port](https://github.com/user-attachments/assets/83d8da67-1d79-40f2-8c6a-dcf66194bc8e)

After the receiving port has been set, data should now start being sent from the index to the Splunk server, generating some telemetry in our Splunk search data. 

  ![Endpoint data on Splunk](https://github.com/user-attachments/assets/255362bf-be00-46d4-aa09-6dfd89431ed5)

    NOTE: All Splunk and Sysmon configuration steps are repeated on both WIN10-PC and ADDC01 endpoints.

Splunk data after both endpoints are successfully configured:

  ![Both Endpoints configured](https://github.com/user-attachments/assets/8c35ebdc-b39d-4a85-9279-d7c392edb48c)


##
### Step 5: Active Directory configuration
##
The following steps were conducted on the Active Directory domain controller (ADDC01):

Static IP address set and connectivity established.

  ![ADDC01 static IP connectivity](https://github.com/user-attachments/assets/68e51dd9-653c-49a1-9042-5f136b396089)

In Server Manager dashboard, select "Add roles and features".

  ![Add roles and features](https://github.com/user-attachments/assets/857bbbd2-bb96-4f17-9bfd-3521384f1634)

  ![Add roles and features 2](https://github.com/user-attachments/assets/e478ed5b-24c4-4bbd-9c87-1cdddb86ecd7)

  ![Add roles and features 3](https://github.com/user-attachments/assets/56993384-764f-452b-84b7-a9d4efa96314)

Select Active Directory Domain Services in the server roles tab. 

  ![AD domain services](https://github.com/user-attachments/assets/0ff5060b-00e5-4bb7-8537-a66b406db377)

Skip through other setup tabs and install server role. 

On server manager dashboard, select flag icon, and select "promote this server to a domain controller". 

  ![Promote this server to DC](https://github.com/user-attachments/assets/2ccd616a-771a-4288-93a9-e254e9eb340a)

Fill out deployment config. 

  ![Deployment config](https://github.com/user-attachments/assets/f29c39f3-f572-4ea8-81d3-207faa21a097)

Leave all other options default and add a password.
  
  ![DC options](https://github.com/user-attachments/assets/222b74a2-4ad7-442f-b847-0e1d3d5a0d43)

Skip to installation page and complete install. 

  ![Complete AD install](https://github.com/user-attachments/assets/3e244a2c-58dd-4bdf-ba3f-0b09142846d3)

On server dashboard, select tools, AD users and Computers. 

  ![AD users and computers](https://github.com/user-attachments/assets/48e2bc88-5410-4593-b6e0-438ab55eb4eb)

Create a new Organizational Unit (OU) in the domain.

  ![New OU](https://github.com/user-attachments/assets/42acacbc-505d-4695-b55a-dadce5fb6407)

Create a new user within the OU.

  ![New user within OU](https://github.com/user-attachments/assets/71c9a2b6-6c6f-4152-9a05-5c5fe8c20757)

  ![New user within OU 2](https://github.com/user-attachments/assets/c7ff473a-3f3a-4f13-a440-ec89b4168dc9)

Create as many additional users or OUs as needed.

  ![Bob smith OU](https://github.com/user-attachments/assets/fb4cfa40-21e2-43b5-ba31-ab60fdca493a)

For this project, it was essential to have at least one organizational unit and one user to serve as the target for the simulated attack later on.
With this user operating on a domain registered endpoint, if any suspicious activity emerges from this (or any) account on the domain, it will be logged and flagged as suspicious behavior within our Splunk enterprise instance.

In this project I created two OU's, IT Department & HR Department, each with one user, Ash Toohill (username=atoohill) & Bob Smith (username=bsmith) respectively.


##
### Step 6: Joining Win10-PC endpoint to Domain
##
First, the Win10-PC DNS settings need to be configured to point to the DC server.

  ![Win10-PC DNS config](https://github.com/user-attachments/assets/45fef664-f0b1-4cc9-a744-7883f6deb723)

Then verify that DNS server settings have changed.

  ![Win10-PC DNS change](https://github.com/user-attachments/assets/d41d5680-8256-49cc-afeb-c41cd0fc4c49)

The Win10-PC can now be added as a domain registered endpoint.
In advanced system properties, add a PC name and make it a member of the domain.

  ![Win10-PC domain registration](https://github.com/user-attachments/assets/e3386a18-2210-4d86-a54a-59a210d1bc9e)
  ![Win10-PC added to domain](https://github.com/user-attachments/assets/550574f0-689e-4a19-8936-bc14410d13cc)

Domain user credentials can now be used to log into the domain registered Win10-PC.


##
### Step 7: Enable RDP on Win10-PC
##
Remote Desktop Protocol (RDP) is a commonly used protocol designed to remotely provide access to network endpoints for authorized users only. In this case the authorized users would be the domain registered user accounts.
Whilst simply enabling RDP is not in itself creating a vulnerability within the domain, it does create a potential access point for malicious actors, and the common attack vector of using weak user credentials is what will be used in this project demonstration to exploit this protocol.

On the Win10-PC, enable remote connections in system properties.

  ![Enable RDP](https://github.com/user-attachments/assets/d17527f4-0ae3-4ef5-8a61-0caaba18c87b)

Domain users can then be added and authorized to use this protocol on this domain endpoint.

  ![RDP Users](https://github.com/user-attachments/assets/90c1a0c1-70b3-4d08-93d2-bc072bbd66aa)


##
### Step 8: Kali Linux configuration and attack simulation setup
##
For this part of the project, this Kali machine is to be used as the attacker in the simulated scenario in order to test the domain's SIEM functionality.
I used my existing Kali home lab VM for this project component, however i created a VirtualBox snapshot of my original Kali configuration before making changes and modifications to the system that are specific to this project example.

Initial static IP configuration and connectivity verified.

  ![Kali static IP](https://github.com/user-attachments/assets/d69a6bb2-9e75-4bbc-99c8-a3c9290404e0)
  ![Kali ping test](https://github.com/user-attachments/assets/857eb6ad-07b3-421f-8a2a-a43415b4de39)

For the attack simulation against the domain, we are going to be conducting a brute-force attack against one of the domain user accounts to crack credentials and gain access to the domain.
This attack attempt, whether successful or unsuccessful in logging into the targeted account, will generate telemetry within our Splunk Enterprise instance through logs collected in correlation to the attack activity and sent to the Splunk server using the endpoint's Universal Forwarder.

For this project, the focus is on the domain's SIEM and the functionality of the Universal Forwarders using Sysmon logs. Therefore the setup and execution of this attack simulation is rather simple and curated for smooth demonstration purposes.

    NOTE: When setting up user account "bsmith" on the domain, the password "supersafepassw0rd!" was set for this account's credentials.

The brute force tool Crowbar was installed and is what will be used for the attack.

  ![crowbar install](https://github.com/user-attachments/assets/629b8bd4-cac5-4ed0-8f84-17a0d8858797)

This tool operates on a wordlist to guess/crack credentials.
Within Kali, the "rockyou.txt" wordlist is available by default.

  ![rockyou wordlist](https://github.com/user-attachments/assets/6899554b-5710-4e91-8686-bc42daaf7edc)

  ![rockyou wordlist copy](https://github.com/user-attachments/assets/d8e05d83-233f-42b7-824b-6ce62084b56b)

Copy first 20 lines of the wordlist to a new .txt file.

  ![head -n 20 rockyou](https://github.com/user-attachments/assets/3c0676eb-744d-4c8c-97aa-a8591c2db67b)

Edit passwords.txt file to include passwords used during AD setup. 

  ![password list edit](https://github.com/user-attachments/assets/4197994c-17d7-40b1-aeb3-9dae12bb2336)


##
### Step 9: Attack simulation
##
Enter crowbar command with previously created password list. 

    NOTE: -b flag signifies protocol used, -u flag represents user account, -C flag selects wordlist file, -s flag selects source ip of target. 

Use /32 CIDR notation to narrow down search for single ip address. 

We know RDP protocol is enabled on the targeted domain endpoint, so we will target the user bsmith by cracking their RDP login credentials to gain access to the domain.

![Crowbar](https://github.com/user-attachments/assets/560490d8-14de-4161-ba73-aeefa397c811)


##
### Step 10: Using Splunk to detect and analyze brute force attack
##

In Splunk's search and reporting app, enter the endpoint index and user involved In the attack. Enter 15 minutes as the event window as the attack recently occurred to narrow down the results. 

![Splunk search](https://github.com/user-attachments/assets/6c46e7c2-09a0-47bd-86c6-400dc7eb3e3a)

Look at the EventCode Field to see a suspicious amount of activity regarding the "4625" event code, which signifies "An account failed to logon". 

![Event code 4625](https://github.com/user-attachments/assets/b486ac91-2d06-4365-808a-0458285cb99c)

    NOTE: the count of the event code is 22, which matches the amount of passwords in our wordlist file used on kali minus the one successful password. Also notice that all these events take place in quick succession, which is a clear indication of a brute force attacks. 

There is also one event log for EventCode 4624, which signifies "An account was successfully logged on". 
This indicated the one correct password in the wordlist that granted access to the account.

![Event codes](https://github.com/user-attachments/assets/b5bb9ea0-d224-4ed1-8d70-b39e395b53d7)

By selecting this log and expanding all lines, it can be found that the workstation name and source ip indicate malicious activity. 

![malicious log](https://github.com/user-attachments/assets/ba1c2638-d74d-4b27-8531-54170cc5db9f)

For further intrusion detection methods, a Splunk alert can be created for EventCode 4625 "failed logon attempts".

![4625 Alert](https://github.com/user-attachments/assets/004e08b3-290f-436f-9f6b-27984cb3e53b)

![4625 Alert pt2](https://github.com/user-attachments/assets/0c331f78-c951-4fbf-916b-52c61405f9f2)

In future, when the domain encounters potential brute force attacks, these kinds of alerts can be set up to enable security teams to respond rapidly and enforce effective incident response strategies.
In Splunk, the "triggered alerts" tab displays the alerts and correlating log events.

![Triggered alerts](https://github.com/user-attachments/assets/0d59f01c-bf6e-4cca-a800-d216fd6809ba)


##
# Project Summary

Within this project the following was achieved:

   - Active Directory Domain was configured and running with organizational units and users.
   - Splunk Universal Forwarder and Sysmon event log services were successfully installed and running on both domain endpoints.
   - Telemetry was generated in the Splunk enterprise instance, with brute force attack logs being successfully collected on the endpoint and sent to the Splunk indexer, generating telemetry for more detailed analysis via the use of custom configured Sysmon event logs.

With Universal Forwarders and Sysmon set up and successfully logging and monitoring d1omain activity, it would make for a suitable SIEM solution, giving security professionals and incident response a deeper insight into the details of suspicious domain activity.
Sysmon event log configuration is also highly customizable and scalable to account for more specific domain activity or potential attack vectors and IoCs.


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

 
