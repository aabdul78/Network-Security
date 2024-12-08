# Network-Security
Homework 11
Part 1: Review Questions

Security Control Types
The concept of defense in depth can be broken down into three different security control types. Identify the security control type of each set of defense tactics.

1- Walls, bollards, fences, guard dogs, cameras, and lighting are what type of security control?

Answer:
Physical security

2- Security awareness programs, BYOD policies, and ethical hiring practices are what type of security control?

Answer:
Administrative Security

3- Encryption, biometric fingerprint readers, firewalls, endpoint security, and intrusion detection systems are what type of security control?

Answer:
Operational Security

Intrusion Detection and Attack indicators
What's the difference between an IDS and an IPS?

Answer:
IPS logs & takes action against potential threat traffic, IDS does not. to expline, IDS is a stateless network monitor, which doesn't alter packets or frames, but rather logs and/or notifies individuals about network traffic. An IPS; however, plays a more active role in network monitoring. Being a stateful control system, an IPS is capable of blocking traffic and intializing other security protocols.

What's the difference between an Indicator of Attack and an Indicator of Compromise?

Answer:
Indicator of attacks are real time indicators, or a breach indicators of compromise are like attamted attack. to expline, An indicator of compromise focuses on gathering conclusive evidence, that a system has been breached, while an indicator of attack focuses on spotting attempted attacks or reconaissance and deducing the actor's intent. Modern security tools tend to aim more on indicators of attack

The Cyber Kill Chain
Name each of the seven stages for the Cyber Kill chain and provide a brief example of each.

Answer
Stage 1: Recon - Gathering info on an individual in preparation for an attack.

Stage 2: Weaponization - Injecting the malicious software or installing some sort of back door on said target's machine.

Stage 3: Delivery - Attacker sends malicious payload by means of email or instant message.

Stage 4: Exploitation - Gaining access & compromising the user's machine.

Stage 5: Installation - Installing more malicious code such as granting your own user root access.

Stage 6: C2 - Command channel used to control another computer.

Stage 7: Exfiltration - Accomplishing the final goal on the user's machine.


Snort Rule Analysis
Use the Snort rule to answer the following questions: Snort Rule #1 alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"ET SCAN Potential VNC Scan 5800-5820"; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2002910; classtype:attempted-recon; sid:2002910; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

Break down the Sort Rule header and explain what is happening?
Answer:
A remote host, using any port, attempted to scan the local host ($HOME_NET) on ports ranging from 5800 to 5820, using TCP/IP protocol. This is likely the result of port mapping with a tool such as nmap or metasploit.

What stage of the Cyber Kill Chain does this alert violate?

Answer:
Reconnaissance

What kind of attack is indicated?
Answer:
Port Mapping

Snort Rule #2
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET POLICY PE EXE or DLL Windows file download HTTP"; flow:established,to_client; flowbits:isnotset,ET.http.binary; flowbits:isnotset,ET.INFO.WindowsUpdate; file_data; content:"MZ"; within:2; byte_jump:4,58,relative,little; content:"PE|00 00|"; distance:-64; within:4; flowbits:set,ET.http.binary; metadata: former_category POLICY; reference:url,doc.emergingthreats.net/bin/view/Main/2018959; classtype:policy-violation; sid:2018959; rev:4; metadata:created_at 2014_08_19, updated_at 2017_02_01;)

Break down the Sort Rule header and explain what is happening?
Answer:
The remote host, through http ports, attempted to deliver a malicous payload to any port of the local machine.

What layer of the Defense in Depth model does this alert violate?
Answer:
Delivery

What kind of attack is indicated?

Answer:
Cross site scripting

Snort Rule #3
Your turn! Write a Snort rule that alerts when traffic is detected inbound on port 4444 to the local network on any port. Be sure to include the msg in the Rule Option.

Answer:
alert tcp $EXTERNAL_NET any -> $HOME_NET 4444 (msg:"gg no re")

** Part 2: "Drop Zone" Lab
Log into the Azure firewalld machine Log in using the following credentials:

Username: sysadmin

Password: cybersecurity

Uninstall ufw
Before getting started, you should verify that you do not have any instances of ufw running. This will avoid conflicts with your firewalld service. This also ensures that firewalld will be your default firewall.

Run the command that removes any running instance of ufw.

Answer
sudo apt -y remove ufwD

![image](https://github.com/user-attachments/assets/2997af47-593d-4ba9-9c5b-bc8a92524676)

