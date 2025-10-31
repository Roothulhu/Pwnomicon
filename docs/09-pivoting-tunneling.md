# 🔄 Pivoting, Tunneling, and Port Forwarding  
*Once a foothold is secured within the shadowed network, the true journey begins. Pivoting enables passage through the compromised host to unseen realms, while port forwarding and tunneling cloak the traveler’s path in layers of deception, bending the flow of traffic like an eldritch stream.*

> *“The deeper you delve, the more the paths twist and the darkness thickens.”*

---

<details>
<summary><h1>📢 Introduction</h1></summary>

**Understanding Pivoting in Network Assessments**

During security assessments—such as red team engagements, penetration tests, or Active Directory assessments—a common scenario arises: you possess the necessary credentials (passwords, SSH keys, hashes, tokens) to access a new target, but that host is not directly reachable from your attack machine.

In these situations, you must use a pivot host—a previously compromised system—to route your traffic and reach the next target.

Upon first accessing a host, it is critical to perform immediate reconnaissance. Key checks include:

* **Privilege Level**: What user permissions do you have?
* **Network Connections**: What other systems is this host communicating with?
* **VPN & Remote Access Software**: Is the host acting as a gateway to other networks?

If a host has multiple network adapters, it is a prime candidate for pivoting to different network segments.

<details>
<summary><h2>Pivoting</h2></summary>

Pivoting is the technique of **using a compromised host to gain access to otherwise unreachable networks**, allowing you to discover and engage with new targets on different network segments.

**Common Terminology for a Pivot Host**

A host used for this purpose is often referred to by several names:

* **Pivot Host**
* **Jump Host**
* **Proxy**
* **Foothold**
* **Beach Head System**

Pivoting's primary use is to defeat segmentation (both physically and virtually) to access an isolated network.

**Practical example**

*During one tricky engagement, the target had their network physically and logically separated. This separation made it difficult for us to move around and complete our objectives. We had to search the network and compromise a host that turned out to be the engineering workstation used to maintain and monitor equipment in the operational environment, submit reports, and perform other administrative duties in the enterprise environment. That host turned out to be dual-homed (having more than one physical NIC connected to different networks). Without it having access to both enterprise and operational networks, we would not have been able to pivot as we needed to complete our assessment.*

</details>

<details>
<summary><h2>Tunneling</h2></summary>

Tunneling is a technique used to **encapsulate network traffic within another protocol**. This creates a "tunnel" through a compromised host, allowing you to covertly route traffic and bypass network security controls.

**Common Terminology for Tunneling**

This technique is often described using several related terms:

* **Tunneling**
* **Protocol Tunneling**
* **Traffic Encapsulation**
* **Proxying (in certain contexts)**

Tunneling's primary use is to enable stealthy pivoting. It defeats network segmentation and monitoring by disguising malicious traffic as legitimate, allowed protocol communications (such as HTTP, DNS, or ICMP), making it difficult for defenders to detect.

**Practical example**

*One way we used Tunneling was to craft our traffic to hide in HTTP and HTTPS. This is a common way we maintained Command and Control (C2) of the hosts we had compromised within a network. We masked our instructions inside GET and POST requests that appeared as normal traffic and, to the untrained eye, would look like a web request or response to any old website. If the packet were formed properly, it would be forwarded to our Control server. If it were not, it would be redirected to another website, potentially throwing off the defender checking it out.*

</details>

<details>
<summary><h2>Lateral Movement</h2></summary>

Lateral Movement is the technique adversaries use to **progressively explore, access, and control additional hosts, applications, and services within a network environment after gaining an initial foothold**.

Common Terminology for Lateral Movement
This phase of an attack is often described using several related terms:

* **Lateral Movement**
* **Horizontal Movement**
* **East-West Movement**

The primary purpose of Lateral Movement is to expand access within a network segment. It is used to find specific targets, access critical domain resources, and escalate privileges across multiple systems to achieve the final objective.

**Practical Example**

*During an assessment, we gained initial access to the target environment and were able to gain control of the local administrator account. We performed a network scan and found three more Windows hosts in the network. We attempted to use the same local administrator credentials, and one of those devices shared the same administrator account. We used the credentials to move laterally to that other device, enabling us to compromise the domain further.*

</details>

</details>

---

<details>
<summary><h1>🌐 The Networking Behind Pivoting</h1></summary>

Being able to grasp the concept of pivoting well enough to succeed at it on an engagement requires a solid fundamental understanding of some key networking concepts. This section will be a quick refresher on essential foundational networking concepts to understand pivoting.

<details>
<summary><h2>IP Addressing & Network Interface Controllers (NICs)</h2></summary>

**What is an IP Address?**
Every computer communicating on a network requires an IP address. Without one, a host is effectively not on the network. This address is a software-assigned identifier, typically obtained in one of two ways:

* **Dynamically**: Automatically assigned by a DHCP server.

* **Statically**: Manually configured, which is common for critical network infrastructure and services, such as:
    * Servers
    * Routers
    * Switch Virtual Interfaces
    * Printers

**The Role of the Network Interface Controller (NIC)**

The IP address is assigned to a Network Interface Controller (NIC)—also commonly known as a Network Interface Card or Network Adapter.

A single computer can have multiple NICs (both physical and virtual), each with its own IP address. This allows a host to communicate on multiple, separate networks simultaneously.

**Importance for Pivoting**

Identifying pivoting opportunities is directly dependent on understanding the IP addresses of a compromised host. Additional NICs and their associated networks are primary indicators of other, potentially valuable network segments the host can reach.

**Therefore, one of the first commands to run on a newly compromised host is to check its network configuration:**

<details>
<summary><h3>Windows Example</h3></summary>

```powershell
ipconfig /all
```
```powershell
Windows IP Configuration

Unknown adapter NordLynx:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::1a9
   IPv6 Address. . . . . . . . . . . : dead:beef::f58b:6381:c648:1fb0
   Temporary IPv6 Address. . . . . . : dead:beef::dd0b:7cda:7118:3373
   Link-local IPv6 Address . . . . . : fe80::f58b:6381:c648:1fb0%8
   IPv4 Address. . . . . . . . . . . : 10.129.221.36
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:df81%8
                                       10.129.0.1

Ethernet adapter Ethernet:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
```

**Network interfaces (summary)**

| Interface                    |             Address(es) |                      Mask / Prefix | Role / Notes                                                                                                                                                                           |
| ---------------------------- | ----------------------: | ---------------------------------: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NordLynx` (Unknown adapter) |                       — |                                  — | Not connected (media disconnected) — likely a WireGuard/WireGuard-based adapter (NordVPN).                                                                                             |
| `Ethernet0 2`                | IPv4: **10.129.221.36** | Subnet Mask: **255.255.0.0** (/16) | Active interface on HTB lab network (`.htb` DNS suffix). Dual-stack with several IPv6 addresses. Default gateways: IPv6 link-local `fe80::250:56ff:feb9:df81%8` and IPv4 `10.129.0.1`. |
| `Ethernet`                   |                       — |                                  — | Disconnected physical adapter.         

**Key observations & implications**

* The system is on a private IPv4 network (10.129.0.0/16). This is an RFC1918 address space and is reachable only inside the lab network or via VPN/tunnel, not directly from the public Internet.
* The host uses dual-stack: it has both IPv4 and IPv6 addresses. Services or hosts may be reachable over either protocol; testing should consider both when possible.
* The NordLynx adapter is present but disconnected — if it becomes active it may provide an alternative VPN route (different lab or Internet VPN).
* The subnet mask (255.255.0.0) indicates the host shares the 10.129.0.0/16 network with any 10.129.x.x addresses; traffic to other subnets will be sent to the default gateway (10.129.0.1).
* For pivoting or lateral movement: the networks visible from this host are limited to the subnets reachable via its assigned interfaces (and whatever routes the gateway provides). Documenting the IPs, masks and gateway is essential to know what this host can reach.                                                                                                                                                |

</details>

<details>
<summary><h3>Linux & macOS Example</h3></summary>

```bash
ifconfig 
```
```bash
ip addr
```

Example output:
```bash
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 134.122.100.200  netmask 255.255.240.0  broadcast 134.122.111.255
        inet6 fe80::e973:b08d:7bdf:dc67  prefixlen 64  scopeid 0x20<link>
        ether 12:ed:13:35:68:f5  txqueuelen 1000  (Ethernet)
        RX packets 8844  bytes 803773 (784.9 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5698  bytes 9713896 (9.2 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.106.0.172  netmask 255.255.240.0  broadcast 10.106.15.255
        inet6 fe80::a5bf:1cd4:9bca:b3ae  prefixlen 64  scopeid 0x20<link>
        ether 4e:c7:60:b0:01:8d  txqueuelen 1000  (Ethernet)
        RX packets 15  bytes 1620 (1.5 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 18  bytes 1858 (1.8 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 19787  bytes 10346966 (9.8 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 19787  bytes 10346966 (9.8 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.15.54  netmask 255.255.254.0  destination 10.10.15.54
        inet6 fe80::c85a:5717:5e3a:38de  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef:2::1034  prefixlen 64  scopeid 0x0<global>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 7  bytes 336 (336.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

**Network interfaces (summary)**

| Interface |                                  Address(es) |    Netmask / Prefix | Role / Notes                                     |
| --------- | -------------------------------------------: | ------------------: | ------------------------------------------------ |
| `eth0`    |                              134.122.100.200 | 255.255.240.0 (/20) | Public IP — host reachable via Internet / DMZ    |
| `eth1`    |                                 10.106.0.172 | 255.255.240.0 (/20) | Private/internal network                         |
| `lo`      |                                    127.0.0.1 |           255.0.0.0 | Local loopback                                   |
| `tun0`    | 10.10.15.54 (IPv4), dead:beef:2::1034 (IPv6) | 255.255.254.0 (/23) | VPN tunnel interface — indicates an active OpenVPN/HTB tunnel. |

**Key observations & implications**

* The presence of `tun0` confirms an active VPN connection. HTB lab access is provided over such a tunnel: without it, lab networks are unreachable.
* `eth0` has a public IP (routable on the Internet). Public-facing interfaces are typically in DMZs and can be reached from outside, subject to firewall rules.
* `eth1` uses a private address (RFC1918) and is routable only inside the local/internal network. Private addresses are not directly reachable from the Internet.
* NAT is typically used at the network edge to translate between private addresses and a public IP on the appliance that connects to the Internet. Devices without a public IP rely on NAT to communicate externally.
* VPNs encrypt traffic and create a logical tunnel over the public network; this enables access to internal lab resources while protecting traffic in transit.

</details>

</details>

<details>
<summary><h2>Routing</h2></summary>

</details>

<details>
<summary><h2>Protocols, Services & Ports</h2></summary>

</details>

</details>

---