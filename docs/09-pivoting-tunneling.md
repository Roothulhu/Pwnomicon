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
<summary><h2>IP Addressing & NICs</h2></summary>

</details>

<details>
<summary><h2>Routing</h2></summary>

</details>

<details>
<summary><h2>Protocols, Services & Ports</h2></summary>

</details>

</details>

---