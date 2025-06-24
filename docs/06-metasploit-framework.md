
# 🕷️ Metasploit Framework  
*Within this eldritch grimoire lies a vast arsenal of arcane tools for network divination, weaving attacks, and unraveling the deepest secrets of target systems. Harness its dark power to evade the watchful eyes, ascend to forbidden privileges, and command dominion after the breach.*

> *“To command the shadows is to master the unseen forces that bind the network.”*

Advices:

> *Do not get tunnel vision. Use the tool as a tool, not as a backbone or life support for our complete assessment.*

> *Please read all the technical documentation you can find for any of our tools.*

> *Many tools can prove to be unpredictable. Some can leave traces of activity on the target system, and some may leave our attacker platform with open gates.*


---

<details>
<summary><h2>📥 Installation</h2></summary>

The official Metasploit Repository can be found [here](https://github.com/rapid7/metasploit-framework/).  

1. Update your system:  

```bash
sudo apt update && sudo apt install
```

2. Install required dependencies:  

```bash
sudo apt install curl gpg gnupg2 -y
```

3. Download and run the installer:  

```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfinstall > msfinstall
chmod +x msfinstall
sudo ./msfinstall
```

4. Verify installation:  

```bash
msfconsole
```  

Metasploit exploit modules are kept in:

/usr/share/metasploit-framework/modules/exploits

</details>

---
