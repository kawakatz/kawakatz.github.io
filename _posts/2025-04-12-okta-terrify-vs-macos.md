---
layout: post
title: Okta Terrify vs macOS
description: The macOS security mechanisms against Oktat Terrify and how to abuse Okta Verify

date: 2025-04-12 01:30:00 +0900
image:
    path: /assets/img/20250412/18.png
---

Hello.    
This is my first blog, so I will start with this small one.  

In this blog, I will write about the macOS security mechanisms preventing Okta Terrify's logic from working and how to abuse Okta Verify on macOS.

Note: Although images were acquired using both an Intel Mac with a Secure Enclave and an Intel Mac VM without a Secure Enclave, this does not affect the content of this article.

## Topic
- Basic bypass of certificate pinning with lldb on macOS
- Basic debugging of macOS applications
- How to abuse Okta Verify on macOS

## Table of Contents
1. [Okta Verify & Okta FastPass](#okta-verify--okta-fastpass)
2. [Okta Terrify](#okta-terrify)
3. [Bypassing certificate pinning](#bypassing-certificate-pinning)
4. [Debugging Okta Verify](#debugging-okta-verify)
5. [Why is the logic avalable on Windows?](#why-is-the-logic-avalable-on-windows)
6. [How to abuse Okta Verify](#how-to-abuse-okta-verify)
7. [Trusted App Filters](#trusted-app-filters)
8. [Conclusion](#conclusion)

## Okta Verify & Okta FastPass
Okta Verify is a software developed by Okta.  
Its role is to enable passwordless authentication. Okta Verify for macOS is primarily used to provide phishing‐resistant authentication with FIDO-like features, known as Okta FastPass.

Okta Verify for macOS listens for HTTP traffic on 8769/tcp and operates as follows:
<img src="/assets/img/20250412/1.png" width="470" style="border: 1px solid black; display: block; margin: 0;" alt=""/>

## Okta Terrify
[Okta Terrify](https://github.com/CCob/okta-terrify) is a tool developed by [CCob](https://x.com/_EthicalChaos_) to abuse Okta Verify on Windows. It consists of OktaTerrify, which is executed at attacker's devices, and OktaInk, which is executed at victim's devices.  

Okta Terrify backdoor mode launches an Okta authentication session using the official OAuth client ID, triggering the victim's device to sign a device bind JWT. It then enrolls a fake biometric (user verification) key to grant persistent passwordless access.  

During this process, OktaInk asks the TPM to sign and obtains the signed device bind JWT. The important question is if it can be done with Secure Enclave on macOS.  

While the answer is definitively "No", this article will detail the methods to confirm this behavior and explore potential abuse scenarios on macOS.

## Bypassing certificate pinning
As the Proxyman error indicates, Okta Verify uses certificate pinning for *.okta.com. 
<img src="/assets/img/20250412/2.png" width="700" style="border: 1px solid black; display: block; margin: 0;" alt=""/>

#### Basic
There are scripts like [disable-ssl-pin.js](https://gist.github.com/onewayticket255/94c1f58c5a84b8a09fe94aea3ee5a5eb) intended to bypass certificate pinning with Frida. One problem for me was that Okta Verify hated Frida. When I attached Frida to its process, the process would crash. However, lldb worked fine.  
<img src="/assets/img/20250412/3.png" width="700" style="border: 1px solid black; display: block; margin: 0;" alt=""/>

So, I implemented the same logic with lldb. I found that handling callbacks with lldb was somewhat challenging. To patch SSL_CTX_set_custom_verify() correctly, I had to create a fake callback that always returns 0 and replace the real one.Although this process was somewhat tedious, the actual callback was consistently boringssl_context_certificate_verify_callback(), so I patched it to always return 0.

This script partially worked, but not completely.  
In brief, I encountered problems with authentication using 8769/tcp and during Okta Verify setup, whereas authentication via ‘Open Okta Verify’ or removing account information from Okta Verify posed no issues.

#### Additional work for Okta Verify
I found an error log in Console.app.
```log
{🛑 "Handle CUS": {"message": "Error validating apple event: invalidProperties", "defaultProperties": "", "location": "CustomURLHandlingCoordinator.swift:handleAppleEvent(event:replyEvent:):115"}}
```

The upper log corresponds to normal operation, while the lower log indicates errors caused by an HTTP proxy. Okta Verify is supposed to get "TLS Trust result of 0", but when an HTTP proxy is present, it fails to obtain the expected log.
<img src="/assets/img/20250412/4.png" width="700" style="border: 1px solid black; display: block; margin: 0;" alt=""/>
<img src="/assets/img/20250412/5.png" width="700" style="border: 1px solid black; display: block; margin: 0;" alt=""/>

When I examined the details, it became clear that the function SecTrustEvaluateIfNecessary() is involved.
```sh
log stream --level trace --predicate 'process == "Okta Verify"'
```
<img src="/assets/img/20250412/6.png" width="750" style="border: 1px solid black; display: block; margin: 0;" alt=""/>

This function was called from functions such as SecTrustEvaluateWithError(), which has already been patched. Importantly, SecTrustCopyCertificateChain() is called directly by Okta Verify, and then the above error occurs.
<img src="/assets/img/20250412/7.png" width="700" style="border: 1px solid black; display: block; margin: 0;" alt=""/>

After analyzing the relevant section, I confirmed that SecTrustCopyCertificateChain() is invoked after SecTrustEvaluateWithError() to perform its own certificate validation.
<img src="/assets/img/20250412/8.png" width="520" style="border: 1px solid black; display: block; margin: 0;" alt=""/>

The location to be patched can be easily identified. If the first argument is 1, it indicates that the verification has been completed successfully.  
<img src="/assets/img/20250412/9.png" width="530" style="border: 1px solid black; display: block; margin: 0;" alt=""/>
<img src="/assets/img/20250412/10.png" width="670" style="border: 1px solid black; display: block; margin: 0;" alt=""/>

After applying the patch, everything works as expected.
<img src="/assets/img/20250412/11.png" width="520" style="border: 1px solid black; display: block; margin: 0;" alt=""/>

The final script is here.  
**Link**: [https://github.com/kawakatz/scripts-for-okta-verify](https://github.com/kawakatz/scripts-for-okta-verify)

## Debugging Okta Verify
To debug Okta Verify, we first need to disable SIP at first. Then, attach lldb with sudo:  
```sh
$ sudo lldb -n 'Okta Verify'
```

To understand the restrictions, we can debug the function SecKeyCreateRandomKey() which is called to create a new key pair. The first argument, "parameters", is a dictionary — “A dictionary you use to specify the attributes of the generated keys” — as defined in the documentation.  
Link: [SecKeyCreateRandomKey(_:_:)](https://developer.apple.com/documentation/security/seckeycreaterandomkey(_:_:))  

In lldb, set a breakpoint at SecKeyCreateRandomKey():
```sh
(lldb) b SecKeyCreateRandomKey 
```

During Okta Verify setup, SecKeyCreateRandomKey() was called three times.  
The most important thing here is that the kSecAttrAccessGroup (argp) is always set to "B7F62B65BN.group.okta.verify.shared". Additionaly, each key has a diffrent kSecAttrApplicationTag (atag).  
<img src="/assets/img/20250412/15.png" width="720" style="border: 1px solid black; display: block; margin: 0;" alt=""/>

This means that applications must meet the following conditions to access the keys. This is why Okta Terrify’s logic does not work on macOS. If there were an older version of Okta Verify that was vulnerable to Dylib Injection, we could bypass these restrictions. However, I couldn’t find one.  
- The app should be signed by a certificate with the TeamID “B7F62B65BN”
- The app should have the entitlement “group.okta.verify.shared”

At the second call, SecAccessControlRef is set as follows. This indicates that using the key requires authentication of the device owner (passcode, Touch ID/Face ID, etc.), which is characteristic of the user verification key in Okta Verify.  
```
accc = "<SecAccessControlRef: cku;od(cpo(DeviceOwnerAuthentication));odel(true);oe(true)>"
```

Let’s examine the actual request at the completion of the setup. By comparing the value of "kid" with the value of "atag", we can confirm that the keys are generated in the following order:
1. proofOfPossession
2. userVerificationBioOrPin
3. clientInstanceKey

<img src="/assets/img/20250412/16.png" width="640" style="border: 1px solid black; display: block; margin: 0;" alt=""/>

## Why is the logic avalable on Windows?
Both TPM (Trusted Platform Module) and Secure Enclave offer hardware-based security solutions for cryptographic operations. However, they differ significantly in how they handle access restrictions, especially regarding application-specific key usage.

TPMs do not offer mechanisms to restrict cryptographic operations to a particular application. This means that any application running with sufficient privileges can execute signing operations, regardless of which application originally stored the keys. In contrast, Secure Enclave enforces application-specific restrictions, ensuring that only the explicitly permitted application can use its stored keys.

## How to abuse Okta Verify
As we have seen, it is extremely difficult to abuse Okta Verify on macOS in the same way as on Windows.  
Currently, it is possible to abuse it by forwarding 8769/tcp on the attacker's device to the victim's Okta Verify through a SOCKS proxy.  
<img src="/assets/img/20250412/18.png" width="500" style="border: 1px solid black; display: block; margin: 0;" alt=""/>

Okta Verify's responses on macOS are missing the final empty line, causing some HTTP proxy tools, including Burp Suite, to fail to recognize them correctly. Also, Okta expects responses from Okta Verify to be returned instantly, so passing through a SOCKS proxy will result in a timeout. Fortunately, Okta Verify's responses are almost always fixed, so I used a Python script that only forwards challenges to Okta Verify on the victim device and always returns spoofed responses.   
1. Build a SOCKS proxy with a C2 agent or [Chisel](https://github.com/jpillora/chisel)
2. Run the PoC Python script on the attacker's device  
Link: [https://github.com/kawakatz/scripts-for-okta-verify](https://github.com/kawakatz/scripts-for-okta-verify)
```sh
python3 poc.py --proxy-host <proxy host> --proxy-port <proxy port> --origin 'https://<company>.okta.com'
```
3. Start authentication as Okta FastPass on the attacker's device

<img src="/assets/img/20250412/17.png" width="780" style="border: 1px solid black; display: block; margin: 0;" alt=""/>

The problem with this approach is that it requires user approval in most cases. However, from my experience so far, I think this is still sufficient to abuse Okta Verify. It is much more responsive than sending notifications to Okta Verify on an iPhone or Android. In some cases, simply obtaining an authenticated session from the browser is enough. This method is particularly useful in the following scenarios:
- When you need to add Okta Verify for some reason
  - For instance, VDI or VPN might require an Okta Verify authentication code
- When Device Trust requires authentication as Okta FastPass every time you perform SSO with an authenticated session.

If Okta FastPass by Device Trust is deployed, certificates for Device Trust are often issued by Jamf or Intune. In this case, the certificate and private key are stored in the system keychain. The system keychain's key at "/var/db/SystemKey" is protected by SIP, malware cannot extract the private key. Although the ACL of the private key in the system keychain should be checked, but the expectation is quite low.

When actually abusing this method, I recommend that the browser communication also go through a SOCKS proxy in order to utilize a more legitimate IP address, and that the email address "no-reply@okta.com" that sends the sign-in notification be blocked in advance in the victim's account.

Depending on the configuration and circumstances at the time, it can be possible to authenticate without user approval.
<img src="/assets/img/20250412/19.png" width="750" style="border: 1px solid black; display: block; margin: 0;"  alt=""/>
<img src="/assets/img/20250412/20.png" width="750" style="border: 1px solid black; display: block; margin: 0;" alt=""/>

#### Side Note
Before publication, I realized that the method described here had already been published in the article linked below (I guess I really had a silly moment!🤦‍♂️). Since the exact same results can be reproduced using the script provided in their repositories, I recommend referring to that repositories.
- by [Adam Chester](https://x.com/_xpn_)  
**Blog**: [Identity Providers for RedTeamers](https://blog.xpnsec.com/identity-providers-redteamers/) | **Tool**: OktaRealFast of [OktaPostExToolkit](https://github.com/xpn/OktaPostExToolkit)    
- by the GitLab Red Team  
**Blog**: [Tech Note - Okta Verify Bypass](https://gitlab-com.gitlab.io/gl-security/security-tech-notes/red-team-tech-notes/okta-verify-bypass-sept-2024/) | **Tool**: [8769_forwarder](https://gitlab.com/gitlab-com/gl-security/security-operations/redteam/redteam-public/pocs/8769_forwarder)

## Trusted App Filters
Trusted App Filters is mentioned as below in the article.  
**Link**: [Trusted app filters](https://help.okta.com/oie/en-us/content/topics/identity-engine/authenticators/trusted-app-filters-for-fastpass.htm)
> Specifically, trusted app filters enable the blocking of unsigned binaries and creating an allowlist of binaries. By preventing unsigned binaries from invoking Okta FastPass, you enhance security against unauthorized or malicious software.

By using Trusted App Filters, you can restrict the applications that are permitted to request signatures on Okta Verify, thereby serving as a countermeasure against the method.
In the following article, a general explanation of how Trusted App Filters operate is provided while mentioning the method. You can find the explanation specifically in the "How it works" section.  
**Link**: [Stay secure with FastPass and Trusted App Filters](https://www.okta.com/blog/2025/04/stay-secure-with-fastpass-and-trusted-app-filters/)

I haven't yet been able to test Trusted App Filters, so I plan to investigate how it works and whether it can be bypassed in the future.

## Conclusion
In this blog, I noted the macOS security mechanisms that prevent Okta Terrify's logic from working and how Okta Verify can be abused.
- Certificate pinning can be bypassed using lldb
- Okta Terrify's logic doesn't work because of the app-based macOS security mechanisms
- Abuse is still possible by forwarding port 8769/tcp, though user approval is typically required
- Trusted App Filters have been developed as a countermeasure against this method