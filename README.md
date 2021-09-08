# CredMaster #

Launch a password spray / brute force attach via Amazon AWS passthrough proxies, shifting the requesting IP address for every authentication attempt. This dynamically creates FireProx APIs for more evasive password sprays.  

Shoutout to [@ustayready](https://twitter.com/ustayready) for his [CredKing](https://github.com/ustayready/CredKing) and [FireProx](https://github.com/ustayready/fireprox) tools, which form the base of this suite.

See all the full notes on the [Wiki](https://github.com/knavesec/CredMaster/wiki), tool released with specifics in this [blogpost](https://whynotsecurity.com/blog/credmaster/)

For detection tips, see the blogpost and detection section.

**Be careful for account lockouts, know the reset policies of your target**


## Benefits ##

* Fully supports all AWS Regions
* Automatically generates APIs for proxy passthru
* Spoofs API tracking numbers, forwarded-for IPs, and other proxy tracking headers
* Multi-threaded processing
* Password delay counters & configuration for lockout policy evasion
* Easily add new plugins
* Fully [anonymous](https://github.com/knavesec/CredMaster/wiki/Anonymity)

![general](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster-screenshots/credmaster-default.png)


## Quick Use ##

The following plugins are currently supported:

* [OWA](https://github.com/knavesec/CredMaster/wiki/OWA) - Outlook Web Access
* [EWS](https://github.com/knavesec/CredMaster/wiki/EWS) - Exchange Web Services
* [O365](https://github.com/knavesec/CredMaster/wiki/O365) - Office365
* [MSOL](https://github.com/knavesec/CredMaster/wiki/MSOL) - Microsoft Online
* [Okta](https://github.com/knavesec/CredMaster/wiki/Okta) - Okta Authentication Portal
* [FortinetVPN](https://github.com/knavesec/CredMaster/wiki/FortinetVPN) - Fortinet VPN Client
* [HTTPBrute](https://github.com/knavesec/CredMaster/wiki/HTTPBrute) - Generic HTTP Brute Methods (Basic/Digest/NTLM)

Example Use:
```
python3 credmaster.py --plugin {pluginname} --access_key {key} --secret_access_key {key} -u userfile -p passwordfile -a useragentfile {otherargs}
```

This tool requires AWS API access keys, a walkthrough on how to acquire these keys can be found here: https://bond-o.medium.com/aws-pass-through-proxy-84f1f7fa4b4b

All other usage details can be found [here](https://github.com/knavesec/CredMaster/wiki/Usage)


## Credits ##

- Mike Felch ([ustayready](https://twitter.com/ustayready)) - CredKing & FireProx
- Beau Bullock ([dafthack](https://twitter.com/dafthack)) - MSOLSpray tool
- Martin Ingesen ([mrtn9](https://twitter.com/Mrtn9)) - MSOLSpray Python tool
- Oliver Morton ([grimhacker](https://twitter.com/grimhacker)) - Office365UserEnum tool
- Marcello ([byt3bl33d3r](https://twitter.com/byt3bl33d3r)) - SprayingToolkit
- Erforschr - HTTP Bruteforce tool
- Florian Hauser ([frycos](https://twitter.com/frycos) from [codewhitesec](https://twitter.com/codewhitesec)) - ADFS plugin

Feel free to drop me a line
[keybase] - \@knave
[twitter] - \@knavesec
