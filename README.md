# CredMaster #

Launch a password spray / brute force attach via Amazon AWS passthrough proxies, shifting the requesting IP address for every authentication attempt. This dynamically creates FireProx APIs for more evasive password sprays.  

Shoutout to [@ustayready](https://twitter.com/ustayready) for his [CredKing](https://github.com/ustayready/CredKing) and [FireProx](https://github.com/ustayready/fireprox) tools, which form the base of this suite.

See all the full notes on the [Wiki](https://github.com/knavesec/CredMaster/wiki), tool released with specifics in this [blogpost](https://whynotsecurity.com/blog/credmaster/)

For detection tips, see the blogpost and detection section.

**Be careful for account lockouts, know the reset policies of your target**

## TL;DR
1. git clone the repo down
2. If unsure how to create correct keys see this [blog](https://bond-o.medium.com/aws-pass-through-proxy-84f1f7fa4b4b).
3. `pip install -r requirements.txt`
4. Fill out the config file ([wiki](https://github.com/knavesec/CredMaster/wiki/Config-File)) with desired options, or provide through CLI


## Benefits & Features ##

* Rotates the requesting IP address for every request
* Automatically generates APIs for proxy passthru
* Spoofs API tracking numbers, forwarded-for IPs, and other proxy tracking headers
* Multi-threaded processing
* Password delay counters & configuration for lockout policy evasion
* Easily configuation via config file
* Easily add new plugins
* [WeekdayWarrior](https://github.com/knavesec/CredMaster/wiki/Weekday-Warrior) setting for timed spraying and SOC evasion
* Fully [anonymous](https://github.com/knavesec/CredMaster/wiki/Anonymity)
* Colourised output
* Notification systems for Slack & Pushover
  * Operator option within notify function to allow multiple users to use same webhook or instance, operator ID to differentiate users.

![general](https://raw.githubusercontent.com/whynotsecurity/whynotsecurity.github.io/master/assests/images/credmaster-screenshots/credmaster-default.png)


## Quick Use ##

The following plugins are currently supported:

* [OWA](https://github.com/knavesec/CredMaster/wiki/OWA) - Outlook Web Access
  * `--plugin owa`
* [EWS](https://github.com/knavesec/CredMaster/wiki/EWS) - Exchange Web Services
  * `--plugin ews`
* [O365](https://github.com/knavesec/CredMaster/wiki/O365) - Office365
  * `--plugin o365`
* [ADFS](https://github.com/knavesec/CredMaster/wiki/ADFS) - Active Directory Federation Services
  * `--plugin adfs`
* [O365Enum](https://github.com/knavesec/CredMaster/wiki/O365Enum) - Office365 User Enum (No Authentication Request)
  * `--plugin o365enum`
* [MSOL](https://github.com/knavesec/CredMaster/wiki/MSOL) - Microsoft Online
  * `--plugin msol`
* [Okta](https://github.com/knavesec/CredMaster/wiki/Okta) - Okta Authentication Portal
  * `--plugin okta`
* [FortinetVPN](https://github.com/knavesec/CredMaster/wiki/FortinetVPN) - Fortinet VPN Client
  * `--plugin fortinetvpn`
* [HTTPBrute](https://github.com/knavesec/CredMaster/wiki/HTTPBrute) - Generic HTTP Brute Methods (Basic/Digest/NTLM)
  * `--plugin httpbrute`
* [GMailEnum](https://github.com/knavesec/CredMaster/wiki/GmailEnum) - GSuite/Gmail enumeration
  * `--plugin gmailenum`
* [AzureSSO](https://github.com/knavesec/CredMaster/wiki/AzureSSO) - Azure AD Seamless SSO Endpoint
  * `--plugin azuresso`
* [AzVault](https://github.com/knavesec/CredMaster/wiki/AzureVault) - AzVault Module, Azure SSO spray point, different to msol/azuresso, takes just user/pass list or singular input
  * `--plugin azvault`


Example Use:
```
python3 credmaster.py --plugin {pluginname} --access_key {key} --secret_access_key {key} -u userfile -p passwordfile -a useragentfile {otherargs}
```

This tool requires AWS API access keys, a walkthrough on how to acquire these keys can be found here: https://bond-o.medium.com/aws-pass-through-proxy-84f1f7fa4b4b

All other usage details can be found [here](https://github.com/knavesec/CredMaster/wiki/Usage)


## TODO ##

PRs welcome :)

* New Plugin: [Optiv's Go365 Method](https://github.com/optiv/Go365) - Includes Office365 auth and userenum capabilities via SOAP
* "Resume" functionality for paused/cancelled scans. Ideally storing data for APIs used, if they were destroyed and what user/pwd the spray was on
* Password file read dynamically so you can add/delete pwds mid-scan and it will perform as desired
* Method to reliably determine if an auth attempt was throttled, so the username could be re-queued and tried again later for full cover (would have to be per-plugin, return "throttled" boolean value in plugin script, requeue if throttled)
* Notification system for webhooks (Discord[Work in progress]/Teams TODO)
* Automatic logging of valid users
* Stop on success flag
* Spray profile overhaul
* Development notes


## Credits ##

- Mike Felch ([ustayready](https://twitter.com/ustayready)) - CredKing & FireProx
- Beau Bullock ([dafthack](https://twitter.com/dafthack)) - MSOLSpray tool
- Martin Ingesen ([mrtn9](https://twitter.com/Mrtn9)) - MSOLSpray Python tool
- Oliver Morton ([grimhacker](https://twitter.com/grimhacker)) - Office365UserEnum tool
- Marcello ([byt3bl33d3r](https://twitter.com/byt3bl33d3r)) - SprayingToolkit
- Erforschr - HTTP Bruteforce tool
- Florian Hauser ([frycos](https://twitter.com/frycos) from [codewhitesec](https://twitter.com/codewhitesec)) - ADFS plugin
- [nyxgeek](https://twitter.com/nyxgeek) - Azure AD Seamless SSO python implementation
- Joe Helle ([joehelle](https://twitter.com/joehelle)) - Oh365UserFinder
- Cameron Geehr ([BarrelTit0r](https://twitter.com/BarrelTit0r)) - o365enum tool
- Max Gruenberg ([Max_Gruenberg](https://twitter.com/Max_Gruenberg)) - o365enum plugin
- x0rz - GmailEnum technique
- Kole Swesey ([0xPanic_](https://twitter.com/0xPanic_)) - Assorted PR
- Logan ([TheToddLuci0](https://twitter.com/TheToddLuci0)) - Assorted PRs
- Andy Gill ([ZephrFish](https://twitter.com/ZephrFish)) - Colour functions + Tweaks/Notifications, helping on dev rewrite, azvault module


Feel free to drop me a line
- \@knave on Keybase
- [Twitter - knavesec](https://twitter.com/knavesec)
