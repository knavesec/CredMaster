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
* Spoofs API tracking numbers, forwarded-for IPs, and other proxy tracking headers = fully [anonymous](https://github.com/knavesec/CredMaster/wiki/Anonymity)
* Easily configuation via config file
* Multi-threaded processing
* Password delay counters & configuration for lockout policy evasion
* Easily add new plugins
* Colourised output
* Notification systems for Slack, Discord, Teams & Pushover
* [WeekdayWarrior](https://github.com/knavesec/CredMaster/wiki/Weekday-Warrior) setting for timed spraying and SOC evasion

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
* [MSGraph](https://github.com/knavesec/CredMaster/wiki/MSGraph) - MSGraph Module, msgraph spray point for azure and MSOL credentials
  * `--plugin msgraph`
* [AzureSSO](https://github.com/knavesec/CredMaster/wiki/AzureSSO) - Azure AD Seamless SSO Endpoint
  * `--plugin azuresso`
* [AzVault](https://github.com/knavesec/CredMaster/wiki/AzureVault) - AzVault Module, Azure spray point different to MSOL/AzureSSO
  * `--plugin azvault`
* [Okta](https://github.com/knavesec/CredMaster/wiki/Okta) - Okta Authentication Portal (**note this module is limited to one thread therefore will error unless run with** `-t 1`)
  * `--plugin okta`
* [FortinetVPN](https://github.com/knavesec/CredMaster/wiki/FortinetVPN) - Fortinet VPN Client
  * `--plugin fortinetvpn`
* [HTTPBrute](https://github.com/knavesec/CredMaster/wiki/HTTPBrute) - Generic HTTP Brute Methods (Basic/Digest/NTLM)
  * `--plugin httpbrute`
* [GMailEnum](https://github.com/knavesec/CredMaster/wiki/GmailEnum) - GSuite/Gmail enumeration
  * `--plugin gmailenum`


Example Use:
```
python3 credmaster.py --plugin {pluginname} --access_key {key} --secret_access_key {key} -u userfile -p passwordfile -a useragentfile {otherargs}
```

or

```
python3 credmaster.py --config config.json
```

This tool requires AWS API access keys, a walkthrough on how to acquire these keys can be found here: https://bond-o.medium.com/aws-pass-through-proxy-84f1f7fa4b4b

All other usage details can be found [on the wiki](https://github.com/knavesec/CredMaster/wiki/Usage)


## TODO ##

PRs welcome :)

* New Plugin: [Optiv's Go365 Method](https://github.com/optiv/Go365) - Includes Office365 auth and userenum capabilities via SOAP
* "Resume" functionality for paused/cancelled scans. Ideally storing data for APIs used, if they were destroyed and what user/pwd the spray was on
* Method to reliably determine if an auth attempt was throttled, so the username could be re-queued and tried again later for full cover (would have to be per-plugin, return "throttled" boolean value in plugin script, requeue if throttled)
* Notification system for webhooks (Teams TODO)
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
- [x0rz](https://twitter.com/x0rz) - GmailEnum technique
- Kole Swesey ([0xPanic_](https://twitter.com/0xPanic_)) - Assorted PR
- Logan ([TheToddLuci0](https://twitter.com/TheToddLuci0)) - Assorted PRs
- Andy Gill ([ZephrFish](https://twitter.com/ZephrFish)) - Colour functions + Tweaks/Notifications, helping on dev rewrite, AzVault module


Feel free to drop me a line
- \@knave on Keybase
- [Twitter - knavesec](https://twitter.com/knavesec)
