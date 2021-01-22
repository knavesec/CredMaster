# CredMaster #

- [Overview](#overview)
	- [Benefits](#benefits)
- [Basic Usage](#basic-usage)
- [Plugin Usage](#plugin-usage)
    - [Okta](#okta)
		- [O365](#o365)
		- [MSOL](#msol)
		- [HTTPBrute](#httpbrute)
		- [TBD](#tbd)
- [Installation](#installation)
- [Development](#development)
    - [Plugin specific arguments](#plugin-specific-arguments)
- [Credits](#credits)


## Overview ##

Launch a password spray via Amazon AWS passthrough proxies, shifting the requesting IP address for every authentication attempt. This dynamically creates FireProx APIs to create more evasive password sprays.  

Shoutout to [@ustayready](https://twitter.com/ustayready) for his [CredKing](https://github.com/ustayready/CredKing) and [FireProx](https://github.com/ustayready/fireprox) tools, which form the base of this suite.


### Benefits ###

 * Fully supports all AWS Regions
 * Automatically generates APIs for proxy passthru
 * Spoofs API tracking numbers, forwarded-for IPs, and other proxy tracking headers
 * Multi-threaded processing
 * Generates user/password pairs
 * Easily add new plugins


## Basic Usage ##

usage: credmaster.py [-h] --plugin PLUGIN -u USERFILE -p PASSWORDFILE
				[-a USERAGENTFILE] [-o OUTFILE] [-t THREADS] [-j JITTER] [-m JITTER_MIN]
				[-d DELAY] [--passwordsperdelay PASSWORDSPERDELAY] [--profile_name PROFILE_NAME]
				[--access_key ACCESS_KEY] [--secret_access_key SECRET_ACCESS_KEY]
				[--session_token SESSION_TOKEN] [--config CONFIG] [--clean]

```
-h, --help            show this help message and exit
--plugin PLUGIN       Spray plugin
-u USERFILE, --userfile USERFILE
											Username file
-p PASSWORDFILE, --passwordfile PASSWORDFILE
											Password file
-a USERAGENTFILE, --useragentfile USERAGENTFILE
											Useragent file
-o OUTFILE, --outfile OUTFILE
											Output file to write contents (omit extension)
-t THREADS, --threads THREADS
											Thread count (default: 1)
-j JITTER, --jitter JITTER
											Jitter delay between requests in seconds (applies per-thread)
-m JITTER_MIN, --jitter_min JITTER_MIN
											Minimum jitter time in seconds, defaults to 0
-d DELAY, --delay DELAY
											Delay between unique passwords, in minutes
--passwordsperdelay PASSWORDSPERDELAY
											Number of passwords to be tested per delay cycle
--profile_name PROFILE_NAME
											AWS Profile Name to store/retrieve credentials
--access_key ACCESS_KEY
											AWS Access Key
--secret_access_key SECRET_ACCESS_KEY
											AWS Secret Access Key
--session_token SESSION_TOKEN
											AWS Session Token
--config CONFIG       Authenticate to AWS using config file aws.config
--clean               Clean up ALL AWS APIs from every region, warning irreversible
```

- `outfile` - multithreaded file writes are hard so this is incomplete. Will write to `threads`+1 files. These can be put in order with a simple `sort outfilename-credmaster*` since they are all timestamped
- `threads` - pretty straight forward, for quicker results. Each thread is a unique AWS region so there is less overlap
- `jitter`, `jitter_min` - provide upper and lower limit settings for jittering requests
- `delay` - provided a password list, it can be configured to move to the next password after `delay` minutes to help prevent lockouts. Helpful if you know the clients lockout reset counter, you can set the delay between passwords long enough to trigger the reset
- `passwordsperdelay` - spray X passwords per delay cycle, helpful for when the lockout counter is high (like 10 passwords) and you can spray more than one password per delay
- `access_key`, `secret_access_key`, `profile_name`, `session_token` - input parameters for AWS access to create FireProx APIs, details can be found on that GitHub page
- `config` - an easy config file that you can store your AWS access tokens in, a template can be found in the repo
- `clean` - remove all APIs from AWS, if you cancel the spray mid-test credmaster may not be able to clean up all APIs correctly

Example: `python3 credmaster.py --access_key <key> --secret_access_key <key> --plugin o365 -u userfile.txt -p passfile.txt -a useragents.txt -t 5 -o outputfile -j 20 -m 10 -d 360 --passwordsperdelay 3`

This will run the `o365` module with 5 threads and a 10-20 second jitter. It will attempt 3 passwords every 6 hrs (360 min).


## Plugin Usage ##

### Okta ###

The Okta plugin adds one new required argument, `url`, and one optional argument `force`.

usage: **credmaster.py** \<usual arguments\> **--url** https://example.okta.com

#### Throttle Notes: ####

Okta throttles based on `(amount of authentication attempts) / (time)`, running multiple threads will result in getting throttled _very_ quickly. It is highly recommended to use only 1 thread, CredMaster will warn if more are used. Jitter/delay also can help with this problem, though it will not solve it.

usage: **credmaster.py** \<usual arguments\> --threads 5 **--force**


### O365 ###

The o365 module is specific to Federated Office365 environments due to the authentication method used. If your target is a Managed environment, use the MSOL module as this one _will not work_.

You can use this link to check which type it is, in the "NameSpaceType" key. Change `acmecomputercompany.com` to your target domain.

https://login.microsoftonline.com/getuserrealm.srf?login=username@acmecomputercompany.com&xml=1

This plugin does not require any additional arguments.

#### Throttle Notes: ####

TBD, more research required (feel free to PR with notes)

**Credits:** This module was based off GrimHacker's [Office365UserEnum](https://bitbucket.org/grimhacker/office365userenum/src/master/README.md) tool.


### MSOL ###

The MSOL module is specific to Managed Office65 environments due to the authentication method used. If your target is a Federated environment, use the o365 module as this one _will not work_.

You can use this link to check which type it is, in the "NameSpaceType" key. Change `acmecomputercompany.com` to your target domain.

https://login.microsoftonline.com/getuserrealm.srf?login=username@acmecomputercompany.com&xml=1

This plugin does not require any additional arguments.

#### Throttle Notes: ####

TBD, more research required (feel free to PR with notes)

**Credits:** This module was based off DaftHack's [MSOLSpray](https://github.com/dafthack/MSOLSpray) tool, specifically the Python implementation of it [here](https://github.com/MartinIngesen/MSOLSpray).


### HTTPBrute ###

This module allows for HTTP Basic, Digest and NTLM authentication brute forcing. It adds two new plugin args: `url` and `auth`. The HTTP `auth`

Note: This module has not been tested to the fullest yet

usage: **credmaster.py** \<usual arguments\> **--url** https://example.com/endpoint/to/test **--auth** basic/digest/ntlm

#### Throttle Notes: ####

This depends on a per-application basis. Use your own discretion.

**Credits:** This module was based off erforschr's [bruteforce-http-auth](https://github.com/erforschr/bruteforce-http-auth) tool


### TBD ###

Since plugin creation is simple, I'm hoping others try their hand at creating these. Plugins from CredKing PRs include Gmail, Microsoft Live and CiscoVPN, I haven't had the time to port.


## Installation ##

### Ubuntu/Kali ###

You can install and run automatically using Python 3 with the following command:

```bash
$ git clone https://github.com/knavesec/CredMaster
$ cd CredMaster
$ pip3 install -r requirements.txt
$ python3 credmaster.py
```

Note that Python 3 is required.

**Bug reports, feature requests and patches are welcome**


## Development ##

You can create new plugins by following the instructions below. A template is provided in the `plugins/template` directory.

```bash
$ cd plugins
$ mkdir newplugin
$ cd newplugin
$ touch __init__.py
$ touch newplugin.py
```

A template is provided in the `plugins/template` directory. Instructions within that file should give you all the information you need to add a new plugin.


### Plugin specific arguments ###

Plugin specific arguments can be specified with no modifications to credmaster.py, simply pass them as *--argumentname value*

If your plugin requirements plugin-specific arguments, you can implement a validate function in the \_\_init\_\_.py file of your plugin directory that will be passed an dictionary of all optional arguments. An example of plugin argument validation can be found in any of the plugins provided.

All validate functions _must_ return a `pluginargs['url']` value to be used for the API creation, which cannot include the URI. FireProx will not work properly if the URI is provided. The `httpbrute` and `o365` methods are good examples if you need clarification. Everything else will be passed to the authentication function to be used.


### Credits ###

- Mike Felch ([ustayready](https://twitter.com/ustayready)) - CredKing & FireProx
- Beau Bolloc ([dafthack](https://twitter.com/dafthack)) - MSOLSpray tool
- Martin Ingesen ([mrtn9](https://twitter.com/Mrtn9)) - MSOLSpray Python tool
- Oliver Morton ([grimhacker](https://twitter.com/grimhacker)) - Office365UserEnum tool
- Erforschr - HTTP Bruteforce tool
- My team at [RSM](https://rsmus.com/what-we-do/services/risk-advisory/cybersecurity-data-privacy/security-testing/network-penetration-testing.html) for help with testing and development
