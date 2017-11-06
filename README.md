[![Build Status](https://travis-ci.org/egeland/nagios-rbl-check.svg?branch=master)](https://travis-ci.org/egeland/nagios-rbl-check)
[![Coverage Status](https://coveralls.io/repos/github/egeland/nagios-rbl-check/badge.svg?branch=master)](https://coveralls.io/github/egeland/nagios-rbl-check?branch=master)

# Nagios RBL / DNSBL Check
A Python-based Nagios/Icinga plugin to check whether a host is listed on any known DNS-based spam blacklists.

# Requirements
The plugin requires Python version 2.6 or higher. If you are using a system with more than one version of Python installed, edit the first line of the `check_rbl.py` script to point to the locally-installed version of Python you wish to use. On RHEL systems, for example, this might look like:

    #! /usr/bin/env python26

The Python library for IPv4/IPv6 manipulation is required. You can install it using pip:

    pip install ipaddress

Or download it using a package manager, it's usually referred as `python-ipaddress`

# Usage
You can run the plugin using either a **hostname** (which will be resolved to an IP address) or an **IP address**:

    ./check_rbl.py -w <WARN level> -c <CRIT level> -h <hostname>
    ./check_rbl.py -w <WARN level> -c <CRIT level> -a <ipv4 address>
    ./check_rbl.py -w <WARN level> -c <CRIT level> -a <ipv6 address>

For example, to test whether hostname `mail.google.com` is listed on any known blacklist, with a **Warning** level of 1 blacklist and a **Critical** level of 3 blacklists, do:

    ./check_rbl.py -w 1 -c 3 -h mail.google.com

To test the plugin, check `127.0.0.2` or `::FFFF:7F00:2` which should always come back as "listed" on every known blacklist. For example:

     ./check_rbl.py -w 1 -c 3 -a 127.0.0.2
     ./check_rbl.py -w 1 -c 3 -a ::FFFF:7F00:2

# Known Blacklists
A list of known blacklists included in the `check_rbl.py` script is located on this Wiki page:

https://github.com/egeland/nagios-rbl-check/wiki

If you know of other DNS-based blacklists that should be considered for inclusion, please open an "Enhancement" issue.

# Contributors
* Frode Egeland - https://github.com/egeland
* Steve Jenkins - https://github.com/stevejenkins
* Tim Stoop - https://github.com/timstoop
* Guillaume Subiron - https://github.com/maethor

# License
Licensed under the GPL v3. Enjoy.
