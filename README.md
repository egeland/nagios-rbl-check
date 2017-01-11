#nagios-rbl-check
A Python-based Nagios/Icinga plugin to check whether a host is listed on any known DNS-based spam blacklists.

#Usage
    ./check_rbl.py -w <WARN level> -c <CRIT level> -h <hostname>
    ./check_rbl.py -w <WARN level> -c <CRIT level> -a <ipv4 address>

For example, to test whether hostname `mail.google.com` is listed on any known blacklist, with a **Warning** level of 1 blacklist and a **Critical** level of 3 blacklists, do:

    ./check_rbl.py -w 1 -c 3 -h mail.google.com

To test the plugin, check `127.0.0.2` which should always come back as "listed" on every known blacklist. For example:

     ./check_rbl.py -w 1 -c 3 -a 172.0.0.2

#Contributors
* Frode Egeland - https://github.com/egeland
* Steve Jenkins - https://github.com/stevejenkins
* Tim Stoop - https://github.com/timstoop
* Guillaume Subiron - https://github.com/maethor

#License
Licensed under the GPL v3. Enjoy.
