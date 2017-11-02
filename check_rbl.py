#! /usr/bin/env python
#
# This is a multi-threaded RBL lookup check for Icinga / Nagios.
# Copyright (C) 2012 Frode Egeland <egeland[at]gmail.com>
#
# Modified by Kumina bv in 2013. We only added an option to use an
# address instead of a hostname.
#
# Modified by Guillaume Subiron (Sysnove) in 2015 : mainly PEP8.
#
# Modified by Steve Jenkins (SteveJenkins.com) in 2017. Added a number
# of additional DNSRBLs and made 100% PEP8 compliant.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

# Import Modules
import sys
import os
import getopt
import socket
import string
import Queue
import threading
import ipaddress

# Python version check
rv = (2, 6)
if rv >= sys.version_info:
    print "ERROR: Requires Python 2.6 or greater"
    sys.exit(3)

# List of DNS blacklists
serverlist = [
    "0spam.fusionzero.com",
    "access.redhawk.org",
    "all.rbl.webiron.net",
    "all.s5h.net",
    "b.barracudacentral.org",
    "bad.psky.me",
    "bhnc.njabl.org",
    "bl.blocklist.de",
    "bl.deadbeef.com",
    "bl.emailbasura.org",
    "bl.mailspike.net",
    "bl.spamcannibal.org",
    "bl.spamcop.net",
    "bl.spameatingmonkey.net",
    "bl.technovision.dk",
    "blackholes.five-ten-sg.com",
    "blackholes.mail-abuse.org",
    "blacklist.sci.kun.nl",
    "blacklist.woody.ch",
    "bogons.cymru.com",
    "cbl.abuseat.org",
    "cdl.anti-spam.org.cn",
    "cidr.bl.mcafee.com",
    "combined.abuse.ch",
    "combined.rbl.msrbl.net",
    "db.wpbl.info",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "dnsbl.anticaptcha.net",
    "dnsbl.cobion.com",
    "dnsbl.cyberlogic.net",
    "dnsbl.dronebl.org",
    "dnsbl.inps.de",
    "dnsbl.kempt.net",
    "dnsbl.njabl.org",
    "dnsbl.solid.net",
    "dnsbl.sorbs.net",
    "dnsrbl.org",
    "drone.abuse.ch",
    "duinv.aupads.org",
    "dul.dnsbl.sorbs.net",
    "dul.ru",
    "dyna.spamrats.com",
    "dynip.rothen.com",
    "forbidden.icm.edu.pl",
    "hostkarma.junkemailfilter.com",
    "hil.habeas.com",
    "images.rbl.msrbl.net",
    "ips.backscatterer.org",
    "ix.dnsbl.manitu.net",
    "korea.services.net",
    "mail-abuse.blacklist.jippg.org",
    "no-more-funn.moensted.dk",
    "noptr.spamrats.com",
    "ohps.dnsbl.net.au",
    "omrs.dnsbl.net.au",
    "orvedb.aupads.org",
    "osps.dnsbl.net.au",
    "osrs.dnsbl.net.au",
    "owfs.dnsbl.net.au",
    "owps.dnsbl.net.au",
    "phishing.rbl.msrbl.net",
    "probes.dnsbl.net.au",
    "proxy.bl.gweep.ca",
    "proxy.block.transip.nl",
    "psbl.surriel.com",
    "rbl.abuse.ro",
    "rbl.interserver.net",
    "rbl.megarbl.net",
    "rbl.orbitrbl.com",
    "rbl.realtimeblacklist.com",
    "rbl.schulte.org",
    "rdts.dnsbl.net.au",
    "relays.bl.gweep.ca",
    "relays.bl.kundenserver.de",
    "relays.nether.net",
    "residential.block.transip.nl",
    "ricn.dnsbl.net.au",
    "rmst.dnsbl.net.au",
    "short.rbl.jp",
    "singular.ttk.pte.hu",
    "spam.abuse.ch",
    "spam.dnsbl.sorbs.net",
    "spam.rbl.msrbl.net",
    "spam.spamrats.com",
    "spamguard.leadmon.net",
    "spamlist.or.kr",
    "spamrbl.imp.ch",
    "spamsources.fabel.dk",
    "spamtrap.drbl.drand.net",
    "srnblack.surgate.net",
    "t3direct.dnsbl.net.au",
    "tor.dnsbl.sectoor.de",
    "torserver.tor.dnsbl.sectoor.de",
    "truncate.gbudb.net",
    "ubl.lashback.com",
    "ubl.unsubscore.com",
    "virbl.dnsbl.bit.nl",
    "virus.rbl.jp",
    "virus.rbl.msrbl.net",
    "wormrbl.imp.ch",
    "zen.spamhaus.org"
]

####

queue = Queue.Queue()
global on_blacklist
on_blacklist = []


class ThreadRBL(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            # Grab hosts from queue
            hostname, root_name = self.queue.get()
            check_host = "%s.%s" % (hostname, root_name)
            try:
                check_addr = socket.gethostbyname(check_host)
            except socket.error:
                check_addr = None
            if check_addr is not None and "127.0.0." in check_addr:
                on_blacklist.append(root_name)

            # Signal queue that job is done
            self.queue.task_done()


def usage(argv0):
    print "%s -w <WARN level> -c <CRIT level> -h <hostname>" % argv0
    print " or"
    print "%s -w <WARN level> -c <CRIT level> -a <ip address>" % argv0


def main(argv, environ):
    options, remainder = getopt.getopt(argv[1:],
                                       "w:c:h:a:",
                                       ["warn=", "crit=", "host=", "address="])
    status = {'OK': 0, 'WARNING': 1, 'CRITICAL': 2, 'UNKNOWN': 3}
    host = None
    addr = None

    if 3 != len(options):
        usage(argv[0])
        sys.exit(status['UNKNOWN'])

    for field, val in options:
        if field in ('-w', '--warn'):
            warn_limit = int(val)
        elif field in ('-c', '--crit'):
            crit_limit = int(val)
        elif field in ('-h', '--host'):
            host = val
        elif field in ('-a', '--address'):
            addr = val
        else:
            usage(argv[0])
            sys.exit(status['UNKNOWN'])

    if host and addr:
        print "ERROR: Cannot use both host and address. Please choose one."
        sys.exit(status['UNKNOWN'])

    if host:
        try:
            addr = socket.gethostbyname(host)
        except:
            print "ERROR: Host '%s' not found - maybe try a FQDN?" % host
            sys.exit(status['UNKNOWN'])

    ip = ipaddress.ip_address(unicode(addr))
    if (ip.version == 6):
        addr_exploded = ipaddress.ip_address(unicode(addr)).exploded
        check_name = string.join([c for c in addr_exploded if c != ':'], '.')[::-1]
    else:
        addr_parts = string.split(addr, '.')
        addr_parts.reverse()
        check_name = string.join(addr_parts, '.')
    # Make host and addr the same thing to simplify output functions below
    host = addr

# ##### Start thread stuff

    # Spawn a pool of threads then pass them the queue
    for i in range(10):
        t = ThreadRBL(queue)
        t.setDaemon(True)
        t.start()

    # Populate the queue
    for blhost in serverlist:
        queue.put((check_name, blhost))

    # Wait for everything in the queue to be processed
    queue.join()

# ##### End thread stuff

# Create output
    if on_blacklist:
        output = '%s on %s blacklist(s): %s' % (
            host, len(on_blacklist), ', '.join(on_blacklist))
        # Status is CRITICAL
        if len(on_blacklist) >= crit_limit:
            print 'CRITICAL: %s' % output
            sys.exit(status['CRITICAL'])
        # Status is WARNING
        if len(on_blacklist) >= warn_limit:
            print 'WARNING: %s' % output
            sys.exit(status['WARNING'])
        else:
            # Status is OK and host is blacklisted
            print 'OK: %s' % output
            sys.exit(status['OK'])
    else:
        # Status is OK and host is not blacklisted
        print 'OK: %s not on any known blacklists' % host
        sys.exit(status['OK'])

if __name__ == "__main__":
    main(sys.argv, os.environ)
