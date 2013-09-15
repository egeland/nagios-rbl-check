#! /usr/bin/env python
#
# This is a multi-threaded RBL lookup check for Icinga / Nagios.
# Copyright (C) 2012 Frode Egeland <egeland[at]gmail.com>
#
# Modified by Kumina bv in 2013. We only added an option to use an
# address instead of a hostname.
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
#

import sys, os, getopt, socket, string

rv = (2,6)
if rv >= sys.version_info:
    print "ERROR: Requires Python 2.6 or greater"
    sys.exit(3)

import Queue, threading

serverlist = [
"0spam.fusionzero.com",
"access.redhawk.org",
"b.barracudacentral.org",
"bhnc.njabl.org",
"bl.deadbeef.com",
"bl.spamcannibal.org",
"bl.spamcop.net",
"bl.technovision.dk",
"blackholes.five-ten-sg.com",
"blackholes.mail-abuse.org",
"blacklist.sci.kun.nl",
"blacklist.woody.ch",
"bogons.cymru.com",
"cbl.abuseat.org",
"cdl.anti-spam.org.cn",
"combined.abuse.ch",
"combined.rbl.msrbl.net",
"db.wpbl.info",
"dnsbl-1.uceprotect.net",
"dnsbl-2.uceprotect.net",
"dnsbl-3.uceprotect.net",
"dnsbl.ahbl.org",
"dnsbl.cyberlogic.net",
"dnsbl.inps.de",
"dnsbl.kempt.net",
"dnsbl.njabl.org",
"dnsbl.solid.net",
"dnsbl.sorbs.net",
"drone.abuse.ch",
"duinv.aupads.org",
"dul.ru",
"dyna.spamrats.com",
"dynip.rothen.com",
"forbidden.icm.edu.pl",
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
"rbl.interserver.net",
"rbl.orbitrbl.com",
"rbl.schulte.org",
"rdts.dnsbl.net.au",
"relays.bl.gweep.ca",
"relays.bl.kundenserver.de",
"relays.nether.net",
"residential.block.transip.nl",
"ricn.dnsbl.net.au",
"rmst.dnsbl.net.au",
"short.rbl.jp",
"spam.abuse.ch",
"spam.dnsbl.sorbs.net",
"spam.rbl.msrbl.net",
"spam.spamrats.com",
"spamguard.leadmon.net",
"spamlist.or.kr",
"spamrbl.imp.ch",
"spamsources.fabel.dk",
"spamtrap.drbl.drand.net",
"t3direct.dnsbl.net.au",
"tor.ahbl.org",
"tor.dnsbl.sectoor.de",
"torserver.tor.dnsbl.sectoor.de",
"ubl.lashback.com",
"ubl.unsubscore.com",
"virbl.bit.nl",
"virus.rbl.jp",
"virus.rbl.msrbl.net",
"wormrbl.imp.ch",
"zen.spamhaus.org",
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
            #grabs host from queue
            hostname,root_name = self.queue.get()

            check_host = "%s.%s" % (hostname, root_name)
            try:
                check_addr = socket.gethostbyname(check_host)
            except socket.error:
                check_addr = None
            if check_addr != None and "127.0.0." in check_addr:
                on_blacklist.append(root_name)

            #signals to queue job is done
            self.queue.task_done()

def usage(argv0):
    print "%s -w <WARN level> -c <CRIT level> -h <hostname>" % argv0
    print " or"
    print "%s -w <WARN level> -c <CRIT level> -a <ipv4 address>" % argv0

def main(argv, environ):
    options, remainder = getopt.getopt(argv[1:], "w:c:h:a:", ["warn=","crit=","host=","address="])
    status = { 'OK' : 0 , 'WARNING' : 1, 'CRITICAL' : 2 , 'UNKNOWN' : 3}
    host = None
    addr = None

    if 3 != len(options):
        usage (argv[0])
        sys.exit(status['UNKNOWN'])

    for field, val in options:
        if field in ('-w','--warn'):
            warn_limit = int(val)
        elif field in ('-c','--crit'):
            crit_limit = int(val)
        elif field in ('-h','--host'):
            host = val
        elif field in ('-a','--address'):
            addr = val
        else:
            usage (argv[0])
            sys.exit(status['UNKNOWN'])

    if host and addr:
        print "ERROR: Cannot use both host and address, choose one."
        sys.exit(status['UNKNOWN'])

    if host:
        try:
            addr = socket.gethostbyname(host)
        except:
            print "ERROR: Host '%s' not found - maybe try a FQDN?" % host
            sys.exit(status['UNKNOWN'])
    addr_parts = string.split(addr, '.')
    addr_parts.reverse()
    check_name = string.join(addr_parts, '.')
    # We set this to make sure the output is nice. It's not used except for the output after this point.
    host = addr

###### Thread stuff:

    #spawn a pool of threads, and pass them queue instance 
    for i in range(10):
        t = ThreadRBL(queue)
        t.setDaemon(True)
        t.start() 
   
    #populate queue with data
    for blhost in serverlist:
        queue.put((check_name,blhost))

    #wait on the queue until everything has been processed
    queue.join()

###### End Thread stuff
    
    warn=False
    if len(on_blacklist) >= warn_limit :
        warn = True

    crit=False
    if len(on_blacklist) >= crit_limit:
        crit = True
    if warn == True:
        if crit == True:
            print 'CRITICAL: %s on %s spam blacklists|%s' % (host,len(on_blacklist),on_blacklist)
            sys.exit(status['CRITICAL'])
        else:
            print 'WARNING: %s on spam blacklist %s' % (host,on_blacklist[0],)
            sys.exit(status['WARNING'])
    else:
        print 'OK: %s not on known spam blacklists' % host
        sys.exit(status['OK'])

if __name__ == "__main__":
    main (sys.argv, os.environ)
