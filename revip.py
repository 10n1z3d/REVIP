#!/usr/bin/env python
#
# REVIP (Reverse IP) - Simple reverse IP lookup tool using the Bing API.
#
# Copyright (C) 2010 10n1z3d <10n1z3d[at]w[dot]cn>
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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import sys
import socket
from urllib2 import urlopen
from xml.dom import minidom
from optparse import OptionParser

__version__ = '0.1'

BING_APP_ID = 'C2B36F733D8DCB48CE2E075CC145014122BE4724'

def header():
    print '\t _____ _____ _____ _____ _____ '
    print '\t| __  |   __|  |  |     |  _  |'
    print '\t|    -|   __|  |  |-   -|   __|'
    print '\t|__|__|_____|\___/|_____|__|   '
    print '\t       Reverse IP lookup       '
    print '\t         Version: {0}          '.format(__version__)
    print '\t      10n1z3d[at]w[dot]cn    \n'

def usage():
    print 'Usage: python revip.py <ip/host> [options]'
    print 'Options:'
    print '      -o, --output_file=<filename>   Specify output file name'

def get_ip_address(host):
    '''Gets IP addres of url.'''
    if not re.match('\d+\.\d+\.\d+\.\d+', host):
        if not host.startswith('www.'):
            host = 'www.{0}'.format(host)
        try:
            return socket.gethostbyname(host)
        except:
            return None

    return host


def parse_options():
    '''Parses the command line options.'''
    try:
        host = sys.argv[1]
        parser = OptionParser(add_help_option=False)
        parser.add_option('-h', '--help', action='store_true',
                          dest='help', default=False)
        parser.add_option('-o', '--output_file', dest="output_file",
                          default=None)

        (options, args) = parser.parse_args()

        return (host, options.help, options.output_file)
    except:
        header()
        usage()
        exit(2)

def bing_ip_search(ip_addr, index=0):
    results = []
    req_url = ('http://api.search.live.net/xml.aspx?Appid={0}&query=ip:{1}' \
               '&sources=web&market=en-us&web.count=50&web.offset={2}')

    try:
        handle = urlopen(req_url.format(BING_APP_ID, ip_addr, index))
        xml = minidom.parse(handle)
    except:
        print '[-] Error. Cannot parse any results.'
        print '[-] Quitting...\n'
        exit(0)

    for node in xml.getElementsByTagName('web:Url'):
        temp = node.childNodes[0].data

        if not re.match('\d+\.\d+\.\d+\.\d+', temp):
            host = temp.split('/')[2]
            if not host in results:
                results.append(host)

    return results

def main():
    (host, help, output_file) = parse_options()

    header()
    if help: usage(); exit(0)
    ip_addr = get_ip_address(host)

    if ip_addr:
        print '[+] Looking for domains associated with "{0}"...'.format(ip_addr)
        
        results = bing_ip_search(ip_addr)
        res_count = len(results)

        if res_count > 0:
            print '[+] Results found:\n'

            for result in results:
                print '\t{0}'.format(result)
                
            print '\n[+] Total results: {0}'.format(res_count)
            
            if output_file:
                print '[+] Writing the results to "{0}"...'.format(output_file)

                with open(output_file, 'a') as output:
                    for result in results:
                        output.write(result + '\n')
        else:
            print '[-] No results found.'
            
        print '[+] Done.\n'
        exit(0)
    else:
        print '[-] Cannot parse the ip/host!'
        print '[-] Quitting...\n'
        exit(0)
            
if __name__ == "__main__":
    main()
