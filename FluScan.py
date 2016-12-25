#!/usr/bin/python

#import re
import socket

import sys

import pygeoip

from Ports import getcommonports

def geo(_file, _ip):
    ''' This function search the geolocation values of an IP address '''
    geoDb = pygeoip.GeoIP(_file)
    ip_dictionary_values = geoDb.record_by_addr(_ip)
    ip_list_values = ip_dictionary_values.items()
    print "*******************"
    print "*** Geolocation ***"
    print "*******************"
    for value in ip_list_values:
        print str(value[0]) + ": " + str(value[1])

def hosts(_ip):
    ''' This function search the hostnames '''
    print "\n*******************"
    print "***    Hosts    ***"
    print "*******************"
    try:
        hosts_values = socket.gethostbyaddr(_ip)
        print hosts_values

        #hosts_values = socket.gethostbyname(_ip)
        #print "gethostbyname --> ", hosts_values
        
        """
        hosts_values = socket.gethostbyaddr(_ip)
        print hosts_values
        print str(hosts_values[0])
        """
        
    except:
        print 'No hosts associate'

def portscan(_host, _port):
    ''' This function execute a port scan '''
    banner = ''
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #sock.settimeout(0.10)
        sock.settimeout(0.25)
        result = sock.connect_ex((_host, _port))
        sock.send('GET HTTP/1.1 \r\n')
        banner = sock.recv(1024)
        sock.close()
    except:
        pass
    return result, banner

def ports(_ip):
    ''' This function search open ports '''
    common_ports = getcommonports()
    print "\n"
    print "*******************"
    print "***    Ports    ***"
    print "*******************"
    for value in common_ports:
        banner_exists, banner = portscan(_ip, value)
        if not banner_exists:
            print 'Port: [' + str(value) + '] Protocol: [' + str(common_ports[value]) + ']'
            print 'Banner: [' + str(banner) + ']'
            print ''

def ip_order(_ip1, _ip2):
    _ip1_split = _ip1.split('.')
    _ip2_split = _ip2.split('.')

    for i in range(0, 4):
        if _ip2_split[i] < _ip1_split[i]:
            return _ip1, _ip2
        elif _ip2_split[i] > _ip1_split[i]:
            return _ip2, _ip1
        
        return _ip2, _ip1


def ip_add(_ip):
    _ip_split = _ip.split('.')

    if int(_ip_split[3]) < 255:
        return "%s.%s.%s.%d" % (_ip_split[0], _ip_split[1], _ip_split[2], int(_ip_split[3])+1)
    elif int(_ip_split[2]) < 255:
        return "%s.%s.%d.%d" % (_ip_split[0], _ip_split[1], int(_ip_split[2])+1, 0)
    elif int(_ip_split[1]) < 255:
        return "%s.%d.%d.%d" % (_ip_split[0], int(_ip_split[1])+1, 0, 0)
    elif int(_ip_split[0]) < 255:
        return "%d.%d.%d.%d" % (int(_ip_split[0])+1, 0, 0, 0)
    else:
        return _ip

def main(_ip1,_ip2):
    ''' Main function, launch the main activities '''
    ''' You can download GeoIP databases from here: https://dev.maxmind.com/geoip/legacy/geolite '''

    if _ip1 == _ip2:
        print "************************"
        print " IP: %s" % (_ip1)
        print "************************"

        # Extract geolocation values
        geo('GeoIP/GeoLiteCity.dat', _ip1)
        hosts(_ip1)
        ports(_ip1)
    else:
        _ip3 = _ip1 
        _ip2 = ip_add(_ip2)
        
        while _ip3 <> _ip2:
            print "************************"
            print " IP: %s" % (_ip3)
            print "************************"

            # Extract geolocation values
            geo('GeoIP/GeoLiteCity.dat', _ip3)
            hosts(_ip3)
            ports(_ip3)

            _ip3 = ip_add(_ip3)

if __name__ == "__main__":
    print 'FluScan, an IPv4 scanner. Created by http://www.flu-project.com\n'
    # main('8.8.8.8')
    # main('195.55.73.115') # www.asmred.com
    #main('82.223.52.25') # es.asmred.com
    #main('37.152.88.9') # elbitseguro.com 

    ip1 = '37.152.88.9'
    ip2 = '37.152.88.9'

    ip2, ip1 = ip_order(ip1, ip2)

    main(ip1, ip2)