'''
Created on Sep 17, 2015

@author: luodichen
'''

import re
import os, sys, inspect
import socket
import xml.etree.ElementTree as et

def current_file_directory():
    path = os.path.realpath(sys.path[0])        # interpreter starter's path
    if os.path.isfile(path):                    # starter is excutable file
        path = os.path.dirname(path)
        return os.path.abspath(path)            # return excutable file's directory
    else:                                       # starter is python script
        caller_file = inspect.stack()[1][1]     # function caller's filename
        return os.path.abspath(os.path.dirname(caller_file))# return function caller's file's directory
        
class WhoisServerNotFoundError(Exception):
    pass

class ServerList(object):
    def __init__(self, file_path=current_file_directory() \
                 + os.sep + 'whois-server-list.xml'):
        self.dom_root = et.parse(file_path).getroot()
        
    def whois_server(self, domain_name):
        ret = None
        domains = domain_name.split('.')[::-1]
        target = ''
        cur = self.dom_root
        
        for i in xrange(len(domains)):
            target = (domains[i] if 0 == i else ('.' + domains[i])) + target
            
            cur = cur.find("./domain[@name='%s']/whoisServer/.." % (target, ))
            if cur is None:
                break
            else:
                ret = cur.find("./whoisServer").attrib['host']
        
        return ret

class PyWhois(object):
    MULTI_RECORD_PATT = 'To single out one record, look it up with "xxx", ' + \
                        'where xxx is one of the\\s+records displayed above\\. ' + \
                        'If the records are the same, look them up\\s+' + \
                        'with "=xxx" to receive a full display for each record\\.'

    REDIRECT_PATT = r'Domain names in the \.com and \.net domains can now ' + \
                    r'be registered\s+with many different competing ' + \
                    r'registrars\. Go to http://www\.internic\.net\s+for ' + \
                    r'detailed information\..*\s*Domain Name:.*\s+' + \
                    r'Whois Server:\s+(.+?)\s+'

    def __init__(self, server_list=None):
        if server_list is None:
            self.servers = ServerList()
        else:
            self.servers = ServerList(server_list)
            
    def query(self, domain_name, server):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server, 43, ))
        s.send(domain_name + '\r\n')
        
        result = ''
        while True:
            buf = s.recv(1024)
            if len(buf) > 0:
                result += buf
            else:
                s.close()
                break
        
        return result
    '''
            ret = result
            redirect = result.find('Domain names in the .com and .net domains '
                                   + 'can now be registered\nwith many different '
                                   + 'competing registrars. '
                                   + 'Go to http://www.internic.net\nfor '
                                   + 'detailed information.')
            
            match = re.search(r'^\s*Whois Server:\s+(.+)$', result, re.M)
            server = None if match is None or redirect == -1 else match.groups()[0]
        
        return ret
    '''
   
    def getwhois(self, domain_name):
        original_domain_name = domain_name
        server = self.servers.whois_server(domain_name)
        if server is None:
            raise WhoisServerNotFoundError()

        ret = None
        
        while True:
            response = self.query(domain_name, server)
            multi_record = re.search(self.MULTI_RECORD_PATT, response)
            redirect = re.search(self.REDIRECT_PATT, response, re.S)
            if multi_record:
                domain_name = '=' + original_domain_name
            elif redirect:
                domain_name = original_domain_name
                server = redirect.groups()[0]
            else:
                ret = response
                break
        
        return ret
