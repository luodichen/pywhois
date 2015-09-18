#!encoding=utf-8

import sys
reload(sys)
sys.setdefaultencoding('utf-8')

from pywhois import PyWhois
from pywhois import WhoisServerNotFoundError

def main(argv):
    if len(argv) != 2:
        print 'Usage: %s <domain name>' % (argv[0], )
        exit(0)
    
    try:
        domain_name = argv[1].decode(sys.stdin.encoding).encode('utf-8')
        result = PyWhois().getwhois(domain_name)
        print result.decode('utf-8', 'replace').encode(sys.stdin.encoding, 'replace')
    except WhoisServerNotFoundError:
        print 'Whois server not found.'
        exit(0)
    except Exception, e:
        print 'Error: ' + str(e)
        exit(1)
    
if __name__ == '__main__':
    main(sys.argv)
