#!encoding=utf-8

import sys
reload(sys)
sys.setdefaultencoding('utf-8')

from pywhois import PyWhois

def main(argv):
    if len(argv) != 2:
        print 'Usage: %s <domain name>' % (argv[0], )
        exit(0)
        
    domain_name = argv[1].decode(sys.stdin.encoding).encode('utf-8')
    result = PyWhois().getwhois(domain_name)
    print result.decode('utf-8', 'replace').encode(sys.stdin.encoding, 'replace')
    
if __name__ == '__main__':
    main(sys.argv)
