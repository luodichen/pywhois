#!encoding=utf-8

import sys
reload(sys)
sys.setdefaultencoding('utf-8')

from pywhois import PyWhois

def main(argv):
    if len(argv) != 2:
        print 'Usage: %s <domain name>' % (argv[0], )
        exit(0)
        
    print PyWhois().getwhois(argv[1])
    
if __name__ == '__main__':
    main(sys.argv)
