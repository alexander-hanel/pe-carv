# Name: 
#    pe-carv.py
# Version: 
#    0.2
# Description: 
#    This script can be used to carve out portable executable files from a data stream.
#    It relies on pefile by Ero Carrera parse the portable executable format and calculate 
#    the file size. This script will not account for the size of  file overlays (data 
#    . appended to the end of the file).
#          
# Author
#    alexander<dot>hanel<at>gmail<dot>com

import re
import sys
import imp 
try:
    imp.find_module('pefile')
    import pefile
except ImportError as error:
    print '\t[IMPORT ERROR] %s - aborting' % error
    sys.exit()

class CARVER():
    def __init__(self):
        self.args = sys.argv
        self.argumentCheck()
        self.readStream()
        self.carve()
        
    def argumentCheck(self):
        if len(self.args) < 2:
            print "\t[USAGE] pe-carv.py <file-stream>"
            sys.exit()
    
    def readStream(self):
        try:
            self.fileH = open(sys.argv[1], "rb")
        except:
            print '\t[FILE ERROR] could not access file: %s' % sys.argv[1]
            sys.exit()
      
    def getExt(self, pe):
        if pe.is_dll() == True:
            return 'dll'
        if pe.is_driver() == True:
            return 'sys'
        if pe.is_exe() == True:
            return 'exe'
        else:
            return 'bin'
            
    def writeFile(self, count, ext, pe):
        try:
            out  = open(str(count)+ '.' + ext, 'wb')
        except:
            print '\t[FILE ERROR] could not write file'
            sys.exit()
        # remove overlay or junk in the trunk
        out.write(pe.trim())
        out.close()

    def carve(self):
        c = 1
        # For each address that contains MZ
        for y in [tmp.start() for tmp in re.finditer('\x4d\x5a',self.fileH.read())]:
            self.fileH.seek(y)
            try:
                pe = pefile.PE(data=self.fileH.read())
            except:
                continue 
            # determine file ext
            ext = self.getExt(pe)
            print '\t*', ext , 'found at offset', hex(y) 
            self.writeFile(c,ext,pe)
            c += 1
            ext = ''
            self.fileH.seek(0)
            pe.close()
            
if __name__== '__main__':
    CARVER()
    