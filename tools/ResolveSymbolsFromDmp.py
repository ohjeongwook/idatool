import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import struct

import idatool.disassembly
import idatool.util
import windbgtool.debugger

class Util:
    def __init__(self, filename = r''):
        self.Disasm = idatool.disassembly.Disasm()
        self.debugger = windbgtool.debugger.Debugger(dump_file = filename)
        self.debugger.SetSymbolPath()

    def FindAddrBytes(self, type = ""):
        for addr in self.Disasm.Addresses(4):
            bytes = self.Disasm.DumpBytes(addr, 4)
            if bytes != None and len(bytes) == 4:
                (dword, ) = struct.unpack("<L", bytes)
                if dword>0:
                    symbol = self.debugger.ResolveSymbol(dword)
                    if symbol and symbol.find('+')<0:
                        self.Disasm.Redefine(addr, 4, 'data', data_type = 'DWORD')
                        idatool.util.Cmt.Set(addr, symbol, 1)
                        name = symbol.split('!')[1]
                        self.Disasm.SetName(addr, name)
                        print('%.8x %.8x %s' % (addr, dword, symbol))
            
if __name__ == '__main__':
    import logging
    import idatool.ui

    logging.basicConfig(level = logging.DEBUG)
    logger = logging.getLogger(__name__)    
   
    if not os.path.isfile(filename):
        title = 'ResolveSymbol'
        try:
            form.OnClose(form)
            form = idatool.ui.Form(title)
        except:
            form = idatool.ui.Form(title)

        form.Show()

        filename = form.AskOpenFileName("DMP (*.dmp)")

    if filename:
        util = Util(filename = filename)
        util.FindAddrBytes()
