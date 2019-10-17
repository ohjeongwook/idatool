import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import pprint
import logging
import json

import idatool.disassembly

logging.basicConfig(level = logging.DEBUG)
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    disasm = idatool.disassembly.Disasm()
    ea = idatool.util.Area.GetSelectionStart()
    instruction = disasm.GetInstruction(ea)
    
    pprint.pprint(instruction)
    disasm.Exit()
