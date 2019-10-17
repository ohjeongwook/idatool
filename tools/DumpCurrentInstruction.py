import sys
import os
import pprint
import logging
import json

import idatool.disassembly
import windbgtool.command

logging.basicConfig(level = logging.DEBUG)
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    disasm = idatool.disassembly.Disasm()
    ea = idatool.util.Area.GetSelectionStart()
    instruction = disasm.GetInstruction(ea)
    
    pprint.pprint(instruction)
    disasm.Exit()
