import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import pprint
import logging
import json

import idatool.disassembly
import windbgtool.command

logging.basicConfig(level = logging.DEBUG)
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    disasm = idatool.disassembly.Disasm()
    for (address, function_hash, sequence, type, value) in disasm.GetNotations():
        print '%.8x: %s+%d %s %s' % (address, function_hash, sequence, type, value)

