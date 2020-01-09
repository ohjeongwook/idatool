import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import idatool.disassembly

if __name__ == '__main__':
    import logging

    logging.basicConfig(level = logging.DEBUG)
    logger = logging.getLogger(__name__)

    disasm = idatool.disassembly.Disasm()
    for (address, function_hash, sequence, type, value) in disasm.get_notations():
        print('%.8x: %s+%d %s %s' % (address, function_hash, sequence, type, value))

