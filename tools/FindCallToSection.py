import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import logging

import idatool.disassembly

if __name__ == '__main__':
    logging.basicConfig(level = logging.DEBUG)
    logger = logging.getLogger(__name__)
    disasm = idatool.disassembly.Disasm()
    disasm.GetInstructionsByType("All", "CallToSection")
