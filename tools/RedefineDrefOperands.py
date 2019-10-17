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

    for (instruction, imm_operands) in disasm.FindImmediateSegmentsRefs():    
        print(disasm.GetInstructionText(instruction))
        for imm_operand in imm_operands:
            print('\t%.8x' % imm_operand)
            drefs = disasm.GetDREFTo(imm_operand)
            for dref in drefs:
                print('\t\tdref: %.8x' % dref)
                
            if len(drefs) == 0:
                disasm.Redefine(imm_operand, 1, type = 'Data')
        disasm.Redefine(instruction['Address'], instruction['Size'], type = 'Code')

    disasm.Exit()
