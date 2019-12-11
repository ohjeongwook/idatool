import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import idatool.disassembly

if __name__ == '__main__':
    import logging

    logging.basicConfig(level = logging.DEBUG)
    logger = logging.getLogger(__name__)

    disasm = idatool.disassembly.Disasm()

    for (instruction, imm_operands) in disasm.find_immediate_segments_references():    
        print(disasm.get_instructionText(instruction))
        for imm_operand in imm_operands:
            print('\t%.8x' % imm_operand)
            drefs = disasm.get_dref_to(imm_operand)
            for dref in drefs:
                print('\t\tdref: %.8x' % dref)
                
            if len(drefs) == 0:
                disasm.redefine(imm_operand, 1, type = 'Data')
        disasm.redefine(instruction['Address'], instruction['Size'], type = 'Code')

    disasm.exit()
