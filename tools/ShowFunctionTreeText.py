import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import idatool.disassembly
import idatool.util

disasm = idatool.disassembly.Disasm()
(function_list, function_instructions) = disasm.get_function_tree(threshold = 10000)
for (level, name, address, caller_address) in function_list:
    cmt = idatool.util.Cmt.get(caller_address)
    print('%s%s ( %.8x ) @ %.8x ; %s' % ('    '*level, name, address, caller_address, cmt))
