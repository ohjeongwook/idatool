import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import pprint

import windbgtool.command
import windbgtool.breakpoints_storage
import idatool.ui

class Util:
    def __init__(self):
        self.Disasm = idatool.disassembly()
        self.Lines = []
        self.Breakpoints = []

    def add(self, range_str = '', type = ""):
        filter = self.Disasm.get_filter(type)

        command_generator = windbgtool.command.Generator(
                                                self.Disasm.ImageBase, 
                                                self.Disasm.ImageBase
                                            )

        if range_str == 'FunctionTree':
            for (func_name, instructions) in self.Disasm.get_function_tree_instructions(filter = filter).items():
                for line in command_generator.GenerateCommandsForInstructions(instructions, func_name = func_name):
                    print(line)
        else:
            instructions = self.Disasm.get_instructions(filter = filter)
            self.Breakpoints += instructions

    def add_functions(self):
        patterns = ['LocalAlloc', 'OutputDebugString', 'FreeStructure', 
                  'memset', 'LocalFree', 'DecodeString', 'MultiByte', 'memcpy', 
                  'LoadLibraryA', 'GetProcAddress', 'lstrcpyW', 'ResolveAPI', '__alloca_probe'
                 ]

        for function in self.Disasm.get_functions():
            name = function['Name']
            bp = True
            for pattern in patterns:
                if name.find(pattern) >= 0:
                    bp = False
                    break

            if not bp:
                continue

            self.idatool.breakpoints.append(function)

    def add_current_instruction(self):
        ea = idatool.util.Area.get_selection_start()
        instruction = self.Disasm.get_instruction(ea)        
        pprint.pprint(instruction)
        self.idatool.breakpoints.append(instruction)

    def save(self, filename = ''):
        if not filename:
            if len(self.Disasm.Args)>0:
                filename = self.Disasm.Args[0]

            if not filename:
                form = ui.Form('Breakpoints-UI')
                form.show()
                filename = form.ask_save_filename("DB (*.db);;Command (*.txt)")

        if filename:
            print('Saving breakpoints to ' + filename)

            if filename.endswith('.db'):
                module_name = self.Disasm.get_base_filename()
                stoage = windbgtool.breakpoints_storage.Storage(filename, module_name = module_name)
                stoage.save(self.Breakpoints)

            elif filename.endswith('.txt'):
                command_generator = windbgtool.command.Generator(
                                                self.Disasm.ImageBase, 
                                                self.Disasm.ImageBase
                                            )

                command_generator.SaveBreakpoints(filename, self.Breakpoints)

    def exit(self):
        self.Disasm.exit()

if __name__ == '__main__':
    import logging

    logging.basicConfig(level = logging.DEBUG)
    logger = logging.getLogger(__name__)

    breakpoints = Util()
    breakpoints.add("All", "IndirectCall")
