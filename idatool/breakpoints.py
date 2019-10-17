import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import pprint

import windbgtool.command
import windbgtool.breakpoints_storage
import idatool.ui

class Util:
    def __init__(self, ida_disasm = None):
        if ida_disasm != None:
            self.IDADisasm = ida_disasm
        else:
            self.IDADisasm = idatool.disassembly()

        self.Lines = []
        self.Breakpoints = []

    def Add(self, range_str = '', type = ""):
        filter = self.IDADisasm.GetFilter(type)

        command_generator = windbgtool.command.Generator(
                                                self.IDADisasm.ImageBase, 
                                                self.IDADisasm.ImageBase
                                            )

        if range_str == 'FunctionTree':
            for (func_name, instructions) in self.IDADisasm.GetFunctionTreeInstructions(filter = filter).items():
                for line in command_generator.GenerateCommandsForInstructions(instructions, func_name = func_name):
                    print line
        else:
            instructions = self.IDADisasm.GetInstructions(filter = filter)
            self.Breakpoints += instructions

    def AddFunctions(self):
        patterns = ['LocalAlloc', 'OutputDebugString', 'FreeStructure', 
                  'memset', 'LocalFree', 'DecodeString', 'MultiByte', 'memcpy', 
                  'LoadLibraryA', 'GetProcAddress', 'lstrcpyW', 'ResolveAPI', '__alloca_probe'
                 ]

        for function in self.IDADisasm.GetFunctions():
            name = function['Name']
            bp = True
            for pattern in patterns:
                if name.find(pattern) >= 0:
                    bp = False
                    break

            if not bp:
                continue

            self.idatool.breakpoints.append(function)

    def AddCurrentInstruction(self):
        ea = idatool.util.Area.GetSelectionStart()
        instruction = self.IDADisasm.GetInstruction(ea)        
        pprint.pprint(instruction)
        self.idatool.breakpoints.append(instruction)

    def Save(self, filename = ''):
        if not filename:
            if len(self.IDADisasm.Args)>0:
                filename = self.IDADisasm.Args[0]

            if not filename:
                form = ui.Form('Breakpoints-UI')
                form.Show()
                filename = form.AskSaveFileName("DB (*.db);;Command (*.txt)")

        if filename:
            print 'Saving breakpoints to', filename

            if filename.endswith('.db'):
                module_name = self.IDADisasm.GetFileBasename()
                stoage = windbgtool.breakpoints_storage.Storage(filename, module_name = module_name)
                stoage.Save(self.Breakpoints)

            elif filename.endswith('.txt'):
                command_generator = windbgtool.command.Generator(
                                                self.IDADisasm.ImageBase, 
                                                self.IDADisasm.ImageBase
                                            )

                command_generator.SaveBreakpoints(filename, self.Breakpoints)

    def Exit(self):
        self.IDADisasm.Exit()

if __name__ == '__main__':
    import logging

    logging.basicConfig(level = logging.DEBUG)
    logger = logging.getLogger(__name__)

    breakpoints = Util()
    breakpoints.Add("All", "IndirectCall")
