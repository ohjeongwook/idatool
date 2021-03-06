import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import json
import sqlite3
import base64

import idatool.disassembly

class Hunter:
    Debug = 0
    def __init__(self, log_filename = ''):
        self.Disasm = idatool.disassembly.Disasm()
        self.open_log(log_filename)        
        self.Matches = {}

    def open_log(self, log_filename):
        if log_filename:
            self.fd = open(log_filename, 'w')
        else:
            self.fd = None

    def write_log(self, line):
        if self.fd != None:
            self.fd.write(line+'\n')
        else:
            print(line)

    def close(self):
        if self.fd != None:
            self.fd.close()
        self.Disasm.exit()

    def find_loops(self):
        for loop in self.Disasm.find_loops():
            for loop in loop['Loops']:
                print('\t' + self.Disasm.dump_paths(loop))
                block_instructions = []
                for block_start in loop:
                    for instruction in self.Disasm.get_block_instructions(block_start):
                        print('\t\t' + self.Disasm.get_instructionText(instruction))
                        block_instructions.append(instruction)
                self.add_instructions(block_instructions)
        
    def add_instructions(self, block_instructions, max_call_instruction_cnt = 0):
        call_instruction_cnt = 0
        block_bytes = ''
        for block_instruction in block_instructions:
            bytes = self.Disasm.get_instruction_bytes(block_instruction['Address'])
            block_instruction['Bytes'] = base64.b64encode(bytes)
            block_bytes += bytes
            if block_instruction['Op'] == 'call':
                call_instruction_cnt += 1
            
        if call_instruction_cnt>max_call_instruction_cnt:
            return

        block_hash = self.Disasm.get_instructions_hash(block_instructions)
        
        if not block_hash in self.Matches:
            self.Matches[block_hash] = {}
        
        if not yara_match_str in self.Matches[block_hash]:
            self.Matches[block_hash][yara_match_str] = []
            
        self.Matches[block_hash][yara_match_str].append(block_instructions)
    
    def find_encoding_instructions(self):
        min = 0xffff
        black_list = [0x40000000, 0x4000, 0xffffffff, 0xFFFFFFF6, 0x0FFFFFFFE, 0xcccccccc, 0x400000, 0x80000000, 0x7FFFFFFF, 0x7EFEFEFF]

        self.Matches = {}
        for instruction in self.Disasm.get_all_instructions(filter = {'Op': ['xor', 'add', 'mov', 'sub', 'imul', 'mul'], 'Target': 'Immediate'}):
            drefs = idatool.util.Refs.get_dref_from(instruction['Address'])
            if len(drefs) == 0:
                found_interesting_immediate_value = False
                for operand in instruction['Operands']:
                    if operand['Type'] == 'Immediate' and operand['Value']>min and not operand['Value'] in black_list:
                        found_interesting_immediate_value = True
                        break

                if found_interesting_immediate_value:
                    self.add_instructions(self.Disasm.get_block_instructions(instruction['Address']))

    def save(self, db_filename = ''):
        if not db_filename:
            db_filename = self.Disasm.Options.db_filename
        
        try:
            conn = sqlite3.connect(db_filename)
        except:
            return

        conn.text_factory = str

        c = conn.cursor()

        create_table_sql = """CREATE TABLE
                            IF NOT EXISTS BlockInformation (
                                id integer PRIMARY KEY, 
                                FileName text, 
                                FileHash text, 
                                FunctionName text, 
                                BlockStart Integer, 
                                BlockEnd Integer, 
                                BlockHashType text, 
                                BlockHash text, 
                                YaraMatches text, 
                                InstructionText text, 
                                unique (FileName, FileHash, FunctionName, BlockStart, BlockEnd, BlockHashType, BlockHash, YaraMatches, InstructionText)
                            );"""

        c.execute(create_table_sql)

        file_name = self.Disasm.get_base_filename()
        file_hash = self.Disasm.get_file_hash()

        for (block_hash, block_hash_items) in self.Matches.items():
            self.write_log('Block Hash: %s' % (block_hash))

            for (yara_match_str, block_instructions_list) in block_hash_items.items():
                self.write_log('\tYara Match: %s' % (yara_match_str))
                for block_instructions in block_instructions_list:
                    if len(block_instructions) == 0:
                        continue

                    block_start = block_instructions[0]['Address']
                    block_end = block_instructions[-1]['Address']

                    function_name = self.Disasm.get_function_name(block_start)
                    self.write_log('\t\tFuction: %s' % (function_name))
                    
                    for block_instruction in block_instructions:
                        instruction_line = self.Disasm.get_instructionText(block_instruction, include_bytes = True)+'\n'
                        self.write_log('\t\t\t%s' % instruction_line)

                    try:
                        c.execute('INSERT INTO BlockInformation (FileName, FileHash, FunctionName, BlockStart, BlockEnd, BlockHashType, BlockHash, YaraMatches, InstructionText) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', 
                                (
                                    file_name, file_hash, function_name, block_start, 
                                    block_end, '', block_hash, yara_match_str, json.dumps(block_instructions)
                                )
                            )
                    except:
                        pass

        conn.commit()
        conn.close()
