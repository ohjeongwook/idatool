import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from collections import *
import copy
import logging

from idaapi import *
from idautils import *
from idc import *
import idc

from optparse import OptionParser, Option

import idatool.util

class Block:
    DebugLevel = 0
    def __init__(self, addr = None):
        self.logger = logging.getLogger(__name__)

        if addr == None:
            self.Address = idatool.util.Area.get_selection_start()
        else:
            self.Address = addr
        self.Blocks = []
        self.BlockRangeMap = {}
        self.BlockInstructions = {}
        self.CurrentBlock = self.__get_block_start(self.Address)
        self.__get_previous_block_map()

    def get_block_bytes(self, ea):
        bytes = GetManyBytes(ea, self.BlockRangeMap[ea]-ea)
        return bytes

    def get_instruction_bytes(self, ea):
        if ea in self.BlockInstructions:
            instructions = self.BlockInstructions[ea]
            instructions.reverse()
            return instructions
        return []

    def __get_block_start(self, ea, prefix = ''):
        start_ea = ea
        
        self.logger.debug(prefix+'__get_block_start: %x', ea)
        instructions = []
        while 1:
            ea_size = get_item_size(ea)
            instructions.append((ea, GetManyBytes(ea, ea_size)))
            if idatool.util.Refs.get_jump_cref_to(ea) != 1:
                break

            if len(idatool.util.Refs.get_jump_cref_from(prev_list[0])) != 1:
                break

            prev_ea = prev_list[0]
            ea = prev_ea
            
            self.logger.debug(prefix+'\t%x', ea)

        self.BlockRangeMap[ea] = start_ea+get_item_size(start_ea)
        instructions.reverse()
        self.BlockInstructions[ea] = instructions
        return ea

    def __get_previous_blocks(self, bb, prefix = ''):
        prev_bbs = []
        
        self.logger.debug(prefix+'FindPrevBBs: %x', bb)
        for (cref_type, cref) in idatool.util.Refs.get_cref_to(bb):
            if cref_type != 'Call':
                prev_bbs.append(self.__get_block_start(prev_ea, prefix+'\t'))
            
        return prev_bbs

    def __get_previous_block_map(self):
        bb_list = [self.CurrentBlock]
        bb_map = {self.CurrentBlock:1}
        self.RevMap = {}
        self.Map = {}
        for bb in bb_list:
            prev_bb_list = self.__get_previous_blocks(bb)
            self.RevMap[bb] = prev_bb_list
            for src in prev_bb_list:
                if not src in self.Map:
                    self.Map[src] = []
                self.Map[src].append(bb)
            for prev_bb in prev_bb_list:                
                if not prev_bb in bb_map:
                    bb_list.append(prev_bb)
                    bb_map[prev_bb] = 1

        self.Blocks = bb_map.keys()
        
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug('self.Blocks: %x', bb)
            for bb in self.Blocks:
                self.logger.debug('\t%x', bb)
            self.logger.debug('')

    def __traverse_block(self, block, map, blocks, level = 0):
        prefix = '\t'*level
        
        self.logger.debug(prefix+'%x', block)
        paths = []
        blocks.append(block)
        if block in map:
            for prev_block in map[block]:
                if prev_block in blocks:
                    continue
                paths += self.__traverse_block(prev_block, map, copy.deepcopy(blocks), level+1)

        if len(paths) == 0:
            paths.append(blocks)

        return paths

    def get_block_paths(self):
        blocks = []
        paths = self.__traverse_block(self.CurrentBlock, self.RevMap, blocks)
        return paths
        
    def get_bytes(self, blocks):
        bytes_list = []
        for block in blocks:
            bytes_list.append((block, self.get_block_bytes(block)))

        return bytes_list
    
    def dump_blocks(self, blocks, sep = ' '):
        line = ''
        for block in blocks:
            if line != '':
                line += sep
            line += '%x' % block
        return line
        
    def get_root_blocks(self):
        roots = []

        for target in self.RevMap.keys():
            self.logger.debug('target: %x', target)
            if len(self.RevMap[target]) == 0:
                roots.append(target)

            if self.logger.isEnabledFor(logging.DEBUG):
                for src in self.RevMap[target]:
                    self.logger.debug('\tsrc: %x (rev key: %d)', src, src in self.RevMap)

        if len(roots)>1:
            children = {}
            for root in roots:
                for child in self.Map[root]:
                    children[child] = 1
                    
            if len(children) == 1:
                roots = children

        return roots

    def get_function_name(self, demangle = True):    
        for root in self.get_root_blocks():
            return idatool.util.Function.get_name(root, demangle = demangle)