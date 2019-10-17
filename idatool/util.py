import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import pprint
import math
import json
import hashlib
import re
import copy
import logging
import sqlite3

from idaapi import *
from idautils import *
from idc import *
import idc

class Area:
    @staticmethod
    def GetSelection():
        (selection, start, end) = read_selection()
        start = get_screen_ea()
        end = start+1
        return (start, end)

    @staticmethod
    def GetSelectionStart():
        (ea, end) = Area.GetSelection()
        return ea

class Function:
    @staticmethod
    def GetAddress(ea = None):
        if ea == None:
            ea = Area.GetSelectionStart()

        func = get_func(ea)

        if func:
            return func.startEA
        else:
            return -1

    @staticmethod
    def GetName(ea, demangle = True):
        name = get_func_name(ea)
        demangled_name = idc.Demangle(name, idc.GetLongPrm(idc.INF_SHORT_DN))
        
        if demangled_name == None:
            return name
        else:
            return demangled_name

class Name:
    @staticmethod
    def GetName(current_address):
        return get_true_name(current_address)

    @staticmethod
    def SetName(ea, name):
        set_name(ea, str(name))

    @staticmethod
    def IsReserved(name):
        if name.startswith("sub_") or \
            name.startswith("loc_") or \
            name.startswith("locret_") or \
            name.startswith("dword_") or \
            name.startswith("word_") or \
            name.startswith("unknown_") or \
            name.startswith("unk_") or \
            name.startswith("dbl_") or \
            name.startswith("stru_") or \
            name.startswith("byte_") or \
            name.startswith("asc_") or \
            name.startswith("xmmword_") or \
            name.startswith("off_"):
            return True
        return False

class Seg:
    @staticmethod
    def GetName(addr):
        for i in range(0, get_segm_qty(), 1):
            seg = getnseg(i)
            seg_name = get_segm_name(seg.startEA)
            if seg.startEA <= addr and addr <= seg.endEA:
                return seg_name
        return ''        

class Cmt:
    @staticmethod
    def Set(ea, cmt, flag = 0):
        set_cmt(ea, str(cmt), flag)

    @staticmethod        
    def Get(current_address, get_repeatable_cmt = False):
        if not has_cmt(current_address):
            return None

        if get_repeatable_cmt:
            flag = 1    
        else:
            flag = 0

        return get_cmt(current_address, flag)

class Refs:
    @staticmethod
    def GetItemSize(ea):
        return get_item_size(ea)

    @staticmethod
    def GetNextItem(ea):
        return ea+get_item_size(ea)

    @staticmethod
    def GetCREFFrom(ea):
        refs = []
        ref = get_first_cref_from(ea)
        while ref != BADADDR:           
            if ea+get_item_size(ea) == ref:
                refs.append(('Next', ref))
            else:
                decode_insn(ea)
                if cmd.get_canon_feature() & CF_CALL:
                    refs.append(('Call', ref))
                else:
                    refs.append(('Jmp', ref))

            ref = get_next_cref_from(ea, ref)
        return refs
        
    @staticmethod
    def GetJMPCREFFrom(ea):
        jmp_crefs = 0
        for (cref_type, cref) in Refs.GetCREFFrom(ea):
            if cref_type == 'Jmp':
                jmp_crefs.append(cref)
        return jmp_crefs

    @staticmethod
    def GetCREFTo(ea):
        refs = []
        ref = get_first_cref_to(ea)
        while ref != BADADDR:
            if ref+get_item_size(ref) == ea:
                refs.append(('Next', ref))
            else:
                decode_insn(ref)
                if cmd.get_canon_feature() & CF_CALL:
                    refs.append(('Call', ref))
                else:
                    refs.append(('Jmp', ref))
            ref = get_next_cref_to(ea, ref)

        return refs

    @staticmethod
    def GetJMPCREFTo(ea):
        jmp_crefs = 0
        for (cref_type, cref) in self.GetCREFTo(ea):
            if cref_type == 'Jmp':
                jmp_crefs.append(cref)
        return jmp_crefs

    @staticmethod
    def GetDREFFrom(ea):
        refs = []
        ref = get_first_dref_from(ea)
        while ref != BADADDR:
            refs.append(ref)
            ref = get_next_dref_from(ea, ref)
            
        return refs

    @staticmethod
    def GetDREFTo(ea):
        refs = []
        ref = get_first_dref_to(ea)
        while ref != BADADDR:
            refs.append(ref)
            ref = get_next_dref_to(ea, ref)
            
        return refs
