import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import functools
import Queue

import traceback
import zerorpc
import threading

from idaapi import *
from idc import *
import idaapi
import idautils
from idaapi import PluginForm

import Disasm
import Disasm.Vex
import Disasm.Tool

from Util.Config import *
from WinDBG.RunLog import *
from TraceLoader import *

import idatool.util
import idatool.disassembly

class IDASyncError(Exception): pass

class IDASafety:
    SAFE_NONE = 0
    SAFE_READ = 1
    SAFE_WRITE = 2

call_stack = Queue.LifoQueue()

def sync_wrapper(ff, safety_mode):
    logger.debug('sync_wrapper: {}, {}'.format(ff.__name__, safety_mode))

    if safety_mode not in [IDASafety.SAFE_READ, IDASafety.SAFE_WRITE]:
        error_str = 'Invalid safety mode {} over function {}'\
                .format(safety_mode, ff.__name__)
        logger.error(error_str)
        raise IDASyncError(error_str)

    queue = Queue.Queue()
    def runned():
        logger.debug('Inside runned')

        if not call_stack.empty():
            last_func_name = call_stack.get()
            error_str = ('Call stack is not empty while calling the '
                            'function {} from {}').format(ff.__name__, last_func_name)
            logger.error(error_str)
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        try:
            queue.put(ff())
        except:
            queue.put(None)
            traceback.print_exc(file = sys.stdout)
        finally:
            call_stack.get()
            logger.debug('Finished runned')

    idaapi.execute_sync(runned, safety_mode)
    return queue.get()

def idawrite(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_WRITE)
    return wrapper

def idaread(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_READ)
    return wrapper

class IDARPCServer(object):
    def __init__(self):
        self.Disasm = idatool.disassembly.Disasm()
        self.DisasmTool = Disasm.Tool.Analyzer('x86', 64)

    @idaread
    def get_function_instructions(self, ea = None):
        return self.Disasm.get_function_instructions(ea)
        
    @idaread
    def get_functions(self):
        return self.Disasm.get_functions()
        
    @idaread
    def get_function_hashes(self):
        return self.Disasm.get_function_hashes(hash_types = ['op'])
        
    @idaread
    def get_function_tree(self, ea = None, threshold = 10):
        return self.Disasm.get_function_tree(ea, threshold)

    @idaread
    def get_imports(self):
		return self.Disasm.get_imports()

    @idawrite
    def load_function_name_by_hashes(self, filename):
        return self.Disasm.load_function_name_by_hashes(filename)

    @idawrite
    def load_names_and_comments(self, filename):
        return self.Disasm.load_names_and_comments(filename)
        
    @idawrite    
    def set_comments(self, cmt_map):
        for kv in cmt_map.items():
            idatool.util.Cmt.set(kv[0], kv[1])

    @idaread
    def get_indirect_calls(self):
        return self.Disasm.get_indirect_calls()

    @idaread
    def disassemble_bytes(self, bytes, addr):
        return self.DisasmTool.Disasm(bytes, addr)

    @idawrite
    def load_windbg_log(self, filename):
        record_analyzer = RunLogAnalyzer(filename)
        def address_callback(address):
            idaapi.set_item_color(address, 0x00ff00)

        record_analyzer.RunAddressCallback(address_callback)

    @idaread
    def export(self, lst_filename = ''):
        return self.DisasmTool.export(lst_filename)

class ThreadWorker(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        s = zerorpc.Server(IDARPCServer())
        s.bind("tcp://0.0.0.0:4242")
        s.run()

if __name__ == '__main__':
    import logging
    logging.basicConfig(level = logging.DEBUG)
    logger = logging.getLogger(__name__)

    thread_worker = ThreadWorker()
    thread_worker.start()
