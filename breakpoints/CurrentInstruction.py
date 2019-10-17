import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import pprint
import logging
import json

import windbgtool.command
import idatool.breakpoints

logging.basicConfig(level = logging.DEBUG)
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    breakpoints = idatool.breakpoints.Util()
    breakpoints.AddCurrentInstruction()
    breakpoints.Save()
    breakpoints.Exit()