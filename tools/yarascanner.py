import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import json
import yara
import sqlite3
import base64

import idatool.disassembly

class YaraScanner:
    def __init__(self, yara_filename):
        self.YaraRules = yara.compile(yara_filename)

    def Scan(self, bytes):
        yara_match_str = ''
        if self.YaraRules != None:
            yara_matches = self.YaraRules.match(data = block_bytesbytes)
            
            for yara_match in yara_matches:
                yara_match_str += str(yara_match)+' '
