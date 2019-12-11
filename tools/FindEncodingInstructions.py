import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import idatool.hunting

if __name__ == '__main__':
    hunter = idatool.hunting.Hunter()
    hunter.find_encoding_instructions()
    hunter.save()
    hunter.close()
