import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import idatool.breakpoints

if __name__ == '__main__':
    import logging

    logging.basicConfig(level = logging.DEBUG)
    logger = logging.getLogger(__name__)

    breakpoints = idatool.breakpoints.Util()
    breakpoints.add_functions()
    breakpoints.save()
    breakpoints.exit()

    
