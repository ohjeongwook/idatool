import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import idatool.breakpoints

if __name__ == '__main__':
    breakpoints = idatool.breakpoints.Util()
    breakpoints.AddFunctions()
    breakpoints.Add("All", "DisplacementCall")
    breakpoints.Add("All", "Pointer")
    breakpoints.Add("All", "IndirectCall")
    breakpoints.Save()
    breakpoints.Exit()
