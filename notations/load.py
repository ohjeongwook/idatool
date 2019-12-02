import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import idatool.disassembly

if __name__ == '__main__':
    import logging
    import idaapi
    import idatool.ui

    logging.basicConfig(level = logging.DEBUG)
    logger = logging.getLogger(__name__)

    disasm = idatool.disassembly.Disasm()

    global form

    title = 'Load Notations'
    try:
        form.OnClose(form)
        form = idatool.ui.Form(title)
    except:
        form = idatool.ui.Form(title)

    form.Show()

    filename = form.AskOpenFileName(filter = "DB (*.db)", dir_name = os.path.dirname(disasm.GetFilename()))

    if filename:
        print('Loading file: ' + filename)
        disasm.LoadNotations(filename, hash_types = [])
    disasm.Exit()
