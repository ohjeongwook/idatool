import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import idatool.disassembly

if __name__ == '__main__':
    import logging

    logging.basicConfig(level = logging.DEBUG)
    logger = logging.getLogger(__name__)

    disasm = idatool.disassembly.Disasm()

    import idatool.ui

    global form

    title = 'Load Notations'
    try:
        form
        form.OnClose(form)
        form = idatool.ui.Form(title)
    except:
        form = idatool.ui.Form(title)

    form.Show()

    filename = form.AskOpenFileName("DB (*.db)")

    if filename:
        print('Loading file: ' + filename)
        disasm.LoadNotations(filename, hash_types = [])
    disasm.Exit()
