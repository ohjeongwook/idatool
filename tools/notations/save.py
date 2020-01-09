import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import idatool.disassembly

if __name__ == '__main__':
    import logging

    logging.basicConfig(level = logging.DEBUG)
    logger = logging.getLogger(__name__)

    disasm = idatool.disassembly.Disasm()
    
    save_filename = ''
    if len(disasm.Args)>0:
        save_filename = disasm.Args[0]
    else:        
        import idatool.ui

        global form

        title = 'Breakpoints-UI'
        try:
            form
            form.on_close(form)
            form = idatool.ui.Form(title)
        except:
            form = idatool.ui.Form(title)

        form.Show()

        save_filename = form.ask_save_filename("SQLite (*.db)")

    if not save_filename:
        save_filename = r'InstructioNotations.db'

    if save_filename:
        print('Saving file: ' + save_filename)
        disasm.save_notations(save_filename, hash_types = [])
    disasm.exit()
