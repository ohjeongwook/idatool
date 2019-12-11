import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from random import randint
import idaapi
from idc import *
import PyQt5

class Form(idaapi.PluginForm):
    def __init__(self, title):
        super(Form, self).__init__()
        self.Title = title + ':%x' % randint(0, 0xffffffff)

    def add_combo_box(self, items):
        widget = PyQt5.QtWidgets.QComboBox(self.parent)
        for item in items:
            widget.addItem(item)
        self.Widgets.append(widget)
        
    def add_line_edit(self, title):
        self.FileName = PyQt5.QtWidgets.QLineEdit()
        browser_button = PyQt5.QtWidgets.QPushButton(title)
        browser_button.clicked.connect(self.Browse)
        
    def checkbox_pushed(self):
        pass

    def add_checkbox(self, name):
        widget = PyQt5.QtWidgets.QCheckBox(name, self.parent)
        widget.toggle()
        widget.stateChanged.connect(self.checkbox_pushed)
        self.Widgets.append(widget)
        
    def add_tree(self, labels):
        self.Tree = PyQt5.QtWidgets.QTreeWidget()
        self.Tree.setHeaderLabels(labels)
        self.Tree.setColumnWidth(0, 200)
        #self.Tree.itemClicked.connect(self.tree_clicked)
        
    def ask_save_filename(self, filter = "Log (*.log)"):
        filename, _ = PyQt5.QtWidgets.QFileDialog.getSaveFileName(
                                                    self.parent, 
                                                    'Open file', 
                                                    '', 
                                                    filter
                                                )
        return filename

    def ask_open_filename(self, filter = "Log (*.log)", dir_name = ''):
        filename, _ = PyQt5.QtWidgets.QFileDialog.getOpenFileName(self.parent, 'Open file', dir_name, filter)
        return filename

    def on_create(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.Widgets = []

        grid = PyQt5.QtWidgets.QGridLayout()

        for widget in self.Widgets:
            grid.addWidget(widget, 0, 0)

        main = PyQt5.QtWidgets.QVBoxLayout()
        main.addLayout(grid)
        main.addStretch()        
        self.parent.setLayout(main)

    def change_append(self):
        if self.Append:
            self.Append = False
        else:
            self.Append = True

    def on_close(self, form):
        pass
        
    def show(self):
        return idaapi.PluginForm.show(
            self, 
            self.Title,
            options = (idaapi.PluginForm.FORM_CLOSE_LATER | idaapi.PluginForm.FORM_RESTORE | idaapi.PluginForm.FORM_SAVE)
        )

if __name__ == '__main__':
    def main(title):
        global IDAOps
        
        try:
            IDAOps
            IDAOps.on_close(IDAOps)
            IDAOps = Form(title)
            return    
        except:
            IDAOps = Form(title)

        IDAOps.show()

    title = 'Test'
    main(title)

