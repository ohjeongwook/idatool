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

    def AddComboBox(self, items):
        widget = PyQt5.QtWidgets.QComboBox(self.parent)
        for item in items:
            widget.addItem(item)
        self.Widgets.append(widget)
        
    def AddLineEdit(self, title):
        self.FileName = PyQt5.QtWidgets.QLineEdit()
        browser_button = PyQt5.QtWidgets.QPushButton(title)
        browser_button.clicked.connect(self.Browse)
        
    def CheckBoxPushed(self):
        pass

    def AddCheckBox(self, name):
        widget = PyQt5.QtWidgets.QCheckBox(name, self.parent)
        widget.toggle()
        widget.stateChanged.connect(self.CheckBoxPushed)
        self.Widgets.append(widget)
        
    def AddTree(self, labels):
        self.Tree = PyQt5.QtWidgets.QTreeWidget()
        self.Tree.setHeaderLabels(labels)
        self.Tree.setColumnWidth(0, 200)
        #self.Tree.itemClicked.connect(self.treeClicked)
        
    def AskSaveFileName(self, filter = "Log (*.log)"):
        filename, _ = PyQt5.QtWidgets.QFileDialog.getSaveFileName(
                                                    self.parent, 
                                                    'Open file', 
                                                    '', 
                                                    filter
                                                )
        return filename

    def AskOpenFileName(self, filter = "Log (*.log)"):
        filename, _ = PyQt5.QtWidgets.QFileDialog.getOpenFileName(
                                                    self.parent, 
                                                    'Open file', 
                                                    '', 
                                                    filter
                                                )
        return filename

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.Widgets = []

        grid = PyQt5.QtWidgets.QGridLayout()

        for widget in self.Widgets:
            grid.addWidget(widget, 0, 0)

        main = PyQt5.QtWidgets.QVBoxLayout()
        main.addLayout(grid)
        main.addStretch()        
        self.parent.setLayout(main)

    def ChangeAppend(self):
        if self.Append:
            self.Append = False
        else:
            self.Append = True

    def OnClose(self, form):
        pass
        
    def Show(self):
        return idaapi.PluginForm.Show(
            self, 
            self.Title,
            options = (idaapi.PluginForm.FORM_CLOSE_LATER | idaapi.PluginForm.FORM_RESTORE | idaapi.PluginForm.FORM_SAVE)
        )

if __name__ == '__main__':
    def main(title):
        global IDAOps
        
        try:
            IDAOps
            IDAOps.OnClose(IDAOps)
            IDAOps = Form(title)
            return    
        except:
            IDAOps = Form(title)

        IDAOps.Show()

    title = 'Test'
    main(title)

