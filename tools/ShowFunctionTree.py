import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import idaapi
from idaapi import PluginForm
from PyQt5 import QtGui, QtCore, QtWidgets

import idatool.util

class OperationForm_t(PluginForm):
	def populate_tree(self):
		self.Tree.clear()
		
		ea = idatool.util.Function.get_address()
		current_root = self.add_item(self.Tree, ea)

		ea_list = self.enumerate_tree(current_root, ea, 0)
		for [ea, item, level] in ea_list:
			if level>4:
				continue
			ea_list += self.enumerate_tree(item, ea, level+1)

	def enumerate_tree(self, current_root, parent, level):		
		address_list = []
		for ea in idatool.util.Function.DumpFunctionCalls(parent): # TODO: DumpFunctionCalls is missing
			item = self.add_item(current_root, ea)
			address_list.append([ea, item, level+1])
		return address_list

	def add_item(self, current_root, ea):
		name = idaapi.get_true_name(int(ea), int(ea))
		new_item = QtWidgets.QTreeWidgetItem(current_root)
		new_item.setText(0, "%s" % name)
		new_item.setText(1, "%x" % ea)
		
		return new_item

	def tree_clicked(self, treeItem):
		if treeItem != None:
			address = int(treeItem.text(1), 16)
			idaapi.jumpto(address)
			
	def on_create(self, form):
		self.ImageName = idaapi.get_root_filename()
		self.ImageBase = idaapi.get_imagebase()

		self.parent = self.FormToPyQtWidget(form)

		self.Tree = QtWidgets.QTreeWidget()
		self.Tree.setHeaderLabels(("Name", "Address"))
		self.Tree.setColumnWidth(0, 200)
		self.Tree.setColumnWidth(1, 100)

		self.Tree.itemClicked.connect(self.tree_clicked)
		
		layout = QtWidgets.QVBoxLayout()
		layout.addWidget(self.Tree)
		
		self.populate_tree()
		self.parent.setLayout(layout)
		
	def on_close(self, form):
		global OperationForm
		del OperationForm
		
	def show(self):
		return PluginForm.show(self, "IDA Tree", options = (PluginForm.FORM_CLOSE_LATER | PluginForm.FORM_RESTORE | PluginForm.FORM_SAVE))

def main():
	global OperationForm

	try:
		OperationForm
		OperationForm.on_close(OperationForm)
		print("reloading OperationForm")
		OperationForm = OperationForm_t()
		return	
	except:
		OperationForm = OperationForm_t()
		
	OperationForm.show()

main()