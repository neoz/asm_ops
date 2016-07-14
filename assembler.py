import idaapi
import idautils
import idc
import sys
from keystone import *

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class InputError(Error):
    """Exception raised for errors in the input.

    Attributes:
        expr -- input expression in which the error occurred
        msg  -- explanation of the error
    """

    def __init__(self, expr, msg):
        self.expr = expr
        self.msg = msg

def get_arch():
	(arch, bits) = (None, None)
	for x in idaapi.ph_get_regnames():
		name = x
		if name == 'RAX':
			arch = KS_ARCH_X86
			bits = KS_MODE_64
			break
		elif name == 'EAX':
			arch = KS_ARCH_X86
			bits = KS_MODE_32
			break
		elif name == 'R0':
			arch = KS_ARCH_ARM
			bits = KS_MODE_ARM
			break
	return (arch, bits)

def get_thumb(ea):
	val = idc.GetReg(ea,'T')
	return val

class myplugin_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_UNL
	comment = "Opcode Assembler helper (using Keystone framework)"
	help = "This is help"
	wanted_name = "Opcode Assembler"
	wanted_hotkey = "Alt-N"
	(arch, bits) = (None,None)

	def init(self):
		(self.arch, self.bits) = get_arch()
		return idaapi.PLUGIN_OK

	def run(self, arg):
		startasm()

	def term(self):
		pass

def PLUGIN_ENTRY():
	return myplugin_t()

def tohex(val, nbits):
	return hex((val + (1 << nbits)) % (1 << nbits))

def remove_doublespace(str):
	pos = str.find("  ")
	while pos != -1:
		str = str.replace("  "," ")
		pos = str.find("  ")
	return str

def clean_part(str):
	str = str.strip()
	pos = str.find(' ')
	while pos != -1:
		str = str.replace(' ','')
		pos = str.find(' ')
	return str

def asm_keystone(startea,instruction_string):
	(arch, mode) = get_arch()	
	if arch==KS_ARCH_ARM:
		thumb = get_thumb(startea)
		if thumb==1:
			mode = KS_MODE_THUMB
	ks = Ks(arch, mode)
	encoding, count = ks.asm(instruction_string,startea)
	beginea=startea
	total=0
	for i in encoding:
		PatchByte(beginea,i)
		beginea=beginea+1
	return beginea-startea

def startasm():
	curEA = idc.ScreenEA()
	isCont = 1
	while isCont:
		t = idaapi.generate_disasm_line(curEA)
		if t:
			line = idaapi.tag_remove(t)
		else:
			line = ""
		str = AskStr(line,"Address :"+hex(curEA)+"\nInstruction")
		if str:
			try:
				next=asm_keystone(curEA,str)
				curEA = curEA + next
			except InputError as e:
				print e.msg
		else:
			isCont = 0
