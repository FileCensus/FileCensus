print()

import sys
sys.exit(0)

import_ok = False
try:
    import PyCPU_RETRO70Z_ID0000_CPP
    import_ok = True
except:
    pass

from pycpu_retro70z_id0000 import control

control.interpret_line("#7 #2 #5 dump-stack")
print("\nExpecting: 7 2 5\n")

control.interpret_line("* dump-stack")
print("\nExpecting: 7 10\n")

PyCPU_RETRO70Z_ID0000_CPP.hello("PyCPU")
print("\nExpecting: Hello, PyCPU!\n")

#print("Expecting: PANIC")
#control.interpret_line("drop drop drop")
