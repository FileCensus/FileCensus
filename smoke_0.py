print()

import sys
sys.exit(0)

from pycpu_retro70z_id0000 import control

control.interpret_line("#7 #2 #5 dump-stack")
print("\nExpecting: 7 2 5\n")

control.interpret_line("* dump-stack")
print("\nExpecting: 7 10\n")

print("Expecting: PANIC")
control.interpret_line("drop drop drop")
