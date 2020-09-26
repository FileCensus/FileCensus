#!/usr/bin/env python3

# POW4TH-OS
# Copyright (c) 2020, https://linkedin.com/in/scott-mccallum
# Copyright (c) https://git.sr.ht/~crc_/retroforth
# -----------------------------------------------------

import click

import os, sys, math, time, struct

class POW4TH_VM:

    def __init__(self, memory_size=524288):
        self.ip = [0]
        self.stack = [] * 1024
        self.address = []
        self.memory = []
        self.memory_max = memory_size

    def extractString(self, at):
        i = at
        s = ''
        while self.memory[i] != 0:
            s = s + chr(self.memory[i])
            i = i + 1
        return s

    def findEntry(self, named):
        header = self.memory[2]
        Done = False
        while header != 0 and not Done:
            if named == self.extractString(header + 3):
                Done = True
            else:
                header = self.memory[header]
        print('findEntry for ', named, ' = ', header)
        return header

    def injectString(self, s, to):
        i = to
        for c in s:
            self.memory[i] = ord(c)
            i = i + 1
        self.memory[i] = 0

    def execute(self):

        ip, memory, stack, address = (self.ip, self.memory, self.stack, self.address)

        def rxGetInput():
            return ord(sys.stdin.read(1))

        def rxDisplayCharacter():
            if stack[-1] > 0 and stack[-1] < 128:
                if stack[-1] == 8:
                    sys.stdout.write(chr(stack.pop()))
                    sys.stdout.write(chr(32))
                    sys.stdout.write(chr(8))
                else:
                    sys.stdout.write(chr(stack.pop()))
            else:
                sys.stdout.write("\033[2J\033[1;1H")
                stack.pop()
            sys.stdout.flush()

        def i_no():
            pass

        def i_li():
            ip[0] += 1
            stack.append(memory[ip[0]])

        def i_du():
            stack.append(stack[-1])

        def i_dr():
            stack.pop()

        def i_sw():
            a = stack[-2]
            stack[-2] = stack[-1]
            stack[-1] = a

        def i_pu():
            address.append(stack.pop())

        def i_po():
            stack.append(address.pop())

        def i_ju():
            ip[0] = stack.pop() - 1

        def i_ca():
            address.append(ip[0])
            ip[0] = stack.pop() - 1

        def i_cc():
            target = stack.pop()
            if stack.pop() != 0:
                address.append(ip[0])
                ip[0] = target - 1

        def i_re():
            ip[0] = address.pop()

        def i_eq():
            a = stack.pop()
            b = stack.pop()
            if b == a:
                stack.append(-1)
            else:
                stack.append(0)

        def i_ne():
            a = stack.pop()
            b = stack.pop()
            if b != a:
                stack.append(-1)
            else:
                stack.append(0)

        def i_lt():
            a = stack.pop()
            b = stack.pop()
            if b < a:
                stack.append(-1)
            else:
                stack.append(0)

        def i_gt():
            a = stack.pop()
            b = stack.pop()
            if b > a:
                stack.append(-1)
            else:
                stack.append(0)

        def i_fe():
            if stack[-1] == -1:
                stack[-1] = len(stack) - 1
            elif stack[-1] == -2:
                stack[-1] = len(address)
            elif stack[-1] == -3:
                stack[-1] = len(memory)
            elif stack[-1] == -4:
                stack[-1] = -9223372036854775808  # normal memory unbounded, 64bit for persistent memory
            elif stack[-1] == -5:
                stack[-1] = 9223372036854775807  # normal memory unbounded, 64bit for persistent memory
            else:
                stack[-1] = memory[stack[-1]]

        def i_st():
            mi = stack.pop()
            memory[mi] = stack.pop()

        def i_ad():
            t = stack.pop()
            stack[-1] += t

        def i_su():
            t = stack.pop()
            stack[-1] -= t

        def i_mu():
            t = stack.pop()
            stack[-1] *= t

        def i_di():
            a = stack[-1]
            b = stack[-2]

            q, r = divmod(abs(b), abs(a))
            if a < 0 and b < 0:
                r *= -1
            elif a > 0 and b < 0:
                q *= -1
            elif a < 0 and b > 0:
                r *= -1
                q *= -1

            stack[-1] = q
            stack[-2] = r

        def i_an():
            t = stack.pop()
            stack[-1] &= t

        def i_or():
            t = stack.pop()
            stack[-1] |= t

        def i_xo():
            t = stack.pop()
            stack[-1] ^= t

        def i_sh():
            t = stack.pop()
            stack[-1] <<= t
            t = stack.pop()
            stack[-1] >>= t

        def i_zr():
            if stack[-1] == 0:
                stack.pop()
                ip[0] = address.pop()

        def i_ha():
            ip[0] = 9000000

        def i_ie():
            stack.push(1)

        def i_iq():
            stack.pop()
            stack.push(0)
            stack.push(0)

        def i_ii():
            stack.pop()
            rxDisplayCharacter()

        instructions = [i_no, i_li, i_du, i_dr, i_sw, i_pu, i_po, i_ju,
                        i_ca, i_cc, i_re, i_eq, i_ne, i_lt, i_gt, i_fe,
                        i_st, i_ad, i_su, i_mu, i_di, i_an, i_or, i_xo,
                        i_sh, i_zr, i_ha, i_ie, i_iq, i_ii]

        def inner(word):

            ip[0] = word
            address.append(0)

            while ip[0] < 100000 and len(address) > 0:
                opcode = memory[ip[0]]
                instructions[opcode & 0xFF]()
                instructions[(opcode >> 8) & 0xFF]()
                instructions[(opcode >> 16) & 0xFF]()
                instructions[(opcode >> 24) & 0xFF]()
                ip[0] = ip[0] + 1

        return inner

    def firmware_load(self, source):
        cells = int(os.path.getsize(source) / 4)
        f = open(source, 'rb')
        self.memory = list(struct.unpack(cells * 'i', f.read()))
        f.close()
        remaining = self.memory_max - cells
        self.memory.extend([0] * remaining)

    def firmware_build(self, source):

        if len(self.memory) == 0:

            i_two = {}
            i_var = {}

            instructions = ['nop', 'lit', 'dup', 'drop', 'swap', 'push', 'pop', 'jump', 'call', 'ccall', 'ret',
                            'eq', 'neq', 'lt', 'gt', 'fetch', 'store', 'add', 'sub', 'mul', 'div', 'and', 'or', 'xor',
                            'shift', 'zret', 'halt',
                            'ienum', 'iquery', 'iinvoke']

            for instruction in instructions:
                i_two[instruction[:2]] = len(i_two)
                i_var[instruction] = len(i_var)

            i_two['..'] = 0

            lines = []
            include = False
            for line in open(source, encoding='utf-8').readlines():
                if line[:3] == '~~~':
                    include = not include
                    continue
                if not include:
                    continue
                line = line.strip()
                if len(line):
                    lines.append(line)

            print("Pass 1\n")

            offsets = {}
            for line in lines:
                print("%04i %s" % (len(self.memory), line))
                if line[0] == 'i':
                    I0, I1, I2, I3 = (line[2:4], line[4:6], line[6:8], line[8:10])
                    opcode = (i_two[I0]) + (i_two[I1] << 8) + (i_two[I2] << 16) + (i_two[I3] << 24)
                    self.memory.append(opcode)
                elif line[0] == 'r':
                    self.memory.append(-1)
                elif line[0] == 'd':
                    self.memory.append(int(line[2:]))
                elif line[0] == 's':
                    for c in iter(line[2:]):
                        self.memory.append(ord(c))
                    self.memory.append(0)
                elif line[0] == 'a':  # alloc n words of 0
                    self.memory.expand([0] * int(line[2:]))
                elif line[0] == ':':
                    offsets[line[2:]] = len(self.memory)

            print("\n\nPass 2\n")

            offset = 0
            for line in lines:
                if line[0] == 'i':
                    offset = offset + 1
                elif line[0] == 'r':
                    print("%04i %s = %i" % (offset, line, offsets[line[2:]]))
                    self.memory[offset] = offsets[line[2:]]
                    offset = offset + 1
                elif line[0] == 'd':
                    offset = offset + 1
                elif line[0] == 's':
                    offset = offset + len(line[2:]) + 1
                elif line[0] == 'a':
                    offset = offset + int(line[2])
                elif line[0] == ':':
                    pass

            remaining = self.memory_max - len(self.memory)
            self.memory.extend([0] * remaining)

            return

        POW4TH_engine = self.execute()

        interpret = self.memory[self.findEntry('interpret') + 1]
        include = False
        for line in open(source, encoding='utf-8').readlines():
            if line[:3] == '~~~':
                include = not include
                continue
            if not include:
                continue
            print(line)
            for token in line.split(' '):
                print('>>', token)
                self.injectString(token, 1025)
                self.stack.append(1025)
                POW4TH_engine(interpret)

    def interact(self):
        POW4TH_go = self.execute()

        done = False
        interpret_entry = self.memory[self.findEntry('interpret') + 1]
        while not done:
            line = input('\nPOW4TH> ')
            if line == 'bye':
                done = True
            else:
                for token in line.split(' '):
                    self.injectString(token, 1025)
                    self.stack.append(1025)
                    POW4TH_go(interpret_entry)


@click.command()
def interact():
    vm = POW4TH_VM()
    #vm.firmware_build(".firmware\\BIOS.muri")
    #vm.firmware_build(".firmware\\BIOS.retro")

    # check = POW4TH_VM()
    vm.firmware_load(".firmware\\ngaImage")

    # for i in range(0, len(check.memory)):
    #    if interpreter.memory[i] != check.memory[i]:
    #        print('Missmatch at address ', i, 'Found', interpreter.memory[i], 'Expecting', check.memory[i])

    vm.interact()


if __name__ == "__main__":
    interact()
