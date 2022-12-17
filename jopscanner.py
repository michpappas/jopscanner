#!/usr/bin/env python3
import pkg_resources

from argparse import ArgumentParser
from binascii import hexlify
from capstone import *
from elftools.elf.elffile import ELFFile
from packaging import version

def jop_scan(binary, depth):

    gadgets = []
    g = []

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    # skip unknown instructions
    md.skipdata = True

    with open(binary, 'rb') as f:
        text = ELFFile(f).get_section_by_name('.text')
        for i in md.disasm(text.data(), text['sh_addr']):

            if "ret" in i.mnemonic:
                # End of fuction, discard
                g = []
                continue

            g.append(i)

            if i.mnemonic == "br" or  i.mnemonic == "blr":
                # End of gadget
                gadgets.append(g)
                g = []

    return [g[-depth:] for g in gadgets]

def jop_scan_bti(binary, depth):

    gadgets = []
    in_gadget = False;

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.skipdata = True

    with open(binary, 'rb') as f:
        text = ELFFile(f).get_section_by_name('.text')
        for i in md.disasm(text.data(), text['sh_addr']):

            if i.mnemonic == "bti":
                # Start a new gadget
                in_gadget = True
                g = [i]
                continue
            elif "ret" in i.mnemonic:
                # End of fuction, discard
                in_gadget = False;
                g = []
                continue

            if in_gadget is True:
                # End of gadget
                if i.mnemonic == "br" or i.mnemonic == "blr":
                        g.append(i)
                        gadgets.append(g)
                        in_gadget = False;
                else:
                  # Still in gadget, append current line
                  g.append(i)

    return [g for g in gadgets if len(g) <= depth]

if __name__ == '__main__':
    parser = ArgumentParser(description="A JOP gadget scanner for arm64")
    parser.add_argument('file', help="elf file to analyze")
    parser.add_argument("-d", "--depth", dest="depth", type=int, default=10, help="number of gadget instructions", required=False)
    parser.add_argument("-b", "--bti", action='store_true', help="enable BTI mode", required=False)
    args = vars(parser.parse_args())

    capstone_version = pkg_resources.get_distribution("capstone").version
    capstone_min_version = "5.0.0"
    if version.parse(capstone_version) < version.parse(capstone_min_version):
        raise pkg_resources.VersionConflict("found capstone {}, require >= {}".format(capstone_version, capstone_min_version))

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if args['bti']:
        gadgets = jop_scan_bti(args['file'], args['depth'])
    else:
        gadgets = jop_scan(args['file'], args['depth'])

    for g in gadgets:
        for i in g:
            print('0x{:08x}:\t{}\t{}\t{}'.format(i.address, hexlify(i.bytes).decode(), i.mnemonic, i.op_str))
        print("\n")

    print('Gadgets found: {}'.format(len(gadgets)))
