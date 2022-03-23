#!/usr/bin/python3

import r2pipe # add dependency to list
import base64
import lief
import keystone
import logging
import sys
import stackprinter
from itertools import cycle


"""
Steps:

1. List XREFS to all strings (done)
2. Insert 3 instructions, with the decrypt_string function already present in the binary.
3. Insert the decrypt_string function in a new section. (done)


OR

2. Replace instruction with a JMP
3. To a new code section with the 3 aforementioned instructions.
4. JMP to return address.

Needs to add a new section statically, at the end of the binary. Either LIEF or radare2.
Needs to compute the JMP destination (+ check 2 MB restrictions :O).
Needs to a PIE code able to decrypt a function O.o
    1. Find strings, replace with Vigenere :D
    2. Write other PIE elf bin that de-Vignere strings (done)
    3. Steal the code section and patch it in the binary in a new code section (done).

Add new section (".toto"): (done)

1. JMP instruction lands here
2. Need to remember the EIP address 
3. Copy original instruction in that section. (done)
4. Replace original instruction by JMP NEAR + offset to new section + offset to instruction
5. JMP to section ".test" O.o absolute jmp is best. (done)
6. Add JMP to ".toto", after function call. (done)
7. JMP to original EIP + 1 (address of step 2). (done)


TODO:

1. Encrypt string in .data section (with vigenere for the PoC). (done)
2. Implement add_jump_table_section (done)

1. Chiffrer automatiquement les strings dans le binaire (easy) (P1) (done)
4. Améliorer le hook pour se rappeler automatiquement l'adresse de retour. (P2) (done)
2. Appliquer l'algo à toutes les strings (done)
3. Check pour pas déchiffrer deux fois la même string dans le cas où elle est employée plusieurs fois. (LP)


TODO:
1. Do not encrypt strings if patch_xref won't handle it.l (done)
"""

# config init
stackprinter.set_excepthook(style='darkbg2') # stacktraces with variables' values
logging.basicConfig(level=logging.INFO)

# constants
BINARY = "bin/simple_test.bin"
STUB = "bin/simple_vigenere.bin"
TRAMPOLINE_SECTION = ".switch"
DECRYPT_SECTION = ".test"
KEY = "MUSIQUE"
SZ_BLK_PER_STRING = 29 # space required to handle 1 string in the switch section

# global variables
g_is_pe = False
ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

"""
    takes a position-independant function in a given binary
    and copy it.
    @name: function name
    @binary: a binary already parsed with LIEF.
"""
def strip_function(name: str, binary: lief.ELF.Binary):

    address = 0 # offset of the function within the binary
    size = 0 # size of the function

    if binary.format == lief.EXE_FORMATS.ELF:
        symbol = binary.get_static_symbol(name)

        address = symbol.value
        size = symbol.size

    # lief does not appear to be able to locate function by name in PE files.
    elif binary.format == lief.EXE_FORMATS.PE:

        r2 = r2pipe.open(STUB)
        r2.cmd("aaa")
        all_functions = r2.cmdj("aflj")
        matching_functions = []

        for fn in all_functions:

            if name in fn['name']:
                logging.info(f"Found function matching '{name}': {fn}")
                matching_functions += [fn]

        if len(matching_functions) > 1:
            logging.warning(f"More than 1 function found with name {name}. Bug incoming.")

        address = matching_functions[0]['offset']
        size = matching_functions[0]['size']

    else:
        raise Exception("Unsupported file format")

    function_bytes = binary.get_content_from_virtual_address(address, size)
    return function_bytes, address, size

"""
    TODO: bad function name
    TODO: document
    TODO: cleanup
"""
def add_section(original_binary):

    r2 = r2pipe.open(BINARY)
    strings = get_strings(r2)
    nb_strings = len(strings)

    # :(
    if g_is_pe:

        section = original_binary.get_section(".rdata")
        section.characteristics = lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE | lief.PE.SECTION_CHARACTERISTICS.MEM_READ# make the section writable :O


        section = lief.PE.Section(DECRYPT_SECTION)
        section.characteristics = lief.PE.SECTION_CHARACTERISTICS.CNT_CODE | lief.PE.SECTION_CHARACTERISTICS.MEM_READ | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
        content,_,_   = strip_function("decrypt", lief.parse(STUB))

        section.content = content
        section = original_binary.add_section(section)

        section = lief.PE.Section(TRAMPOLINE_SECTION)
        section.characteristics = lief.PE.SECTION_CHARACTERISTICS.CNT_CODE | lief.PE.SECTION_CHARACTERISTICS.MEM_READ | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE

        section.content = [0x90 for i in range(SZ_BLK_PER_STRING * nb_strings)] # placeholder
        section = original_binary.add_section(section)
        return original_binary, section
    else:

        section = original_binary.get_section(".rodata")
        section += lief.ELF.SECTION_FLAGS.WRITE # make the section writable :O

        section = lief.ELF.Section(DECRYPT_SECTION, lief.ELF.SECTION_TYPES.PROGBITS)
        section += lief.ELF.SECTION_FLAGS.EXECINSTR
        section += lief.ELF.SECTION_FLAGS.WRITE
        content,_,_   = strip_function("decrypt", lief.parse(STUB))

        section.content = content
        section = original_binary.add(section, loaded=True)

        section = lief.ELF.Section(TRAMPOLINE_SECTION, lief.ELF.SECTION_TYPES.PROGBITS)
        section += lief.ELF.SECTION_FLAGS.EXECINSTR
        section += lief.ELF.SECTION_FLAGS.WRITE

        section.content = [0x90 for i in range(SZ_BLK_PER_STRING * nb_strings)] # placeholder # TODO compute in advanced the required size
        section = original_binary.add(section, loaded=True)
        return original_binary, section

def get_instructions_size(current_instructions: str, placeholder_value: list) -> int:

    ins, _ = ks.asm(current_instructions.format(*placeholder_value))
    return len(ins)

def adjust_signedness(offset):

    if type(offset) == int:
        offset = hex(offset)

    sign = '-'
    if offset[0] == '-':

        sign = '+'
        offset = offset[1:]

    return sign + offset


"""
    lea rdi, str.offset1 ; load the string
    mov r12, label1 ; or EIP+len(next_instruction)
    jmp decrypt_section ; absolute jmp # end of decrypt section will jmp on r12
    label1:
    pop rax ; original instruction pointer
    jmp rax

"""
def add_jump_table_section(binary, radare_pipe, string, previous_block_sz, original_instruction):

    proper_assembly = ["push rdi\npush rsi\npush rax\nlea rdi, [rip{}]\n", #offset_to_str, sign to be included
        "mov rsi, {}\n", #str_size
        "lea rax, [rip{}\n", #offset_to_decrypt_section
        "call rax\n",
        "pop rax\npop rsi\npop rdi\n",
        "lea rdi, [rip{}]\n",# offset_to_str2 # assert unused
        "ret"]

    if g_is_pe:
        proper_assembly = ["push rcx\npush rdx\npush rax\nlea rcx, [rip{}]\n", #offset_to_str, sign to be included
        "mov rdx, {}\n", #str_size
        "lea rax, [rip{}\n", #offset_to_decrypt_section
        "call rax\n",
        "pop rax\npop rdx\npop rcx\n",
        "lea rdi, [rip{}]\n",# offset_to_str2 # assert unused TODO cleanup
        "ret"]

    string_offset = string["vaddr"]
    section = binary.get_section(TRAMPOLINE_SECTION)
    binary_base_address = 0

    if g_is_pe:
        binary_base_address = radare_pipe.cmdj("ij")['bin']['baddr']

    new_data_address = binary.get_section(".data").virtual_address
    new_decrypt_address = binary.get_section(DECRYPT_SECTION).virtual_address
    new_text_address = binary.get_section(".text").virtual_address

    # load string in rdi
    offset_to_str = hex(binary_base_address+section.virtual_address-string_offset)
    offset_to_str = adjust_signedness(offset_to_str)
    crt_ins_size = get_instructions_size(proper_assembly[0], [offset_to_str])
    offset_to_str = hex(binary_base_address+section.virtual_address-string_offset+crt_ins_size+previous_block_sz)
    offset_to_str = adjust_signedness(offset_to_str)
    assembly  = proper_assembly[0].format(offset_to_str)

    # load string size
    str_size = string["length"]
    assembly += proper_assembly[1].format(str_size)

    # call decrypt_function
    sections_offset = section.virtual_address - new_decrypt_address
    crt_ins_size = get_instructions_size(assembly + proper_assembly[2], [adjust_signedness(sections_offset)])
    offset_to_decrypt_section = hex(sections_offset + crt_ins_size + previous_block_sz)
    offset_to_decrypt_section = adjust_signedness(offset_to_decrypt_section)
    assembly += proper_assembly[2].format(offset_to_decrypt_section)
    assembly += proper_assembly[3]

    # restore registers
    assembly += proper_assembly[4]

    # load original instruction
    offset_to_str2 = binary_base_address+section.virtual_address-string_offset
    offset_to_str2 += get_instructions_size(assembly+proper_assembly[5], [offset_to_str])
    offset_to_str2 += previous_block_sz
    #assembly += proper_assembly[5].format(hex(offset_to_str2)) # original instruction here
    assert(original_instruction["mnemonic"] == "lea") # TODO: handle more cases
    first_operand = original_instruction["opex"]['operands'][0]

    assert(first_operand["type"] == "reg")
    dest_reg = first_operand["value"]
    assembly += f"lea {dest_reg}, [rip{adjust_signedness(offset_to_str2)}]\n"

    # return to original instructi"]on
    assembly += proper_assembly[-1]
    encoding, _ = ks.asm(assembly)

    current_content = section.content[:previous_block_sz]
    section.content = current_content + encoding

    # write the new binary to disk
    binary.write(BINARY+".patch")
    return len(encoding)

"""
    @key: encryption key :str:
    @string: the string to encrypt

    As a PoC, Vigenere is used :D
"""
def encrypt_string(key, plaintext):

    universe = [c for c in (chr(i) for i in range(32,127) if not i == 92) ]
    uni_len = len(universe)
    ret_txt = ''
    k_len = len(key)

    for i, l in enumerate(plaintext):

        if l not in universe:
            ret_txt += l
        else:
            txt_idx = universe.index(l)

            k = key[i % k_len]
            key_idx = universe.index(k)
            code = universe[(txt_idx + key_idx) % uni_len]
            ret_txt += code

    return ret_txt

def xor(key, message):
    return ''.join(chr(ord(c)^ord(k)) for c,k in zip(message, cycle(key)))

"""
    relies on radare2 to retrieve all the strings
    in a binary.

    \return strings as JSON objects
"""
def get_strings(radare_pipe):

    # list strings in .data section as JSON objects
    radare_pipe.cmd("aaa")
    all_strings = radare_pipe.cmdj("izj")
    return all_strings

"""
    Todo: handle several strings.
"""
def patch_xref(binary, string, radare_pipe, previous_block_sz) -> bool:

    # patch the instruction that originally references the string
    # this allows to decrypt beforehand, so as no to alter the
    # program's behavior.
    xrefs = radare_pipe.cmdj(f"axtj @ {string['vaddr']}")
    original_instruction = None

    # For now, several XREFS to the same strings is an unhandled
    # case, for simplicity.
    if len(xrefs) > 1:

        logging.warning(f"Skipping string \'{string['string']}\' because more than 1 XREF was found")
        return False, original_instruction

    # no xref found
    elif len(xrefs) < 1:
        logging.warning(f"Skipping string \'{string['string']}\' because less than 1 XREF could be found")
        return False, original_instruction

    xref = xrefs[0]

    # corner cases that can't be handled right for now
    if not xref["opcode"].startswith("lea"):

        logging.warning(f"Skipping string \'{string['string']}\'. Unhandle opcode {xref['opcode']}\'")
        return False, original_instruction
    """
    if string["section"] in [".rodata", ".rdata"]:
        logging.warning(f"Skipping string \'{string['string']}\' because it's located in a read-only section.")
        return False, original_instruction
    """

    logging.info(f"Encrypting string \'{base64.b64decode(string['string'])}\'...")
    location = xref["from"]

    # store original instruction infomration
    original_instruction = radare_pipe.cmdj(f"aoj @ {location}")
    switch_address= binary.get_section(TRAMPOLINE_SECTION).virtual_address
    binary_base_address = 0

    # LIEF creates new sections for PE with virtual_address relative to image base.
    if g_is_pe:
        binary_base_address = radare_pipe.cmdj("ij")['bin']['baddr']

    jmp_destination = binary_base_address+switch_address - location + previous_block_sz # displacement between the original instruction and the switch section
    assembly = f"call {hex(jmp_destination)}"
    tmp_encoding, _ = ks.asm(assembly)

    # TODO: clean up below
    res = ""
    for i in tmp_encoding:
        if i < 10:
            res += "0" + str(hex(i))[2:]
        else:
            res += str(hex(i))[2:]

    res += "9090"
    radare_pipe.cmd(f"wx {res} @ {hex(location)}")
    return True, original_instruction

def encrypt_strings(binary):

    r2 = r2pipe.open(BINARY+".patch", flags=["-w"])
    all_strings = get_strings(r2)
    previous_block_sz = 0
    nb_encrypted_strings = 0

    for index, string in enumerate(all_strings):

        decoded_string = base64.b64decode(string["string"])
        binary = lief.parse(BINARY+".patch") # is this needed?

        # hook the binary where the string is referenced. Skip if the string
        # is used several times.
        can_proceed, original_instruction = patch_xref(binary, string, r2, previous_block_sz)

        if not can_proceed:
            continue

        # encrypt the string in .data (or whatever else) section.
        encrypted = encrypt_string(KEY, base64.b64decode(string["string"]).decode()) # convert_encoding(string["type"])
        encoded = base64.b64encode(encrypted.encode()).decode()
        r2.cmd(f"w6d {encoded} @ {string['vaddr']}")

        # prepare the trampoline for the hook.
        # takes care of decrypting the string and resuming the original control flow.
        binary = lief.parse(BINARY+".patch") # is this needed?
        previous_block_sz += add_jump_table_section(binary, r2, string, previous_block_sz, original_instruction[0]) # TODO handle > 1 opcodes
        nb_encrypted_strings += 1

    logging.info(f"Successfully encrypted {nb_encrypted_strings}/{len(all_strings)} strings!")

if __name__ == "__main__":

    if len(sys.argv) > 1:
        BINARY =  sys.argv[1]

    if len(sys.argv) > 2:
        STUB = sys.argv[2]

    logging.info(f"Encrypting strings of {BINARY}")
    logging.info(f"Decryption routine will be copied from {STUB}")

    original_binary = lief.parse(BINARY)

    if original_binary.format == lief.EXE_FORMATS.ELF:
        logging.info("ELF executable detected")

    elif original_binary.format == lief.EXE_FORMATS.PE:
        logging.info("PE Executable detected.")
        g_is_pe = True

    else:
        logging.error("Unrecognized binary")
        exit(1)

    new_binary, section = add_section(original_binary)

    # make a copy of the original binary
    new_binary.write(BINARY+".patch")

    # parse strings references and encrypt
    encrypt_strings(new_binary)
