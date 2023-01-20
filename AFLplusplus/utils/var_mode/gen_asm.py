
# script to generate a .s file that save and restore the target global variables
# author: junxzm1990

import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS

total_vars = 0

all_pages = set()

def align_num(num, align):
	if num % align:
		num -= num % align
		num += align
	return num


def load_vars(var_file):
	try:
		with open(var_file, 'r') as f:
			return f.read().splitlines()
	except IOError as e:
		print("Error: cannot open the file for global variables")
		print(e)


#note: need to open it as raw bytes, namely 'rb'
def load_elf(elf_file):
	try:
		f= open(elf_file, 'rb')
		return  ELFFile(f)
	except IOError as e:
		print("Error: cannot open the binary file")
		print(e)


def get_sec_by_addr(elf, addr):
	for nsec, section in enumerate(elf.iter_sections()):
		if section['sh_addr'] <= addr and section['sh_addr'] + section['sh_size'] > addr:
			return section
	return None

def process_nonstatic_vars(elf, gvars):

        global all_pages

        symtab = elf.get_section_by_name('.symtab')

        var_map = {}

        for var in gvars:

                if len(var) == 0 or var[0] != "G":
                        continue
                        
                items = var.split(':')

                syms = symtab.get_symbol_by_name(items[1])

                if not syms: #or len(syms) > 1:
                        print("Warning: missing definition of global variable " + items[1])
                        syms = symtab.get_symbol_by_name(items[1]+"@@GLIBC_2.2.5")
                        if syms:
                                print("\t Note: found it in glibc:" + items[1])
                        else:
                                continue

                if len(syms) > 1:
                        print("Warning: duplicated definition of global variable " + items[1])
                        continue

                sec = get_sec_by_addr(elf, syms[0]['st_value'])
                if sec:
                        if syms[0]['st_size'] != 0 and sec['sh_flags'] & SH_FLAGS.SHF_WRITE and sec['sh_flags'] & SH_FLAGS.SHF_ALLOC:
                                var_map[items[1]] = syms[0]['st_size']
                                all_pages.add(hex(syms[0]['st_value'] & 0xfffffffffffff000))
        return var_map


#example: S:tu_count_ptr_ddsddsbinutilssdwarfdc:tu_count:4
def process_static_vars(elf, gvars):
        
        symtab = elf.get_section_by_name('.symtab')

        var_map = {}

        for var in gvars:

                #not static variables
                if len(var) == 0 or var[0] != "S":
                        continue
                items = var.split(':')
                if len(items) < 3:
                    continue

                ptr_syms = symtab.get_symbol_by_name(items[1])
                var_syms = symtab.get_symbol_by_name(items[2])

                if not var_syms or len(var_syms) == 0:
                        print("Warning: cannot find symbol for static variable " + items[2])
                        continue

                if not ptr_syms or len(ptr_syms) == 0:
                        print("Warning: cannot find symbol for pointer of static variable " + items[2])
                        continue

                if len(var_syms) > 1:
                         print("Warning: find duplicated symbols for static variable " + items[2])

                if var_syms[0]['st_size'] != int(items[3]):
                        print("Warning: conflicting size of variable " + items[2])

                sec = get_sec_by_addr(elf, var_syms[0]['st_value'])
                
                if sec and var_syms[0]['st_size'] != 0 and sec['sh_flags'] & SH_FLAGS.SHF_WRITE and sec['sh_flags'] & SH_FLAGS.SHF_ALLOC:
                        var_map[items[1]] = var_syms[0]['st_size']
                        all_pages.add(hex(var_syms[0]['st_value'] & 0xfffffffffffff000))

        return var_map



def generate_header(fname, f, size):
	f.write("\t.file\t\"" + fname+ "\"\n"
		+ "\t.text\n"
		+ "\t.comm\t" + "shadow," + str(size) + ",32\n")


def generate_snapshot_func(f, static_vars, nonstatic_vars):
    
        global total_vars

        f.write("\t.globl\ttake_snapshot\n")
        f.write("\t.type\ttake_snapshot, @function\n")
        f.write("take_snapshot:\n")
        f.write(".LFB0:\n")
        f.write("\tpushq\t%rbp\n")
        f.write("\tmovq\t%rsp, %rbp\n")
        #load the address of the shadow buffer, so we do not have to get it every time
        f.write("\tleaq\tshadow(%rip), %rax\n")

        for var in static_vars:
                sz = static_vars[var]
                aligned_sz = align_num(sz, 0x4);

		# this would be wired, but let's forget about it for now
                if sz == 0:
                        continue

                if sz == 3 or sz == 5 or sz == 7 or sz == 11:
                        sys.exit("Alert: variable with size " + str(sz))

		#a one-byte variable
                if sz == 1:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovb\t(%r11), %r11b\n")
                        f.write("\tmovb\t%r11b, (%rax)\n")
	
                if sz == 2:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovw\t(%r11), %r11w\n")
                        f.write("\tmovw\t%r11w, (%rax)\n")
                        
                if sz == 4:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmov\t(%r11), %r11d\n")
                        f.write("\tmov\t%r11d, (%rax)\n")

                if sz == 6:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmov\t(%r11), %r11d\n")
                        f.write("\tmov\t%r11d, (%rax)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovw\t0x4(%r11), %r11w\n")
                        f.write("\tmovw\t%r11w, 0x4(%rax)\n")


                if sz == 8:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t(%r11), %r11\n")
                        f.write("\tmovq\t%r11, (%rax)\n")

                if sz == 9:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t(%r11), %r11\n")
                        f.write("\tmovq\t%r11, (%rax)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovb\t0x8(%r11), %r11b\n")
                        f.write("\tmovb\t%r11b, 0x8(%rax)\n")

                if sz == 10:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t(%r11), %r11\n")
                        f.write("\tmovq\t%r11, (%rax)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovw\t0x8(%r11), %r11w\n")
                        f.write("\tmovw\t%r11w, 0x8(%rax)\n")

                if sz == 12:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t(%r11), %r11\n")
                        f.write("\tmovq\t%r11, (%rax)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmov\t0x8(%r11), %r11d\n")
                        f.write("\tmov\t%r11d, 0x8(%rax)\n")

                if sz == 13:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t(%r11), %r11\n")
                        f.write("\tmovq\t%r11, (%rax)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmov\t0x8(%r11), %r11d\n")
                        f.write("\tmov\t%r11d, 0x8(%rax)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovb\t0xc(%r11), %r11b\n")
                        f.write("\tmovb\t%r11b, 0xc(%rax)\n")

                if sz == 14:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t(%r11), %r11\n")
                        f.write("\tmovq\t%r11, (%rax)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmov\t0x8(%r11), %r11d\n")
                        f.write("\tmov\t%r11d, 0x8(%rax)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovw\t0xc(%r11), %r11w\n")
                        f.write("\tmovw\t%r11w, 0xc(%rax)\n")

                if sz == 15:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t(%r11), %r11\n")
                        f.write("\tmovq\t%r11, (%rax)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmov\t0x8(%r11), %r11d\n")
                        f.write("\tmov\t%r11d, 0x8(%rax)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovw\t0xc(%r11), %r11w\n")
                        f.write("\tmovw\t%r11w, 0xc(%rax)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovb\t0xe(%r11), %r11b\n")
                        f.write("\tmovb\t%r11b, 0xe(%rax)\n")

                if sz == 16:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovups\t(%r11), %xmm8\n")
                        f.write("\tmovups\t%xmm8, (%rax)\n")

                #for a big chunk of data, let's do memcpy
                if sz > 16:
                        f.write("\tpush\t%rax\n")
                        f.write("\tmovl\t$"+str(sz) +", %edx\n")
                        f.write("\tmovq\t"+var+"(%rip), %rsi\n")
                        f.write("\tmovq\t%rax, %rdi\n")
                        f.write("\tcall\tmemcpy@PLT\n")
                        f.write("\tpop\t%rax\n")

                f.write("\tadd\t$"+str(aligned_sz)+", %rax\n")
                total_vars += 1
                
        for var in nonstatic_vars:
                sz = nonstatic_vars[var] 
                aligned_sz = align_num(sz, 0x4);
                
                # this would be wired, but let's forget about it for now
                if sz == 0:
                        continue
 
                if sz == 3 or sz == 5 or sz == 7 or sz == 11:
                        sys.exit("Alert: variable with size " + str(sz))
                        
                #a one-byte variable
                if sz == 1:
                        f.write("\tmovb\t"+var+"(%rip), %r11b\n")
                        f.write("\tmovb\t%r11b, (%rax)\n")
                
                if sz == 2:
                        f.write("\tmovw\t"+var+"(%rip), %r11w\n")
                        f.write("\tmovw\t%r11w, (%rax)\n")
                        
                if sz == 4:
                        f.write("\tmov\t"+var+"(%rip), %r11d\n")
                        f.write("\tmov\t%r11d, (%rax)\n")
                        
                if sz == 6:
                        f.write("\tmov\t"+var+"(%rip), %r11d\n")
                        f.write("\tmov\t%r11d, (%rax)\n")

                        f.write("\tmovw\t"+var+"+0x4(%rip), %r11w\n")
                        f.write("\tmovw\t%r11w, 0x4(%rax)\n")

                if sz == 8:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t%r11, (%rax)\n")
                
                if sz == 9:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t%r11, (%rax)\n")

                        f.write("\tmovb\t"+var+"+0x8(%rip), %r11b\n")
                        f.write("\tmovb\t%r11b, 0x8(%rax)\n")

                if sz == 10:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t%r11, (%rax)\n")
                        
                        f.write("\tmovw\t"+var+"+0x8(%rip), %r11w\n")
                        f.write("\tmovw\t%r11w, 0x8(%rax)\n")

                if sz == 12:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t%r11, (%rax)\n")

                        f.write("\tmov\t"+var+"+0x8(%rip), %r11d\n")
                        f.write("\tmov\t%r11d, 0x8(%rax)\n")

                if sz == 13:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t%r11, (%rax)\n")

                        f.write("\tmov\t"+var+"+0x8(%rip), %r11d\n")
                        f.write("\tmov\t%r11d, 0x8(%rax)\n")
                    
                        f.write("\tmovb\t"+var+"+0xc(%rip), %r11b\n")
                        f.write("\tmovb\t%r11b, 0xc(%rax)\n")

                if sz == 14:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t%r11, (%rax)\n")

                        f.write("\tmov\t"+var+"+0x8(%rip), %r11d\n")
                        f.write("\tmov\t%r11d, 0x8(%rax)\n")

                        f.write("\tmovw\t"+var+"+0xc(%rip), %r11w\n")
                        f.write("\tmovw\t%r11w, 0xc(%rax)\n")


                if sz == 15:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t%r11, (%rax)\n")

                        f.write("\tmov\t"+var+"+0x8(%rip), %r11d\n")
                        f.write("\tmov\t%r11d, 0x8(%rax)\n")

                        f.write("\tmovw\t"+var+"+0xc(%rip), %r11w\n")
                        f.write("\tmovw\t%r11w, 0xc(%rax)\n")
                    
                        f.write("\tmovb\t"+var+"+0xe(%rip), %r11b\n")
                        f.write("\tmovb\t%r11b, 0xe(%rax)\n")

                if sz == 16:
                        f.write("\tmovups\t"+var+"(%rip), %xmm8\n")
                        f.write("\tmovups\t%xmm8, (%rax)\n")
                        
                #for a big chunk of data, let's do memcpy
                if sz > 16:
                        f.write("\tpush\t%rax\n")
                        f.write("\tmovl\t$"+str(sz) +", %edx\n")
                        f.write("\tleaq\t"+var+"(%rip), %rsi\n")
                        f.write("\tmovq\t%rax, %rdi\n")
                        f.write("\tcall\tmemcpy@PLT\n")
                        f.write("\tpop\t%rax\n")

                f.write("\tadd\t$"+str(aligned_sz)+", %rax\n")
                total_vars += 1
        
        f.write("\tpopq\t%rbp\n")
        f.write("\tret\n")
        f.write(".LFE0:\n")
        f.write("\t.size   take_snapshot, .-take_snapshot\n")

def generate_restore_func(f, static_vars, nonstatic_vars):

        #global variable recovery function
        f.write("\t.globl\trestore_snapshot\n")
        f.write("\t.type\trestore_snapshot, @function\n")
        f.write("restore_snapshot:\n")
        f.write(".LFB1:\n")
        f.write("\tpushq\t%rbp\n")
        f.write("\tmovq\t%rsp, %rbp\n")
        #load the address of the shadow buffer, so we do not have to get it every time
        f.write("\tleaq\tshadow(%rip), %rax\n")

        for var in static_vars:
                sz = static_vars[var]
                aligned_sz = align_num(sz, 0x4);

		# this would be wired, but let's forget about it for now
                if sz == 0:
                        continue

                if sz == 3 or sz == 5 or sz == 7 or sz == 11:
                        sys.exit("Alert: variable with size " + str(sz))

		#a one-byte variable
                if sz == 1:
                        #load gv location from gv_ptr; load byte from shadow memory; save byte to gv
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovb\t(%rax), %r10b\n")
                        f.write("\tmovb\t%r10b, (%r11)\n")
	
                if sz == 2:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovw\t(%rax), %r10w\n")
                        f.write("\tmovw\t%r10w, (%r11)\n")
                        
                if sz == 4:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmov\t(%rax), %r10d\n")
                        f.write("\tmov\t%r10d, (%r11)\n")

                if sz == 6:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmov\t(%rax), %r10\n")
                        f.write("\tmov\t%r10, (%r11)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovw\t0x4(%rax), %r10w\n")
                        f.write("\tmovw\t%r10w, 0x4(%r11)\n")

                if sz == 8:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t(%rax), %r10\n")
                        f.write("\tmovq\t%r10, (%r11)\n")

                if sz == 9:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t(%rax), %r10\n")
                        f.write("\tmovq\t%r10, (%r11)\n")
                
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovb\t0x8(%rax), %r10b\n")
                        f.write("\tmovb\t%r10b, 0x8(%r11)\n")
 

                if sz == 10:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t(%rax), %r10\n")
                        f.write("\tmovq\t%r10, (%r11)\n")
                
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovw\t0x8(%rax), %r10w\n")
                        f.write("\tmovw\t%r10w, 0x8(%r11)\n")
                

                if sz == 12:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t(%rax), %r10\n")
                        f.write("\tmovq\t%r10, (%r11)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmov\t0x8(%rax), %r10d\n")
                        f.write("\tmov\t%r10d, 0x8(%r11)\n")

                if sz == 13:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t(%rax), %r10\n")
                        f.write("\tmovq\t%r10, (%r11)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmov\t0x8(%rax), %r10d\n")
                        f.write("\tmov\t%r10d, 0x8(%r11)\n")
                        
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovb\t0xc(%rax), %r10b\n")
                        f.write("\tmovb\t%r10b, 0xc(%r11)\n")


                if sz == 14:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t(%rax), %r10\n")
                        f.write("\tmovq\t%r10, (%r11)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmov\t0x8(%rax), %r10d\n")
                        f.write("\tmov\t%r10d, 0x8(%r11)\n")
                
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovw\t0xc(%rax), %r10w\n")
                        f.write("\tmovw\t%r10w, 0xc(%r11)\n")

                if sz == 15:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovq\t(%rax), %r10\n")
                        f.write("\tmovq\t%r10, (%r11)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmov\t0x8(%rax), %r10d\n")
                        f.write("\tmov\t%r10d, 0x8(%r11)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovw\t0xc(%rax), %r10w\n")
                        f.write("\tmovw\t%r10w, 0xc(%r11)\n")

                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovb\t0xe(%rax), %r10b\n")
                        f.write("\tmovb\t%r10b, 0xe(%r11)\n")

                if sz == 16:
                        f.write("\tmovq\t"+var+"(%rip), %r11\n")
                        f.write("\tmovups\t(%rax), %xmm8\n")
                        f.write("\tmovups\t%xmm8, (%r11)\n")
		#for a big chunk of data, let's do memcpy
                if sz > 16:

                        f.write("\tpush\t%rax\n")
                        f.write("\tmovl\t$"+str(sz) +", %edx\n")
                        f.write("\tmovq\t"+var+"(%rip), %rsi\n")
                        f.write("\tmovq\t%rax, %rdi\n")
                        f.write("\tcall\tmemcpy@PLT\n")
                        f.write("\tpop\t%rax\n")
                
                f.write("\tadd\t$"+str(aligned_sz)+", %rax\n")
                
        for var in nonstatic_vars:
                sz = nonstatic_vars[var] 
                aligned_sz = align_num(sz, 0x4);
                
                # this would be wired, but let's forget about it for now
                if sz == 0:
                        continue
 
                if sz == 3 or sz == 5 or sz == 7 or sz == 11:
                        sys.exit("Alert: variable with size " + str(sz))
                        
                #a one-byte variable
                #move the one byte from the shadow memory to r11b and then move that to the destination
                if sz == 1:
                        f.write("\tmovb\t(%rax), %r11b\n")
                        f.write("\tmovb\t %r11b, "+var+"(%rip)\n")
                
                if sz == 2:
                        f.write("\tmovw\t(%rax), %r11w\n")
                        f.write("\tmovw\t %r11w, "+var+"(%rip)\n")
                        
                if sz == 4:
                        f.write("\tmov\t(%rax), %r11d\n")
                        f.write("\tmov\t %r11d, "+var+"(%rip)\n")

                if sz == 6:
                        f.write("\tmov\t(%rax), %r11d\n")
                        f.write("\tmov\t %r11d, "+var+"(%rip)\n")

                        f.write("\tmovw\t0x4(%rax), %r11w\n")
                        f.write("\tmovw\t %r11w, "+var+"+0x4(%rip)\n")

                if sz == 8:
                        f.write("\tmovq\t(%rax), %r11\n")
                        f.write("\tmovq\t %r11, "+var+"(%rip)\n")

                if sz == 9:
                        f.write("\tmovq\t(%rax), %r11\n")
                        f.write("\tmovq\t %r11, "+var+"(%rip)\n")

                        f.write("\tmovb\t0x8(%rax), %r11b\n")
                        f.write("\tmovb\t %r11b, "+var+"+0x8(%rip)\n")

                if sz == 10:
                        f.write("\tmovq\t(%rax), %r11\n")
                        f.write("\tmovq\t %r11, "+var+"(%rip)\n")

                        f.write("\tmovw\t0x8(%rax), %r11w\n")
                        f.write("\tmovw\t %r11w, "+var+"+0x8(%rip)\n")


                if sz == 12:
                        f.write("\tmovq\t(%rax), %r11\n")
                        f.write("\tmovq\t %r11, "+var+"(%rip)\n")

                        f.write("\tmov\t0x8(%rax), %r11d\n")
                        f.write("\tmov\t %r11d, "+var+"+0x8(%rip)\n")

                if sz == 13:
                        f.write("\tmovq\t(%rax), %r11\n")
                        f.write("\tmovq\t %r11, "+var+"(%rip)\n")

                        f.write("\tmov\t0x8(%rax), %r11d\n")
                        f.write("\tmov\t %r11d, "+var+"+0x8(%rip)\n")
               
                        f.write("\tmovb\t0xc(%rax), %r11b\n")
                        f.write("\tmovb\t %r11b, "+var+"+0xc(%rip)\n")

                if sz == 14:
                        f.write("\tmovq\t(%rax), %r11\n")
                        f.write("\tmovq\t %r11, "+var+"(%rip)\n")

                        f.write("\tmov\t0x8(%rax), %r11d\n")
                        f.write("\tmov\t %r11d, "+var+"+0x8(%rip)\n")

                        f.write("\tmovw\t0xc(%rax), %r11w\n")
                        f.write("\tmovw\t %r11w, "+var+"+0xc(%rip)\n")


                if sz == 15:
                        f.write("\tmovq\t(%rax), %r11\n")
                        f.write("\tmovq\t %r11, "+var+"(%rip)\n")

                        f.write("\tmov\t0x8(%rax), %r11d\n")
                        f.write("\tmov\t %r11d, "+var+"+0x8(%rip)\n")

                        f.write("\tmovw\t0xc(%rax), %r11w\n")
                        f.write("\tmovw\t %r11w, "+var+"+0xc(%rip)\n")

                        f.write("\tmovb\t0xe(%rax), %r11b\n")
                        f.write("\tmovb\t %r11b, "+var+"+0xe(%rip)\n")

                if sz == 16:
                        f.write("\tmovups\t(%rax), %xmm8\n")
                        f.write("\tmovups\t %xmm8, "+var+"(%rip)\n")

                #for a big chunk of data, let's do memcpy
                if sz > 16:
                        f.write("\tpush\t%rax\n")
                        f.write("\tmovl\t$"+str(sz) +", %edx\n")
                        f.write("\tmovq\t%rax, %rsi\n")
                        f.write("\tleaq\t"+var+"(%rip), %rdi\n")
                        f.write("\tcall\tmemcpy@PLT\n")
                        f.write("\tpop\t%rax\n")

                f.write("\tadd\t$"+str(aligned_sz)+", %rax\n")
        
        f.write("\tpopq\t%rbp\n")
        f.write("\tret\n")
        f.write(".LFE1:\n")
        f.write("\t.size   restore_snapshot, .-restore_snapshot\n")

def generate_asm(asm_file, static_vars, nonstatic_vars):

	#get the size needed in total to keep the global vars
	size = 0

	for var in static_vars:
		sz = static_vars[var]
		size += align_num(sz, 0x4)

	for var in nonstatic_vars:
		sz = nonstatic_vars[var]
		size += align_num(sz, 0x4)

	# now let's generate the asm file
	try:
		f = open(asm_file, 'w')
		generate_header(asm_file, f, size)
		generate_snapshot_func(f, static_vars, nonstatic_vars)
		generate_restore_func(f, static_vars, nonstatic_vars)
                #generate_recovery_func(f, processed_vars)

	except IOError as e:
		print("Error: cannot create the file to save the assembly code")
		print(e)
            
	return size


if __name__ == "__main__":
        
        if len(sys.argv) != 4:
                print("Usage: python3 gen_asm.py /path/to/target/binary /path/to/global_var/list /path/to/generated/asmfile")
                exit(1)
        
        elf = load_elf(sys.argv[1])
        
        gvars = load_vars(sys.argv[2])
        
        static_vars = process_static_vars(elf, gvars)

        nonstatic_vars = process_nonstatic_vars(elf, gvars)
        
        size = generate_asm(sys.argv[3], static_vars, nonstatic_vars)

        print("Total processed vars:", str(total_vars))
        print("Total memory pages to be modified: ", len(all_pages))
        print("Total number of bytes to be recovered: ", size)
