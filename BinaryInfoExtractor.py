'''
Created on 2014-12-2
fix in python 3.x by datahackor 2022-06-20
@author: M.R. Farhadi
'''

import idaapi
import idautils
import idc
import ida_kernwin
import _locale
_locale._getdefaultlocale = (lambda *args: ['cp1252', 'ISO-8859-1'])

def block_split(output_file, start_ea, end_ea):
    curName = get_func_name(start_ea);
    dem = idc.demangle_name(curName, idc.get_inf_attr(INF_SHORT_DN));
    if dem != None:
        curName = dem;
    
    first=start_ea
    h = idautils.Heads(start_ea, end_ea)
    for i in h:
        mnem = idc.print_insn_mnem(i)
        if mnem == "call" and i != end_ea:
            first=idc.next_head(i, end_ea+1)
            #print ("		CALL ADDRESS: %#x" % (i), file=output_file)
           
# end of block_split
#------------------------------------------------------------------------------------------------------------------------

def function_extract(output_file, func, cg_adjmat, funcs_id, callees, asm_filename):
    func_name = get_func_name(func)
    function_start_phrase = func_name + " proc near" 
    function_end_phrase = func_name + " endp" 

    print ("+++++++++++++++++++++++++++++" , file=output_file)
    print ("Function Name: %s" % (func_name), file=output_file)
    print ("     Function ID: %s" % (funcs_id[func_name]), file=output_file)
    func_asm_start_address = get_line_number(function_start_phrase, asm_filename)
    func_asm_end_address = get_line_number(function_end_phrase, asm_filename)
    print ("     ASM File Starting Address: %#s" % (func_asm_start_address), file=output_file)
    print ("     ASM File Ending Address: %#s" % (func_asm_end_address), file=output_file)
    print ("     Binary File Starting Address: %#x" % (func), file=output_file)
    print ("     Binary File Ending Address: %#x" % (find_func_end(func)), file=output_file)
    print ("", file=output_file)
    print ("     Caller Functions:", file=output_file)
    
    for ref_ea in CodeRefsTo(func, 0):    
        caller_name = get_func_name(ref_ea)
        callees[caller_name] = callees.get(caller_name,set()) #add the functions from "CodesRefsTo" to a dictionary for extracting CG and CG adjacency Matrix
        callees[caller_name].add(func_name)  
        print ("		%s" % (caller_name), file=output_file)
    
# end of function_extract
#------------------------------------------------------------------------------------------------------------------------

def function_export(func_ea,func_name_):

    func_name = get_func_name(func_ea)
    if(func_name_==func_name):
        filepath = sprintf("%s\\func_%s.asm", get_idb_dir(), func_name);
        f_asm = fopen(filepath, "w+");
        idc.gen_file(idc.OFILE_ASM, f_asm, func_ea, (find_func_end(func_ea)), 0);
        msg("path: %s\n", filepath);
        print (";Starting Address: %#x" % (func_ea), file=f_asm)

    
# end of function_export
#------------------------------------------------------------------------------------------------------------------------

def cg_extract(output_file, cg_adjmat, funcs_id, callees, func_num):
    functions = callees.keys()
    
    for key in functions:
        cg_row =['null']*func_num
        print ("Function: %s " % (key) , file=output_file)
        if callees.__contains__(key):
            for calling in callees[key]:
                cg_row[funcs_id[calling]] = calling
                print ("	%s " % (calling), file=output_file)
        #print ("cg_row: ", cg_row, file=output_file)
        if key in funcs_id:
            cg_adjmat[funcs_id[key]].append(cg_row)            
                                                          
    print ("CG Adjacency Matrix:\n", file=output_file)
    funcs_id_key_list = list(funcs_id.keys())
    funcs_id_val_list = list(funcs_id.values())
    cnt = 0
    for cg_row in cg_adjmat:
        if len(cg_row) > 0:
            for it in cg_row[0][:]: # remove empty value
                if it == 'null':
                    cg_row[0].remove(it)
        print ("Function [%s]: " %(funcs_id_key_list[funcs_id_val_list.index(cnt)]) , cg_row, file=output_file)
        cnt += 1

# end of cg_extract
#------------------------------------------------------------------------------------------------------------------------

def BB_extract(output_file, func, asmplus_filename):
    cnt = 0
    f = idaapi.FlowChart(idaapi.get_func(func))
    cfg_adjmat = []
    
    for block in f:
        cfg_row =[0]*f.size
        print ("", file=output_file)
        print ("	Basic Block:", file=output_file)
        block_split(output_file, block.start_ea, block.end_ea)
        print ("		BB_ID: [%d]" % (block.id), file=output_file)
        
        bb_asm_start_address = "{0:x}".format(block.start_ea)
        bb_asm_end_address = "{0:x}".format(block.end_ea)        
        
        print ("		ASM File Starting Address: %#s" % (get_line_number(bb_asm_start_address.upper(), asmplus_filename)), file=output_file)
        print ("		ASM File Ending Address: %#s" % (get_line_number(bb_asm_end_address.upper(), asmplus_filename) - 1 ), file=output_file)
        
        print ("		Binary File Starting Address: %#x" % (block.start_ea), file=output_file)
        print ("		Binary File Ending Address: %#x" % (block.end_ea), file=output_file)
        
        print ("		Basic Block Successors:", file=output_file)
        
        for succ_block in block.succs():
            cfg_row[succ_block.id] = 1
            print ("			Starting Address: %x - Ending Address: %x - BB_ID: [%d]" % (succ_block.start_ea, succ_block.end_ea, succ_block.id), file=output_file)
        #print ("Basic Block predecessors:"
        #for pred_block in block.preds():
        #   print ("Starting Address: %x - Ending Address: %x BB_ID:[%d]:" % (pred_block.start_ea, pred_block.end_ea, pred_block.id)
        cfg_adjmat.append(cfg_row)
        print ("-----------------------------"	, file=output_file)
            
    print ("CFG Adjacency Matrix for Function: %s\n" % (get_func_name(func)), file=output_file)
    for cfg_row in cfg_adjmat:
        print ("BB_ID [%d]: " %(cnt), cfg_row, file=output_file)
        cnt += 1
        print ("\n", file=output_file)
        
# end of BB_extract
#------------------------------------------------------------------------------------------------------------------------

def get_line_number(phrase, file_name):
	try:
		with open(file_name) as f:
			for i, line in enumerate(f, 1):
				if phrase in line:
					return i
					
	finally:
		return i
# end of get_line_number
#------------------------------------------------------------------------------------------------------------------------
                
def controller():
    funcs_id = dict()  # to store functions and their IDs 
    callees = dict()
    func_num = 0
    func_id = 0
    cg_adjmat = []
    info_filename = ida_kernwin.ask_file(1, "*.*", "Extract Binary File Info")

    basename = idc.get_input_file_path()
    info_filename = basename + ".info"    
    asm_filename = basename + ".asm"  
    asmplus_filename = basename + ".asmplus"    
    idc.gen_file(idc.OFILE_ASM, basename + ".asm", 0, idc.BADADDR, 0)
    idc.gen_file(idc.OFILE_LST, basename + ".asmplus", 0, idc.BADADDR, 0)
         
    output_file = open(info_filename,'w+')        
    asm_file = open(asm_filename,'r')
    asmplus_file = open(asm_filename,'r')
    
    funcs = idautils.Functions()
    funcs_iterator = idautils.Functions()
    
    # scan all functions to extract number of functions and add them to the funcs_id
    for i in funcs_iterator:
        func_name = get_func_name(i)
        funcs_id.update({func_name:func_id})
        func_num += 1
        func_id += 1
        cg_adjmat.append([])
        
    for f in funcs:        
        func_name = get_func_name(f)     
		#function_export(f,"yyparse")
        function_extract(output_file, f, cg_adjmat, funcs_id, callees, asm_filename) # extract functions data
        BB_extract(output_file, f, asmplus_filename) # extract basic blocks data, CFG and CFG adjacency matrices                                

    cg_extract(output_file, cg_adjmat, funcs_id, callees, func_num) # extract CG and CG adjacency matrix

        
# end of controller
#------------------------------------------------------------------------------------------------------------------------      

q = None
f = None
idc.auto_wait()
controller()

