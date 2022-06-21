#include <idc.idc>

static get_idb_dir() {
  auto file_full_path = get_idb_path();
  auto idbdir = qdirname(file_full_path);
  return idbdir;
}

static main() {
  auto cea = ScreenEA();
  msg("ea = 0x08%x\n", cea);

  auto addr_func_start = get_func_attr(cea, FUNCATTR_START);
  auto addr_func_end = get_func_attr(cea, FUNCATTR_END);
  if (addr_func_start != -1 && addr_func_end != -1) {
    if (addr_func_start >= addr_func_end) {
      msg("ERR: start addr <= end addr");
      return;
    }

    msg("func start: %08x\n", addr_func_start);
    msg("func end  : %08x\n", addr_func_end);

    auto filepath = sprintf("%s\\func_%08x.asm", get_idb_dir(), addr_func_start);
    msg("path: %s\n", filepath);
    auto hf = fopen(filepath, "w+");
    if (hf != 0) {
      auto f = gen_file(OFILE_ASM, hf, addr_func_start, addr_func_end, GENFLG_ASMTYPE);
      if (f != -1) {
        msg("make asm file ok.\n");
      } else {
        msg("ERR: gen_file error.\n");
      }
    } else {
      msg("ERR: fopen %s error.\n", filepath);
    }
  } else {
    msg("ERR: find func error.\n");
  }
}#include <idc.idc>

static get_idb_dir() {
  auto file_full_path = get_idb_path();
  auto idbdir = qdirname(file_full_path);
  return idbdir;
}

static main() {
  auto cea = ScreenEA();
  msg("ea = 0x08%x\n", cea);
  auto func_name = get_func_name(cea);
  auto eas = object();// = {0x404F80,0x404FC0,0x405020,0x405060,0x4050C0,0x405120,0x4063A0,0x406C80,0x406BA0,0x406E00,0x4076E0,0x4077B0,0x407500,0x407820};
  eas[0] =  0x404F80;
  eas[1] =  0x404FC0;
  eas[2] =  0x405020;
  eas[3] =  0x405060;
  eas[4] =  0x4050C0;
  eas[5] =  0x405120;
  eas[6] =  0x4063A0;
  eas[7] =  0x406C80;
  eas[8] =  0x406BA0;
  eas[9] =  0x406E00;
  eas[10] =  0x4076E0;
  eas[11] =  0x4077B0;
  eas[12] =  0x407500;
  eas[13] =  0x407820;
  eas[14] =  0x406E10;
  auto ea_size = 15,i = 0 ,addr_func_start,addr_func_end,asm_string;
  auto wfilepath = sprintf("%s\\yyparse.asm", get_idb_dir());
  auto filepath = sprintf("%s\\tempxxx.asm", get_idb_dir());
  auto filehandle = fopen(wfilepath,"w+");
  for(i = 0;i < ea_size; i++)
  {
    cea = eas[i];
	  addr_func_start = get_func_attr(cea, FUNCATTR_START);
	  addr_func_end = get_func_attr(cea, FUNCATTR_END);
	  if (addr_func_start != -1 && addr_func_end != -1) {
	    if (addr_func_start >= addr_func_end) {
	      msg("ERR: start addr <= end addr");
	      return;
	    }

	    msg("func start: %08x\n", addr_func_start);
	    msg("func end  : %08x\n", addr_func_end);

	    
	    //msg("path: %s\n", filepath);
	    auto hf = fopen(filepath, "w+");
	    if (hf != 0) {
	      auto f = gen_file(OFILE_ASM, hf, addr_func_start, addr_func_end, GENFLG_ASMTYPE);
	      if (f != -1) {
		msg("make asm file ok.\n");
		fclose(hf);
		auto toPrint;
		auto stream = fopen(filepath, "r"); 
		do {
			toPrint = readstr(stream);
			 if (toPrint != -1)
			   writestr(filehandle,toPrint);
		    } while (toPrint != -1);
		
	      } else {
		msg("ERR: gen_file error.\n");
	      }
	    } else {
	      msg("ERR: fopen %s error.\n", filepath);
	    }
	  } else {
	    msg("ERR: find func error.\n");
	  }
  }

}
