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
}