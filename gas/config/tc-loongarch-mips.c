#include "as.h"
#include "tc-loongarch.h"
#include "opcode/loongarch.h"

/* pinfo of MIPS insns */
#define MIPS_HAS_DELAYSLOT 0x1l
#define MIPS_IS_LIKELY_BRANCH 0x2l

static const char * const mips_r_direct_map[32] =
{
  "$0", "$1", "$2", "$3", "$4", "$5", "$6", "$7",
  "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15",
  "$16", "$17", "$18", "$19", "$20", "$21", "$22", "$23",
  "$24", "$25", "$26", "$27", "$28", "$29", "$30", "$31",
};

static const char * const mips_r_n64_to_lp64_map[32] =
{
  "$0", "$31", "$28", "$29", "$4", "$5", "$6", "$7",
  "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15",
  "$25", "$2", "$3", "", "$24", "", "$30", "$16",
  "$17", "$18", "$19", "$20", "$21", "$22", "$23", "$28",
};

static const char * const mips_r_n64_to_lp64_map1[32] =
{
  "$zero", "$ra", "$gp", "$sp", "$a0", "$a1", "$a2", "$a3",
  "$a4", "$a5", "$a6", "$a7", "$t0", "$t1", "$t2", "$t3",
  "$t9", "$v0", "$v1", "", "$t8", "", "$s8", "$s0",
  "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7", "$gp",
};

static const char * const mips_r_n64_to_lp64_map2[32] =
{
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "$fp", "",
  "", "", "", "", "", "", "", "",
};

/* FIXME!!!!!!!! FOR BIOS ASKING!!!!!!!!! */
static const char * const mips_r_n64_to_lp64_map3[32] =
{
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "$r17", "$r18", "", "", "$r21", "$r22", "",
  "", "", "", "", "", "", "", "",
};

static const char * const mips_f_direct_map[32] =
{
  "$f0", "$f1", "$f2", "$f3", "$f4", "$f5", "$f6", "$f7",
  "$f8", "$f9", "$f10", "$f11", "$f12", "$f13", "$f14", "$f15",
  "$f16", "$f17", "$f18", "$f19", "$f20", "$f21", "$f22", "$f23",
  "$f24", "$f25", "$f26", "$f27", "$f28", "$f29", "$f30", "$f31",
};

static const char * const mips_f_n64_to_lp64_map[32] =
{
  "$f12", "$f13", "$f14", "$f15", "$f16", "$f17", "$f18", "$f19",
  "$f1", "$f3", "$f4", "$f5", "$f6", "$f7", "$f8", "$f9",
  "$f10", "$f11", "$f20", "$f21", "$f22", "$f23", "$f0", "$f2",
  "$f24", "$f25", "$f26", "$f27", "$f28", "$f29", "$f30", "$f31",
};

static const char * const mips_c_direct_map[8] =
{
  "$fcc0", "$fcc1", "$fcc2", "$fcc3", "$fcc4", "$fcc5", "$fcc6", "$fcc7",
};

static const char * const loongarch_r_mips_o32_name[32] =
{
  "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
  "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
  "$t8", "$t9", "$s0", "$s1", "$s2", "$s3", "$s4", "$s5",
  "$s6", "$s7", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
};

static const char * const loongarch_r_mips_n32_n64_name[32] =
{
  "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
  "$a4", "$a5", "$a6", "$a7", "$t4", "$t5", "$t6", "$t7",
  "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
  "$t8", "$t9", "$kt0", "$kt1", "$gp", "$sp", "$fp", "$ra",
};

static const char * const loongarch_r_mips_o32_n32_n64_name1[32] =
{
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "$s8", "",
};

static const char * const mips_v_direct_map[32] =
{
  "$w0", "$w1", "$w2", "$w3", "$w4", "$w5", "$w6", "$w7",
  "$w8", "$w9", "$w10", "$w11", "$w12", "$w13", "$w14", "$w15",
  "$w16", "$w17", "$w18", "$w19", "$w20", "$w21", "$w22", "$w23",
  "$w24", "$w25", "$w26", "$w27", "$w28", "$w29", "$w30", "$w31",
};

static const char * const mips_x_direct_map[32] =
{
  "$x0", "$x1", "$x2", "$x3", "$x4", "$x5", "$x6", "$x7",
  "$x8", "$x9", "$x10", "$x11", "$x12", "$x13", "$x14", "$x15",
  "$x16", "$x17", "$x18", "$x19", "$x20", "$x21", "$x22", "$x23",
  "$x24", "$x25", "$x26", "$x27", "$x28", "$x29", "$x30", "$x31",
};

static struct hash_control *mips_r_map_htab = NULL;
static struct hash_control *mips_f_map_htab = NULL;
static struct hash_control *mips_c_map_htab = NULL;
static struct hash_control *mips_v_map_htab = NULL;
static struct hash_control *mips_x_map_htab = NULL;

struct mips_converter_opts {
  struct mips_converter_opts *next;
  int mips_branch_has_delay_slot;
};
static struct mips_converter_opts *MIPS_opts = NULL;

static struct loongarch_ase loongarch_mips_ASEs[];

static void
init_MIPS_opts (struct mips_converter_opts *opts)
{
  opts->next = NULL;
  opts->mips_branch_has_delay_slot = 0;
}

static void
s_loongarch_mips_set (int x ATTRIBUTE_UNUSED)
{
  char *name = input_line_pointer, ch;

  while (!is_end_of_line[(unsigned char) *input_line_pointer])
    ++input_line_pointer;
  ch = *input_line_pointer;
  *input_line_pointer = '\0';

  if (strchr (name, ','))
    {
      /* Generic ".set" directive; use the generic handler.  */
      *input_line_pointer = ch;
      input_line_pointer = name;
      s_set (0);
      return;
    }

  if (strcmp (name, "reorder") == 0)
    MIPS_opts->mips_branch_has_delay_slot = 0;
  else if (strcmp (name, "noreorder") == 0)
    MIPS_opts->mips_branch_has_delay_slot = 1;
  else if (strcmp (name, "push") == 0)
    {
      struct mips_converter_opts *s = XNEW (struct mips_converter_opts);
      init_MIPS_opts (s);
      s->next = MIPS_opts;
      MIPS_opts = s;
    }
  else if (strcmp (name, "pop") == 0)
    {
      struct mips_converter_opts *s = MIPS_opts->next;
      if (s == NULL)
	as_fatal (_(".set pop with no .set push"));
      else
	{
	  free (MIPS_opts);
	  MIPS_opts = s;
	}
    }

  *input_line_pointer = ch;
  demand_empty_rest_of_line ();
}

static void
s_loongarch_mips_abicalls (int x ATTRIBUTE_UNUSED)
{
  as_fatal ("\n"
"LoongISA-MIPS translation not support abicalls and explicit relocs.\n"
"Re-compile src with '-mno-abicalls -mno-explicit-relocs'.");
}

static void
s_loongarch_mips_nan (int x ATTRIBUTE_UNUSED)
{
  char *name = input_line_pointer, ch;

  while (!is_end_of_line[(unsigned char) *input_line_pointer])
    ++input_line_pointer;
  ch = *input_line_pointer;
  *input_line_pointer = '\0';

  if (strcmp (name, "2008") != 0)
    as_fatal ("\n"
"LoongISA support IEEE 754-2008 only, legacy IEEE 754 MIPS procedure will\n"
"result to fail. Re-compile src with '-mnan=2008 -mabs=2008'.");

  *input_line_pointer = ch;
  demand_empty_rest_of_line ();
}

static void
s_loongarch_mips_change_sec (int sec)
{
  segT seg;

#ifdef OBJ_ELF
  /* The ELF backend needs to know that we are changing sections, so
     that .previous works correctly.  We could do something like check
     for an obj_section_change_hook macro, but that might be confusing
     as it would not be appropriate to use it in the section changing
     functions in read.c, since obj-elf.c intercepts those.  FIXME:
     This should be cleaner, somehow.  */
  obj_elf_section_change_hook ();
#endif
  switch (sec)
    {
    case 'r':
      seg = subseg_new (".rodata", (subsegT) get_absolute_expression ());
      bfd_set_section_flags (stdoutput, seg, (SEC_ALLOC | SEC_LOAD | SEC_READONLY | SEC_RELOC | SEC_DATA));
      if (strcmp (TARGET_OS, "elf") != 0)
	record_alignment (seg, 4);
      demand_empty_rest_of_line ();
      break;
    case 's':
      seg = subseg_new (".sdata", (subsegT) get_absolute_expression ());
      bfd_set_section_flags (stdoutput, seg, SEC_ALLOC | SEC_LOAD | SEC_RELOC | SEC_DATA);
      if (strcmp (TARGET_OS, "elf") != 0)
	record_alignment (seg, 4);
      demand_empty_rest_of_line ();
      break;
    }
}

static const pseudo_typeS loongarch_mips_pseudo_table[] =
{
  {"align", s_loongarch_align, -4},
  {"rdata", s_loongarch_mips_change_sec, 'r'},
  {"ent", s_ignore, 0},
  {"end", s_ignore, 0},
  {"set", s_loongarch_mips_set, 0},
  {"frame", s_ignore, 0},
  {"mask", s_ignore, 0},
  {"fmask", s_ignore, 0},
  {"insn", s_ignore, 0},
  {"cpload", s_ignore, 0},
  {"cpsetup", s_ignore, 0},
  {"cprestore", s_ignore, 0},
  {"cpreturn", s_ignore, 0},
  {"cplocal", s_ignore, 0},
  {"abicalls", s_loongarch_mips_abicalls, 0},
  {"nan", s_loongarch_mips_nan, 0},
  {"module", s_ignore, 0},
  {"dword", cons, 8},
  {"word", cons, 4},
  {"half", cons, 2},
  {"dtprelword", s_dtprel, 4},
  {"dtpreldword", s_dtprel, 8},
  {"asciiz", stringer, 8 + 1},
  { NULL, NULL, 0 },
};

static void
loongarch_mips_converter_init (void)
{
  if (LARCH_opts.ase_test)
    {
      const struct loongarch_opcode *it;
      struct loongarch_ase *ase;
      for (ase = loongarch_mips_ASEs; ase->enabled; ase++)
	for (it = ase->opcodes; it->name; it++)
	  {
	    if (loongarch_check_format (it->format) != 0)
	      as_fatal (_("MIPS insn name: %s\tformat: %s\tsyntax error"),
			it->name, it->format);
	    if (it->macro == 0)
	      as_fatal (_("insn name: %s\nformat: %s\n"
			  "We want all MIPS insns are macro insn\n"
			  "Make sure 'mask' is 0 and 'macro' is not NULL"),
			it->name, it->format);
	    if (it->macro && loongarch_check_macro (it->format, it->macro) != 0)
	      as_fatal (_("MIPS insn name: %s\nformat: %s\n"
			  "macro: %s\tsyntax error"),
			it->name, it->format, it->macro);
	  }
    }

  size_t i;

  MIPS_opts = XNEW (struct mips_converter_opts);
  init_MIPS_opts (MIPS_opts);

  ASM_opts.mips_ase_fix = 1;
  ASM_opts.mips_ase_float = 1;
  ASM_opts.mips_ase_msa = 1;
  ASM_opts.mips_ase_lasx = 1;

  if (ASM_opts.mips_abi_is_n64 == 0)
    {
      as_warn (_("We just support for MIPS n64 map to LoongISA lp64"));
      ASM_opts.mips_abi_is_n64 = 1;
    }

  if (!mips_r_map_htab)
    {
      mips_r_map_htab = hash_new ();
      hash_insert (mips_r_map_htab, "", 0);
    }
  if (!mips_f_map_htab)
    {
      mips_f_map_htab = hash_new ();
      hash_insert (mips_f_map_htab, "", 0);
    }
  if (!mips_c_map_htab)
    {
      mips_c_map_htab = hash_new ();
      hash_insert (mips_c_map_htab, "", 0);
    }
  if (!mips_v_map_htab)
    {
      mips_v_map_htab = hash_new ();
      hash_insert (mips_v_map_htab, "", 0);
    }
  if (!mips_x_map_htab)
    {
      mips_x_map_htab = hash_new ();
      hash_insert (mips_x_map_htab, "", 0);
    }

  if (LARCH_opts.abi_is_lp64 && ASM_opts.mips_abi_is_n64)
    {
      for (i = 0; i < ARRAY_SIZE (mips_r_n64_to_lp64_map); i++)
	hash_insert
	  (mips_r_map_htab, mips_r_n64_to_lp64_map[i], (void *) (i + 1));
      for (i = 0; i < ARRAY_SIZE (mips_r_n64_to_lp64_map1); i++)
	hash_insert
	  (mips_r_map_htab, mips_r_n64_to_lp64_map1[i], (void *) (i + 1));
      for (i = 0; i < ARRAY_SIZE (mips_r_n64_to_lp64_map2); i++)
	hash_insert
	  (mips_r_map_htab, mips_r_n64_to_lp64_map2[i], (void *) (i + 1));
      for (i = 0; i < ARRAY_SIZE (mips_r_n64_to_lp64_map3); i++)
	hash_insert
	  (mips_r_map_htab, mips_r_n64_to_lp64_map3[i], (void *) (i + 1));
      for (i = 0; i < ARRAY_SIZE (mips_f_n64_to_lp64_map); i++)
	hash_insert
	  (mips_f_map_htab, mips_f_n64_to_lp64_map[i], (void *) (i + 1));
      hash_insert (r_htab, "$at", (void *) 20); // for those MIPS insn need 'at' to expand
    }
  else if (ASM_opts.mips_abi_is_n64)
    as_fatal (_("MIPS n64 can only map to LoongISA lp64"));
  else if (ASM_opts.mips_abi_is_n32)
    as_fatal (_("not support n32"));
  else if (ASM_opts.mips_abi_is_o32)
    as_fatal (_("not support o32"));
  else
    {
      for (i = 0; i < ARRAY_SIZE (mips_r_direct_map); i++)
        hash_insert (mips_r_map_htab, mips_r_direct_map[i], (void *) (i + 1));
      for (i = 0; i < ARRAY_SIZE (mips_f_direct_map); i++)
        hash_insert (mips_f_map_htab, mips_f_direct_map[i], (void *) (i + 1));
    }

  for (i = 0; i < ARRAY_SIZE (mips_c_direct_map); i++)
    hash_insert (mips_c_map_htab, mips_c_direct_map[i], (void *) (i + 1));
  for (i = 0; i < ARRAY_SIZE (mips_v_direct_map); i++)
    hash_insert (mips_v_map_htab, mips_v_direct_map[i], (void *) (i + 1));
  for (i = 0; i < ARRAY_SIZE (mips_x_direct_map); i++)
    hash_insert (mips_x_map_htab, mips_x_direct_map[i], (void *) (i + 1));
}

static int
tc_loongarch_mips_dw2regnum_mapping (int regnum)
{
  if (0 <= regnum && regnum < 32)
    regnum =
      (offsetT) hash_find (mips_r_map_htab, mips_r_direct_map[regnum]) - 1;
  return regnum;
}

struct match_helper
{
  int match_now;
  int all_match;
};

static int32_t
loongarch_mips_args_parser_can_match_arg_helper (char esc_ch1,
					   char esc_ch2,
					   const char *bit_field,
					   const char *arg,
					   void *context)
{
  struct match_helper *match = context;
  int ret = 0;
  int64_t imm;
  expressionS const_expr;

  if (!match->match_now)
    return 0;

  switch (esc_ch1)
    {
    case 'l':
      switch (esc_ch2)
	{
	default:
	  match->match_now = is_label (arg);
	  if (!match->match_now && is_label_with_addend (arg))
	    as_fatal (_("This label shouldn't be with addend."));
	  break;
	case 'a':
	  match->match_now = is_label_with_addend (arg);
	  break;
	}
      break;
    case 's':
      my_getExpression (&const_expr, arg);
      match->match_now = const_expr.X_op == O_constant;
      break;
    case 'u':
      my_getExpression (&const_expr, arg);
      match->match_now = const_expr.X_op == O_constant
		       && const_expr.X_unsigned == 1;
      break;
    case 'r':
      if (esc_ch2 == 'z')
	{
	  match->match_now = (strcmp (arg, "$0") == 0
			      || (LARCH_opts.abi_is_lp64
				  && strcmp (arg, "$zero") == 0));
	  break;
	}
      else if (esc_ch2 == 'a' && LARCH_opts.abi_is_lp64)
        {
	  match->match_now = strcmp (arg, "$31") == 0
			   || strcmp (arg, "$ra") == 0;
	  break;
	}
      imm = (offsetT) hash_find (mips_r_map_htab, arg);
      match->match_now = 0 < imm;
      break;
    case 'f':
      imm = (offsetT) hash_find (mips_f_map_htab, arg);
      match->match_now = 0 < imm;
      break;
    case 'c':
      imm = (offsetT) hash_find (mips_c_map_htab, arg);
      match->match_now = 0 < imm;
      break;
    case 'v':
      imm = (offsetT) hash_find (mips_v_map_htab, arg);
      match->match_now = 0 < imm;
      break;
    case 'x':
      imm = (offsetT) hash_find (mips_x_map_htab, arg);
      match->match_now = 0 < imm;
      break;
    case '\0':
      match->all_match = match->match_now? 1 : 0;
    }
  switch (esc_ch1)
    {
    case 's':
    case 'u':
      if (match->match_now)
	{
	  int bit_width, bits_needed_s, bits_needed_u;
	  char *bit_field_1 = (char *) bit_field;
	  imm = const_expr.X_add_number;

	  bit_width = loongarch_get_bit_field_width (bit_field_1, &bit_field_1);

	  if (bit_width == -1)
	    // no specify
	    break;

	  // 在这里求出实际填入的二进制数。这部分内容和loongarch_encode_imm
	  // 有重合。但是需要在这里加入一些判断内容，比如分支指令立即数
	  // 右移两位，要保证立即数低两位为0
	  if (bit_field_1[0] == '<' && bit_field_1[1] == '<')
	    {
	      int i = strtol (bit_field_1 += 2, &bit_field_1, 10), j;
	      for (j = i; 0 < j; j--, imm >>= 1)
	        if (imm & 1)
		  match->match_now = 0;
	    }
	  else if (*bit_field_1 == '+')
	    imm -= strtol (bit_field_1, &bit_field_1, 10);

	  bits_needed_u = loongarch_bits_imm_needed (imm, 0);
	  bits_needed_s = loongarch_bits_imm_needed (imm, 1);
	  // 在这里判断立即数是否溢出。关于有符号立即数我有两种理解
	  // 一是代数意义上的溢出，如果传入的值超出定义域，那么报错。
	  // 二是程序员可能希望指定位域表示，那么在有符号立即数数中可能指定一个很大的正数。
	  // MIPS的情况两种都有，这里按照第一种来判断，如果真的溢出了则认为匹配失败，而不报错。
	  // 因此留下了余地，对于那种特殊情况，比如当立即数为0或者是某个位宽时展开特殊指令。
	  if ((esc_ch1 == 's' && bit_width < bits_needed_s)
	      || (esc_ch1 == 'u'&& bit_width < bits_needed_u))
	    match->match_now = 0;
	}
    }
  return ret;
}

static const struct loongarch_opcode *
get_loongarch_mips_opcode_by_name (const char *name, const char *arg_strs[])
{
  const struct loongarch_opcode *it;
  struct loongarch_ase *ase;
  for (ase = loongarch_mips_ASEs; ase->enabled; ase++)
    {
      if (!*ase->enabled
          || (ase->include && !*ase->include)
	  || (ase->exclude && *ase->exclude))
	continue;

      if (!ase->name_hash_entry)
	{
	  ase->name_hash_entry = hash_new ();
	  for (it = ase->opcodes; it->name; it++)
	    hash_insert (ase->name_hash_entry, it->name, (void *) it);
	}

      if ((it = hash_find (ase->name_hash_entry, name)) == NULL)
	continue;

      do
	{
	  struct match_helper match_helper = {
	    .match_now = 1,
	    .all_match = 0
	  };
	  loongarch_foreach_args (it->format, arg_strs,
	    loongarch_mips_args_parser_can_match_arg_helper, &match_helper);
	  if (match_helper.all_match
	      && !(it->include && !*it->include)
	      && !(it->exclude && *it->exclude))
	    return it;
	  it++;
	}
      while (it->name && strcasecmp (it->name, name) == 0);
    }
  return NULL;
}

static const char *
loongarch_mips_macro_expand_arg_map (char esc_ch1, char esc_ch2, const char *arg)
{
  const char *ret;
  int i;
  switch (esc_ch1)
    {
    case 'r':
      i = (int64_t) hash_find (mips_r_map_htab, arg);
      if (i == 0)
	as_fatal (_("MIPS converter\nformat:%c%c\nnot found arg: %s"),
		  esc_ch1, esc_ch2, arg);
      ret = loongarch_r_normal_name[i - 1];
      break;
    case 'f':
      i = (int64_t) hash_find (mips_f_map_htab, arg);
      if (i == 0)
	as_fatal (_("MIPS converter\nformat:%c%c\nnot found arg: %s"),
		  esc_ch1, esc_ch2, arg);
      ret = loongarch_f_normal_name[i - 1];
      break;
    case 'c':
      i = (int64_t) hash_find (mips_c_map_htab, arg);
      if (i == 0)
	as_fatal (_("MIPS converter\nformat:%c%c\nnot found arg: %s"),
		    esc_ch1, esc_ch2, arg);
      ret = loongarch_c_normal_name[i - 1];
      break;
    case 'v':
      i = (int64_t) hash_find (mips_v_map_htab, arg);
      if (i == 0)
	as_fatal (_("MIPS converter\nformat:%c%c\nnot found arg: %s"),
		  esc_ch1, esc_ch2, arg);
      ret = loongarch_v_normal_name[i - 1];
      break;
    case 'x':
      i = (int64_t) hash_find (mips_x_map_htab, arg);
      if (i == 0)
	as_fatal (_("MIPS converter\nformat:%c%c\nnot found arg: %s"),
		  esc_ch1, esc_ch2, arg);
      ret = loongarch_x_normal_name[i - 1];
      break;
    default:
      ret = arg;
    }
  return ret;
}

static char *
loongarch_mips_macro_helper (const char * const args[], void *context_ptr)
{
  struct loongarch_opcode *insn = context_ptr;
  char *ret = NULL;
  if (strcmp (insn->name, "rdhwr") == 0)
    {
      const char * const t_args[2] = {args[0], NULL};
      if (strcmp (args[1], "$0") == 0)
	ret = loongarch_expand_macro_with_format_map ("r", "rdtime.d $r0,%1",
		t_args, loongarch_mips_macro_expand_arg_map, NULL, NULL,
                strlen(args[0]));
      else if (strcmp (args[1], "$2") == 0)
	ret = loongarch_expand_macro_with_format_map ("r", "rdtime.d %1,$r0",
		t_args, loongarch_mips_macro_expand_arg_map, NULL, NULL,
                strlen(args[0]));
      else
	as_fatal ("rdhwr not support HWR[%s]", args[1]);
    }
  return ret;
}

static int contrary_branch_cond_check = 0;

static char *
loongarch_converte_one_mips (char *str)
{
  static const struct loongarch_opcode *b;
  static char *b_duped_args_buf;
  static const char *b_arg_strs[MAX_ARG_NUM_PLUS_2];
  static int this_is_likely_branch = 0;
  static int not_seen_delay_slot_yet = 0;
  int this_insn_is_in_delay_slot = not_seen_delay_slot_yet;
  not_seen_delay_slot_yet = 0;

  const char *name;
  const char *arg_strs[MAX_ARG_NUM_PLUS_2];
  name = str;
  for (; *str && *str != ' '; str++);
  if (*str == ' ')
    *str++ = '\0';
  str = strdup (str);
  size_t str_len = strlen(str);
  
  do
    {
      /* 然后把诸如sd $ra, 8($sp)最后一个实参，结尾括号里的寄存器单独拿出来
	 此外，对于ld $3,($4)这种写法，转化为ld $3,0($4) */
      int implicit_last_2nd_zero = 0;
      char *t1, *t2;
      for (t1 = str; *t1; t1++);
      if (*--t1 == ')')
	{
	  t2 = t1;
	  for (; str + 1 < t1 && *t1 != '('; t1--);
	  if (t1[-1] == ',' && t1[0] == '(' && t1[1] == '$')
	    implicit_last_2nd_zero = 1;
	  if (t1[0] != '(' || t1[1] != '$')
	    t1 = NULL;
	}
      else
	t1 = NULL;

      size_t num = loongarch_split_args_by_comma (str, arg_strs);
      if (!t1)
	break;
      *t2 = '\0';
      *t1 = '\0';
      arg_strs[num] = t1 + 1;
      arg_strs[num + 1] = NULL;
      if (implicit_last_2nd_zero)
	arg_strs[num - 1] = "0";
    }
  while (0);

  const struct loongarch_opcode *insn;

  if ((insn = get_loongarch_mips_opcode_by_name (name, arg_strs)) == NULL)
    as_fatal (_("no match MIPS insn: %s\t%s"),
	      name, loongarch_cat_splited_strs (arg_strs));

  char *expanded_insn =
    loongarch_expand_macro_with_format_map (insn->format, insn->macro,
      arg_strs, loongarch_mips_macro_expand_arg_map,
      loongarch_mips_macro_helper, (void *) insn, str_len);

  if (insn->pinfo & MIPS_HAS_DELAYSLOT
      && MIPS_opts->mips_branch_has_delay_slot)
    {
      if (this_insn_is_in_delay_slot)
	as_fatal (_("a MIPS insn with delay-slot:\n%s %s\n"
		    "followed another MIPS insn with delay-slot:\n%s %s"),
		  b->name, loongarch_cat_splited_strs (b_arg_strs),
		  name, loongarch_cat_splited_strs (arg_strs));
      b = insn;
      b_duped_args_buf = str;
      memcpy (b_arg_strs, arg_strs, sizeof (b_arg_strs));

      this_is_likely_branch = (insn->pinfo & MIPS_IS_LIKELY_BRANCH) != 0;
      not_seen_delay_slot_yet = 1;

      free (expanded_insn);
      return strdup ("");
    }
  else if (this_insn_is_in_delay_slot)
    {
      /* 我们关注几类分支指令和延迟槽指令存在WAR相关的情况：
	 第一种是条件判断时的WAR相关，such as
	    bne $x, $y, sym
	    ori $x, $z, imm */
      int exist_cond_check_WAR_hazards = 0;

      /* 第二种是跳转目标寄存器有WAR相关， such as
	    j $x
	    ori $x, $y, imm */
      int exist_target_reg_WAR_hazards = 0;

      /* 第三种，很奇怪的情况是子程序调用指令的返回寄存器有WAW相关， such as
	    jalr $x, $y
	    ori $x, $z, imm */
      int exist_link_reg_WAW_hazards = 0;

      char tgt_esc1 = '\0', tgt_esc2 ATTRIBUTE_UNUSED;
      const char *tgt = NULL;
      int64_t tgt_value;

      char link_esc1, link_esc2 ATTRIBUTE_UNUSED;
      const char *link = NULL;
      int64_t link_value = 0;

      char *branch_stub_buf;

      {
	char dupped_b_format[strlen (b->format) + 1];
	const char *b_format_strs[MAX_ARG_NUM_PLUS_2];
	int64_t b_arg_value[MAX_ARG_NUM_PLUS_2];
	size_t i, j;
	char clobber_esc1 = '\0', clobber_esc2;
	int64_t clobber_value = 0;

	strcpy (dupped_b_format, b->format);
	loongarch_split_args_by_comma (dupped_b_format, b_format_strs);

	do
	  {
	    /* To find out the clobber register of delay-slot insn */

	    if (arg_strs[0])
	      {
		/* Usually, the first arg is clobber register */
		clobber_esc1 = insn->format[0];
		clobber_esc2 = insn->format[1];
		if (clobber_esc1 == 'r' && clobber_esc2 == 'c')
		  clobber_value =
		    (int64_t) hash_find (mips_r_map_htab, arg_strs[0]) - 1;
		else if (clobber_esc1 == 'c')
		  clobber_value =
		    (int64_t) hash_find (mips_c_map_htab, arg_strs[0]) - 1;
		else
		  clobber_esc1 = clobber_esc2 = '\0';
	      }

	    if (clobber_esc1 != '\0')
	      break;

	    if (strncmp (name, "c.", 2) == 0
		&& strcmp (insn->format, "f,f") == 0)
	      /* for float cond insn */
	      clobber_esc1 = 'c'
		, clobber_value =
		    (int64_t) hash_find (mips_c_map_htab, "$fcc0") - 1;
	  }
	while (0);

	i = 0;

	/* To find out link-register of subrounting call insn */
	if (strcmp (b->name, "jalr") == 0 && strcmp (b->format, "r,r") == 0)
	  /* The first arg of 'jalr r,r' is link-register */
	  i = 1
	    , link_esc1 = 'r', link = b_arg_strs[0]
	    , link_value = (int64_t) hash_find
				       (mips_r_map_htab, link) - 1;
	else if (strcmp (b->name, "jalr") == 0
		 || strcmp (b->name, "jal") == 0
		 || strcmp (b->name, "bal") == 0)
	  /* jalr r
	     jal r
	     jal l
	     bal l */
	  link_esc1 = 'r', link = "$31"
	    , link_value = (int64_t) hash_find
				       (mips_r_map_htab, link) - 1;
	else
	  link_esc1 = '\0';

	j = i;

	for (; b_format_strs[i]; i++)
	  switch (b_format_strs[i][0])
	    {
	    case 'r':
	      b_arg_value[i] =
		(int64_t) hash_find (mips_r_map_htab, b_arg_strs[i]) - 1;
	      break;
	    case 'c':
	      b_arg_value[i] =
		(int64_t) hash_find (mips_c_map_htab, b_arg_strs[i]) - 1;
	      break;
	    case 's':
	    case 'l':
	      break;
	    default:
	      as_fatal ("unknown branch arg");
	    }

	/* branch insn must have actual arg. */
	gas_assert (0 < i);

	for (; j < i - 1; j++)
	  if (clobber_esc1 == b_format_strs[j][0]
	      && clobber_value == b_arg_value[j])
	    exist_cond_check_WAR_hazards = 1;

	if ((strcmp (b->name, "bc1t") == 0 || strcmp (b->name, "bc1f") == 0)
	    && strcmp (b->format, "l") == 0 && clobber_esc1 == 'c'
	    && clobber_value ==
		 (int64_t) hash_find (mips_c_map_htab, "$fcc0") - 1)
	  exist_cond_check_WAR_hazards = 1;

	/* The last arg of branch insn is target */
	tgt_esc1 = b_format_strs[j][0];
	tgt_esc2 = b_format_strs[j][1];
	tgt = b_arg_strs[j];
	tgt_value = b_arg_value[j];

	gas_assert (tgt);

	if (clobber_esc1 == 'r'
	    && clobber_esc1 == tgt_esc1 && clobber_value == tgt_value)
	  exist_target_reg_WAR_hazards = 1;
      }

      /* 刚才的三种数据相关情况理论上来说是可以叠加出现的。但实际上MIPS没有
	 条件调用子程序的指令，因此 */
      gas_assert
	(exist_cond_check_WAR_hazards + exist_link_reg_WAW_hazards < 2);

      if (exist_target_reg_WAR_hazards)
	/* 这种情况需要先把目标寄存器存在其他地方，不太可能是$at，因为延迟槽
	   指令会用。这样说的话必须是一个专用的周转寄存器来暂存跳转目标。不过
	   这种情况极少，为这种情况单独分配一个周转寄存器显得代价太大了。
	   因此我们先不支持这种情况。 */
	as_fatal (_("Subrouting call dest reg has WAR hazards.\n"
		    "branch:     %s\t%s\n"
		    "delay-slot: %s\t%s"),
		  b->name, loongarch_cat_splited_strs (b_arg_strs),
		  name, loongarch_cat_splited_strs (arg_strs));

      if (exist_link_reg_WAW_hazards)
	/* 这种情况等效于不进行子程序调用
	    With delay-slot         Without delay-slot
	    jalr $x, $y       ==>    ori $x, $z, imm
	    ori $x, $z, imm          j $y
	*/
	link_esc1 = '\0';

      if (exist_cond_check_WAR_hazards || this_is_likely_branch)
	{
/* 这种情况我们首先检查条件，根据条件真假前往两个基本块，基本块中有延迟槽
   指令，基本块出口是跳转目标。对likely分支的处理和这种情况类似。
non likely branch:
    With delay-slot         Without delay-slot       Without delay-slot
    bne $x, $y, sym    ==>    bne $x, $y, 1f    ==>    beq $x, $y, 1f
    ori $x, $z, imm           ori $x, $z, imm          ori $x, $z, imm
                              b 2f                     b sym
                            1:ori $x, $z, imm        1:ori $x, $z, imm
                              b sym
                            2:

likely branch:
    With delay-slot         Without delay-slot       Without delay-slot
    bnel $x, $y, sym   ==>    bne $x, $y, 1f    ==>    beq $x, $y, 1f
    ori $x, $z, imm           b 2f                     ori $x, $z, imm
                            1:ori $x, $z, imm          b sym
                              b sym                  1:
                            2:
*/
	  char *contrary_check_cond, *branch_tgt;
	  const char *branch_tgt_args[3] = {NULL, NULL, NULL};
	  const struct loongarch_opcode *c_b;

	  contrary_branch_cond_check = 1;
	  c_b = get_loongarch_mips_opcode_by_name (b->name, b_arg_strs);
	  if (c_b == NULL)
	    as_fatal (_("No contrary branch cond check insn?\n"
			"branch:     %s\t%s"),
		      b->name, loongarch_cat_splited_strs (b_arg_strs));
	  contrary_check_cond =
	    loongarch_expand_macro_with_format_map (c_b->format, c_b->macro,
	      b_arg_strs, loongarch_mips_macro_expand_arg_map, NULL, NULL,
              str_len);
	  contrary_branch_cond_check = 0;

	  if (link_esc1 == '\0')
	    link_esc1 = 'r', link = "$0"
	      , link_value = (int64_t) hash_find (mips_r_map_htab, link) - 1;

	  if (link_esc1 == 'r')
	    branch_tgt_args[0] = loongarch_r_normal_name[link_value];
	  else
	    abort ();

	  if (tgt_esc1 == 'r')
	    branch_tgt_args[1] = loongarch_r_normal_name[tgt_value];
	  else if (tgt_esc1 == 'l')
	    branch_tgt_args[1] = tgt;
	  else
	    abort ();

          size_t len_branch_tgt_args = strlen (branch_tgt_args[0]) + strlen
                  (branch_tgt_args[1]) + strlen  (branch_tgt_args[2]);
	  if (LARCH_opts.abi_is_lp64
	      && link_esc1 == 'r' && link_value == 0
	      && tgt_esc1 == 'r' && tgt_value == 1)
	    branch_tgt = strdup ("or $v0,$t5,$r0;or $v1,$t6,$r0;"
				 "fmov.d $fv0,$ft14;fmov.d $fv1,$ft15;"
				 "jirl $r0,$r1;");
	  else if (LARCH_opts.abi_is_lp64
		   && link_esc1 == 'r' && link_value == 1
		   && tgt_esc1 == 'r')
	    branch_tgt = loongarch_expand_macro
			   ("jirl $r1,%2;"
			    "or $t5,$v0,$r0;or $t6,$v1,$r0;"
			    "fmov.d $ft14,$fv0;fmov.d $ft15,$fv1;",
			    branch_tgt_args, NULL, NULL, len_branch_tgt_args);
	  else if (LARCH_opts.abi_is_lp64
		   && link_esc1 == 'r' && link_value == 1
		   && tgt_esc1 == 'l')
	    branch_tgt = loongarch_expand_macro
			   ("bl %2;"
			    "or $t5,$v0,$r0;or $t6,$v1,$r0;"
			    "fmov.d $ft14,$fv0;fmov.d $ft15,$fv1;",
			    branch_tgt_args, NULL, NULL, len_branch_tgt_args);
	  else if (LARCH_opts.abi_is_lp64
		   && link_esc1 == 'r' && link_value != 0 && link_value != 1)
	    as_fatal (_("MIPS n64 to LARCH lp64 not support jalr r,r"));
	  else if (link_esc1 == 'r' && link_value == 0 && tgt_esc1 == 'l')
	    branch_tgt = loongarch_expand_macro
			   ("b %2;", branch_tgt_args, NULL, NULL,
                            len_branch_tgt_args);
	  else if (link_esc1 == 'r' && link_value != 0 && tgt_esc1 == 'l')
	    branch_tgt = loongarch_expand_macro
			   ("la %1,%2;jirl %1,%1;", branch_tgt_args, NULL, NULL
                            , len_branch_tgt_args);
	  else if (link_esc1 == 'r' && tgt_esc1 == 'r')
	    branch_tgt = loongarch_expand_macro
			   ("jirl %1,%2;", branch_tgt_args, NULL, NULL,
                            len_branch_tgt_args);



	  else
	    abort ();

          char *branch_stub_buf_tem = (char *) malloc (
                                strlen (contrary_check_cond) +
                                strlen (expanded_insn) +
                                strlen (branch_tgt) + 10);
	  strcat (branch_stub_buf_tem, contrary_check_cond);
	  strcat (branch_stub_buf_tem, ";");
	  strcat (branch_stub_buf_tem, expanded_insn);
	  strcat (branch_stub_buf_tem, ";");
	  strcat (branch_stub_buf_tem, branch_tgt);
	  strcat (branch_stub_buf_tem, ";:0:;");
	  if (!this_is_likely_branch)
	    strcat (branch_stub_buf_tem, expanded_insn);
	  free (b_duped_args_buf);
	  free (expanded_insn);
	  free (contrary_check_cond);
	  free (branch_tgt);
          branch_stub_buf = branch_stub_buf_tem;
	}
      else
	{
	  /* Without WAR hazards and it's not likely branch, we reverse
	     the branch insn and the insn in delay-slot.
	       With delay-slot		Without delay-slot
	       bne $x, $y, sym    ==>    ori $m, $n, imm
	       ori $m, $n, imm           bne $x, $y, sym  */
	  char *expanded_b =
	    loongarch_expand_macro_with_format_map (b->format, b->macro,
	      b_arg_strs, loongarch_mips_macro_expand_arg_map, NULL, NULL,
                                             str_len);

          char *branch_stub_buf_tem = (char *) malloc (
                                strlen (expanded_insn) +
                                strlen (expanded_b) + 10);
	  strcat (branch_stub_buf_tem, expanded_insn);
	  strcat (branch_stub_buf_tem, ";");
	  strcat (branch_stub_buf_tem, expanded_b);
	  free (b_duped_args_buf);
	  free (expanded_insn);
	  free (expanded_b);
          branch_stub_buf = branch_stub_buf_tem;
        }
      return branch_stub_buf;
    }
  else
    {
      free (str);
      return expanded_insn;
    }
}

static struct loongarch_opcode loongarch_MIPS_branch[] = {
/* match,    mask,       name, format, macro, include, exclude, pinfo */
{0, 0, "b", "l", "b %1", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bal", "l",
"bl %1;"
"or $t5,$v0,$r0;or $t6,$v1,$r0;"
"fmov.d $ft14,$fv0;fmov.d $ft15,$fv1;"
, &LARCH_opts.abi_is_lp64, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bal", "l", "la $r31,%1;jirl $r31,$r31,0", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "beq", "r,r,l", "beq %1,%2,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "beq", "r,s,l", "dli $at,%2;beq %1,$at,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "beql", "r,r,l", "beq %1,%2,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "beql", "r,s,l", "dli $at,%2;beq %1,$at,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bne", "r,r,l", "bne %1,%2,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bne", "r,s,l", "dli $at,%2;bne %1,$at,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bnel", "r,r,l", "bne %1,%2,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bnel", "r,s,l", "dli $at,%2;bne %1,$at,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "ble", "r,r,l", "bge %2,%1,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "ble", "r,s,l", "dli $at,%2;bge $at,%1,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "blel", "r,r,l", "bge %2,%1,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "blel", "r,s,l", "dli $at,%2;bge $at,%1,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bleu", "r,r,l", "bgeu %2,%1,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bleu", "r,s,l", "dli $at,%2;bgeu $at,%1,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bleul", "r,r,l", "bgeu %2,%1,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bleul", "r,s,l", "dli $at,%2;bgeu $at,%1,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bge", "r,r,l", "bge %1,%2,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bge", "r,s,l", "dli $at,%2;bge %1,$at,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bgel", "r,r,l", "bge %1,%2,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bgel", "r,s,l", "dli $at,%2;bge %1,$at,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bgeu", "r,r,l", "bgeu %1,%2,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bgeu", "r,s,l", "dli $at,%2;bgeu %1,$at,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bgeul", "r,r,l", "bgeu %1,%2,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bgeul", "r,s,l", "dli $at,%2;bgeu %1,$at,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "blt", "r,r,l", "blt %1,%2,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "blt", "r,s,l", "dli $at,%2;blt %1,$at,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bltl", "r,r,l", "blt %1,%2,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bltl", "r,s,l", "dli $at,%2;blt %1,$at,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bltu", "r,r,l", "bltu %1,%2,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bltu", "r,s,l", "dli $at,%2;bltu %1,$at,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bltul", "r,r,l", "bltu %1,%2,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bltul", "r,s,l", "dli $at,%2;bltu %1,$at,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bgt", "r,r,l", "blt %2,%1,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bgt", "r,s,l", "dli $at,%2;blt $at,%1,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bgtl", "r,r,l", "blt %2,%1,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bgtl", "r,s,l", "dli $at,%2;blt $at,%1,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bgtu", "r,r,l", "bltu %2,%1,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bgtu", "r,s,l", "dli $at,%2;bltu $at,%1,%3", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bgtul", "r,r,l", "bltu %2,%1,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bgtul", "r,s,l", "dli $at,%2;bltu $at,%1,%3", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "beqz", "r,l", "beqz %1,%2", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "beqzl", "r,l", "beqz %1,%2", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bnez", "r,l", "bnez %1,%2", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bnezl", "r,l", "bnez %1,%2", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "blez", "r,l", "bge $r0,%1,%2", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "blezl", "r,l", "bge $r0,%1,%2", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bgez", "r,l", "bge %1,$r0,%2", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bgezl", "r,l", "bge %1,$r0,%2", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bltz", "r,l", "blt %1,$r0,%2", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bltzl", "r,l", "blt %1,$r0,%2", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bgtz", "r,l", "blt $r0,%1,%2", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bgtzl", "r,l", "blt $r0,%1,%2", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "j", "ra",
"or $v0,$t5,$r0;or $v1,$t6,$r0;"
"fmov.d $fv0,$ft14;fmov.d $fv1,$ft15;"
"jirl $r0,$ra,0"
, &LARCH_opts.abi_is_lp64, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "j", "r", "jirl $r0,%1,0", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "j", "l", "b %1", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "jr", "ra",
"or $v0,$t5,$r0;or $v1,$t6,$r0;"
"fmov.d $fv0,$ft14;fmov.d $fv1,$ft15;"
"jirl $r0,$ra,0"
, &LARCH_opts.abi_is_lp64, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "jr", "r", "jirl $r0,%1,0", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "jal", "r",
"jirl $ra,%1,0;"
"or $t5,$v0,$r0;or $t6,$v1,$r0;"
"fmov.d $ft14,$fv0;fmov.d $ft15,$fv1;"
, &LARCH_opts.abi_is_lp64, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "jal", "r", "jirl $r31,%1,0", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "jal", "l",
"bl %1;"
"or $t5,$v0,$r0;or $t6,$v1,$r0;"
"fmov.d $ft14,$fv0;fmov.d $ft15,$fv1;"
, &LARCH_opts.abi_is_lp64, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "jal", "l", "la $r31,%1;jirl $r31,$r31,0", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "jalr", "r,r", "jirl %1,%2,0", 0, &LARCH_opts.abi_is_lp64, MIPS_HAS_DELAYSLOT},
{0, 0, "jalr", "r",
"jirl $ra,%1,0;"
"or $t5,$v0,$r0;or $t6,$v1,$r0;"
"fmov.d $ft14,$fv0;fmov.d $ft15,$fv1;"
, &LARCH_opts.abi_is_lp64, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "jalr", "r", "jirl $r31,%1,0", 0, 0, MIPS_HAS_DELAYSLOT},
{0} /* Terminate the list.  */
};

static struct loongarch_opcode loongarch_MIPS_branch_contrary[] = {
/* match,    mask,       name, format, macro, include, exclude, pinfo */
{0, 0, "b", "l", "", 0, 0, 0},
{0, 0, "bal", "l", "", 0, 0, 0},
{0, 0, "beq", "r,r,l", "bne %1,%2,:0f", 0, 0, 0},
{0, 0, "beq", "r,s,l", "dli $at,%2;bne %1,$at,:0f", 0, 0, 0},
{0, 0, "beql", "r,r,l", "bne %1,%2,:0f", 0, 0, 0},
{0, 0, "beql", "r,s,l", "dli $at,%2;bne %1,$at,:0f", 0, 0, 0},
{0, 0, "bne", "r,r,l", "beq %1,%2,:0f", 0, 0, 0},
{0, 0, "bne", "r,s,l", "dli $at,%2;beq %1,$at,:0f", 0, 0, 0},
{0, 0, "bnel", "r,r,l", "beq %1,%2,:0f", 0, 0, 0},
{0, 0, "bnel", "r,s,l", "dli $at,%2;beq %1,$at,:0f", 0, 0, 0},
{0, 0, "ble", "r,r,l", "blt %2,%1,:0f", 0, 0, 0},
{0, 0, "ble", "r,s,l", "dli $at,%2;blt $at,%1,:0f", 0, 0, 0},
{0, 0, "blel", "r,r,l", "blt %2,%1,:0f", 0, 0, 0},
{0, 0, "blel", "r,s,l", "dli $at,%2;blt $at,%1,:0f", 0, 0, 0},
{0, 0, "bleu", "r,r,l", "bltu %2,%1,:0f", 0, 0, 0},
{0, 0, "bleu", "r,s,l", "dli $at,%2;bltu $at,%1,:0f", 0, 0, 0},
{0, 0, "bleul", "r,r,l", "bltu %2,%1,:0f", 0, 0, 0},
{0, 0, "bleul", "r,s,l", "dli $at,%2;bltu $at,%1,:0f", 0, 0, 0},
{0, 0, "bge", "r,r,l", "blt %1,%2,:0f", 0, 0, 0},
{0, 0, "bge", "r,s,l", "dli $at,%2;blt %1,$at,:0f", 0, 0, 0},
{0, 0, "bgel", "r,r,l", "blt %1,%2,:0f", 0, 0, 0},
{0, 0, "bgel", "r,s,l", "dli $at,%2;blt %1,$at,:0f", 0, 0, 0},
{0, 0, "bgeu", "r,r,l", "bltu %1,%2,:0f", 0, 0, 0},
{0, 0, "bgeu", "r,s,l", "dli $at,%2;bltu %1,$at,:0f", 0, 0, 0},
{0, 0, "bgeul", "r,r,l", "bltu %1,%2,:0f", 0, 0, 0},
{0, 0, "bgeul", "r,s,l", "dli $at,%2;bltu %1,$at,:0f", 0, 0, 0},
{0, 0, "blt", "r,r,l", "bge %1,%2,:0f", 0, 0, 0},
{0, 0, "blt", "r,s,l", "dli $at,%2;bge %1,$at,:0f", 0, 0, 0},
{0, 0, "bltl", "r,r,l", "bge %1,%2,:0f", 0, 0, 0},
{0, 0, "bltl", "r,s,l", "dli $at,%2;bge %1,$at,:0f", 0, 0, 0},
{0, 0, "bltu", "r,r,l", "bgeu %1,%2,:0f", 0, 0, 0},
{0, 0, "bltu", "r,s,l", "dli $at,%2;bgeu %1,$at,:0f", 0, 0, 0},
{0, 0, "bltul", "r,r,l", "bgeu %1,%2,:0f", 0, 0, 0},
{0, 0, "bltul", "r,s,l", "dli $at,%2;bgeu %1,$at,:0f", 0, 0, 0},
{0, 0, "bgt", "r,r,l", "bge %2,%1,:0f", 0, 0, 0},
{0, 0, "bgt", "r,s,l", "dli $at,%2;bge $at,%1,:0f", 0, 0, 0},
{0, 0, "bgtl", "r,r,l", "bge %2,%1,:0f", 0, 0, 0},
{0, 0, "bgtl", "r,s,l", "dli $at,%2;bge $at,%1,:0f", 0, 0, 0},
{0, 0, "bgtu", "r,r,l", "bgeu %2,%1,:0f", 0, 0, 0},
{0, 0, "bgtu", "r,s,l", "dli $at,%2;bgeu $at,%1,:0f", 0, 0, 0},
{0, 0, "bgtul", "r,r,l", "bgeu %2,%1,:0f", 0, 0, 0},
{0, 0, "bgtul", "r,s,l", "dli $at,%2;bgeu $at,%1,:0f", 0, 0, 0},
{0, 0, "beqz", "r,l", "bnez %1,:0f", 0, 0, 0},
{0, 0, "beqzl", "r,l", "bnez %1,:0f", 0, 0, 0},
{0, 0, "bnez", "r,l", "beqz %1,:0f", 0, 0, 0},
{0, 0, "bnezl", "r,l", "beqz %1,:0f", 0, 0, 0},
{0, 0, "blez", "r,l", "blt $r0,%1,:0f", 0, 0, 0},
{0, 0, "blezl", "r,l", "blt $r0,%1,:0f", 0, 0, 0},
{0, 0, "bgez", "r,l", "blt %1,$r0,:0f", 0, 0, 0},
{0, 0, "bgezl", "r,l", "blt %1,$r0,:0f", 0, 0, 0},
{0, 0, "bltz", "r,l", "bge %1,$r0,:0f", 0, 0, 0},
{0, 0, "bltzl", "r,l", "bge %1,$r0,:0f", 0, 0, 0},
{0, 0, "bgtz", "r,l", "bge $r0,%1,:0f", 0, 0, 0},
{0, 0, "bgtzl", "r,l", "bge $r0,%1,:0f", 0, 0, 0},
{0, 0, "j", "r", "", 0, 0, 0},
{0, 0, "j", "l", "", 0, 0, 0},
{0, 0, "jr", "r", "", 0, 0, 0},
{0, 0, "jal", "r", "", 0, 0, 0},
{0, 0, "jal", "l", "", 0, 0, 0},
{0, 0, "jalr", "r,r", "", 0, &LARCH_opts.abi_is_lp64, 0},
{0, 0, "jalr", "r", "", 0, 0, 0},
{0} /* Terminate the list.  */
};

static struct loongarch_opcode loongarch_MIPS_fix_opcodes[] = {
/* match,    mask,       name, format, macro, include, exclude, pinfo */

{0, 0, "la", "rc,la", "la %1,%2", 0, 0, 0},
{0, 0, "dla", "rc,la", "la %1,%2", 0, 0, 0},
{0, 0, "li", "rc,s", "li %1,%2;", 0, 0, 0},
{0, 0, "dli", "rc,s", "dli %1,%2", 0, 0, 0},

{0, 0, "lui", "rc,u", "li %1,(%2)<<16;", 0, 0, 0},
{0, 0, "move", "rc,r", "or %1,%2,$r0", 0, 0, 0},
{0, 0, "movz", "rc,r,r", "bnez %3,:1f;or %1,%2,$r0;:1:;", 0, 0, 0},
{0, 0, "movn", "rc,r,r", "beqz %3,:1f;or %1,%2,$r0;:1:;", 0, 0, 0},

{0, 0, "rdhwr", "rc,r", "%f", 0, 0, 0},
{0, 0, "sync", "", "dbar 0", 0, 0, 0},
{0, 0, "break", "", "break 0", 0, 0, 0},
{0, 0, "break", "u0:10", "break %1", 0, 0, 0},
{0, 0, "sdbbp", "u", "dbgcall %1", 0, 0, 0},
{0, 0, "syscall", "", "syscall 0", 0, 0, 0},
{0, 0, "pref", "u,s,r", "", 0, 0, 0},
{0, 0, "tlt", "r,r", "bge %1,%2,:1f;break 7;:1:;", 0, 0, 0},
{0, 0, "tlt", "r,s", "dli $at,%2;bge %1,$at,:1f;break 7;:1:;", 0, 0, 0},
{0, 0, "teq", "r,r", "bne %1,%2,:1f;break 7;:1:;", 0, 0, 0},
{0, 0, "teq", "r,s", "dli $at,%2;bne %1,$at,:1f;break 7;:1:;", 0, 0, 0},
{0, 0, "teq", "r,r,u", "bne %1,%2,:1f;break %3;:1:;", 0, 0, 0},
{0, 0, "tne", "r,r", "beq %1,%2,:1f;break 7;:1:;", 0, 0, 0},
{0, 0, "tne", "r,s", "dli $at,%2;beq %1,$at,:1f;break 7;:1:;", 0, 0, 0},

{0, 0, "nop", "", "nop", 0, 0, 0},

{0, 0, "lb", "rc,s0:12,r", "ld.b %1,%3,%2", 0, 0, 0},
{0, 0, "lb", "rc,s,r", "dli $at,%2;add.d $at,$at,%3;ld.b %1,$at,0", 0, 0, 0},
{0, 0, "lb", "rc,la", "la $at,%2;ld.b %1,$at,0", 0, 0, 0},
{0, 0, "lh", "rc,s0:12,r", "ld.h %1,%3,%2", 0, 0, 0},
{0, 0, "lh", "rc,s,r", "dli $at,%2;add.d $at,$at,%3;ld.h %1,$at,0", 0, 0, 0},
{0, 0, "lh", "rc,la", "la $at,%2;ld.h %1,$at,0", 0, 0, 0},
{0, 0, "lw", "rc,s0:12,r", "ld.w %1,%3,%2", 0, 0, 0},
{0, 0, "lw", "rc,s,r", "dli $at,%2;add.d $at,$at,%3;ld.w %1,$at,0", 0, 0, 0},
{0, 0, "lw", "rc,la", "la $at,%2;ld.w %1,$at,0", 0, 0, 0},
{0, 0, "ld", "rc,s0:12,r", "ld.d %1,%3,%2", 0, 0, 0},
{0, 0, "ld", "rc,s,r", "dli $at,%2;add.d $at,$at,%3;ld.d %1,$at,0", 0, 0, 0},
{0, 0, "ld", "rc,la", "la $at,%2;ld.d %1,$at,0", 0, 0, 0},
{0, 0, "sb", "r,s0:12,r", "st.b %1,%3,%2", 0, 0, 0},
{0, 0, "sb", "r,s,r", "dli $at,%2;add.d $at,$at,%3;st.b %1,$at,0", 0, 0, 0},
{0, 0, "sb", "r,la", "la $at,%2;st.b %1,$at,0", 0, 0, 0},
{0, 0, "sh", "r,s0:12,r", "st.h %1,%3,%2", 0, 0, 0},
{0, 0, "sh", "r,s,r", "dli $at,%2;add.d $at,$at,%3;st.h %1,$at,0", 0, 0, 0},
{0, 0, "sh", "r,la", "la $at,%2;st.h %1,$at,0", 0, 0, 0},
{0, 0, "sw", "r,s0:12,r", "st.w %1,%3,%2", 0, 0, 0},
{0, 0, "sw", "r,s,r", "dli $at,%2;add.d $at,$at,%3;st.w %1,$at,0", 0, 0, 0},
{0, 0, "sw", "r,la", "la $at,%2;st.w %1,$at,0", 0, 0, 0},
{0, 0, "sd", "r,s0:12,r", "st.d %1,%3,%2", 0, 0, 0},
{0, 0, "sd", "r,s,r", "dli $at,%2;add.d $at,$at,%3;st.d %1,$at,0", 0, 0, 0},
{0, 0, "sd", "r,la", "la $at,%2;st.d %1,$at,0", 0, 0, 0},
{0, 0, "lbu", "rc,s0:12,r", "ld.bu %1,%3,%2", 0, 0, 0},
{0, 0, "lbu", "rc,s,r", "dli $at,%2;add.d $at,$at,%3;ld.bu %1,$at,0", 0, 0, 0},
{0, 0, "lbu", "rc,la", "la $at,%2;ld.bu %1,$at,0", 0, 0, 0},
{0, 0, "lhu", "rc,s0:12,r", "ld.hu %1,%3,%2", 0, 0, 0},
{0, 0, "lhu", "rc,s,r", "dli $at,%2;add.d $at,$at,%3;ld.hu %1,$at,0", 0, 0, 0},
{0, 0, "lhu", "rc,la", "la $at,%2;ld.hu %1,$at,0", 0, 0, 0},
{0, 0, "lwu", "rc,s0:12,r", "ld.wu %1,%3,%2", 0, 0, 0},
{0, 0, "lwu", "rc,s,r", "dli $at,%2;add.d $at,$at,%3;ld.wu %1,$at,0", 0, 0, 0},
{0, 0, "lwu", "rc,la", "la $at,%2;ld.wu %1,$at,0", 0, 0, 0},
{0, 0, "lwl", "rc,s0:12,r", "ldl.w %1,%3,%2", 0, 0, 0},
{0, 0, "lwl", "rc,s,r", "dli $at,%2;add.d $at,$at,%3;ldl.w %1,$at,0", 0, 0, 0},
{0, 0, "lwl", "rc,la", "la $at,%2;ldl.w %1,$at,0", 0, 0, 0},
{0, 0, "lwr", "rc,s0:12,r", "ldr.w %1,%3,%2", 0, 0, 0},
{0, 0, "lwr", "rc,s,r", "dli $at,%2;add.d $at,$at,%3;ldr.w %1,$at,0", 0, 0, 0},
{0, 0, "lwr", "rc,la", "la $at,%2;ldr.w %1,$at,0", 0, 0, 0},
{0, 0, "ldl", "rc,s0:12,r", "ldl.d %1,%3,%2", 0, 0, 0},
{0, 0, "ldl", "rc,s,r", "dli $at,%2;add.d $at,$at,%3;ldl.d %1,$at,0", 0, 0, 0},
{0, 0, "ldl", "rc,la", "la $at,%2;ldl.d %1,$at,0", 0, 0, 0},
{0, 0, "ldr", "rc,s0:12,r", "ldr.d %1,%3,%2", 0, 0, 0},
{0, 0, "ldr", "rc,s,r", "dli $at,%2;add.d $at,$at,%3;ldr.d %1,$at,0", 0, 0, 0},
{0, 0, "ldr", "rc,la", "la $at,%2;ldr.d %1,$at,0", 0, 0, 0},
{0, 0, "swl", "r,s0:12,r", "stl.w %1,%3,%2", 0, 0, 0},
{0, 0, "swl", "r,s,r", "dli $at,%2;add.d $at,$at,%3;stl.w %1,$at,0", 0, 0, 0},
{0, 0, "swl", "r,la", "la $at,%2;stl.w %1,$at,0", 0, 0, 0},
{0, 0, "swr", "r,s0:12,r", "str.w %1,%3,%2", 0, 0, 0},
{0, 0, "swr", "r,s,r", "dli $at,%2;add.d $at,$at,%3;str.w %1,$at,0", 0, 0, 0},
{0, 0, "swr", "r,la", "la $at,%2;str.w %1,$at,0", 0, 0, 0},
{0, 0, "sdl", "r,s0:12,r", "stl.d %1,%3,%2", 0, 0, 0},
{0, 0, "sdl", "r,s,r", "dli $at,%2;add.d $at,$at,%3;stl.d %1,$at,0", 0, 0, 0},
{0, 0, "sdl", "r,la", "la $at,%2;stl.d %1,$at,0", 0, 0, 0},
{0, 0, "sdr", "r,s0:12,r", "str.d %1,%3,%2", 0, 0, 0},
{0, 0, "sdr", "r,s,r", "dli $at,%2;add.d $at,$at,%3;str.d %1,$at,0", 0, 0, 0},
{0, 0, "sdr", "r,la", "la $at,%2;str.d %1,$at,0", 0, 0, 0},

{0, 0, "ll", "r,s0:14<<2,r", "ll.w %1,%3,%2", 0, 0, 0},
{0, 0, "ll", "r,s,r", "dli $at,%2;add.d $at,$at,%3;ll.w %1,$at,0", 0, 0, 0},
{0, 0, "ll", "r,la", "la $at,%2;ll.w %1,$at,0", 0, 0, 0},
{0, 0, "sc", "r,s0:14<<2,r", "sc.w %1,%3,%2", 0, 0, 0},
{0, 0, "sc", "r,s,r", "dli $at,%2;add.d $at,$at,%3;sc.w %1,$at,0", 0, 0, 0},
{0, 0, "sc", "r,la", "la $at,%2;sc.w %1,$at,0", 0, 0, 0},
{0, 0, "lld", "r,s0:14<<2,r", "ll.d %1,%3,%2", 0, 0, 0},
{0, 0, "lld", "r,s,r", "dli $at,%2;add.d $at,$at,%3;ll.d %1,$at,0", 0, 0, 0},
{0, 0, "lld", "r,la", "la $at,%2;ll.d %1,$at,0", 0, 0, 0},
{0, 0, "scd", "r,s0:14<<2,r", "sc.d %1,%3,%2", 0, 0, 0},
{0, 0, "scd", "r,s,r", "dli $at,%2;add.d $at,$at,%3;sc.d %1,$at,0", 0, 0, 0},
{0, 0, "scd", "r,la", "la $at,%2;sc.d %1,$at,0", 0, 0, 0},

{0, 0, "and", "rc,r,r", "and %1,%2,%3", 0, 0, 0},
{0, 0, "and", "rc,r,u0:12", "andi %1,%2,%3", 0, 0, 0},
{0, 0, "and", "rc,r,s", "dli $at,%3;and %1,%2,$at", 0, 0, 0},
{0, 0, "and", "rc,r", "and %1,%1,%2", 0, 0, 0},
{0, 0, "and", "rc,u0:12", "andi %1,%1,%2", 0, 0, 0},
{0, 0, "and", "rc,s", "dli $at,%2;and %1,%1,$at", 0, 0, 0},
{0, 0, "andi", "rc,r,u0:12", "andi %1,%2,%3", 0, 0, 0},
{0, 0, "andi", "rc,r,u0:16", "dli $at,%3;and %1,%2,$at", 0, 0, 0},
{0, 0, "andi", "rc,r,u", "throw_error overflow_%3", 0, 0, 0},
{0, 0, "andi", "rc,u0:12", "andi %1,%1,%2", 0, 0, 0},
{0, 0, "andi", "rc,u0:16", "dli $at,%2;and %1,%1,$at", 0, 0, 0},
{0, 0, "andi", "rc,u", "throw_error overflow_%2", 0, 0, 0},
{0, 0, "or", "rc,r,r", "or %1,%2,%3", 0, 0, 0},
{0, 0, "or", "rc,r,u0:12", "ori %1,%2,%3", 0, 0, 0},
{0, 0, "or", "rc,r,u", "dli $at,%3;or %1,%2,$at", 0, 0, 0},
{0, 0, "or", "rc,r", "or %1,%1,%2", 0, 0, 0},
{0, 0, "or", "rc,u0:12", "ori %1,%1,%2", 0, 0, 0},
{0, 0, "or", "rc,u", "dli $at,%2;or %1,%1,$at", 0, 0, 0},
{0, 0, "ori", "rc,r,u0:12", "ori %1,%2,%3", 0, 0, 0},
{0, 0, "ori", "rc,r,u0:16", "dli $at,%3;or %1,%2,$at", 0, 0, 0},
{0, 0, "ori", "rc,r,u", "throw_error overflow_%3", 0, 0, 0},
{0, 0, "ori", "rc,u0:12", "ori %1,%1,%2", 0, 0, 0},
{0, 0, "ori", "rc,u0:16", "dli $at,%2;or %1,%1,$at", 0, 0, 0},
{0, 0, "ori", "rc,u", "throw_error overflow_%2", 0, 0, 0},
{0, 0, "xor", "rc,r,r", "xor %1,%2,%3", 0, 0, 0},
{0, 0, "xor", "rc,r,u0:12", "xori %1,%2,%3", 0, 0, 0},
{0, 0, "xor", "rc,r,u", "dli $at,%3;xor %1,%2,$at", 0, 0, 0},
{0, 0, "xor", "rc,r", "xor %1,%1,%2", 0, 0, 0},
{0, 0, "xor", "rc,u0:12", "xori %1,%1,%2", 0, 0, 0},
{0, 0, "xor", "rc,u", "dli $at,%2;xor %1,%1,$at", 0, 0, 0},
{0, 0, "xori", "rc,r,u0:12", "xori %1,%2,%3", 0, 0, 0},
{0, 0, "xori", "rc,r,u0:16", "dli $at,%3;xor %1,%2,$at", 0, 0, 0},
{0, 0, "xori", "rc,r,u", "xori %1,%2,%3", 0, 0, 0},
{0, 0, "xori", "rc,u0:12", "xori %1,%1,%2", 0, 0, 0},
{0, 0, "xori", "rc,u0:16", "dli $at,%2;xor %1,%1,$at", 0, 0, 0},
{0, 0, "xori", "rc,u", "xori %1,%1,%2", 0, 0, 0},
{0, 0, "not", "rc,r", "nor %1,%2,$r0", 0, 0, 0},
{0, 0, "not", "rc", "nor %1,%1,$r0", 0, 0, 0},
{0, 0, "nor", "rc,r,r", "nor %1,%2,%3", 0, 0, 0},

{0, 0, "clo", "rc,r", "clo.w %1,%2", 0, 0, 0},
{0, 0, "clz", "rc,r", "clz.w %1,%2", 0, 0, 0},
{0, 0, "cto", "rc,r", "cto.w %1,%2", 0, 0, 0},
{0, 0, "ctz", "rc,r", "ctz.w %1,%2", 0, 0, 0},
{0, 0, "dclo", "rc,r", "clo.d %1,%2", 0, 0, 0},
{0, 0, "dclz", "rc,r", "clz.d %1,%2", 0, 0, 0},
{0, 0, "dcto", "rc,r", "cto.d %1,%2", 0, 0, 0},
{0, 0, "dctz", "rc,r", "ctz.d %1,%2", 0, 0, 0},
{0, 0, "wsbh", "rc,r", "revb.2h %1,%2", 0, 0, 0},
{0, 0, "dsbh", "rc,r", "revb.4h %1,%2", 0, 0, 0},
{0, 0, "dshd", "rc,r", "revh.d %1,%2", 0, 0, 0},
{0, 0, "bitswap", "rc,r", "bitrev.4b %1,%2", 0, 0, 0},
{0, 0, "dbitdwap", "rc,r", "bitrev.8b %1,%2", 0, 0, 0},
{0, 0, "seh", "rc,r", "ext.w.h %1,%2", 0, 0, 0},
{0, 0, "seb", "rc,r", "ext.w.b %1,%2", 0, 0, 0},

{0, 0, "slt", "rc,r,r", "slt %1,%2,%3", 0, 0, 0},
{0, 0, "slt", "rc,r,s0:12", "slti %1,%2,%3", 0, 0, 0},
{0, 0, "slt", "rc,r,s", "dli $at,%3;slt %1,%2,$at", 0, 0, 0},
{0, 0, "slti", "rc,r,s0:12", "slti %1,%2,%3", 0, 0, 0},
{0, 0, "slti", "rc,r,s0:16", "dli $at,%3;slt %1,%2,$at", 0, 0, 0},
{0, 0, "slti", "rc,r,u0:16", "li $at,(%3)-0x10000;slt %1,%2,$at", 0, 0, 0},
{0, 0, "slti", "rc,r,s", "throw_error 3rd_arg_overflow", 0, 0, 0},
{0, 0, "sltu", "rc,r,r", "sltu %1,%2,%3", 0, 0, 0},
{0, 0, "sltu", "rc,r,s0:12", "sltui %1,%2,%3", 0, 0, 0},
{0, 0, "sltu", "rc,r,s", "dli $at,%3;sltu %1,%2,$at", 0, 0, 0},
{0, 0, "sltiu", "rc,r,s0:12", "sltui %1,%2,%3", 0, 0, 0},
{0, 0, "sltiu", "rc,r,s0:16", "dli $at,%3;sltu %1,%2,$at", 0, 0, 0},
{0, 0, "sltiu", "rc,r,u0:16", "li $at,(%3)-0x10000;sltu %1,%2,$at", 0, 0, 0},
{0, 0, "sltiu", "rc,r,s", "throw_error 3rd_arg_overflow", 0, 0, 0},
{0, 0, "sgt", "rc,r,r", "slt %1,%3,%2", 0, 0, 0},
{0, 0, "sgt", "rc,r,s", "dli $at,%3;slt %1,$at,%2", 0, 0, 0},
{0, 0, "sgtu", "rc,r,r", "sltu %1,%3,%2", 0, 0, 0},
{0, 0, "sgtu", "rc,r,s", "dli $at,%3;sltu %1,$at,%2", 0, 0, 0},
{0, 0, "sle", "rc,r,r", "slt %1,%3,%2;xori %1,%1,1", 0, 0, 0},
{0, 0, "sle", "rc,r,s", "dli $at,%3;slt %1,$at,%2;xori %1,%1,1", 0, 0, 0},
{0, 0, "sleu", "rc,r,r", "sltu %1,%3,%2;xori %1,%1,1", 0, 0, 0},
{0, 0, "sleu", "rc,r,s", "dli $at,%3;sltu %1,$at,%2;xori %1,%1,1", 0, 0, 0},
{0, 0, "sge", "rc,r,r", "slt %1,%2,%3;xori %1,%1,1", 0, 0, 0},
{0, 0, "sge", "rc,r,s0:12", "slti %1,%2,%3;xori %1,%1,1", 0, 0, 0},
{0, 0, "sge", "rc,r,s", "dli $at,%3;slt %1,%2,$at;xori %1,%1,1", 0, 0, 0},
{0, 0, "sgeu", "rc,r,r", "sltu %1,%2,%3;xori %1,%1,1", 0, 0, 0},
{0, 0, "sgeu", "rc,r,s0:12", "sltui %1,%2,%3;xori %1,%1,1", 0, 0, 0},
{0, 0, "sgeu", "rc,r,s", "dli $at,%3;sltu %1,%2,$at;xori %1,%1,1", 0, 0, 0},
{0, 0, "sne", "rc,r,r", "xor %1,%2,%3;sltu %1,$r0,%1", 0, 0, 0},
{0, 0, "sne", "rc,r,s", "dli $at,%3;xor %1,%2,$at;sltu %1,$r0,%1", 0, 0, 0},
{0, 0, "seq", "rc,r,r", "xor %1,%2,%3;sltui %1,%1,1", 0, 0, 0},
{0, 0, "seq", "rc,r,s", "dli $at,%3;xor %1,%2,$at;sltui %1,%1,1", 0, 0, 0},

{0, 0, "add", "rc,r,r",
"add.w $at,%2,%3;"
"bge %3,$r0,:1f;"
"bge %2,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":1:;"
"blt %2,$r0,:2f;"
"bge $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "add", "rc,r,u",
"li $at,%3;"
"add.w $at,%2,$at;"
"blt %2,$r0,:2f;"
"bge $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "add", "rc,r,s",
"li $at,%3;"
"add.w $at,%2,$at;"
"bge %2,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "add", "rc,r",
"add.w $at,%1,%2;"
"bge %2,$r0,:1f;"
"bge %1,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":1:;"
"blt %1,$r0,:2f;"
"bge $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "addi", "rc,r,u0:15",
"li $at,%3;"
"add.w $at,%2,$at;"
"blt %2,$r0,:2f;"
"bge $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "addi", "rc,r,u0:16",
"li $at,(%3)-0x10000;"
"add.w $at,%2,$at;"
"bge %2,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "addi", "rc,r,s0:16",
"li $at,%3;"
"add.w $at,%2,$at;"
"bge %2,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "addi", "rc,r,s", "throw_error 3rd_arg_overflow", 0, 0, 0},

{0, 0, "addi", "rc,u0:15",
"li $at,%2;"
"add.w $at,%1,$at;"
"blt %1,$r0,:2f;"
"bge $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "addi", "rc,u0:16",
"li $at,(%2)-0x10000;"
"add.w $at,%1,$at;"
"bge %1,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "addi", "rc,s0:16",
"li $at,%2;"
"add.w $at,%1,$at;"
"bge %1,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "addi", "rc,s", "throw_error 2nd_arg_overflow", 0, 0, 0},

{0, 0, "addu", "rc,r,r", "add.w %1,%2,%3", 0, 0, 0},
{0, 0, "addu", "rc,r,s0:12", "addi.w %1,%2,%3", 0, 0, 0},
{0, 0, "addu", "rc,r,s", "li $at,%3;add.w %1,%2,$at", 0, 0, 0},
{0, 0, "addu", "rc,r", "add.w %1,%1,%2", 0, 0, 0},
{0, 0, "addu", "rc,s0:12", "addi.w %1,%1,%2", 0, 0, 0},
{0, 0, "addu", "rc,s", "li $at,%2;add.w %1,%1,$at", 0, 0, 0},
{0, 0, "addiu", "rc,r,s0:12", "addi.w %1,%2,%3", 0, 0, 0},
{0, 0, "addiu", "rc,r,s0:16", "li $at,%3;add.w %1,%2,$at", 0, 0, 0},
{0, 0, "addiu", "rc,r,u0:16", "li $at,(%3)-0x10000;add.w %1,%2,$at", 0, 0, 0},
{0, 0, "addiu", "rc,r,s", "throw_error 3rd_arg_overflow", 0, 0, 0},
{0, 0, "addiu", "rc,s0:12", "addi.w %1,%1,%2", 0, 0, 0},
{0, 0, "addiu", "rc,s0:16", "li $at,%2;add.w %1,%1,$at", 0, 0, 0},
{0, 0, "addiu", "rc,u0:16", "li $at,(%2)-0x10000;add.w %1,%1,$at", 0, 0, 0},
{0, 0, "addiu", "rc,s", "throw_error 2nd_arg_overflow", 0, 0, 0},

{0, 0, "dadd", "rc,r,r",
"add.d $at,%2,%3;"
"bge %3,$r0,:1f;"
"bge %2,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":1:;"
"blt %2,$r0,:2f;"
"bge $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, &LARCH_opts.rlen_is_64, 0, 0},

{0, 0, "dadd", "rc,r,u",
"dli $at,%3;"
"add.d $at,%2,$at;"
"blt %2,$r0,:2f;"
"bge $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, &LARCH_opts.rlen_is_64, 0, 0},

{0, 0, "dadd", "rc,r,s",
"dli $at,%3;"
"add.d $at,%2,$at;"
"bge %2,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, &LARCH_opts.rlen_is_64, 0, 0},

{0, 0, "dadd", "rc,r",
"add.d $at,%1,%2;"
"bge %2,$r0,:1f;"
"bge %1,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":1:;"
"blt %1,$r0,:2f;"
"bge $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, &LARCH_opts.rlen_is_64, 0, 0},

{0, 0, "daddi", "rc,r,u0:15",
"dli $at,%3;"
"add.d $at,%2,$at;"
"blt %2,$r0,:2f;"
"bge $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, &LARCH_opts.rlen_is_64, 0, 0},

{0, 0, "daddi", "rc,r,u0:16",
"dli $at,(%3)-0x10000;"
"add.d $at,%2,$at;"
"bge %2,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, &LARCH_opts.rlen_is_64, 0, 0},

{0, 0, "daddi", "rc,r,s0:16",
"dli $at,%3;"
"add.d $at,%2,$at;"
"bge %2,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, &LARCH_opts.rlen_is_64, 0, 0},

{0, 0, "daddi", "rc,r,s", "throw_error 3rd_arg_overflow", &LARCH_opts.rlen_is_64, 0, 0},

{0, 0, "daddi", "rc,u0:15",
"dli $at,%2;"
"add.d $at,%1,$at;"
"blt %1,$r0,:2f;"
"bge $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "daddi", "rc,u0:16",
"dli $at,(%2)-0x10000;"
"add.d $at,%1,$at;"
"bge %1,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "daddi", "rc,s0:16",
"dli $at,%2;"
"add.d $at,%1,$at;"
"bge %1,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "daddi", "rc,s", "throw_error 2nd_arg_overflow", 0, 0, 0},

{0, 0, "daddu", "rc,r,r", "add.d %1,%2,%3", 0, 0, 0},
{0, 0, "daddu", "rc,r,s0:12", "addi.d %1,%2,%3", 0, 0, 0},
{0, 0, "daddu", "rc,r,s", "li $at,%3;add.d %1,%2,$at", 0, 0, 0},
{0, 0, "daddu", "rc,r", "add.d %1,%1,%2", 0, 0, 0},
{0, 0, "daddu", "rc,s0:12", "addi.d %1,%1,%2", 0, 0, 0},
{0, 0, "daddu", "rc,s", "li $at,%2;add.d %1,%1,$at", 0, 0, 0},
{0, 0, "daddiu", "rc,r,s0:12", "addi.d %1,%2,%3", 0, 0, 0},
{0, 0, "daddiu", "rc,r,s0:16", "li $at,%3;add.d %1,%2,$at", 0, 0, 0},
{0, 0, "daddiu", "rc,r,u0:16", "li $at,(%3)-0x10000;add.d %1,%2,$at", 0, 0, 0},
{0, 0, "daddiu", "rc,r,s", "throw_error 3rd_arg_overflow", 0, 0, 0},
{0, 0, "daddiu", "rc,s0:12", "addi.d %1,%1,%2", 0, 0, 0},
{0, 0, "daddiu", "rc,s0:16", "li $at,%2;add.d %1,%1,$at", 0, 0, 0},
{0, 0, "daddiu", "rc,u0:16", "li $at,(%2)-0x10000;add.d %1,%1,$at", 0, 0, 0},
{0, 0, "daddiu", "rc,s", "throw_error 2nd_arg_overflow", 0, 0, 0},

{0, 0, "sub", "rc,r,r",
"sub.w $at,%2,%3;"
"blt %3,$r0,:1f;"
"bge %2,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":1:;"
"blt %2,$r0,:2f;"
"bge $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "sub", "rc,r,u",
"li $at,%3;"
"sub.w $at,%2,$at;"
"bge %2,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "sub", "rc,r,s",
"li $at,%3;"
"sub.w $at,%2,$at;"
"blt %2,$r0,:2f;"
"bge $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "sub", "rc,r",
"sub.w $at,%1,%2;"
"blt %2,$r0,:1f;"
"bge %1,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":1:;"
"blt %1,$r0,:2f;"
"bge $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "subu", "rc,r,r", "sub.w %1,%2,%3", 0, 0, 0},
{0, 0, "subu", "rc,r,s", "li $at,%3;sub.w %1,%2,$at", 0, 0, 0},
{0, 0, "subu", "rc,r", "sub.w %1,%1,%2", 0, 0, 0},
{0, 0, "subu", "rc,s", "li $at,%2;sub.w %1,%1,$at", 0, 0, 0},

{0, 0, "neg", "rc,r",
"li $at,0x80000000;"
"bne $at,%2,:2f;"
"break 6;"
"b :3f;"
":2:;"
"sub.w %1,$r0,%2;"
":3:;"
, 0, 0, 0},
{0, 0, "negu", "rc,r", "sub.w %1,$r0,%2", 0, 0, 0},

{0, 0, "dsub", "rc,r,r",
"sub.d $at,%2,%3;"
"blt %3,$r0,:1f;"
"bge %2,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":1:;"
"blt %2,$r0,:2f;"
"bge $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "dsub", "rc,r,u",
"dli $at,%3;"
"sub.d $at,%2,$at;"
"bge %2,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "dsub", "rc,r,s",
"dli $at,%3;"
"sub.d $at,%2,$at;"
"blt %2,$r0,:2f;"
"bge $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "dsub", "rc,r",
"sub.d $at,%1,%2;"
"blt %2,$r0,:1f;"
"bge %1,$r0,:2f;"
"blt $at,$r0,:2f;"
"break 6;"
"b :3f;"
":1:;"
"blt %1,$r0,:2f;"
"bge $at,$r0,:2f;"
"break 6;"
"b :3f;"
":2:;"
"or %1,$at,$r0;"
":3:;"
, 0, 0, 0},

{0, 0, "dsubu", "rc,r,r", "sub.d %1,%2,%3", 0, 0, 0},
{0, 0, "dsubu", "rc,r,s", "dli $at,%3;sub.d %1,%2,$at", 0, 0, 0},
{0, 0, "dsubu", "rc,r", "sub.d %1,%1,%2", 0, 0, 0},
{0, 0, "dsubu", "rc,s", "dli $at,%2;sub.d %1,%1,$at", 0, 0, 0},

{0, 0, "dneg", "rc,r",
"dli $at,0x8000000000000000;"
"bne $at,%2,:2f;"
"break 6;"
"b :3f;"
":2:;"
"sub.d %1,$r0,%2;"
":3:;"
, 0, 0, 0},
{0, 0, "dnegu", "rc,r", "sub.d %1,$r0,%2", 0, 0, 0},

{0, 0, "mthi", "r", "gr2scr $scr2,%1", 0, 0, 0},
{0, 0, "mtlo", "r", "gr2scr $scr3,%1", 0, 0, 0},
{0, 0, "mfhi", "rc", "scr2gr %1,$scr2", 0, 0, 0},
{0, 0, "mflo", "rc", "scr2gr %1,$scr3", 0, 0, 0},

{0, 0, "madd", "rz,r", "", 0, 0, 0},
{0, 0, "madd", "r,rz", "", 0, 0, 0},
{0, 0, "madd", "r,r",
"gr2scr $scr0,%1;"
"scr2gr $at,$scr3;"
"scr2gr %1,$scr2;"
"bstrins.d $at,%1,63,32;"
"scr2gr %1,$scr0;"
"mul.d %1,%1,%2;"
"add.d $at,$at,%1;"
"bstrins.d %1,$at,63,32;"
"srai.d %1,%1,32;"
"srai.d $at,$at,32;"
"gr2scr $scr3,%1;"
"gr2scr $scr2,$at;"
"scr2gr %1,$scr0;"
, 0, 0, 0},
{0, 0, "msub", "rz,r", "", 0, 0, 0},
{0, 0, "msub", "r,rz", "", 0, 0, 0},
{0, 0, "msub", "r,r",
"gr2scr $scr0,%1;"
"scr2gr $at,$scr3;"
"scr2gr %1,$scr2;"
"bstrins.d $at,%1,63,32;"
"scr2gr %1,$scr0;"
"mul.d %1,%1,%2;"
"sub.d $at,$at,%1;"
"bstrins.d %1,$at,63,32;"
"srai.d %1,%1,32;"
"srai.d $at,$at,32;"
"gr2scr $scr3,%1;"
"gr2scr $scr2,$at;"
"scr2gr %1,$scr0;"
, 0, 0, 0},
{0, 0, "maddu", "rz,r", "", 0, 0, 0},
{0, 0, "maddu", "r,rz", "", 0, 0, 0},
{0, 0, "maddu", "r,r",
"gr2scr $scr0,%1;"
"scr2gr $at,$scr3;"
"scr2gr %1,$scr2;"
"bstrins.d $at,%1,63,32;"
"scr2gr %1,$scr0;"
"gr2scr $scr2,%2;"
"bstrpick.d %1,%1,31,0;"
"bstrpick.d %2,%2,31,0;"
"mul.d %1,%1,%2;"
"add.d $at,$at,%1;"
"scr2gr %2,$scr2;"
"bstrins.d %1,$at,63,32;"
"srai.d %1,%1,32;"
"srai.d $at,$at,32;"
"gr2scr $scr3,%1;"
"gr2scr $scr2,$at;"
"scr2gr %1,$scr0;"
, 0, 0, 0},
{0, 0, "msubu", "rz,r", "", 0, 0, 0},
{0, 0, "msubu", "r,rz", "", 0, 0, 0},
{0, 0, "msubu", "r,r",
"gr2scr $scr0,%1;"
"scr2gr $at,$scr3;"
"scr2gr %1,$scr2;"
"bstrins.d $at,%1,63,32;"
"scr2gr %1,$scr0;"
"gr2scr $scr2,%2;"
"bstrpick.d %1,%1,31,0;"
"bstrpick.d %2,%2,31,0;"
"mul.d %1,%1,%2;"
"sub.d $at,$at,%1;"
"scr2gr %2,$scr2;"
"bstrins.d %1,$at,63,32;"
"srai.d %1,%1,32;"
"srai.d $at,$at,32;"
"gr2scr $scr3,%1;"
"gr2scr $scr2,$at;"
"scr2gr %1,$scr0;"
, 0, 0, 0},

{0, 0, "mul", "rc,r,r", "mul.w %1,%2,%3;", 0, 0, 0},
{0, 0, "mul", "rc,r,s",
"li $at,%3;mulh.w $at,%2,$at;gr2scr $scr2,$at;"
"li $at,%3;mul.w $at,%2,$at;gr2scr $scr3,$at;"
"or %1,$at,$r0;"
, 0, 0, 0},
{0, 0, "mul", "rc,s",
"li $at,%2;mulh.w $at,%1,$at;gr2scr $scr2,$at;"
"li $at,%2;mul.w $at,%1,$at;gr2scr $scr3,$at;"
"or %1,$at,$r0;"
, 0, 0, 0},
{0, 0, "mulo", "rc,r,r",
"mulh.w $at,%2,%3;"
"gr2scr $scr2,$at;"
"beqz $at,:2f;"
"addi.w $at,$at,1;"
"beqz $at,:3f;"
":1:break 6;"
"b :5f;"
":2:;"
"mul.w $at,%2,%3;"
"gr2scr $scr3,$at;"
"blt $at,$r0,:1b;"
"b :4f;"
":3:;"
"mul.w $at,%2,%3;"
"gr2scr $scr3,$at;"
"bge $at,$r0,:1b;"
":4:scr2gr %1,$scr3;"
":5:;"
, 0, 0, 0},
{0, 0, "mulo", "rc,r,s",
"li $at,%3;"
"mulh.w $at,%2,$at;"
"gr2scr $scr2,$at;"
"beqz $at,:2f;"
"addi.w $at,$at,1;"
"beqz $at,:3f;"
":1:break 6;"
"b :5f;"
":2:;"
"li $at,%3;"
"mul.w $at,%2,$at;"
"gr2scr $scr3,$at;"
"blt $at,$r0,:1b;"
"b :4f;"
":3:;"
"li $at,%3;"
"mul.w $at,%2,$at;"
"gr2scr $scr3,$at;"
"bge $at,$r0,:1b;"
":4:scr2gr %1,$scr3;"
":5:;"
, 0, 0, 0},
{0, 0, "mulou", "rc,r,r",
"mulh.wu $at,%2,%3;gr2scr $scr2,$at;"
"beqz $at,:1f;break 6;b :2f;"
":1:mul.w $at,%2,%3;gr2scr $scr3,$at;"
"or %1,$at,$r0;"
":2:;"
, 0, 0, 0},
{0, 0, "mulou", "rc,r,s",
"li $at,%3;mulh.wu $at,%2,$at;gr2scr $scr2,$at;"
"beqz $at,:1f;break 6;b :2f;"
":1:li $at,%3;mul.w $at,%2,$at;gr2scr $scr3,$at;"
"or %1,$at,$r0;"
":2:;"
, 0, 0, 0},
{0, 0, "mult", "rc,r",
"mulh.w $at,%1,%2;gr2scr $scr2,$at;"
"mul.w $at,%1,%2;gr2scr $scr3,$at;"
, 0, 0, 0},
{0, 0, "multu", "rc,r",
"mulh.wu $at,%1,%2;gr2scr $scr2,$at;"
"mul.w $at,%1,%2;gr2scr $scr3,$at;"
, 0, 0, 0},

{0, 0, "dmul", "rc,r,r",
"mulh.du $at,%2,%3;gr2scr $scr2,$at;"
"mul.d $at,%2,%3;gr2scr $scr3,$at;"
"or %1,$at,$r0;"
, 0, 0, 0},
{0, 0, "dmul", "rc,r,s",
"dli $at,%3;mulh.d $at,%2,$at;gr2scr $scr2,$at;"
"dli $at,%3;mul.d $at,%2,$at;gr2scr $scr3,$at;"
"or %1,$at,$r0;"
, 0, 0, 0},
{0, 0, "dmul", "rc,s",
"dli $at,%2;mulh.d $at,%1,$at;gr2scr $scr2,$at;"
"dli $at,%2;mul.d $at,%1,$at;gr2scr $scr3,$at;"
"or %1,$at,$r0;"
, 0, 0, 0},

{0, 0, "dmulo", "rc,r,r",
"mulh.d $at,%2,%3;"
"gr2scr $scr2,$at;"
"beqz $at,:2f;"
"addi.d $at,$at,1;"
"beqz $at,:3f;"
":1:break 6;"
"b :5f;"
":2:;"
"mul.d $at,%2,%3;"
"gr2scr $scr3,$at;"
"blt $at,$r0,:1b;"
"b :4f;"
":3:;"
"mul.d $at,%2,%3;"
"gr2scr $scr3,$at;"
"bge $at,$r0,:1b;"
":4:scr2gr %1,$scr3;"
":5:;"
, 0, 0, 0},
{0, 0, "dmulo", "rc,r,s",
"dli $at,%3;"
"mulh.d $at,%2,$at;"
"gr2scr $scr2,$at;"
"beqz $at,:2f;"
"addi.d $at,$at,1;"
"beqz $at,:3f;"
":1:break 6;"
"b :5f;"
":2:;"
"dli $at,%3;"
"mul.d $at,%2,$at;"
"gr2scr $scr3,$at;"
"blt $at,$r0,:1b;"
"b :4f;"
":3:;"
"dli $at,%3;"
"mul.d $at,%2,$at;"
"gr2scr $scr3,$at;"
"bge $at,$r0,:1b;"
":4:scr2gr %1,$scr3;"
":5:;"
, 0, 0, 0},
{0, 0, "dmulou", "rc,r,r",
"mulh.du $at,%2,%3;gr2scr $scr2,$at;"
"beqz $at,:1f;break 6;b :2f;"
":1:mul.d $at,%2,%3;gr2scr $scr3,$at;"
"or %1,$at,$r0;"
":2:;"
, 0, 0, 0},
{0, 0, "dmulou", "rc,r,s",
"dli $at,%3;mulh.du $at,%2,$at;gr2scr $scr2,$at;"
"beqz $at,:1f;break 6;b :2f;"
":1:dli $at,%3;mul.d $at,%2,$at;gr2scr $scr3,$at;"
"or %1,$at,$r0;"
":2:;"
, 0, 0, 0},

{0, 0, "dmult", "rc,r",
"mulh.d $at,%1,%2;gr2scr $scr2,$at;"
"mul.d $at,%1,%2;gr2scr $scr3,$at;"
, 0, 0, 0},
{0, 0, "dmultu", "rc,r",
"mulh.du $at,%1,%2;gr2scr $scr2,$at;"
"mul.d $at,%1,%2;gr2scr $scr3,$at;"
, 0, 0, 0},

{0, 0, "div", "rz,r,r",
"mod.w $at,%2,%3;gr2scr $scr2,$at;"
"div.w $at,%2,%3;gr2scr $scr3,$at;"
, 0, 0, 0},

{0, 0, "div", "rc,r,r",
"bnez %3,:1f;break 7;b :2f;"
":1:;"
"addi.w $at,%3,1;"
"bnez $at,:1f;"
"bge %2,$r0,:1f;"
"addi.w $at,%2,-1;"
"blt $at,$r0,:1f;"
"break 6;b :2f;"
":1:;"
"mod.w $at,%2,%3;gr2scr $scr2,$at;"
"div.w %1,%2,%3;gr2scr $scr3,%1;"
":2:;"
, 0, 0, 0},

{0, 0, "div", "rc,r,u0:0", "break 7;", 0, 0, 0},
{0, 0, "div", "rc,r,u0:1", "or %1,%2,$r0;", 0, 0, 0},
{0, 0, "div", "rc,r,s0:1",
"bge %2,$r0,:1f;"
"addi.w $at,%2,-1;"
"blt $at,$r0,:1f;"
"break 6;"
"b :2f;"
":1:;"
"sub.w %1,$r0,%2;"
":2:;"
, 0, 0, 0},

{0, 0, "div", "rz,r,s",
"li $at,%3;mod.w $at,%2,$at;gr2scr $scr2,$at;"
"li $at,%3;div.w $at,%2,$at;gr2scr $scr3,$at;"
, 0, 0, 0},

{0, 0, "div", "rc,r,s",
"li $at,%3;"
"bnez $at,:1f;break 7;b :2f;"
":1:;"
"addi.w $at,$at,1;"
"bnez $at,:1f;"
"bge %2,$r0,:1f;"
"addi.w $at,%2,-1;"
"blt $at,$r0,:1f;"
"break 6;b :2f;"
":1:;"
"li $at,%3;mod.w $at,%2,$at;gr2scr $scr2,$at;"
"li $at,%3;div.w %1,%2,$at;gr2scr $scr3,%1;"
":2:;"
, 0, 0, 0},

{0, 0, "div", "rc,r",
"bnez %2,:1f;break 7;b :2f;"
":1:;"
"addi.w $at,%2,1;"
"bnez $at,:1f;"
"bge %1,$r0,:1f;"
"addi.w $at,%1,-1;"
"blt $at,$r0,:1f;"
"break 6;b :2f;"
":1:;"
"mod.w $at,%1,%2;gr2scr $scr2,$at;"
"div.w %1,%1,%2;gr2scr $scr3,%1;"
":2:;"
, 0, 0, 0},

{0, 0, "div", "rc,u0:0", "break 7;", 0, 0, 0},
{0, 0, "div", "rc,u0:1", "", 0, 0, 0},
{0, 0, "div", "rc,s0:1",
"bge %1,$r0,:1f;"
"addi.w $at,%1,-1;"
"blt $at,$r0,:1f;"
"break 6;"
"b :2f;"
":1:;"
"sub.w %1,$r0,%1;"
":2:;"
, 0, 0, 0},

{0, 0, "div", "rc,s",
"li $at,%2;mod.w $at,%1,$at;gr2scr $scr2,$at;"
"li $at,%2;div.w %1,%1,$at;gr2scr $scr3,%1;"
, 0, 0, 0},

{0, 0, "divu", "rz,r,r",
"mod.wu $at,%2,%3;gr2scr $scr2,$at;"
"div.wu $at,%2,%3;gr2scr $scr3,$at;"
, 0, 0, 0},
{0, 0, "divu", "rc,r,r",
"bnez %3,:1f;break 7;b :2f;"
":1:;mod.wu $at,%2,%3;gr2scr $scr2,$at;"
"div.wu %1,%2,%3;gr2scr $scr3,%1;"
":2:;"
, 0, 0, 0},

{0, 0, "divu", "rc,r,u0:0", "break 7;", 0, 0, 0},
{0, 0, "divu", "rc,r,u0:1", "or %1,%2,$r0;", 0, 0, 0},
{0, 0, "divu", "rz,r,s",
"li $at,%3;mod.wu $at,%2,$at;gr2scr $scr2,$at;"
"li $at,%3;div.wu $at,%2,$at;gr2scr $scr3,$at;"
, 0, 0, 0},
{0, 0, "divu", "rc,r,s",
"li $at,%3;mod.wu $at,%2,$at;gr2scr $scr2,$at;"
"li $at,%3;div.wu %1,%2,$at;gr2scr $scr3,%1;"
, 0, 0, 0},
{0, 0, "divu", "rc,r",
"bnez %2,:1f;break 7;b :2f;"
":1:;mod.wu $at,%1,%2;gr2scr $scr2,$at;"
"div.wu %1,%1,%2;gr2scr $scr3,%1;"
":2:;"
, 0, 0, 0},

{0, 0, "divu", "rc,u0:0", "break 7;", 0, 0, 0},
{0, 0, "divu", "rc,u0:1", "", 0, 0, 0},
{0, 0, "divu", "rc,s",
"li $at,%2;mod.wu $at,%1,$at;gr2scr $scr2,$at;"
"li $at,%2;div.wu %1,%1,$at;gr2scr $scr3,%1;"
, 0, 0, 0},

{0, 0, "ddiv", "rz,r,r",
"mod.d $at,%2,%3;gr2scr $scr2,$at;"
"div.d $at,%2,%3;gr2scr $scr3,$at;"
, 0, 0, 0},
{0, 0, "ddiv", "rc,r,r",
"bnez %3,:1f;break 7;b :2f;"
":1:;"
"addi.d $at,%3,1;"
"bnez $at,:1f;"
"bge %2,$r0,:1f;"
"addi.d $at,%2,-1;"
"blt $at,$r0,:1f;"
"break 6;b :2f;"
":1:;"
"mod.d $at,%2,%3;gr2scr $scr2,$at;"
"div.d %1,%2,%3;gr2scr $scr3,%1;"
":2:;"
, 0, 0, 0},

{0, 0, "ddiv", "rc,r,u0:0", "break 7;", 0, 0, 0},
{0, 0, "ddiv", "rc,r,u0:1", "or %1,%2,$r0;", 0, 0, 0},
{0, 0, "ddiv", "rc,r,s0:1",
"bge %2,$r0,:1f;"
"addi.d $at,%2,-1;"
"blt $at,$r0,:1f;"
"break 6;"
"b :2f;"
":1:;"
"sub.d %1,$r0,%2;"
":2:;"
, 0, 0, 0},

{0, 0, "ddiv", "rz,r,s",
"dli $at,%3;mod.d $at,%2,$at;gr2scr $scr2,$at;"
"dli $at,%3;div.d $at,%2,$at;gr2scr $scr3,$at;"
, 0, 0, 0},

{0, 0, "ddiv", "rc,r,s",
"dli $at,%3;"
"bnez $at,:1f;break 7;b :2f;"
":1:;"
"addi.d $at,$at,1;"
"bnez $at,:1f;"
"bge %2,$r0,:1f;"
"addi.d $at,%2,-1;"
"blt $at,$r0,:1f;"
"break 6;b :2f;"
":1:;"
"dli $at,%3;mod.d $at,%2,$at;gr2scr $scr2,$at;"
"dli $at,%3;div.d %1,%2,$at;gr2scr $scr3,%1;"
":2:;"
, 0, 0, 0},

{0, 0, "ddiv", "rc,r",
"bnez %2,:1f;break 7;b :2f;"
":1:;"
"addi.d $at,%2,1;"
"bnez $at,:1f;"
"bge %1,$r0,:1f;"
"addi.d $at,%1,-1;"
"blt $at,$r0,:1f;"
"break 6;b :2f;"
":1:;"
"mod.d $at,%1,%2;gr2scr $scr2,$at;"
"div.d %1,%1,%2;gr2scr $scr3,%1;"
":2:;"
, 0, 0, 0},

{0, 0, "ddiv", "rc,u0:0", "break 7;", 0, 0, 0},
{0, 0, "ddiv", "rc,u0:1", "", 0, 0, 0},
{0, 0, "ddiv", "rc,s0:1",
"bge %1,$r0,:1f;"
"addi.d $at,%1,-1;"
"blt $at,$r0,:1f;"
"break 6;"
"b :2f;"
":1:;"
"sub.d %1,$r0,%1;"
":2:;"
, 0, 0, 0},

{0, 0, "ddiv", "rc,s",
"dli $at,%2;mod.d $at,%1,$at;gr2scr $scr2,$at;"
"dli $at,%2;div.d %1,%1,$at;gr2scr $scr3,%1;"
, 0, 0, 0},

{0, 0, "ddivu", "rz,r,r",
"mod.du $at,%2,%3;gr2scr $scr2,$at;"
"div.du $at,%2,%3;gr2scr $scr3,$at;"
, 0, 0, 0},
{0, 0, "ddivu", "rc,r,r",
"bnez %3,:1f;break 7;b :2f;"
":1:;mod.du $at,%2,%3;gr2scr $scr2,$at;"
"div.du %1,%2,%3;gr2scr $scr3,%1;"
":2:;"
, 0, 0, 0},

{0, 0, "ddivu", "rc,r,u0:0", "break 7;", 0, 0, 0},
{0, 0, "ddivu", "rc,r,u0:1", "or %1,%2,$r0;", 0, 0, 0},
{0, 0, "ddivu", "rz,r,s",
"dli $at,%3;mod.du $at,%2,$at;gr2scr $scr2,$at;"
"dli $at,%3;div.du $at,%2,$at;gr2scr $scr3,$at;"
, 0, 0, 0},
{0, 0, "ddivu", "rc,r,s",
"dli $at,%3;mod.du $at,%2,$at;gr2scr $scr2,$at;"
"dli $at,%3;div.du %1,%2,$at;gr2scr $scr3,%1;"
, 0, 0, 0},

{0, 0, "ddivu", "rc,r",
"bnez %2,:1f;break 7;b :2f;"
":1:;mod.du $at,%1,%2;gr2scr $scr2,$at;"
"div.du %1,%1,%2;gr2scr $scr3,%1;"
":2:;"
, 0, 0, 0},

{0, 0, "ddivu", "rc,u0:0", "break 7;", 0, 0, 0},
{0, 0, "ddivu", "rc,u0:1", "", 0, 0, 0},
{0, 0, "ddivu", "rc,s",
"dli $at,%2;mod.du $at,%1,$at;gr2scr $scr2,$at;"
"dli $at,%2;div.du %1,%1,$at;gr2scr $scr3,%1;"
, 0, 0, 0},

{0, 0, "sll", "rc,r,r", "sll.w %1,%2,%3", 0, 0, 0},
{0, 0, "sll", "rc,r", "sll.w %1,%1,%2", 0, 0, 0},
{0, 0, "sll", "rc,r,u", "slli.w %1,%2,%3", 0, 0, 0},
{0, 0, "sll", "rc,u", "slli.w %1,%1,%2", 0, 0, 0},
{0, 0, "sllv", "rc,r,r", "sll.w %1,%2,%3", 0, 0, 0},
{0, 0, "dsll", "rc,r,r", "sll.d %1,%2,%3", 0, 0, 0},
{0, 0, "dsll", "rc,r,u", "slli.d %1,%2,%3", 0, 0, 0},
{0, 0, "dsll", "rc,r", "sll.d %1,%1,%2", 0, 0, 0},
{0, 0, "dsll", "rc,u", "slli.d %1,%1,%2", 0, 0, 0},
{0, 0, "srl", "rc,r,r", "srl.w %1,%2,%3", 0, 0, 0},
{0, 0, "srl", "rc,r", "srl.w %1,%1,%2", 0, 0, 0},
{0, 0, "srl", "rc,r,u", "srli.w %1,%2,%3", 0, 0, 0},
{0, 0, "srl", "rc,u", "srli.w %1,%1,%2", 0, 0, 0},
{0, 0, "dsrl", "rc,r,r", "srl.d %1,%2,%3", 0, 0, 0},
{0, 0, "dsrl", "rc,r,u", "srli.d %1,%2,%3", 0, 0, 0},
{0, 0, "dsrl", "rc,r", "srl.d %1,%1,%2", 0, 0, 0},
{0, 0, "dsrl", "rc,u", "srli.d %1,%1,%2", 0, 0, 0},
{0, 0, "sra", "rc,r,r", "sra.w %1,%2,%3", 0, 0, 0},
{0, 0, "sra", "rc,r,u", "srai.w %1,%2,%3", 0, 0, 0},
{0, 0, "dsra", "rc,r,r", "sra.d %1,%2,%3", 0, 0, 0},
{0, 0, "dsra", "rc,r,u", "srai.d %1,%2,%3", 0, 0, 0},

{0, 0, "rol", "rc,r,s", "rotri.w %1,%2,-(%3)%%32<0?-(%3)%%32+32:-(%3)%%32", 0, 0, 0},
{0, 0, "rol", "rc,r,r", "li $at,32;sub.w $at,$at,%3;rotr.w %1,%2,$at;", 0, 0, 0},
{0, 0, "ror", "rc,r,s", "rotri.w %1,%2,(%3)%%32<0?(%3)%%32+32:(%3)%%32", 0, 0, 0},
{0, 0, "ror", "rc,r,r", "rotr.w %1,%2,%3", 0, 0, 0},
{0, 0, "rotr", "rc,r,s", "rotri.w %1,%2,(%3)%%32<0?(%3)%%32+32:(%3)%%32", 0, 0, 0},
{0, 0, "rotrv", "rc,r,r", "rotr.w %1,%2,%3", 0, 0, 0},
{0, 0, "drotr32", "rc,r,u", "rotri.d %1,%2,(%3)+32;", 0, 0, 0},
{0, 0, "dror", "rc,r,s", "rotri.d %1,%2,(%3)%%64<0?(%3)%%64+64:(%3)%%64", 0, 0, 0},
{0, 0, "dror", "rc,r,r", "rotr.d %1,%2,%3", 0, 0, 0},
{0, 0, "drotr", "rc,r,s", "rotri.d %1,%2,(%3)%%64<0?(%3)%%64+64:(%3)%%64", 0, 0, 0},
{0, 0, "drotrv", "rc,r,r", "rotr.d %1,%2,%3", 0, 0, 0},

{0, 0, "ext", "rc,r,u0:5,u0:5+1", "bstrpick.w %1,%2,(%3)+(%4)-1,(%3)", 0, 0, 0},
{0, 0, "ext", "rc,r,u,u", "throw_error overflow_%3_%4", 0, 0, 0},
{0, 0, "dext", "rc,r,u,u0:6+1", "bstrpick.d %1,%2,(%3)+(%4)-1,(%3)", 0, 0, 0},
{0, 0, "dext", "rc,r,u,u", "throw_error overflow_%3_%4", 0, 0, 0},
{0, 0, "dextu", "rc,r,u0:5+32,u0:5+1", "bstrpick.d %1,%2,(%3)+(%4)-1,(%3)", 0, 0, 0},
{0, 0, "dextu", "rc,r,u,u", "throw_error overflow_%3_%4", 0, 0, 0},
{0, 0, "dextm", "rc,r,u0:5,u0:5+33", "bstrpick.d %1,%2,(%3)+(%4)-1,(%3)", 0, 0, 0},
{0, 0, "dextm", "rc,r,u,u", "throw_error overflow_%3_%4", 0, 0, 0},
{0, 0, "ins", "rc,r,u,u", "bstrins.w %1,%2,(%3)+(%4)-1,(%3)", 0, 0, 0},
{0, 0, "dins", "rc,r,u,u", "bstrins.d %1,%2,(%3)+(%4)-1,(%3)", 0, 0, 0},
{0, 0, "dinsu", "rc,r,u0:5+32,u0:5+1", "bstrins.d %1,%2,(%3)+(%4)-1,(%3)", 0, 0, 0},
{0, 0, "dinsu", "rc,r,u,u", "throw_error overflow_%3_%4", 0, 0, 0},
{0, 0, "dinsm", "rc,r,u0:5,u0:6+2", "bstrins.d %1,%2,(%3)+(%4)-1,(%3)", 0, 0, 0},
{0, 0, "dinsm", "rc,r,u,u", "throw_error overflow_%3_%4", 0, 0, 0},

{0} /* Terminate the list.  */

};

static struct loongarch_opcode loongarch_MIPS_float_branch[] = {
/* match,    mask,       name, format, macro, include, exclude, pinfo */
{0, 0, "bc1t", "l", "bcnez $fcc0,%1", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bc1t", "c,l", "bcnez %1,%2", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bc1tl", "l", "bcnez $fcc0,%1", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bc1tl", "c,l", "bcnez %1,%2", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bc1f", "l", "bceqz $fcc0,%1", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bc1f", "c,l", "bceqz %1,%2", 0, 0, MIPS_HAS_DELAYSLOT},
{0, 0, "bc1fl", "l", "bceqz $fcc0,%1", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0, 0, "bc1fl", "c,l", "bceqz %1,%2", 0, 0, MIPS_HAS_DELAYSLOT | MIPS_IS_LIKELY_BRANCH},
{0} /* Terminate the list.  */
};

static struct loongarch_opcode loongarch_MIPS_float_branch_contrary[] = {
/* match,    mask,       name, format, macro, include, exclude, pinfo */
{0, 0, "bc1t", "l", "bceqz $fcc0,:0f", 0, 0, 0},
{0, 0, "bc1t", "c,l", "bceqz %1,:0f", 0, 0, 0},
{0, 0, "bc1tl", "l", "bceqz $fcc0,:0f", 0, 0, 0},
{0, 0, "bc1tl", "c,l", "bceqz %1,:0f", 0, 0, 0},
{0, 0, "bc1f", "l", "bcnez $fcc0,:0f", 0, 0, 0},
{0, 0, "bc1f", "c,l", "bcnez %1,:0f", 0, 0, 0},
{0, 0, "bc1fl", "l", "bcnez $fcc0,:0f", 0, 0, 0},
{0, 0, "bc1fl", "c,l", "bcnez %1,:0f", 0, 0, 0},
{0} /* Terminate the list.  */
};

static struct loongarch_opcode loongarch_MIPS_float_opcodes[] = {
/* match,    mask,       name, format, macro, include, exclude, pinfo */


{0, 0, "add.s", "f,f,f", "fadd.s %1,%2,%3", 0, 0, 0},
{0, 0, "add.d", "f,f,f", "fadd.d %1,%2,%3", 0, 0, 0},
{0, 0, "sub.s", "f,f,f", "fsub.s %1,%2,%3", 0, 0, 0},
{0, 0, "sub.d", "f,f,f", "fsub.d %1,%2,%3", 0, 0, 0},
{0, 0, "mul.s", "f,f,f", "fmul.s %1,%2,%3", 0, 0, 0},
{0, 0, "mul.d", "f,f,f", "fmul.d %1,%2,%3", 0, 0, 0},
{0, 0, "div.s", "f,f,f", "fdiv.s %1,%2,%3", 0, 0, 0},
{0, 0, "div.d", "f,f,f", "fdiv.d %1,%2,%3", 0, 0, 0},
{0, 0, "max.s", "f,f,f", "fmax.s %1,%2,%3", 0, 0, 0},
{0, 0, "max.d", "f,f,f", "fmax.d %1,%2,%3", 0, 0, 0},
{0, 0, "min.s", "f,f,f", "fmin.s %1,%2,%3", 0, 0, 0},
{0, 0, "min.d", "f,f,f", "fmin.d %1,%2,%3", 0, 0, 0},
{0, 0, "maxa.s", "f,f,f", "fmaxa.s %1,%2,%3", 0, 0, 0},
{0, 0, "maxa.d", "f,f,f", "fmaxa.d %1,%2,%3", 0, 0, 0},
{0, 0, "mina.s", "f,f,f", "fmina.s %1,%2,%3", 0, 0, 0},
{0, 0, "mina.d", "f,f,f", "fmina.d %1,%2,%3", 0, 0, 0},
{0, 0, "abs.s", "f,f", "fabs.s %1,%2", 0, 0, 0},
{0, 0, "abs.d", "f,f", "fabs.d %1,%2", 0, 0, 0},
{0, 0, "neg.s", "f,f", "fneg.s %1,%2", 0, 0, 0},
{0, 0, "neg.d", "f,f", "fneg.d %1,%2", 0, 0, 0},
{0, 0, "class.s", "f,f", "fclass.s %1,%2", 0, 0, 0},
{0, 0, "class.d", "f,f", "fclass.d %1,%2", 0, 0, 0},
{0, 0, "sqrt.s", "f,f", "fsqrt.s %1,%2", 0, 0, 0},
{0, 0, "sqrt.d", "f,f", "fsqrt.d %1,%2", 0, 0, 0},
{0, 0, "recip.s", "f,f", "frecip.s %1,%2", 0, 0, 0},
{0, 0, "recip.d", "f,f", "frecip.d %1,%2", 0, 0, 0},
{0, 0, "rsqrt.s", "f,f", "frsqrt.s %1,%2", 0, 0, 0},
{0, 0, "rsqrt.d", "f,f", "frsqrt.d %1,%2", 0, 0, 0},
{0, 0, "mov.s", "f,f", "fmov.s %1,%2", 0, 0, 0},
{0, 0, "mov.d", "f,f", "fmov.d %1,%2", 0, 0, 0},
{0, 0, "movf", "r,r,c", "bcnez %3,:1f;or %1,%2,$r0;:1:;", 0, 0, 0},
{0, 0, "movf.s", "f,f,c", "bcnez %3,:1f;fmov.s %1,%2;:1:;", 0, 0, 0},
{0, 0, "movf.d", "f,f,c", "bcnez %3,:1f;fmov.d %1,%2;:1:;", 0, 0, 0},
{0, 0, "movn.s", "f,f,r", "beqz %3,:1f;fmov.s %1,%2;:1:;", 0, 0, 0},
{0, 0, "movn.d", "f,f,r", "beqz %3,:1f;fmov.d %1,%2;:1:;", 0, 0, 0},
{0, 0, "movt", "r,r,c", "bceqz %3,:1f;or %1,%2,$r0;:1:;", 0, 0, 0},
{0, 0, "movt.s", "f,f,c", "bceqz %3,:1f;fmov.s %1,%2;:1:;", 0, 0, 0},
{0, 0, "movt.d", "f,f,c", "bceqz %3,:1f;fmov.d %1,%2;:1:;", 0, 0, 0},
{0, 0, "movz.s", "f,f,r", "bnez %3,:1f;fmov.s %1,%2;:1:;", 0, 0, 0},
{0, 0, "movz.d", "f,f,r", "bnez %3,:1f;fmov.d %1,%2;:1:;", 0, 0, 0},

{0, 0, "madd.s", "f,f,f,f", "fmadd.s %1,%3,%4,%2", 0, 0, 0},
{0, 0, "madd.d", "f,f,f,f", "fmadd.d %1,%3,%4,%2", 0, 0, 0},
{0, 0, "msub.s", "f,f,f,f", "fmsub.s %1,%3,%4,%2", 0, 0, 0},
{0, 0, "msub.d", "f,f,f,f", "fmsub.d %1,%3,%4,%2", 0, 0, 0},
{0, 0, "nmadd.s", "f,f,f,f", "fnmadd.s %1,%3,%4,%2", 0, 0, 0},
{0, 0, "nmadd.d", "f,f,f,f", "fnmadd.d %1,%3,%4,%2", 0, 0, 0},
{0, 0, "nmsub.s", "f,f,f,f", "fnmsub.s %1,%3,%4,%2", 0, 0, 0},
{0, 0, "nmsub.d", "f,f,f,f", "fnmsub.d %1,%3,%4,%2", 0, 0, 0},

{0, 0, "mtc1", "r,f", "movgr2fr.w %2,%1", 0, 0, 0},
{0, 0, "dmtc1", "r,f", "movgr2fr.d %2,%1", 0, 0, 0},
{0, 0, "mthc1", "r,f", "movgr2frh.w %2,%1", 0, 0, 0},
{0, 0, "mfc1", "r,f", "movfr2gr.s %1,%2", 0, 0, 0},
{0, 0, "dmfc1", "r,f", "movfr2gr.d %1,%2", 0, 0, 0},
{0, 0, "mfhc1", "r,f", "movfrh2gr.s %1,%2", 0, 0, 0},
{0, 0, "cvt.ld.d", "f,f", "fcvt.ld.d %1,%2", 0, 0, 0},
{0, 0, "cvt.ud.d", "f,f", "fcvt.ud.d %1,%2", 0, 0, 0},
{0, 0, "cvt.d.ld", "f,f,f", "fcvt.d.ld %1,%2,%3", 0, 0, 0},
{0, 0, "cvt.s.d", "f,f", "fcvt.s.d %1,%2", 0, 0, 0},
{0, 0, "cvt.d.s", "f,f", "fcvt.d.s %1,%2", 0, 0, 0},
{0, 0, "floor.w.s", "f,f", "ftintrm.w.s %1,%2", 0, 0, 0},
{0, 0, "floor.w.d", "f,f", "ftintrm.w.d %1,%2", 0, 0, 0},
{0, 0, "floor.l.s", "f,f", "ftintrm.l.s %1,%2", 0, 0, 0},
{0, 0, "floor.l.d", "f,f", "ftintrm.l.d %1,%2", 0, 0, 0},
{0, 0, "ceil.w.s", "f,f", "ftintrp.w.s %1,%2", 0, 0, 0},
{0, 0, "ceil.w.d", "f,f", "ftintrp.w.d %1,%2", 0, 0, 0},
{0, 0, "ceil.l.s", "f,f", "ftintrp.l.s %1,%2", 0, 0, 0},
{0, 0, "ceil.l.d", "f,f", "ftintrp.l.d %1,%2", 0, 0, 0},
{0, 0, "trunc.w.s", "f,f", "ftintrz.w.s %1,%2", 0, 0, 0},
{0, 0, "trunc.w.d", "f,f", "ftintrz.w.d %1,%2", 0, 0, 0},
{0, 0, "trunc.l.s", "f,f", "ftintrz.l.s %1,%2", 0, 0, 0},
{0, 0, "trunc.l.d", "f,f", "ftintrz.l.d %1,%2", 0, 0, 0},
{0, 0, "round.w.s", "f,f", "ftintrne.w.s %1,%2", 0, 0, 0},
{0, 0, "round.w.d", "f,f", "ftintrne.w.d %1,%2", 0, 0, 0},
{0, 0, "round.l.s", "f,f", "ftintrne.l.s %1,%2", 0, 0, 0},
{0, 0, "round.l.d", "f,f", "ftintrne.l.d %1,%2", 0, 0, 0},
{0, 0, "cvt.w.s", "f,f", "ftint.w.s %1,%2", 0, 0, 0},
{0, 0, "cvt.w.d", "f,f", "ftint.w.d %1,%2", 0, 0, 0},
{0, 0, "cvt.l.s", "f,f", "ftint.l.s %1,%2", 0, 0, 0},
{0, 0, "cvt.l.d", "f,f", "ftint.l.d %1,%2", 0, 0, 0},
{0, 0, "cvt.s.w", "f,f", "ffint.s.w %1,%2", 0, 0, 0},
{0, 0, "cvt.s.l", "f,f", "ffint.s.l %1,%2", 0, 0, 0},
{0, 0, "cvt.d.w", "f,f", "ffint.d.w %1,%2", 0, 0, 0},
{0, 0, "cvt.d.l", "f,f", "ffint.d.l %1,%2", 0, 0, 0},

{0, 0, "lwc1", "f,s0:11,r", "fld.s %1,%3,%2", 0, 0, 0},
{0, 0, "lwc1", "f,s,r", "dli $at,%2;add.d $at,$at,%3;fld.s %1,$at,0", 0, 0, 0},
{0, 0, "lwc1", "f,la", "la $at,%2;fld.s %1,$at,0", 0, 0, 0},
{0, 0, "l.s", "f,s0:11,r", "fld.s %1,%3,%2", 0, 0, 0},
{0, 0, "l.s", "f,s,r", "dli $at,%2;add.d $at,$at,%3;fld.s %1,$at,0", 0, 0, 0},
{0, 0, "l.s", "f,la", "la $at,%2;fld.s %1,$at,0", 0, 0, 0},
{0, 0, "lwxc1", "f,r,r", "fldx.s %1,%3,%2", 0, 0, 0},
{0, 0, "swc1", "f,s0:11,r", "fst.s %1,%3,%2", 0, 0, 0},
{0, 0, "swc1", "f,s,r", "dli $at,%2;add.d $at,$at,%3;fst.s %1,$at,0", 0, 0, 0},
{0, 0, "swc1", "f,la", "la $at,%2;fst.s %1,$at,0", 0, 0, 0},
{0, 0, "s.s", "f,s0:11,r", "fst.s %1,%3,%2", 0, 0, 0},
{0, 0, "s.s", "f,s,r", "dli $at,%2;add.d $at,$at,%3;fst.s %1,$at,0", 0, 0, 0},
{0, 0, "s.s", "f,la", "la $at,%2;fst.s %1,$at,0", 0, 0, 0},
{0, 0, "swxc1", "f,r,r", "fstx.s %1,%3,%2", 0, 0, 0},
{0, 0, "ldc1", "f,s0:11,r", "fld.d %1,%3,%2", 0, 0, 0},
{0, 0, "ldc1", "f,s,r", "dli $at,%2;add.d $at,$at,%3;fld.d %1,$at,0", 0, 0, 0},
{0, 0, "ldc1", "f,la", "la $at,%2;fld.d %1,$at,0", 0, 0, 0},
{0, 0, "l.d", "f,s0:11,r", "fld.d %1,%3,%2", 0, 0, 0},
{0, 0, "l.d", "f,s,r", "dli $at,%2;add.d $at,$at,%3;fld.d %1,$at,0", 0, 0, 0},
{0, 0, "l.d", "f,la", "la $at,%2;fld.d %1,$at,0", 0, 0, 0},
{0, 0, "ldxc1", "f,r,r", "fldx.d %1,%3,%2", 0, 0, 0},
{0, 0, "sdc1", "f,s0:11,r", "fst.d %1,%3,%2", 0, 0, 0},
{0, 0, "sdc1", "f,s,r", "dli $at,%2;add.d $at,$at,%3;fst.d %1,$at,0", 0, 0, 0},
{0, 0, "sdc1", "f,la", "la $at,%2;fst.d %1,$at,0", 0, 0, 0},
{0, 0, "s.d", "f,s0:11,r", "fst.d %1,%3,%2", 0, 0, 0},
{0, 0, "s.d", "f,s,r", "dli $at,%2;add.d $at,$at,%3;fst.d %1,$at,0", 0, 0, 0},
{0, 0, "s.d", "f,la", "la $at,%2;fst.d %1,$at,0", 0, 0, 0},
{0, 0, "sdxc1", "f,r,r", "fstx.d %1,%3,%2", 0, 0, 0},
{0, 0, "trunc.w.s", "f,f", "ftintrz.w.s %1,%2", 0, 0, 0},
{0, 0, "trunc.w.d", "f,f", "ftintrz.w.d %1,%2", 0, 0, 0},
{0, 0, "trunc.l.s", "f,f", "ftintrz.l.s %1,%2", 0, 0, 0},
{0, 0, "trunc.l.d", "f,f", "ftintrz.l.d %1,%2", 0, 0, 0},

{0, 0, "c.f.d", "f,f", "fcmp.caf.d $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.f.d", "c,f,f", "fcmp.caf.d %1,%2,%3;", 0, 0, 0},
{0, 0, "c.un.d", "f,f", "fcmp.cun.d $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.un.d", "c,f,f", "fcmp.cun.d %1,%2,%3;", 0, 0, 0},
{0, 0, "c.eq.d", "f,f", "fcmp.ceq.d $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.eq.d", "c,f,f", "fcmp.ceq.d %1,%2,%3;", 0, 0, 0},
{0, 0, "c.ueq.d", "f,f", "fcmp.cueq.d $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.ueq.d", "c,f,f", "fcmp.cueq.d %1,%2,%3;", 0, 0, 0},
{0, 0, "c.olt.d", "f,f", "fcmp.clt.d $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.olt.d", "c,f,f", "fcmp.clt.d %1,%2,%3;", 0, 0, 0},
{0, 0, "c.ult.d", "f,f", "fcmp.cult.d $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.ult.d", "c,f,f", "fcmp.cult.d %1,%2,%3;", 0, 0, 0},
{0, 0, "c.ole.d", "f,f", "fcmp.cle.d $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.ole.d", "c,f,f", "fcmp.cle.d %1,%2,%3;", 0, 0, 0},
{0, 0, "c.ule.d", "f,f", "fcmp.cule.d $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.ule.d", "c,f,f", "fcmp.cule.d %1,%2,%3;", 0, 0, 0},
{0, 0, "c.sf.d", "f,f", "fcmp.saf.d $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.sf.d", "c,f,f", "fcmp.saf.d %1,%2,%3;", 0, 0, 0},
{0, 0, "c.ngle.d", "f,f", "fcmp.sun.d $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.ngle.d", "c,f,f", "fcmp.sun.d %1,%2,%3;", 0, 0, 0},
{0, 0, "c.seq.d", "f,f", "fcmp.seq.d $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.seq.d", "c,f,f", "fcmp.seq.d %1,%2,%3;", 0, 0, 0},
{0, 0, "c.ngl.d", "f,f", "fcmp.sueq.d $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.ngl.d", "c,f,f", "fcmp.sueq.d %1,%2,%3;", 0, 0, 0},
{0, 0, "c.lt.d", "f,f", "fcmp.slt.d $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.lt.d", "c,f,f", "fcmp.slt.d %1,%2,%3;", 0, 0, 0},
{0, 0, "c.nge.d", "f,f", "fcmp.sult.d $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.nge.d", "c,f,f", "fcmp.sult.d %1,%2,%3;", 0, 0, 0},
{0, 0, "c.le.d", "f,f", "fcmp.sle.d $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.le.d", "c,f,f", "fcmp.sle.d %1,%2,%3;", 0, 0, 0},
{0, 0, "c.ngt.d", "f,f", "fcmp.sule.d $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.ngt.d", "c,f,f", "fcmp.sule.d %1,%2,%3;", 0, 0, 0},

{0, 0, "c.f.s", "f,f", "fcmp.caf.s $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.f.s", "c,f,f", "fcmp.caf.s %1,%2,%3;", 0, 0, 0},
{0, 0, "c.un.s", "f,f", "fcmp.cun.s $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.un.s", "c,f,f", "fcmp.cun.s %1,%2,%3;", 0, 0, 0},
{0, 0, "c.eq.s", "f,f", "fcmp.ceq.s $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.eq.s", "c,f,f", "fcmp.ceq.s %1,%2,%3;", 0, 0, 0},
{0, 0, "c.ueq.s", "f,f", "fcmp.cueq.s $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.ueq.s", "c,f,f", "fcmp.cueq.s %1,%2,%3;", 0, 0, 0},
{0, 0, "c.olt.s", "f,f", "fcmp.clt.s $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.olt.s", "c,f,f", "fcmp.clt.s %1,%2,%3;", 0, 0, 0},
{0, 0, "c.ult.s", "f,f", "fcmp.cult.s $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.ult.s", "c,f,f", "fcmp.cult.s %1,%2,%3;", 0, 0, 0},
{0, 0, "c.ole.s", "f,f", "fcmp.cle.s $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.ole.s", "c,f,f", "fcmp.cle.s %1,%2,%3;", 0, 0, 0},
{0, 0, "c.ule.s", "f,f", "fcmp.cule.s $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.ule.s", "c,f,f", "fcmp.cule.s %1,%2,%3;", 0, 0, 0},
{0, 0, "c.sf.s", "f,f", "fcmp.saf.s $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.sf.s", "c,f,f", "fcmp.saf.s %1,%2,%3;", 0, 0, 0},
{0, 0, "c.ngle.s", "f,f", "fcmp.sun.s $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.ngle.s", "c,f,f", "fcmp.sun.s %1,%2,%3;", 0, 0, 0},
{0, 0, "c.seq.s", "f,f", "fcmp.seq.s $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.seq.s", "c,f,f", "fcmp.seq.s %1,%2,%3;", 0, 0, 0},
{0, 0, "c.ngl.s", "f,f", "fcmp.sueq.s $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.ngl.s", "c,f,f", "fcmp.sueq.s %1,%2,%3;", 0, 0, 0},
{0, 0, "c.lt.s", "f,f", "fcmp.slt.s $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.lt.s", "c,f,f", "fcmp.slt.s %1,%2,%3;", 0, 0, 0},
{0, 0, "c.nge.s", "f,f", "fcmp.sult.s $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.nge.s", "c,f,f", "fcmp.sult.s %1,%2,%3;", 0, 0, 0},
{0, 0, "c.le.s", "f,f", "fcmp.sle.s $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.le.s", "c,f,f", "fcmp.sle.s %1,%2,%3;", 0, 0, 0},
{0, 0, "c.ngt.s", "f,f", "fcmp.sule.s $fcc0,%1,%2;", 0, 0, 0},
{0, 0, "c.ngt.s", "c,f,f", "fcmp.sule.s %1,%2,%3;", 0, 0, 0},

{0} /* Terminate the list.  */
};

static struct loongarch_ase loongarch_mips_ASEs[] = {

{&ASM_opts.mips_ase_fix, loongarch_MIPS_branch, 0, &contrary_branch_cond_check, {0}, 0, 0},
{&ASM_opts.mips_ase_fix, loongarch_MIPS_branch_contrary, &contrary_branch_cond_check, 0, {0}, 0, 0},

{&ASM_opts.mips_ase_fix, loongarch_MIPS_fix_opcodes, &LARCH_opts.rlen_is_64, 0, {0}, 0, 0},
{&ASM_opts.mips_ase_float, loongarch_MIPS_float_branch, 0, &contrary_branch_cond_check, {0}, 0, 0},
{&ASM_opts.mips_ase_float, loongarch_MIPS_float_branch_contrary, &contrary_branch_cond_check, 0, {0}, 0, 0},
{&ASM_opts.mips_ase_float, loongarch_MIPS_float_opcodes, &LARCH_opts.rlen_is_64, 0, {0}, 0, 0},

{0},
};
