#include "as.h"
#include "dw2gencfi.h"
#include "tc-loongarch.h"
#include "elf/loongarch.h"
#include "opcode/loongarch.h"
#include "obj-elf.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* All information about an instruction during assemble */
struct loongarch_cl_insn
{
  /* First split string */
  const char *name;
  const char *arg_strs[MAX_ARG_NUM_PLUS_2];
  size_t arg_num;

  /* Second analyze name_str and each actual args string to match the insn
     in 'loongarch-opc.c'. And actual args may need be relocated.
     We get length of insn. If 'insn_length == 0 && insn_mo->macro != NULL',
     it's a macro insntruction and we call 'md_assemble' recursively
     after expanding it.  */
  int match_now;
  int all_match;

  const struct loongarch_opcode *insn;
  size_t insn_length;

  offsetT args[MAX_ARG_NUM_PLUS_2];
  struct reloc_info reloc_info[MAX_RELOC_NUMBER_A_INSN];
  size_t reloc_num;

  /* For relax reserved. We not support relax now.
     'insn_length < relax_max_length' means need to relax.
     And 'insn_length == relax_max_length' means no need to relax. */
  size_t relax_max_length;
  relax_substateT subtype;

  /* Then we get the binary representation of insn
     and write it in to section. */
  insn_t insn_bin;

  /* The frag that contains the instruction.  */
  struct frag *frag;
  /* The offset into FRAG of the first instruction byte.  */
  long where;
  /* The relocs associated with the instruction, if any.  */
  fixS *fixp[MAX_RELOC_NUMBER_A_INSN];
};

/* This array holds the chars that always start a comment.  If the
   pre-processor is disabled, these aren't very useful */
const char comment_chars[] = "#";

/* This array holds the chars that only start a comment at the beginning of
   a line.  If the line seems to have the form '# 123 filename'
   .line and .file directives will appear in the pre-processed output */
/* Note that input_file.c hand checks for '#' at the beginning of the
   first line of the input file.  This is because the compiler outputs
#NO_APP at the beginning of its output.  */
/* Also note that C style comments are always supported.  */
const char line_comment_chars[] = "#";

/* This array holds machine specific line separator characters.  */
const char line_separator_chars[] = ";";

/* Chars that can be used to separate mant from exp in floating point nums */
const char EXP_CHARS[] = "eE";

/* Chars that mean this number is a floating point constant */
/* As in 0f12.456 */
/* or    0d1.2345e12 */
const char FLT_CHARS[] = "rRsSfFdDxXpP";

static struct
{
  int mips_converter_enabled;
  int mips_abi_is_o32;
  int mips_abi_is_n32;
  int mips_abi_is_n64;
  int mips_ase_fix;
  int mips_ase_float;
  int mips_ase_msa;
  int mips_ase_lasx;
} ASM_opts =
{
  .mips_converter_enabled = 0,
  .mips_abi_is_o32 = 0,
  .mips_abi_is_n32 = 0,
  .mips_abi_is_n64 = 0,
  .mips_ase_fix = 0,
  .mips_ase_float = 0,
  .mips_ase_msa = 0,
  .mips_ase_lasx = 0,
};

const char *md_shortopts = "O::g::G:";

enum options
{
  OPTION_IGNORE = OPTION_MD_BASE,
  OPTION_MIPS,
  OPTION_MIPS_ABI,

  OPTION_SOFT_FLOAT,
  OPTION_HARD_FLOAT,
  OPTION_ABI,

  OPTION_LA_LOCAL_WITH_ABS,
  OPTION_LA_GLOBAL_WITH_PCREL,
  OPTION_LA_GLOBAL_WITH_ABS,

  OPTION_END_OF_ENUM,
};

struct option md_longopts[] =
{
  {"mmips", no_argument, NULL, OPTION_MIPS},
  {"mmips-abi", required_argument, NULL, OPTION_MIPS_ABI},

  {"msoft-float", no_argument, NULL, OPTION_SOFT_FLOAT},
  {"mhard-float", no_argument, NULL, OPTION_HARD_FLOAT},
  {"mabi", required_argument, NULL, OPTION_ABI},

  {"mla-local-with-abs", no_argument, NULL, OPTION_LA_LOCAL_WITH_ABS},
  {"mla-global-with-pcrel", no_argument, NULL, OPTION_LA_GLOBAL_WITH_PCREL},
  {"mla-global-with-abs", no_argument, NULL, OPTION_LA_GLOBAL_WITH_ABS},

  {NULL, no_argument, NULL, 0}
};

size_t md_longopts_size = sizeof (md_longopts);

int
md_parse_option (int c, const char *arg)
{
  int ret = 1;
  switch (c)
    {
    case OPTION_MIPS:
      ASM_opts.mips_converter_enabled = 1;
      break;
    case OPTION_MIPS_ABI:
      if (strcasecmp (arg, "32") == 0)
	ASM_opts.mips_abi_is_o32 = 1;
      else if (strcasecmp (arg, "n32") == 0)
	ASM_opts.mips_abi_is_n32 = 1;
      else if (strcasecmp (arg, "64") == 0)
	ASM_opts.mips_abi_is_n64 = 1;
      else
	ret = 0;
      break;

    case OPTION_SOFT_FLOAT:
      LARCH_opts.ase_float = 0;
      break;
    case OPTION_HARD_FLOAT:
      LARCH_opts.ase_float = 1;
      break;
    case OPTION_ABI:
      if (strcasecmp (arg, "lp64") == 0)
	LARCH_opts.abi_is_lp64 = 1;
      else if (strcasecmp (arg, "lp32") == 0)
	LARCH_opts.abi_is_lp32 = 1;
      else
	ret = 0;
      break;
    case OPTION_LA_LOCAL_WITH_ABS:
      LARCH_opts.la_local_with_abs = 1;
      break;
    case OPTION_LA_GLOBAL_WITH_PCREL:
      LARCH_opts.la_global_with_pcrel = 1;
      break;
    case OPTION_LA_GLOBAL_WITH_ABS:
      LARCH_opts.la_global_with_abs = 1;
      break;
    case OPTION_IGNORE:
      break;
    }
  return ret;
}

static struct hash_control *r_htab = NULL;
static struct hash_control *f_htab = NULL;
static struct hash_control *c_htab = NULL;
static struct hash_control *cr_htab = NULL;
static struct hash_control *v_htab = NULL;
static struct hash_control *x_htab = NULL;

static void
loongarch_mips_converter_init (void);

void
loongarch_after_parse_args ()
{
  size_t i;

  LARCH_opts.ase_test = 1;
  LARCH_opts.ase_fix = 1;
  LARCH_opts.ase_float = 1;
  LARCH_opts.ase_128vec = 1;
  LARCH_opts.ase_256vec = 1;

  if (!r_htab)
    r_htab = hash_new (), hash_insert (r_htab, "", 0);
  if (!f_htab)
    f_htab = hash_new (), hash_insert (f_htab, "", 0);
  if (!c_htab)
    c_htab = hash_new (), hash_insert (c_htab, "", 0);
  if (!cr_htab)
    cr_htab = hash_new (), hash_insert (cr_htab, "", 0);
  if (!v_htab)
    v_htab = hash_new (), hash_insert (v_htab, "", 0);
  if (!x_htab)
    x_htab = hash_new (), hash_insert (x_htab, "", 0);

  for (i = 0; i < ARRAY_SIZE (loongarch_r_normal_name); i++)
    hash_insert (r_htab, loongarch_r_normal_name[i], (void *) (i + 1));
  for (i = 0; i < ARRAY_SIZE (loongarch_f_normal_name); i++)
    hash_insert (f_htab, loongarch_f_normal_name[i], (void *) (i + 1));
  for (i = 0; i < ARRAY_SIZE (loongarch_c_normal_name); i++)
    hash_insert (c_htab, loongarch_c_normal_name[i], (void *) (i + 1));
  for (i = 0; i < ARRAY_SIZE (loongarch_cr_normal_name); i++)
    hash_insert (cr_htab, loongarch_cr_normal_name[i], (void *) (i + 1));
  for (i = 0; i < ARRAY_SIZE (loongarch_v_normal_name); i++)
    hash_insert (v_htab, loongarch_v_normal_name[i], (void *) (i + 1));
  for (i = 0; i < ARRAY_SIZE (loongarch_x_normal_name); i++)
    hash_insert (x_htab, loongarch_x_normal_name[i], (void *) (i + 1));

  if (LARCH_opts.abi_is_lp64
      + LARCH_opts.abi_is_lp32
      == 0)
    {
      // as_warn (_("default LoongISA ABI is lp64"));
      LARCH_opts.abi_is_lp64 = 1;
    }

  if (1 < LARCH_opts.abi_is_lp64
      + LARCH_opts.abi_is_lp32)
    as_fatal (_("we can specify only ONE abi"));

  if (LARCH_opts.abi_is_lp64)
    {
      LARCH_opts.addrwidth_is_64 = 1;
      LARCH_opts.rlen_is_64 = 1;
      for (i = 0; i < ARRAY_SIZE (loongarch_r_lp64_name); i++)
	hash_insert (r_htab, loongarch_r_lp64_name[i], (void *) (i + 1));
      for (i = 0; i < ARRAY_SIZE (loongarch_r_lp64_name1); i++)
	hash_insert (r_htab, loongarch_r_lp64_name1[i], (void *) (i + 1));
      for (i = 0; i < ARRAY_SIZE (loongarch_f_lp64_name); i++)
	hash_insert (f_htab, loongarch_f_lp64_name[i], (void *) (i + 1));
      for (i = 0; i < ARRAY_SIZE (loongarch_f_lp64_name1); i++)
	hash_insert (f_htab, loongarch_f_lp64_name1[i], (void *) (i + 1));
    }

  if (LARCH_opts.abi_is_lp32)
    {
      LARCH_opts.addrwidth_is_32 = 1;
      LARCH_opts.rlen_is_32 = 1;
    }

  if (ASM_opts.mips_converter_enabled)
    loongarch_mips_converter_init ();
}

const char *
loongarch_target_format ()
{
  return LARCH_opts.addrwidth_is_32? "elf32-loongarch" : "elf64-loongarch";
}

void
md_begin ()
{
  if (LARCH_opts.ase_test)
    {
      const struct loongarch_opcode *it;
      struct loongarch_ase *ase;
      for (ase = loongarch_ASEs; ase->enabled; ase++)
	for (it = ase->opcodes; it->name; it++)
	  {
	    if (loongarch_check_format (it->format) != 0)
	      as_fatal (_("insn name: %s\tformat: %s\tsyntax error"),
			it->name, it->format);
	    if (it->mask == 0 && it->macro == 0)
	      as_fatal (_("insn name: %s\nformat: %s\nwe want macro but macro is NULL"),
			it->name, it->format);
	    if (it->macro && loongarch_check_macro (it->format, it->macro) != 0)
	      as_fatal (_("insn name: %s\nformat: %s\nmacro: %s\tsyntax error"),
			it->name, it->format, it->macro);
	  }
    }

  /* FIXME: expressionS use 'offsetT' as constant, we want this is 64-bit type */
  assert (8 <= sizeof (offsetT));
}

void
md_operand (expressionS *e)
{
  /* Because we use 'expression' to check if a actual arg is a expr at first.
     If not, we want a returning. */
  if (e->X_op == O_absent)
    e->X_op = O_illegal;
}

static const expressionS const_0 = {.X_op = O_constant, .X_add_number = 0};

static const char *
my_getExpression (expressionS *ep, const char *str)
{
  char *save_in, *ret;
  save_in = input_line_pointer;
  input_line_pointer = (char *)str;
  expression (ep);
  ret = input_line_pointer;
  input_line_pointer = save_in;
  return ret;
}


/* for compitable with MIPS pesudo insn like '.set reorder'
   but actually ignore them. */
static void
s_loongarch_set (int x ATTRIBUTE_UNUSED)
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

  *input_line_pointer = ch;
  demand_empty_rest_of_line ();
}

static void
s_loongarch_align (int arg)
{
  const char *t = input_line_pointer;
  while (!is_end_of_line[(unsigned char) *t] && *t != ',')
    ++t;
  if (*t == ',')
    s_align_ptwo (arg);
  else
    s_align_ptwo (0);
}

/* Handle the .dtprelword and .dtpreldword pseudo-ops.  They generate
   a 32-bit or 64-bit DTP-relative relocation (BYTES says which) for
   use in DWARF debug information.  */

static void
s_dtprel (int bytes)
{
  expressionS ex;
  char *p;

  expression (&ex);

  if (ex.X_op != O_symbol)
    {
      as_bad (_("Unsupported use of %s"), (bytes == 8
					   ? ".dtpreldword"
					   : ".dtprelword"));
      ignore_rest_of_line ();
    }

  p = frag_more (bytes);
  md_number_to_chars (p, 0, bytes);
  fix_new_exp (frag_now, p - frag_now->fr_literal, bytes, &ex, FALSE,
	       (bytes == 8
		? BFD_RELOC_LARCH_TLS_DTPREL64
		: BFD_RELOC_LARCH_TLS_DTPREL32));

  demand_empty_rest_of_line ();
}

#include "tc-loongarch-mips.c"

static const pseudo_typeS loongarch_pseudo_table[] =
{
  {"align", s_loongarch_align, -4},
  {"dword", cons, 8},
  {"word", cons, 4},
  {"half", cons, 2},
  {"dtprelword", s_dtprel, 4},
  {"dtpreldword", s_dtprel, 8},
  { NULL, NULL, 0 },
};

void
loongarch_pop_insert (void)
{
  if (ASM_opts.mips_converter_enabled)
    pop_insert (loongarch_mips_pseudo_table);
  else
    pop_insert (loongarch_pseudo_table);
}


#define INTERNAL_LABEL_SPECIAL 10
static unsigned long internal_label_count[INTERNAL_LABEL_SPECIAL] = {0};

static const char *
loongarch_internal_label_name (unsigned long label, int augend)
{
  static char symbol_name_build[24];
  unsigned long want_label;
  char *p;

  want_label = internal_label_count[label] + augend;

  p = symbol_name_build;
#ifdef LOCAL_LABEL_PREFIX
  *p++ = LOCAL_LABEL_PREFIX;
#endif
  *p++ = 'L';
  for (; label; label /= 10)
    *p++ = label % 10 + '0';
  /* make sure internal label never belong to normal label namespace */
  *p++ = ':';
  for (; want_label; want_label /= 10)
    *p++ = want_label % 10 + '0';
  *p++ = '\0';
  return symbol_name_build;
}

static void
setup_internal_label_here (unsigned long label)
{
  assert (label < INTERNAL_LABEL_SPECIAL);
  internal_label_count[label]++;
  colon (loongarch_internal_label_name (label ,0));
}

extern void /* no static. used by 'loongarch-parse.y' */
get_internal_label (expressionS *label_expr,
		    unsigned long label,
		    int augend/* 0 for previous, 1 for next */);

void
get_internal_label (expressionS *label_expr,
		    unsigned long label,
		    int augend/* 0 for previous, 1 for next */)
{
  assert (label < INTERNAL_LABEL_SPECIAL);
  if (augend == 0 && internal_label_count[label] == 0)
    as_fatal (_("internal error: we have no internal label yet"));
  label_expr->X_op = O_symbol;
  label_expr->X_add_symbol =
    symbol_find_or_make (loongarch_internal_label_name (label, augend));
  label_expr->X_add_number = 0;
}

extern int loongarch_parse_expr (const char *expr,
				 struct reloc_info *reloc_stack_top,
				 size_t max_reloc_num, size_t *reloc_num,
				 offsetT *imm_if_no_reloc);

int
is_internal_label (const char *c_str)
{
  do
    {
      if (*c_str != ':')
	break;
      c_str++;
      if (!('0' <= *c_str && *c_str <= '9'))
	break;
      while ('0' <= *c_str && *c_str <= '9')
	c_str++;
      if (*c_str != 'b' && *c_str != 'f')
	break;
      c_str++;
      return *c_str == '\0';
    }
  while (0);
  return 0;
}

int
is_label (const char *c_str)
{
  if (is_internal_label (c_str))
    return 1;
  else if ('0' <= *c_str && *c_str <= '9')
    {
      /* [0-9]+[bf]  */
      while ('0' <= *c_str && *c_str <= '9')
	c_str++;
      return *c_str == 'b' || *c_str == 'f';
    }
  else if (is_name_beginner (*c_str))
    {
      /* [a-zA-Z\._\$][0-9a-zA-Z\._\$]*  */
      c_str++;
      while (is_part_of_name (*c_str))
	c_str++;
      return *c_str == '\0';
    }
  else
    return 0;
}

int
is_label_with_addend (const char *c_str)
{
  if (is_internal_label (c_str))
    return 1;
  else if ('0' <= *c_str && *c_str <= '9')
    {
      /* [0-9]+[bf]  */
      while ('0' <= *c_str && *c_str <= '9')
	c_str++;
      if (*c_str == 'b' || *c_str == 'f')
	c_str++;
      else
	return 0;
      return *c_str == '\0'
		       || ((*c_str == '-' || *c_str == '+')
			   && is_unsigned (c_str + 1));
    }
  else if (is_name_beginner (*c_str))
    {
      /* [a-zA-Z\._\$][0-9a-zA-Z\._\$]*  */
      c_str++;
      while (is_part_of_name (*c_str))
	c_str++;
      return *c_str == '\0'
		       || ((*c_str == '-' || *c_str == '+')
			   && is_unsigned (c_str + 1));
    }
  else
    return 0;
}

extern int
loongarch_parse_expr (const char *expr,
		     struct reloc_info *reloc_stack_top,
		     size_t max_reloc_num,
		     size_t *reloc_num,
		     offsetT *imm_if_no_reloc);

static int32_t
loongarch_args_parser_can_match_arg_helper (char esc_ch1,
					   char esc_ch2,
					   const char *bit_field,
					   const char *arg,
					   void *context)
{
  struct loongarch_cl_insn *ip = context;
  offsetT imm, ret = 0;
  size_t reloc_num_we_have = MAX_RELOC_NUMBER_A_INSN - ip->reloc_num;
  size_t reloc_num = 0;

  if (!ip->match_now)
    return 0;

  switch (esc_ch1)
    {
    case 'l':
      switch (esc_ch2)
	{
	default:
	  ip->match_now = is_label (arg);
	  if (!ip->match_now && is_label_with_addend (arg))
	    as_fatal (_("This label shouldn't be with addend."));
	  break;
	case 'a':
	  ip->match_now = is_label_with_addend (arg);
	  break;
	}
      break;
    case 's':
    case 'u':
      ip->match_now =
	loongarch_parse_expr (arg, ip->reloc_info + ip->reloc_num,
	  reloc_num_we_have, &reloc_num, &imm) == 0;

      if (!ip->match_now)
	break;

      if (esc_ch1 == 's')
	switch (esc_ch2)
	  {
	  case 'c':
	    ip->match_now = reloc_num == 0;
	    break;
	  }
      else
	switch (esc_ch2)
	  {
	  case 'c':
	    ip->match_now = reloc_num == 0 && 0 <= imm;
	    break;
	  }

      if (!ip->match_now)
	break;

      ret = imm;
      if (reloc_num)
	{
	  bfd_reloc_code_real_type reloc_type = BFD_RELOC_NONE;
	  reloc_num_we_have -= reloc_num;
	  if (reloc_num_we_have == 0)
	    as_fatal (_("expr too huge") /* want one more reloc */);
	  if (esc_ch1 == 'u')
	    {
	      if (strncmp (bit_field, "10:12", strlen ("10:12")) == 0)
		reloc_type = BFD_RELOC_LARCH_SOP_POP_32_U_10_12;
	    }
	  else if (esc_ch1 == 's')
	    {
	      if (strncmp (bit_field, "10:16<<2", strlen ("10:16<<2")) == 0)
		reloc_type = BFD_RELOC_LARCH_SOP_POP_32_S_10_16_S2;
	      else if (strncmp (bit_field, "0:5|10:16<<2", strlen ("0:5|10:16<<2")) == 0)
		reloc_type = BFD_RELOC_LARCH_SOP_POP_32_S_0_5_10_16_S2;
	      else if (strncmp (bit_field, "0:10|10:16<<2", strlen ("0:10|10:16<<2")) == 0)
		reloc_type = BFD_RELOC_LARCH_SOP_POP_32_S_0_10_10_16_S2;
	      else if (strncmp (bit_field, "10:12", strlen ("10:12")) == 0)
		reloc_type = BFD_RELOC_LARCH_SOP_POP_32_S_10_12;
	      else if (strncmp (bit_field, "5:20", strlen ("5:20")) == 0)
		reloc_type = BFD_RELOC_LARCH_SOP_POP_32_S_5_20;
	      else if (strncmp (bit_field, "10:16", strlen ("10:16")) == 0)
		reloc_type = BFD_RELOC_LARCH_SOP_POP_32_S_10_16;
	      else if (strncmp (bit_field, "10:5", strlen ("10:5")) == 0)
		reloc_type = BFD_RELOC_LARCH_SOP_POP_32_S_10_5;
	    }
	  if (reloc_type == BFD_RELOC_NONE)
	    as_fatal (_("not support reloc bit-field\nfmt: %c%c %s\nargs: %s"),
		      esc_ch1, esc_ch2, bit_field , arg);
	  reloc_num++;
	  ip->reloc_num += reloc_num;
	  ip->reloc_info[ip->reloc_num - 1].type = reloc_type;
	  ip->reloc_info[ip->reloc_num - 1].value = const_0;
	}
      break;
    case 'r':
      imm = (offsetT) hash_find (r_htab, arg);
      ip->match_now = 0 < imm;
      ret = imm - 1;
      break;
    case 'f':
      imm = (offsetT) hash_find (f_htab, arg);
      ip->match_now = 0 < imm;
      ret = imm - 1;
      break;
    case 'c':
      switch (esc_ch2)
	{
	case 'r':
	  imm = (offsetT) hash_find (cr_htab, arg);
	  break;
	default:
	  imm = (offsetT) hash_find (c_htab, arg);
	}
      ip->match_now = 0 < imm;
      ret = imm - 1;
      break;
    case 'v':
      imm = (offsetT) hash_find (v_htab, arg);
      ip->match_now = 0 < imm;
      ret = imm - 1;
      break;
    case 'x':
      imm = (offsetT) hash_find (x_htab, arg);
      ip->match_now = 0 < imm;
      ret = imm - 1;
      break;
    case '\0':
      ip->all_match = ip->match_now;
      ip->insn_length = ip->insn->mask ? loongarch_insn_length (ip->insn->match) : 0;
      /* FIXME: now we have no relax insn */
      ip->relax_max_length = ip->insn_length;
      break;
    default:
      as_fatal (_("unknown escape"));
    }

  do
    {
      // check imm overflow
      int bit_width, bits_needed_s, bits_needed_u;
      char *t;

      if (!ip->match_now)
	break;

      if (0 < reloc_num)
	break;

      bit_width = loongarch_get_bit_field_width (bit_field, &t);

      if (bit_width == -1)
	// no specify bit width
	break;

      // 在这里求出实际填入的二进制数。这部分内容和 loongarch_encode_imm
      // 有重合。但是需要在这里加入一些判断内容，比如分支指令立即数
      // 右移两位，要保证立即数低两位为0
      imm = ret;
      if (t[0] == '<' && t[1] == '<')
	{
	  int i = strtol (t += 2, &t, 10), j;
	  for (j = i; 0 < j; j--, imm >>= 1)
	    if (imm & 1)
	      as_fatal (_("require imm low %d bit is 0."), i);
	}

      if (*t == '+')
	imm -= strtol (t, &t, 10);

      bits_needed_s = loongarch_bits_imm_needed (imm, 1);
      bits_needed_u = loongarch_bits_imm_needed (imm, 0);

      // 在这里判断立即数是否溢出。关于有符号立即数我有两种理解
      // 一是代数意义上的溢出，如果传入的值超出定义域，那么报错。
      // 二是程序员可能希望指定位域表示，那么值可能是一个使得符号位为1的正数。
      // riscv的溢出判断是第一种，这里按照riscv的方法来做
      if ((esc_ch1 == 's' && bit_width < bits_needed_s)
	  || (esc_ch1 != 's' && bit_width < bits_needed_u))
	// how to do after we detect overflow
	as_fatal (_("Immediate overflow.\n"
		    "format: %c%c%s\n"
		    "arg: %s"),
		  esc_ch1, esc_ch2, bit_field, arg);
    }
  while (0);

  if (esc_ch1 != '\0')
    {
      ip->args[ip->arg_num] = ret;
      ip->arg_num++;
    }
  return ret;
}

static void
get_loongarch_opcode (struct loongarch_cl_insn *insn)
{
  const struct loongarch_opcode *it;
  struct loongarch_ase *ase;
  for (ase = loongarch_ASEs; ase->enabled; ase++)
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

      if ((it = hash_find (ase->name_hash_entry, insn->name)) == NULL)
	continue;

      do
	{
	  insn->insn = it;
	  insn->match_now = 1;
	  insn->all_match = 0;
	  insn->arg_num = 0;
	  insn->reloc_num = 0;
	  insn->insn_bin =
	    loongarch_foreach_args (it->format, insn->arg_strs,
	      loongarch_args_parser_can_match_arg_helper, insn);
	  if (insn->all_match
	      && !(it->include && !*it->include)
	      && !(it->exclude && *it->exclude))
	    {
	      insn->insn_bin |= it->match;
	      return;
	    }
	  it++;
	}
      while (it->name && strcasecmp (it->name, insn->name) == 0);
    }
}

static int
check_this_insn_before_appending (struct loongarch_cl_insn *ip)
{
  int ret = 0;
  if (strcmp (ip->name, "la.abs") == 0)
    {
      ip->reloc_info[ip->reloc_num].type = BFD_RELOC_LARCH_MARK_LA;
      my_getExpression (&ip->reloc_info[ip->reloc_num].value, ip->arg_strs[1]);
      ip->reloc_num++;
    }
  else if (ip->insn->mask == 0xffff8000
	   && ((ip->insn_bin & 0xfff00000) == 0x38600000
	       || (ip->insn_bin & 0xffff0000) == 0x38700000
	       || (ip->insn_bin & 0xffff0000) == 0x38710000))
    {
      /* for AMO insn amswap.[wd], amadd.[wd], etc. */
      if (ip->args[0] != 0 &&
	  (ip->args[0] == ip->args[1] || ip->args[0] == ip->args[2]))
	as_fatal (_(
"AMO insns require rd != base && rd != rt when rd isn't $r0"));
    }
  else if ((ip->insn->mask == 0xffe08000
	    && (ip->insn_bin & 0xffe00000) == 0x00600000)
	   || (ip->insn->mask == 0xffc00000
	    && (ip->insn_bin & 0xff800000) == 0x00800000))
    {
      /* for bstr(ins|pick).[wd] */
      if (ip->args[2] < ip->args[3])
	as_fatal (_("bstr(ins|pick).[wd] require msbd >= lsbd"));
    }
  else if (ip->insn->mask != 0
	   && (ip->insn_bin & 0xfe0003c0) == 0x04000000
	   && (strcmp ("csrxchg", ip->name) == 0
	       || strcmp ("gcsrxchg", ip->name) == 0))
    as_fatal (_("g?csrxchg require rj != $r0 && rj != $r1"));

  return ret;
}

static void
install_insn (const struct loongarch_cl_insn *insn)
{
  char *f = insn->frag->fr_literal + insn->where;
  if (0 < insn->insn_length)
    md_number_to_chars (f, insn->insn_bin, insn->insn_length);
}

static void
move_insn (struct loongarch_cl_insn *insn, fragS *frag, long where)
{
  size_t i;
  insn->frag = frag;
  insn->where = where;
  for (i = 0; i < insn->reloc_num; i++)
    {
      insn->fixp[i]->fx_frag = frag;
      insn->fixp[i]->fx_where = where;
    }
  install_insn (insn);
}

/* Add INSN to the end of the output.  */
static void
append_fixed_insn (struct loongarch_cl_insn *insn)
{
  char *f = frag_more (insn->insn_length);
  move_insn (insn, frag_now, f - frag_now->fr_literal);
}

static void 
append_fixp_and_insn (struct loongarch_cl_insn *ip)
{
  reloc_howto_type *howto;
  bfd_reloc_code_real_type reloc_type;
  struct reloc_info *reloc_info = ip->reloc_info;
  size_t i;

  dwarf2_emit_insn (0);

  for (i = 0; i < ip->reloc_num; i++)
    {
      reloc_type = reloc_info[i].type;
      howto = bfd_reloc_type_lookup (stdoutput, reloc_type);
      if (howto == NULL)
	as_fatal (_("no HOWTO loong relocation number %d"), reloc_type);

      ip->fixp[i] =
	fix_new_exp (ip->frag, ip->where, bfd_get_reloc_size (howto),
	  &reloc_info[i].value, FALSE, reloc_type);
    }

  if (ip->insn_length < ip->relax_max_length)
    as_fatal (_ ("Internal error: not support relax now"));
  else
    append_fixed_insn (ip);
}

/* Ask helper for returning a malloced c_str or NULL.  */
static char *
assember_macro_helper (const char * const args[], void *context_ptr)
{
  struct loongarch_cl_insn *insn = context_ptr;
  char *ret = NULL;
  if (strcmp (insn->name, "li.d") == 0
      || strcmp (insn->name, "li.w") == 0)
    {
      char args_buf[50], insns_buf[200];
      const char *arg_strs[6];
      uint32_t hi32, lo32;

      /* We pay attention to sign extend beacause it is chance of reduce insn.
         The exception is 12-bit and hi-12-bit unsigned,
	 we need a 'ori' or a 'lu52i.d' accordingly. */
      char all0_bit_vec, sign_bit_vec, allf_bit_vec, paritial_is_sext_of_prev;

      lo32 = insn->args[1] & 0xffffffff;
      hi32 = insn->args[1] >> 32;


      if (strcmp (insn->name, "li.w") == 0)
        {
          if (hi32 != 0 && hi32 != 0xffffffff)
            as_fatal (_("li overflow: hi32:0x%x lo32:0x%x"), hi32, lo32);
          hi32 = lo32 & 0x80000000 ? 0xffffffff : 0;
        }

      if (strcmp (insn->name, "li.d") == 0 && LARCH_opts.rlen_is_32)
        as_fatal (_("we can't li.d on 32bit-arch"));

      snprintf (args_buf, sizeof (args_buf), "0x%x,0x%x,0x%x,0x%x,%s",
		(hi32 >> 20) & 0xfff, hi32 & 0xfffff,
		(lo32 >> 12) & 0xfffff, lo32 & 0xfff, args[0]);
      loongarch_split_args_by_comma (args_buf, arg_strs);

      all0_bit_vec = (((hi32 & 0xfff00000) == 0) << 3)
		   | (((hi32 & 0x000fffff) == 0) << 2)
		   | (((lo32 & 0xfffff000) == 0) << 1)
		   | ((lo32 & 0x00000fff) == 0);
      sign_bit_vec = (((hi32 & 0x80000000) != 0) << 3)
		   | (((hi32 & 0x00080000) != 0) << 2)
		   | (((lo32 & 0x80000000) != 0) << 1)
		   | ((lo32 & 0x00000800) != 0);
      allf_bit_vec = (((hi32 & 0xfff00000) == 0xfff00000) << 3)
		   | (((hi32 & 0x000fffff) == 0x000fffff) << 2)
		   | (((lo32 & 0xfffff000) == 0xfffff000) << 1)
		   | ((lo32 & 0x00000fff) == 0x00000fff);
      paritial_is_sext_of_prev = (all0_bit_vec ^ allf_bit_vec)
			       & (all0_bit_vec ^ (sign_bit_vec << 1));

      static const char * const li_32bit [] = {
	"lu12i.w %5,%3&0x80000?%3-0x100000:%3;ori %5,%5,%4;",
	"lu12i.w %5,%3&0x80000?%3-0x100000:%3;",
	"addi.w %5,$r0,%4&0x800?%4-0x1000:%4;",
	"or %5,$r0,$r0;",
      };
      static const char * const li_hi_32bit[] = {
	"lu32i.d %5,%2&0x80000?%2-0x100000:%2;"
	  "lu52i.d %5,%5,%1&0x800?%1-0x1000:%1;",
	"lu52i.d %5,%5,%1&0x800?%1-0x1000:%1;",
	"lu32i.d %5,%2&0x80000?%2-0x100000:%2;",
	"",
      };
      do
	{
	  insns_buf[0] = '\0';
	  if (paritial_is_sext_of_prev == 0x7)
	    {
	      strcat (insns_buf, "lu52i.d %5,$r0,%1&0x800?%1-0x1000:%1;");
	      break;
	    }
	  if ((all0_bit_vec & 0x3) == 0x2)
	    strcat (insns_buf, "ori %5,$r0,%4;");
	  else
	    strcat (insns_buf, li_32bit[paritial_is_sext_of_prev & 0x3]);
	  strcat (insns_buf, li_hi_32bit[paritial_is_sext_of_prev >> 2]);
	}
      while (0);

      ret = loongarch_expand_macro (insns_buf, arg_strs, NULL, NULL,
                                    sizeof (args_buf));
    }
  return ret;
}

//accept instructions separated by ';'
//assuming 'not starting with space and not ending with space' or pass in empty c_str
static void
loongarch_assemble_INSNs (char *str)
{
  char *rest;
  size_t len_str = strlen(str);

  for (rest = str; *rest != ';' && *rest != '\0'; rest++);
  if (*rest == ';')
    *rest++ = '\0';

  if (*str == ':')
    {
      str++;
      setup_internal_label_here (strtol (str, &str, 10));
      str++;
    }

  do
    {
      if (*str == '\0')
	break;

      struct loongarch_cl_insn the_one = {0};
      the_one.name = str;

      for (; *str && *str != ' '; str++);
      if (*str == ' ')
	*str++ = '\0';

      loongarch_split_args_by_comma (str, the_one.arg_strs);
      get_loongarch_opcode (&the_one);

      if (!the_one.all_match)
	as_fatal (_("no match insn: %s\t%s"),
	  the_one.name, loongarch_cat_splited_strs (the_one.arg_strs));

      if (check_this_insn_before_appending (&the_one) != 0)
	break;

      append_fixp_and_insn (&the_one);
      if (the_one.insn_length == 0 && the_one.insn->macro)
	{
	  char *c_str =
	    loongarch_expand_macro (the_one.insn->macro,
	      the_one.arg_strs, assember_macro_helper,
              &the_one, len_str);
	  loongarch_assemble_INSNs (c_str);
	  free (c_str);
	}
    }
  while (0);

  if (*rest != '\0')
    loongarch_assemble_INSNs (rest);
}

void
md_assemble (char *str)
{
  if (ASM_opts.mips_converter_enabled)
    {
      char *insns = loongarch_converte_one_mips (str);
      loongarch_assemble_INSNs (insns);
      free (insns);
    }
  else
    loongarch_assemble_INSNs (str);
}

const char *md_atof (int type, char *litP, int *sizeP)
{
  return ieee_md_atof (type, litP, sizeP, FALSE);
}

void md_number_to_chars (char *buf, valueT val, int n)
{
  number_to_chars_littleendian (buf, val, n);
}

/* The location from which a PC relative jump should be calculated,
   given a PC relative reloc.  */
long
md_pcrel_from (fixS *fixP ATTRIBUTE_UNUSED)
{
  return 0;
}

void
md_apply_fix (fixS *fixP, valueT *valP, segT seg ATTRIBUTE_UNUSED)
{
  static int64_t stack_top;
  static int last_reloc_is_sop_push_pcrel_1 = 0;
  int last_reloc_is_sop_push_pcrel = last_reloc_is_sop_push_pcrel_1;
  insn_t insn;
  last_reloc_is_sop_push_pcrel_1 = 0;

  char *buf = fixP->fx_frag->fr_literal + fixP->fx_where;
  switch (fixP->fx_r_type)
    {
    case BFD_RELOC_LARCH_SOP_PUSH_TLS_TPREL:
    case BFD_RELOC_LARCH_SOP_PUSH_TLS_GD:
    case BFD_RELOC_LARCH_SOP_PUSH_TLS_GOT:
      if (fixP->fx_addsy)
	S_SET_THREAD_LOCAL (fixP->fx_addsy);
    case BFD_RELOC_LARCH_SOP_PUSH_PCREL:
    case BFD_RELOC_LARCH_SOP_PUSH_PLT_PCREL:
      if (fixP->fx_addsy == NULL)
	as_bad_where (fixP->fx_file, fixP->fx_line,
		      _("Relocation against a constant"));
      if (fixP->fx_r_type == BFD_RELOC_LARCH_SOP_PUSH_PCREL)
	{
	  /* 分支到内部符号的重定位尽量在这里解决。一方面是为了反汇编更好看；
	     也是为了方便PMON的模块加载。PMON连接器的重定位类型枚举空间很小，
	     无法实现全的重定位。编译时加入-mabiabs使得所有外部符号都有la.abs，
	     从而有MARK_LA这个重定位，PMON连接器重定位时填4条la指令。 */
	  last_reloc_is_sop_push_pcrel_1 = 1;
	  if (S_GET_SEGMENT (fixP->fx_addsy) == seg)
	    stack_top = S_GET_VALUE (fixP->fx_addsy) + fixP->fx_offset
		      - (fixP->fx_where + fixP->fx_frag->fr_address);
	  else
	    stack_top = 0;
	}
      break;

    case BFD_RELOC_LARCH_SOP_POP_32_S_10_5:
      if (!last_reloc_is_sop_push_pcrel)
	break;
      if ((stack_top & ~(uint64_t)0xf) != 0x0
	  && (stack_top & ~(uint64_t)0xf) != ~(uint64_t)0xf)
	as_warn_where (fixP->fx_file, fixP->fx_line, "Reloc overflow");
      insn = bfd_getl32 (buf);
      insn = (insn & (~(uint32_t)0x7c00)) | ((stack_top & 0x1f) << 10);
      bfd_putl32 (insn, buf);
      break;

    case BFD_RELOC_LARCH_SOP_POP_32_U_10_12:
      if (!last_reloc_is_sop_push_pcrel)
	break;
      if (stack_top & ~(uint64_t)0xfff)
	as_warn_where (fixP->fx_file, fixP->fx_line, "Reloc overflow");
      insn = bfd_getl32 (buf);
      insn = (insn & (~(uint32_t)0x3ffc00)) | ((stack_top & 0xfff) << 10);
      bfd_putl32 (insn, buf);
      break;

    case BFD_RELOC_LARCH_SOP_POP_32_S_10_12:
      if (!last_reloc_is_sop_push_pcrel)
	break;
      if ((stack_top & ~(uint64_t)0x7ff) != 0x0
	  && (stack_top & ~(uint64_t)0x7ff) != ~(uint64_t)0x7ff)
	as_warn_where (fixP->fx_file, fixP->fx_line, "Reloc overflow");
      insn = bfd_getl32 (buf);
      insn = (insn & (~(uint32_t)0x3ffc00)) | ((stack_top & 0xfff) << 10);
      bfd_putl32 (insn, buf);
      break;

    case BFD_RELOC_LARCH_SOP_POP_32_S_10_16:
      if (!last_reloc_is_sop_push_pcrel)
	break;
      if ((stack_top & ~(uint64_t)0x7fff) != 0x0
	  && (stack_top & ~(uint64_t)0x7fff) != ~(uint64_t)0x7fff)
	as_warn_where (fixP->fx_file, fixP->fx_line, "Reloc overflow");
      insn = bfd_getl32 (buf);
      insn = (insn & 0xfc0003ff) | ((stack_top & 0xffff) << 10);
      bfd_putl32 (insn, buf);
      break;

    case BFD_RELOC_LARCH_SOP_POP_32_S_10_16_S2:
      if (!last_reloc_is_sop_push_pcrel)
	break;
      if ((stack_top & 0x3) != 0)
	as_warn_where (fixP->fx_file, fixP->fx_line, "Reloc overflow");
      stack_top >>= 2;
      if ((stack_top & ~(uint64_t)0x7fff) != 0x0
	  && (stack_top & ~(uint64_t)0x7fff) != ~(uint64_t)0x7fff)
	as_warn_where (fixP->fx_file, fixP->fx_line, "Reloc overflow");
      insn = bfd_getl32 (buf);
      insn = (insn & 0xfc0003ff) | ((stack_top & 0xffff) << 10);
      bfd_putl32 (insn, buf);
      break;

    case BFD_RELOC_LARCH_SOP_POP_32_S_0_5_10_16_S2:
      if (!last_reloc_is_sop_push_pcrel)
	break;
      if ((stack_top & 0x3) != 0)
	break;
      stack_top >>= 2;
      if ((stack_top & ~(uint64_t)0xfffff) != 0x0
	  && (stack_top & ~(uint64_t)0xfffff) != ~(uint64_t)0xfffff)
	as_warn_where (fixP->fx_file, fixP->fx_line, "Reloc overflow");
      insn = bfd_getl32 (buf);
      insn = (insn & 0xfc0003e0)
	   | ((stack_top & 0xffff) << 10) | ((stack_top & 0x1f0000) >> 16);
      bfd_putl32 (insn, buf);
      break;

    case BFD_RELOC_LARCH_SOP_POP_32_S_5_20:
      if (!last_reloc_is_sop_push_pcrel)
	break;
      if ((stack_top & ~(uint64_t)0x7ffff) != 0x0
	  && (stack_top & ~(uint64_t)0x7ffff) != ~(uint64_t)0x7ffff)
	as_warn_where (fixP->fx_file, fixP->fx_line, "Reloc overflow");
      insn = bfd_getl32 (buf);
      insn = (insn & (~(uint32_t)0x1ffffe0)) | ((stack_top & 0xfffff) << 5);
      bfd_putl32 (insn, buf);
      break;

    case BFD_RELOC_LARCH_SOP_POP_32_S_0_10_10_16_S2:
      if (!last_reloc_is_sop_push_pcrel)
	break;
      if ((stack_top & 0x3) != 0)
	as_warn_where (fixP->fx_file, fixP->fx_line, "Reloc overflow");
      stack_top >>= 2;
      if ((stack_top & ~(uint64_t)0x1ffffff) != 0x0
	  && (stack_top & ~(uint64_t)0x1ffffff) != ~(uint64_t)0x1ffffff)
	as_warn_where (fixP->fx_file, fixP->fx_line, "Reloc overflow");
      insn = bfd_getl32 (buf);
      insn = (insn & 0xfc000000)
	   | ((stack_top & 0xffff) << 10) | ((stack_top & 0x3ff0000) >> 16);
      bfd_putl32 (insn, buf);
      break;

    case BFD_RELOC_LARCH_SOP_POP_32_U:
      if (!last_reloc_is_sop_push_pcrel)
	break;
      if (stack_top & ~(uint64_t)0xffffffff)
	as_warn_where (fixP->fx_file, fixP->fx_line, "Reloc overflow");
      bfd_putl32 (stack_top, buf);
      break;

    case BFD_RELOC_64:
    case BFD_RELOC_32:
      if (fixP->fx_subsy)
	{
    case BFD_RELOC_24:
    case BFD_RELOC_16:
    case BFD_RELOC_8:
	  fixP->fx_next = xmemdup (fixP, sizeof (*fixP), sizeof (*fixP));
	  fixP->fx_next->fx_addsy = fixP->fx_subsy;
	  fixP->fx_next->fx_subsy = NULL;
	  fixP->fx_next->fx_offset = 0;
	  fixP->fx_subsy = NULL;

	  switch (fixP->fx_r_type)
	    {
	    case BFD_RELOC_64:
	      fixP->fx_r_type = BFD_RELOC_LARCH_ADD64;
	      fixP->fx_next->fx_r_type = BFD_RELOC_LARCH_SUB64;
	      break;
	    case BFD_RELOC_32:
	      fixP->fx_r_type = BFD_RELOC_LARCH_ADD32;
	      fixP->fx_next->fx_r_type = BFD_RELOC_LARCH_SUB32;
	      break;
	    case BFD_RELOC_24:
	      fixP->fx_r_type = BFD_RELOC_LARCH_ADD24;
	      fixP->fx_next->fx_r_type = BFD_RELOC_LARCH_SUB24;
	      break;
	    case BFD_RELOC_16:
	      fixP->fx_r_type = BFD_RELOC_LARCH_ADD16;
	      fixP->fx_next->fx_r_type = BFD_RELOC_LARCH_SUB16;
	      break;
	    case BFD_RELOC_8:
	      fixP->fx_r_type = BFD_RELOC_LARCH_ADD8;
	      fixP->fx_next->fx_r_type = BFD_RELOC_LARCH_SUB8;
	      break;
	    default:
	      break;
	    }
	  md_number_to_chars (buf, 0, fixP->fx_size);
	  if (fixP->fx_next->fx_addsy == NULL)
	    fixP->fx_next->fx_done = 1;
	}
      if (fixP->fx_addsy == NULL)
	{
	  fixP->fx_done = 1;
	  md_number_to_chars (buf, *valP, fixP->fx_size);
	}
      break;

    default:
      break;
    }
}

int
loongarch_relax_frag (asection *sec ATTRIBUTE_UNUSED, fragS *fragp ATTRIBUTE_UNUSED, long stretch ATTRIBUTE_UNUSED)
{
  return 0;
}

int
md_estimate_size_before_relax (fragS *fragp ATTRIBUTE_UNUSED, asection *segtype ATTRIBUTE_UNUSED)
{
  return 0;
}

/* Translate internal representation of relocation info to BFD target
   format.  */
arelent *
tc_gen_reloc (asection *section ATTRIBUTE_UNUSED, fixS *fixp)
{
  arelent *reloc = (arelent *) xmalloc (sizeof (arelent));

  reloc->sym_ptr_ptr = (asymbol **) xmalloc (sizeof (asymbol *));
  *reloc->sym_ptr_ptr = symbol_get_bfdsym (fixp->fx_addsy);
  reloc->address = fixp->fx_frag->fr_address + fixp->fx_where;
  reloc->addend = fixp->fx_offset;

  reloc->howto = bfd_reloc_type_lookup (stdoutput, fixp->fx_r_type);
  if (reloc->howto == NULL)
    {
      as_bad_where (fixp->fx_file, fixp->fx_line,
		    _("cannot represent %s relocation in object file"),
		    bfd_get_reloc_code_name (fixp->fx_r_type));
      return NULL;
    }

  return reloc;
}

/* Convert a machine dependent frag.  */
void
md_convert_frag (bfd *abfd ATTRIBUTE_UNUSED, segT asec ATTRIBUTE_UNUSED, fragS *fragp ATTRIBUTE_UNUSED)
{
  // fragp->fr_fix += 8;
}

/* Standard calling conventions leave the CFA at SP on entry.  */
void
loongarch_cfi_frame_initial_instructions (void)
{
  cfi_add_CFA_def_cfa_register (3 /* $sp */);
}

int
loongarch_dwarf2_addr_size (void)
{
  return LARCH_opts.addrwidth_is_32? 4 : 8;
}

void
tc_loongarch_parse_to_dw2regnum (expressionS *exp)
{
  expression_and_evaluate (exp);
  if (ASM_opts.mips_converter_enabled)
    exp->X_add_number =
      tc_loongarch_mips_dw2regnum_mapping (exp->X_add_number);
}

void
md_show_usage (FILE *stream)
{
  fprintf (stream, _("\
		     LoongISA options:\n\
		     "));
}

/* Fill in an rs_align_code fragment.  We want to fill 'andi $r0,$r0,0'.  */
void
loongarch_handle_align (fragS *fragp)
{
//   char nop_opcode;
  char *p;
  int bytes, size, excess;
  valueT opcode;

  if (fragp->fr_type != rs_align_code)
    return;

  struct loongarch_cl_insn nop =
    {.name = "andi", .arg_strs = {"$r0", "$r0", "0", NULL}};

  get_loongarch_opcode (&nop);
  gas_assert (nop.all_match);

  p = fragp->fr_literal + fragp->fr_fix;
//   nop_opcode = *p;
  //   switch (nop_opcode)
  //     {
  //     case NOP_OPCODE_MIPS:
  //     default:
  opcode = nop.insn_bin;
  size = 4;
  //       break;
  //     }

  bytes = fragp->fr_next->fr_address - fragp->fr_address - fragp->fr_fix;
  excess = bytes % size;

  /* Handle the leading part if we're not inserting a whole number of
     instructions, and make it the end of the fixed part of the frag.
     Try to fit in a short microMIPS NOP if applicable and possible,
     and use zeroes otherwise.  */
  gas_assert (excess < 4);
  fragp->fr_fix += excess;
  switch (excess)
    {
    case 3:
      *p++ = '\0';
    case 2:
      *p++ = '\0';
    case 1:
      *p++ = '\0';
    case 0:
      break;
    }

  md_number_to_chars (p, opcode, size);
  fragp->fr_var = size;
}

void
loongarch_elf_final_processing (void)
{
  if (LARCH_opts.abi_is_lp64)
    elf_elfheader (stdoutput)->e_flags |= EF_LARCH_ABI_LP64;
  else if (LARCH_opts.abi_is_lp32)
    elf_elfheader (stdoutput)->e_flags |= EF_LARCH_ABI_LP32;
}
