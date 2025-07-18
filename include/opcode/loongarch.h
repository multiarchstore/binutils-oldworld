#ifndef _LOONGARCH_H_
#define _LOONGARCH_H_
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t insn_t;

struct loongarch_opcode
{
  const insn_t match;
  const insn_t mask; /* High 1 byte is main opcode and it must be 0xf. */
#define LARCH_INSN_OPC(insn) ((insn & 0xf0000000) >> 28)
  const char * const name;

  /* 
     ACTUAL PARAMETER:

  // BNF with regular expression. 
args : token* end

  // just few char separate 'iden'
token : ','
| '('
| ')'
| iden             // maybe a label (include at least one alphabet), maybe a number, maybe a expr
| regname

regname : '$' iden

iden : [a-zA-Z0-9\.\+\-]+

end : '\0'


FORMAT: A string to describe the format of actual parameter including bit field infomation.
For example, "r5:5,r0:5,sr10:16<<2" matches "$12,$13,12345" and "$4,$7,a_label".
That 'sr' means the instruction may need relocate. '10:16' means bit field of instruction.
In a 'format', every 'escape's can be replaced to 'iden' or 'regname' acrroding to its meaning.
We fill all information needed by disassembing and assembing to 'format'.

  // BNF with regular expression. 
format : escape (literal+ escape)* literal* end
| (literal+ escape)* literal* end

end : '\0'       // Get here means parse end.

  // The intersection between any two among FIRST (end), FIRST (literal) and FIRST (escape) must be empty.
  // So we can build a simple parser.
literal : ','
| '('
| ')'

  // Double '<'s means the real number is the immediate after shifting left.
escape : esc_ch bit_field '<' '<' dec2
| esc_ch bit_field
| esc_ch    // for MACRO. non-macro format must indicate 'bit_field'

  // '|' means to concatenate nonadjacent bit fields 
  // For example, "10:16|0:4" means 
  // "16 bits starting from the 10th bit concatenating with 4 bits starting from the 0th bit".
  // This is to say "[25..10]||[3..0]" (little endian).
b_field : dec2 ':' dec2
| dec2 ':' dec2 '|' bit_field

esc_ch : 's' 'r'   // signed immediate or label need relocate
| 's'       // signed immediate no need relocate
| 'u'       // unsigned immediate
| 'l'       // label needed relocate
| 'r'       // general purpose registers
| 'f'       // FPU registers
| 'v'       // 128 bit SIMD register
| 'x'       // 256 bit SIMD register

dec2 : [1-9][0-9]?
| 0

*/
  const char * const format;

  /*
MACRO: Indicate how a macro instruction expand for assembling.
The main is to replace the '%num'(means the 'num'th 'escape' in 'format') in 'macro' string to get the real instruction.
As for marco insn "b" in MIPS, we can say its name is "b", format is "l", macro is "j %1". So "b 3f" will be expanded to "j 3f".
As for marco insn "li" in MIPS, we can say its name is "li", format is "s", macro is "ori"


Maybe need 
*/
  const char * const macro;
  const int *include;
  const int *exclude;

  const unsigned long pinfo;
#define USELESS 0x0l

};

struct hash_control;

struct loongarch_ase
{
  const int *enabled;
  struct loongarch_opcode * const opcodes;
  const int *include;
  const int *exclude;

  /* for disassemble to create main opcode hash table. */
  const struct loongarch_opcode *opc_htab[16];
  unsigned char opc_htab_inited;

  /* for GAS to create hash table. */
  struct hash_control *name_hash_entry;
};

extern int is_unsigned (const char *);
extern int is_signed (const char *);
extern int is_branch_label (const char *);

extern int
loongarch_get_bit_field_width (const char *bit_field, char **end);
extern int32_t
loongarch_decode_imm (const char *bit_field, insn_t insn, int si);

#define MAX_ARG_NUM_PLUS_2 9

extern size_t
loongarch_split_args_by_comma (char *args, const char *arg_strs[]);
extern char *
loongarch_cat_splited_strs (const char *arg_strs[]);
extern insn_t
loongarch_foreach_args (const char *format, const char *arg_strs[],
			int32_t (*helper) (char esc1, char esc2,
					   const char *bit_field,
					   const char *arg, void *context),
			void *context);

extern int
loongarch_check_format (const char *format);
extern int
loongarch_check_macro (const char *format, const char *macro);

extern char *
loongarch_expand_macro_with_format_map (const char *format, const char *macro,
					const char * const arg_strs[],
					const char * (*map) (
					  char esc1, char esc2,
					  const char *arg),
					char * (*helper) (
					  const char * const arg_strs[],
					  void *context),
					void *context, size_t len_str);
extern char *
loongarch_expand_macro (const char *macro, const char * const arg_strs[],
			char * (*helper) (const char * const arg_strs[],
					  void *context),
			void *context, size_t len_str);
extern size_t
loongarch_bits_imm_needed (int64_t imm, int si);

/* 将字符串中指定的连续字符化为1个 */
extern void
loongarch_eliminate_adjacent_repeat_char (char *dest, char c);

/* 下面两个函数计划作为libopcode.a拿出来给一些系统软件反汇编用 */
extern int
loongarch_parse_dis_options (const char *opts_in);
extern void
loongarch_disassemble_one (int64_t pc, insn_t insn,
			   int (*fprintf_func)
			     (void *stream, const char *format, ...),
			   void *stream);

extern const char * const loongarch_r_normal_name[32];
extern const char * const loongarch_r_lp64_name[32];
extern const char * const loongarch_r_lp64_name1[32];
extern const char * const loongarch_f_normal_name[32];
extern const char * const loongarch_f_lp64_name[32];
extern const char * const loongarch_f_lp64_name1[32];
extern const char * const loongarch_c_normal_name[8];
extern const char * const loongarch_cr_normal_name[4];
extern const char * const loongarch_v_normal_name[32];
extern const char * const loongarch_x_normal_name[32];

extern struct loongarch_ase loongarch_ASEs[];

extern struct loongarch_ASEs_option
{
  int ase_test;
  int ase_fix;
  int ase_float;
  int ase_128vec;
  int ase_256vec;

  int addrwidth_is_32;
  int addrwidth_is_64;
  int rlen_is_32;
  int rlen_is_64;
  int la_local_with_abs;
  int la_global_with_pcrel;
  int la_global_with_abs;

  int abi_is_lp32;
  int abi_is_lp64;
} LARCH_opts;

extern size_t loongarch_insn_length (insn_t insn);

#ifdef __cplusplus
}
#endif

#endif /* _LOONGARCH_H_ */
