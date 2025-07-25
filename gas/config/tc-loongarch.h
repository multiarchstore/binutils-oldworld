#ifndef TC_LOONGARCH
#define TC_LOONGARCH

#define TARGET_BYTES_BIG_ENDIAN 0
#define TARGET_ARCH bfd_arch_loongarch

#define WORKING_DOT_WORD	1
#define REPEAT_CONS_EXPRESSIONS

// early than md_begin
#define md_after_parse_args loongarch_after_parse_args
extern void loongarch_after_parse_args (void);

extern void loongarch_pop_insert (void);
#define md_pop_insert()		loongarch_pop_insert ()

#define TARGET_FORMAT loongarch_target_format()
extern const char * loongarch_target_format (void);


#define md_relax_frag(segment, fragp, stretch) \
  loongarch_relax_frag (segment, fragp, stretch)
extern int loongarch_relax_frag (asection *, struct frag *, long);
#define md_section_align(seg,size)	(size)
#define md_undefined_symbol(name)	(0)

/* This is called to see whether a reloc against a defined symbol
   should be converted into a reloc against a section.  */
#define tc_fix_adjustable(fixp) 0

/* Values passed to md_apply_fix don't include symbol values.  */
#define TC_FORCE_RELOCATION_SUB_LOCAL(FIX, SEG) 1
#define TC_VALIDATE_FIX_SUB(FIX, SEG) 1
#define DIFF_EXPR_OK 1

#define TARGET_USE_CFIPOP	1
#define DWARF2_DEFAULT_RETURN_COLUMN	1 /* $ra */
#define DWARF2_CIE_DATA_ALIGNMENT -4
extern int loongarch_dwarf2_addr_size (void);
#define DWARF2_FDE_RELOC_SIZE loongarch_dwarf2_addr_size ()
#define DWARF2_ADDR_SIZE(bfd) loongarch_dwarf2_addr_size ()
#define CFI_DIFF_EXPR_OK 0

#define tc_cfi_frame_initial_instructions loongarch_cfi_frame_initial_instructions
extern void loongarch_cfi_frame_initial_instructions (void);

// 我们不实现 tc_regname_to_dw2regnum，而是重载tc_parse_to_dw2regnum。
// 因为MIPS汇编兼容需要CFA来实现C++异常抛出。我们仅仅对数字作映射，
// 不再考虑寄存器的名字了。
//#define tc_regname_to_dw2regnum tc_loongarch_regname_to_dw2regnum
#define tc_parse_to_dw2regnum tc_loongarch_parse_to_dw2regnum
extern void tc_loongarch_parse_to_dw2regnum (expressionS *);

// a enumerated values to specific how to deal with align in '.text'
// now we want to fill 'andi $r0,$r0,0x0'
#define loongarch_nop_opcode() 0
#define NOP_OPCODE (loongarch_nop_opcode ())

#define HANDLE_ALIGN(fragp)  loongarch_handle_align (fragp)
extern void loongarch_handle_align (struct frag *);
#define MAX_MEM_FOR_RS_ALIGN_CODE  (3 + 4)

#define elf_tc_final_processing loongarch_elf_final_processing
extern void loongarch_elf_final_processing (void);

#define MAX_RELOC_NUMBER_A_INSN 20

struct reloc_info
{
  bfd_reloc_code_real_type type;
  expressionS value;
};

int is_label_with_addend (const char *);
int is_label (const char *);

#endif
