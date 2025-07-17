#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/loongarch.h"
#include "elfxx-loongarch.h"



/* This does not include any relocation information, but should be
   good enough for GDB or objdump to read the file.  */

static reloc_howto_type howto_table[] =
{
#define LOONGARCH_HOWTO(r_name) HOWTO (R_LARCH_##r_name,0,3,32,FALSE,0,complain_overflow_signed,bfd_elf_generic_reloc,"R_LARCH_"#r_name,FALSE,0,0,FALSE)
LOONGARCH_HOWTO (NONE),
LOONGARCH_HOWTO (32),
LOONGARCH_HOWTO (64),
LOONGARCH_HOWTO (RELATIVE),
LOONGARCH_HOWTO (COPY),
LOONGARCH_HOWTO (JUMP_SLOT),
LOONGARCH_HOWTO (TLS_DTPMOD32),
LOONGARCH_HOWTO (TLS_DTPMOD64),
LOONGARCH_HOWTO (TLS_DTPREL32),
LOONGARCH_HOWTO (TLS_DTPREL64),
LOONGARCH_HOWTO (TLS_TPREL32),
LOONGARCH_HOWTO (TLS_TPREL64),
LOONGARCH_HOWTO (IRELATIVE),

LOONGARCH_HOWTO (MARK_LA),
LOONGARCH_HOWTO (MARK_PCREL),
  HOWTO (R_LARCH_SOP_PUSH_PCREL,			/* type */
	 2,				/* rightshift */
	 3,				/* size */
	 32,				/* bitsize */
	 TRUE/* FIXME: somewhat use this */,				/* pc_relative */
	 0,				/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,		/* special_function */
	 "R_LARCH_SOP_PUSH_PCREL",		/* name */
	 FALSE,				/* partial_inplace */
	 0x03ffffff,				/* src_mask */
	 0x03ffffff,				/* dst_mask */
	 FALSE),			/* pcrel_offset */
LOONGARCH_HOWTO (SOP_PUSH_ABSOLUTE),
LOONGARCH_HOWTO (SOP_PUSH_DUP),
LOONGARCH_HOWTO (SOP_PUSH_GPREL),
LOONGARCH_HOWTO (SOP_PUSH_TLS_TPREL),
LOONGARCH_HOWTO (SOP_PUSH_TLS_GOT),
LOONGARCH_HOWTO (SOP_PUSH_TLS_GD),
LOONGARCH_HOWTO (SOP_PUSH_PLT_PCREL),
LOONGARCH_HOWTO (SOP_ASSERT),
LOONGARCH_HOWTO (SOP_NOT),
LOONGARCH_HOWTO (SOP_SUB),
LOONGARCH_HOWTO (SOP_SL),
LOONGARCH_HOWTO (SOP_SR),
LOONGARCH_HOWTO (SOP_ADD),
LOONGARCH_HOWTO (SOP_AND),
LOONGARCH_HOWTO (SOP_IF_ELSE),
LOONGARCH_HOWTO (SOP_POP_32_S_10_5),
LOONGARCH_HOWTO (SOP_POP_32_U_10_12),
LOONGARCH_HOWTO (SOP_POP_32_S_10_12),
LOONGARCH_HOWTO (SOP_POP_32_S_10_16),
LOONGARCH_HOWTO (SOP_POP_32_S_10_16_S2),
LOONGARCH_HOWTO (SOP_POP_32_S_5_20),
LOONGARCH_HOWTO (SOP_POP_32_S_0_5_10_16_S2),
LOONGARCH_HOWTO (SOP_POP_32_S_0_10_10_16_S2),
LOONGARCH_HOWTO (SOP_POP_32_U),
LOONGARCH_HOWTO (ADD8),
LOONGARCH_HOWTO (ADD16),
LOONGARCH_HOWTO (ADD24),
LOONGARCH_HOWTO (ADD32),
LOONGARCH_HOWTO (ADD64),
LOONGARCH_HOWTO (SUB8),
LOONGARCH_HOWTO (SUB16),
LOONGARCH_HOWTO (SUB24),
LOONGARCH_HOWTO (SUB32),
LOONGARCH_HOWTO (SUB64),
};

struct elf_reloc_map
{
  bfd_reloc_code_real_type bfd_val;
  enum elf_loongarch_reloc_type elf_val;
};

static const struct elf_reloc_map loong_reloc_map[] =
{
    { BFD_RELOC_NONE, R_LARCH_NONE },
    { BFD_RELOC_32, R_LARCH_32 },
    { BFD_RELOC_64, R_LARCH_64 },

#define LOONGARCH_reloc_map(r_name) {BFD_RELOC_LARCH_##r_name,R_LARCH_##r_name}
LOONGARCH_reloc_map (TLS_DTPMOD32),
LOONGARCH_reloc_map (TLS_DTPMOD64),
LOONGARCH_reloc_map (TLS_DTPREL32),
LOONGARCH_reloc_map (TLS_DTPREL64),
LOONGARCH_reloc_map (TLS_TPREL32),
LOONGARCH_reloc_map (TLS_TPREL64),

LOONGARCH_reloc_map (MARK_LA),
LOONGARCH_reloc_map (MARK_PCREL),
LOONGARCH_reloc_map (SOP_PUSH_PCREL),
LOONGARCH_reloc_map (SOP_PUSH_ABSOLUTE),
LOONGARCH_reloc_map (SOP_PUSH_DUP),
LOONGARCH_reloc_map (SOP_PUSH_GPREL),
LOONGARCH_reloc_map (SOP_PUSH_TLS_TPREL),
LOONGARCH_reloc_map (SOP_PUSH_TLS_GOT),
LOONGARCH_reloc_map (SOP_PUSH_TLS_GD),
LOONGARCH_reloc_map (SOP_PUSH_PLT_PCREL),
LOONGARCH_reloc_map (SOP_ASSERT),
LOONGARCH_reloc_map (SOP_NOT),
LOONGARCH_reloc_map (SOP_SUB),
LOONGARCH_reloc_map (SOP_SL),
LOONGARCH_reloc_map (SOP_SR),
LOONGARCH_reloc_map (SOP_ADD),
LOONGARCH_reloc_map (SOP_AND),
LOONGARCH_reloc_map (SOP_IF_ELSE),
LOONGARCH_reloc_map (SOP_POP_32_S_10_5),
LOONGARCH_reloc_map (SOP_POP_32_U_10_12),
LOONGARCH_reloc_map (SOP_POP_32_S_10_12),
LOONGARCH_reloc_map (SOP_POP_32_S_10_16),
LOONGARCH_reloc_map (SOP_POP_32_S_10_16_S2),
LOONGARCH_reloc_map (SOP_POP_32_S_5_20),
LOONGARCH_reloc_map (SOP_POP_32_S_0_5_10_16_S2),
LOONGARCH_reloc_map (SOP_POP_32_S_0_10_10_16_S2),
LOONGARCH_reloc_map (SOP_POP_32_U),
LOONGARCH_reloc_map (ADD8),
LOONGARCH_reloc_map (ADD16),
LOONGARCH_reloc_map (ADD24),
LOONGARCH_reloc_map (ADD32),
LOONGARCH_reloc_map (ADD64),
LOONGARCH_reloc_map (SUB8),
LOONGARCH_reloc_map (SUB16),
LOONGARCH_reloc_map (SUB24),
LOONGARCH_reloc_map (SUB32),
LOONGARCH_reloc_map (SUB64),
};

reloc_howto_type *
loongarch_elf_rtype_to_howto (unsigned int r_type)
{
  size_t i;
  for (i = 0; i < ARRAY_SIZE (howto_table); i++)
    if (howto_table[i].type == r_type)
      return &howto_table[i];
  return NULL;
}

reloc_howto_type *
loongarch_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED, bfd_reloc_code_real_type code)
{
  unsigned int i;
  for (i = 0; i < ARRAY_SIZE (loong_reloc_map); i++)
    if (loong_reloc_map[i].bfd_val == code)
      return loongarch_elf_rtype_to_howto ((int) loong_reloc_map[i].elf_val);
  //      return &howto_table[(int) loong_reloc_map[i].elf_val];

  return NULL;
}

reloc_howto_type *
loongarch_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED, const char *r_name)
{
  unsigned int i;

  for (i = 0; i < ARRAY_SIZE (howto_table); i++)
    if (howto_table[i].name && strcasecmp (howto_table[i].name, r_name) == 0)
      return &howto_table[i];

  return NULL;
}
