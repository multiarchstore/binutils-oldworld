#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#define ARCH_SIZE NN
#include "elf-bfd.h"
#include "objalloc.h"
#include "elf/loongarch.h"
#include "elfxx-loongarch.h"

static bfd_boolean
loongarch_info_to_howto_rela (bfd *abfd ATTRIBUTE_UNUSED,
			      arelent *cache_ptr,
			      Elf_Internal_Rela *dst)
{
  cache_ptr->howto = loongarch_elf_rtype_to_howto (ELFNN_R_TYPE (dst->r_info));
  return cache_ptr->howto != NULL;
}

/* Loongarch ELF linker hash entry.  */

struct loongarch_elf_link_hash_entry
{
  struct elf_link_hash_entry elf;

  /* Track dynamic relocs copied for this symbol.  */
  struct elf_dyn_relocs *dyn_relocs;

#define GOT_UNKNOWN     0
#define GOT_NORMAL      1
#define GOT_TLS_GD      2
#define GOT_TLS_IE      4
#define GOT_TLS_LE      8
  char tls_type;
};

#define loongarch_elf_hash_entry(ent) \
  ((struct loongarch_elf_link_hash_entry *)(ent))

struct _bfd_loongarch_elf_obj_tdata
{
  struct elf_obj_tdata root;

  /* tls_type for each local got entry.  */
  char *local_got_tls_type;
};

#define _bfd_loongarch_elf_tdata(abfd) \
  ((struct _bfd_loongarch_elf_obj_tdata *) (abfd)->tdata.any)

#define _bfd_loongarch_elf_local_got_tls_type(abfd) \
  (_bfd_loongarch_elf_tdata (abfd)->local_got_tls_type)

#define _bfd_loongarch_elf_tls_type(abfd, h, symndx)		\
  (*((h) != NULL ? &loongarch_elf_hash_entry (h)->tls_type	\
     : &_bfd_loongarch_elf_local_got_tls_type (abfd) [symndx]))

#define is_loongarch_elf(bfd)				\
  (bfd_get_flavour (bfd) == bfd_target_elf_flavour	\
   && elf_tdata (bfd) != NULL				\
   && elf_object_id (bfd) == LARCH_ELF_DATA)

struct loongarch_elf_link_hash_table
{
  struct elf_link_hash_table elf;

  /* Short-cuts to get to dynamic linker sections.  */
  asection *sdyntdata;

  /* Small local sym to section mapping cache.  */
  struct sym_cache sym_cache;

  /* Used by local STT_GNU_IFUNC symbols.  */
  htab_t loc_hash_table;
  void *loc_hash_memory;

  /* The max alignment of output sections.  */
  bfd_vma max_alignment;
};

/* Get the Loongarch ELF linker hash table from a link_info structure.  */
#define loongarch_elf_hash_table(p) \
  (elf_hash_table_id ((struct elf_link_hash_table *) ((p)->hash)) \
   == LARCH_ELF_DATA \
      ? ((struct loongarch_elf_link_hash_table *) ((p)->hash)) : NULL)

#define MINUS_ONE ((bfd_vma)0 - 1)

#define sec_addr(sec) ((sec)->output_section->vma + (sec)->output_offset)

#define LARCH_ELF_LOG_WORD_BYTES (ARCH_SIZE == 32 ? 2 : 3)
#define LARCH_ELF_WORD_BYTES (1 << LARCH_ELF_LOG_WORD_BYTES)

#define PLT_HEADER_INSNS 8
#define PLT_HEADER_SIZE (PLT_HEADER_INSNS * 4)

#define PLT_ENTRY_INSNS 4
#define PLT_ENTRY_SIZE (PLT_ENTRY_INSNS * 4)

#define GOT_ENTRY_SIZE (LARCH_ELF_WORD_BYTES)

/* .got.plt的前两项预留。我们约定：
   第一项在运行时被动态连接器填入_dl_runtime_resolve的地址
   第二项在连接时，非0指plt header的地址（在no-pic下或prelink）。
   第二项在运行时被动态连接器填入本模块的struct link_map实例的地址。
   详见$glibc/sysdeps/loongarch/dl-machine.h中的elf_machine_runtime_setup */
#define GOTPLT_HEADER_SIZE (GOT_ENTRY_SIZE * 2)

/* .got和.got.plt不合并的好处是，.got.plt和.plt的entry是顺序对应的。
   设法使得stub的size为2的幂，知道.plt和stub的地址就知道了index。 */
#define elf_backend_want_got_plt	1

#define elf_backend_plt_readonly	1

#define elf_backend_want_plt_sym	0
/* 1. 本来想着定义_PROCEDURE_LINKAGE_TABLE_，多了不嫌多。
   2. 但实际上，这个符号会使得GDB调试ifunc函数失效。因为lazy-bind的情况下，
   plt GOT entry中的地址都指向这个符号；GDB读取plt GOT entry来确定ifunc的
   目标函数，从而以为_PROCEDURE_LINKAGE_TABLE_就是ifunc的目标函数（好奇的人
   可以把断点打在elf_gnu_ifunc_record_cache上面看一下GDB的行为，总之是校验从
   GOT entry中拿到的地址，结果发现 'BMSYMBOL_VALUE_ADDRESS (msym) == addr'
   为真），然后直接跳转到plt header上面了，这当然不行。
   3. 我们期望，调用ifunc函数时，要么跳到对应的plt stub上；要么GDB运行一遍
   resolver得到ifunc目标函数的地址后再调用（这是GDB公共代码的做法）。
   4. 观察了aarch64的做法，发现他们就没_PROCEDURE_LINKAGE_TABLE_，
   就不存在msym.minsym，然后认为从GOT entry读ifunc目标函数失败直接退出了。
   5. 我想了想，_PROCEDURE_LINKAGE_TABLE_的存在没有意义，因为对plt stub
   的处理是有重定位R_LARCH_SOP_PUSH_PLT_PCREL由静态连接器一手操办。
   所以就把_PROCEDURE_LINKAGE_TABLE_去了吧。 */
#define elf_backend_plt_alignment	4
#define elf_backend_can_gc_sections	1
//#define elf_backend_can_refcount	1
#define elf_backend_want_got_sym	1

/* .got的第一项预留。我们约定.got的第一项为.dynamic的连接时地址（如果有） */
#define elf_backend_got_header_size	(GOT_ENTRY_SIZE * 1)

#define elf_backend_want_dynrelro	1
//#define elf_backend_rela_normal		1
//#define elf_backend_default_execstack	0

/* Generate a PLT header.  */

static void
loongarch_make_plt_header (bfd_vma got_plt_addr,
			   bfd_vma plt_header_addr,
			   uint32_t *entry)
{
  int64_t pcrel = got_plt_addr - plt_header_addr;
  int64_t hi = (pcrel & 0x800? 1 : 0) + (pcrel >> 12);
  int64_t lo = pcrel & 0xfff;
  if ((hi >> 19) != 0 && (hi >> 19) != -1)
    abort ();//overflow

  /* pcaddu12i	$t2, %hi(%pcrel(.got.plt))
     sub.[wd]	$t1, $t1, $t3
     ld.[wd]	$t3, $t2, %lo(%pcrel(.got.plt)) # _dl_runtime_resolve
     addi.[wd]	$t1, $t1, -(PLT_HEADER_SIZE + 12) + 4 
     addi.[wd]	$t0, $t2, %lo(%pcrel(.got.plt))
     srli.[wd]	$t1, $t1, log2(16 / GOT_ENTRY_SIZE)
     ld.[wd]	$t0, $t0, GOT_ENTRY_SIZE
     jirl	$r0, $t3, 0 */

  if (GOT_ENTRY_SIZE == 8)
    {
      entry[0] = 0x1c00000e
	       | (hi & 0xfffff) << 5;
      entry[1] = 0x0011bdad;
      entry[2] = 0x28c001cf
	       | (lo & 0xfff) << 10;
      entry[3] = 0x02c001ad
	       | ((-(PLT_HEADER_SIZE + 12) + 4) & 0xfff) << 10;
      entry[4] = 0x02c001cc
	       | (lo & 0xfff) << 10;
      entry[5] = 0x004501ad
	       | (4 - LARCH_ELF_LOG_WORD_BYTES) << 10;
      entry[6] = 0x28c0018c
	       | GOT_ENTRY_SIZE << 10;
      entry[7] = 0x4c0001e0;
    }
  else
    {
      entry[0] = 0x1c00000e
	       | (hi & 0xfffff) << 5;
      entry[1] = 0x00113dad;
      entry[2] = 0x288001cf
	       | (lo & 0xfff) << 10;
      entry[3] = 0x028001ad
	       | ((-(PLT_HEADER_SIZE + 12)) & 0xfff) << 10;
      entry[4] = 0x028001cc
	       | (lo & 0xfff) << 10;
      entry[5] = 0x004481ad
	       | (4 - LARCH_ELF_LOG_WORD_BYTES) << 10;
      entry[6] = 0x2880018c
	       | GOT_ENTRY_SIZE << 10;
      entry[7] = 0x4c0001e0;
    }
}

/* Generate a PLT entry.  */

static void
loongarch_make_plt_entry (bfd_vma got_plt_entry_addr,
			  bfd_vma plt_entry_addr,
			  uint32_t *entry)
{
  int64_t pcrel = got_plt_entry_addr - plt_entry_addr;
  int64_t hi = (pcrel & 0x800? 1 : 0) + (pcrel >> 12);
  int64_t lo = pcrel & 0xfff;
  if ((hi >> 19) != 0 && (hi >> 19) != -1)
    abort ();//overflow

  /* pcaddu12i	$t3, %hi(%pcrel(.got.plt entry))
     ld.[wd]	$t3, $t3, %lo(%pcrel(.got.plt entry))
     jirl	$t1, $t3, 0
     addi	$r0, $r0, 0 */

  entry[0] = 0x1c00000f
	   | (hi & 0xfffff) << 5;
  entry[1] = (GOT_ENTRY_SIZE == 8? 0x28c001ef : 0x288001ef)
	   | (lo & 0xfff) << 10;
  //entry[2] = 0x4c0001ed;	/* jirl $r13, $15, 0 */
  //entry[3] = 0x03400000;	/* nop */
  //entry[2] = 0x1800002d;	/* pcaddi $13, 4 */
  entry[2] = 0x1c00000d;	/* pcaddu12i $13, 4 */
  entry[3] = 0x4c0001e0;	/* jirl $r0, $15, 0 */
}

/* Create an entry in an Loongarch ELF linker hash table.  */

static struct bfd_hash_entry *
link_hash_newfunc (struct bfd_hash_entry *entry,
		   struct bfd_hash_table *table, const char *string)
{
  /* Allocate the structure if it has not already been allocated by a
     subclass.  */
  if (entry == NULL)
    {
      entry = bfd_hash_allocate
		(table, sizeof (struct loongarch_elf_link_hash_entry));
      if (entry == NULL)
	return entry;
    }

  /* Call the allocation method of the superclass.  */
  entry = _bfd_elf_link_hash_newfunc (entry, table, string);
  if (entry != NULL)
    {
      struct loongarch_elf_link_hash_entry *eh;

      eh = (struct loongarch_elf_link_hash_entry *) entry;
      eh->dyn_relocs = NULL;
      eh->tls_type = GOT_UNKNOWN;
    }

  return entry;
}

/* Compute a hash of a local hash entry.  We use elf_link_hash_entry
  for local symbol so that we can handle local STT_GNU_IFUNC symbols
  as global symbol.  We reuse indx and dynstr_index for local symbol
  hash since they aren't used by global symbols in this backend.  */

static hashval_t
elfNN_loongarch_local_htab_hash (const void *ptr)
{
  struct elf_link_hash_entry *h
    = (struct elf_link_hash_entry *) ptr;
  return ELF_LOCAL_SYMBOL_HASH (h->indx, h->dynstr_index);
}

/* Compare local hash entries.  */

static int
elfNN_loongarch_local_htab_eq (const void *ptr1, const void *ptr2)
{
  struct elf_link_hash_entry *h1
    = (struct elf_link_hash_entry *) ptr1;
  struct elf_link_hash_entry *h2
    = (struct elf_link_hash_entry *) ptr2;

  return h1->indx == h2->indx && h1->dynstr_index == h2->dynstr_index;
}

/* Find and/or create a hash entry for local symbol.  */
static struct elf_link_hash_entry *
elfNN_loongarch_get_local_sym_hash (struct loongarch_elf_link_hash_table *htab,
				    bfd *abfd, const Elf_Internal_Rela *rel,
				    bfd_boolean create)
{
  struct loongarch_elf_link_hash_entry e, *ret;
  asection *sec = abfd->sections;
  hashval_t h = ELF_LOCAL_SYMBOL_HASH (sec->id, ELFNN_R_SYM (rel->r_info));
  void **slot;

  e.elf.indx = sec->id;
  e.elf.dynstr_index = ELFNN_R_SYM (rel->r_info);
  slot = htab_find_slot_with_hash
	   (htab->loc_hash_table, &e, h, create ? INSERT : NO_INSERT);

  if (!slot)
    return NULL;

  if (*slot)
    {
      ret = (struct loongarch_elf_link_hash_entry *) *slot;
      return &ret->elf;
    }

  ret = (struct loongarch_elf_link_hash_entry *)
	  objalloc_alloc ((struct objalloc *) htab->loc_hash_memory,
			  sizeof (struct loongarch_elf_link_hash_entry));
  if (ret)
    {
      memset (ret, 0, sizeof (*ret));
      ret->elf.indx = sec->id;
      ret->elf.pointer_equality_needed = 0;
      ret->elf.dynstr_index = ELFNN_R_SYM (rel->r_info);
      ret->elf.dynindx = -1;
      ret->elf.needs_plt = 0;
      ret->elf.plt.refcount = -1;
      ret->elf.got.refcount = -1;
      ret->elf.def_dynamic = 0;
      ret->elf.def_regular = 1;
      ret->elf.ref_dynamic = 0; /* this should be always 0 for local  */
      ret->elf.ref_regular = 0;
      ret->elf.forced_local = 1;
      ret->elf.root.type = bfd_link_hash_defined;
      *slot = ret;
    }
  return &ret->elf;
}

/* Destroy an Loongarch elf linker hash table.  */

static void
elfNN_loongarch_link_hash_table_free (bfd *obfd)
{
  struct loongarch_elf_link_hash_table *ret
    = (struct loongarch_elf_link_hash_table *) obfd->link.hash;

  if (ret->loc_hash_table)
    htab_delete (ret->loc_hash_table);
  if (ret->loc_hash_memory)
    objalloc_free ((struct objalloc *) ret->loc_hash_memory);

  _bfd_elf_link_hash_table_free (obfd);
}

/* Create a Loongarch ELF linker hash table.  */

static struct bfd_link_hash_table *
loongarch_elf_link_hash_table_create (bfd *abfd)
{
  struct loongarch_elf_link_hash_table *ret;
  bfd_size_type amt = sizeof (struct loongarch_elf_link_hash_table);

  ret = (struct loongarch_elf_link_hash_table *) bfd_zmalloc (amt);
  if (ret == NULL)
    return NULL;

  if (!_bfd_elf_link_hash_table_init (&ret->elf, abfd, link_hash_newfunc,
	 sizeof (struct loongarch_elf_link_hash_entry), LARCH_ELF_DATA))
    {
      free (ret);
      return NULL;
    }

  ret->max_alignment = MINUS_ONE;

  ret->loc_hash_table = htab_try_create (1024,
					 elfNN_loongarch_local_htab_hash,
					 elfNN_loongarch_local_htab_eq,
					 NULL);
  ret->loc_hash_memory = objalloc_create ();
  if (!ret->loc_hash_table || !ret->loc_hash_memory)
    {
      elfNN_loongarch_link_hash_table_free (abfd);
      return NULL;
    }
  ret->elf.root.hash_table_free = elfNN_loongarch_link_hash_table_free;

  return &ret->elf.root;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

static bfd_boolean
_bfd_loongarch_elf_merge_private_bfd_data (bfd *ibfd,
					   struct bfd_link_info *info)
{
  bfd *obfd = info->output_bfd;
  flagword in_flags = elf_elfheader (ibfd)->e_flags;
  flagword out_flags = elf_elfheader (obfd)->e_flags;

  if (!is_loongarch_elf (ibfd) || !is_loongarch_elf (obfd))
    {
      /* Make sure one of ibfd or obfd e_flags must be set.  */
      /* FIXME: EF_LARCH_ABI_LP64 ? .  */
      if (!is_loongarch_elf (ibfd) && !elf_flags_init (obfd))
	{
	  elf_flags_init (obfd) = TRUE;
	  elf_elfheader (obfd)->e_flags = EF_LARCH_ABI_LP64;
	}

      if (!is_loongarch_elf (obfd) && !elf_flags_init (ibfd))
	{
	  elf_flags_init (ibfd) = TRUE;
	  elf_elfheader (ibfd)->e_flags = EF_LARCH_ABI_LP64;
	}

      return TRUE;
    }

  if (strcmp (bfd_get_target (ibfd), bfd_get_target (obfd)) != 0)
    {
      _bfd_error_handler
	(_("%pB: ABI is incompatible with that of the selected emulation:\n"
	   "  target emulation `%s' does not match `%s'"),
	 ibfd, bfd_get_target (ibfd), bfd_get_target (obfd));
      return FALSE;
    }

  if (!_bfd_elf_merge_object_attributes (ibfd, info))
    return FALSE;

  if (!elf_flags_init (obfd))
    {
      elf_flags_init (obfd) = TRUE;
      elf_elfheader (obfd)->e_flags = in_flags;
      return TRUE;
    }

  /* Disallow linking different float ABIs.  */
  if ((out_flags ^ in_flags) & EF_LARCH_ABI)
    {
      _bfd_error_handler
	(_("%pB: can't link different ABI object."), ibfd);
      goto fail;
    }

  return TRUE;

fail:
  bfd_set_error (bfd_error_bad_value);
  return FALSE;
}

/* Create the .got section.  */

static bfd_boolean
loongarch_elf_create_got_section (bfd *abfd, struct bfd_link_info *info)
{
  flagword flags;
  asection *s, *s_got;
  struct elf_link_hash_entry *h;
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  struct elf_link_hash_table *htab = elf_hash_table (info);

  /* This function may be called more than once.  */
  if (htab->sgot != NULL)
    return TRUE;

  flags = bed->dynamic_sec_flags;

  s = bfd_make_section_anyway_with_flags
	(abfd, bed->rela_plts_and_copies_p ? ".rela.got" : ".rel.got",
	 bed->dynamic_sec_flags | SEC_READONLY);
  if (s == NULL
      || !bfd_set_section_alignment (abfd, s, bed->s->log_file_align))
    return FALSE;
  htab->srelgot = s;

  s = s_got = bfd_make_section_anyway_with_flags (abfd, ".got", flags);
  if (s == NULL
      || !bfd_set_section_alignment (abfd, s, bed->s->log_file_align))
    return FALSE;
  htab->sgot = s;

  /* The first bit of the global offset table is the header.  */
  s->size += bed->got_header_size;

  if (bed->want_got_plt)
    {
      s = bfd_make_section_anyway_with_flags (abfd, ".got.plt", flags);
      if (s == NULL
	  || !bfd_set_section_alignment (abfd, s, bed->s->log_file_align))
	return FALSE;
      htab->sgotplt = s;

      /* 相比_bfd_elf_create_got_section：
	 一方面，RISCV似乎是希望.got.plt和.got都有header；
	 而且_GLOBAL_OFFSET_TABLE_是.got的开头，而不是.got.plt的开头。
	 和公共部分需求有冲突。所以自己实现了 */

      /* Reserve room for the header.  */
      s->size = GOTPLT_HEADER_SIZE;
    }

  if (bed->want_got_sym)
    {
      /* Define the symbol _GLOBAL_OFFSET_TABLE_ at the start of the .got
	 section.  We don't do this in the linker script because we don't want
	 to define the symbol if we are not creating a global offset table.  */
      h = _bfd_elf_define_linkage_sym (abfd, info, s_got,
				       "_GLOBAL_OFFSET_TABLE_");
      elf_hash_table (info)->hgot = h;
      if (h == NULL)
	return FALSE;
    }
  return TRUE;
}

/* Create .plt, .rela.plt, .got, .got.plt, .rela.got, .dynbss, and
   .rela.bss sections in DYNOBJ, and set up shortcuts to them in our
   hash table.  */

static bfd_boolean
loongarch_elf_create_dynamic_sections (bfd *dynobj,
				       struct bfd_link_info *info)
{
  struct loongarch_elf_link_hash_table *htab;

  htab = loongarch_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);

  if (!loongarch_elf_create_got_section (dynobj, info))
    return FALSE;

  if (!_bfd_elf_create_dynamic_sections (dynobj, info))
    return FALSE;

  if (!bfd_link_pic (info))
    {
      htab->sdyntdata =
	bfd_make_section_anyway_with_flags (dynobj, ".tdata.dyn",
					    SEC_ALLOC | SEC_THREAD_LOCAL);
    }

  if (!htab->elf.splt || !htab->elf.srelplt || !htab->elf.sdynbss
      || (!bfd_link_pic (info) && (!htab->elf.srelbss || !htab->sdyntdata)))
    abort ();

  return TRUE;
}

static bfd_boolean
loongarch_elf_record_tls_and_got_reference (bfd *abfd,
					    struct bfd_link_info *info,
					    struct elf_link_hash_entry *h,
					    unsigned long symndx,
					    char tls_type)
{
  struct loongarch_elf_link_hash_table *htab = loongarch_elf_hash_table (info);
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (abfd)->symtab_hdr;

  /* This is a global offset table entry for a local symbol.  */
  if (elf_local_got_refcounts (abfd) == NULL)
    {
      bfd_size_type size =
	symtab_hdr->sh_info * (sizeof (bfd_vma) + sizeof (tls_type));
      if (!(elf_local_got_refcounts (abfd) = bfd_zalloc (abfd, size)))
	return FALSE;
      _bfd_loongarch_elf_local_got_tls_type (abfd)
	= (char *) (elf_local_got_refcounts (abfd) + symtab_hdr->sh_info);
    }

  switch (tls_type)
    {
    case GOT_NORMAL:
    case GOT_TLS_GD:
    case GOT_TLS_IE:
      /* need GOT */
      if (htab->elf.sgot == NULL
	  && !loongarch_elf_create_got_section (htab->elf.dynobj, info))
	return FALSE;
      if (h)
	{
	  if (h->got.refcount < 0)
	    h->got.refcount = 0;
	  h->got.refcount++;
	}
      else
	elf_local_got_refcounts (abfd) [symndx] ++;
      break;
    case GOT_TLS_LE:
      /* no need for GOT */
      break;
    default:
      _bfd_error_handler (_("%pB: Interl error: unreachable."));
      return FALSE;
    }

  char *new_tls_type = &_bfd_loongarch_elf_tls_type (abfd, h, symndx);
  *new_tls_type |= tls_type;
  if ((*new_tls_type & GOT_NORMAL) && (*new_tls_type & ~GOT_NORMAL))
    {
      _bfd_error_handler
	(_("%pB: `%s' accessed both as normal and thread local symbol"),
	 abfd, h ? h->root.root.string : "<local>");
      return FALSE;
    }

  return TRUE;
} 

/* Look through the relocs for a section during the first phase, and
   allocate space in the global offset table or procedure linkage
   table.  */

static bfd_boolean
loongarch_elf_check_relocs (bfd *abfd, struct bfd_link_info *info,
			    asection *sec, const Elf_Internal_Rela *relocs)
{
  struct loongarch_elf_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *rel;
  asection *sreloc = NULL;

  if (bfd_link_relocatable (info))
    return TRUE;

  htab = loongarch_elf_hash_table (info);
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (abfd);

  if (htab->elf.dynobj == NULL)
    htab->elf.dynobj = abfd;

  /* 这个函数的遍历每一个重定位，将一些信息归置到符号中。这之后的处理
     都会通过遍历符号进行，根据符号中的信息来确定最终二进制文件的形态。
     1.根据重定位类型记录那个符号是否需要GOT entry
     2.根据重定位类型记录那个符号的TLS引用模型
     3.处理IFUNC
     4.等等
  */

  for (rel = relocs; rel < relocs + sec->reloc_count; rel++)
    {
      unsigned int r_type;
      unsigned int r_symndx;
      struct elf_link_hash_entry *h;
      Elf_Internal_Sym *isym = NULL;

      /* 意味着在dynamic_sections_created置位的情况下，这个重定位可能需要动态
	 连接器的帮助。如果是这样，我们会在动态重定位表中为其分配一个表项。 */
      int need_dynreloc;

      /* 意味着这个动态重定位仅需要符号的pcrel信息，即符号定义在自身模块内
	 及延伸出来的其他信息。如果是这样，我们就在连接时知道了这个重定位的值，
	 就可以把这个动态重定位取消掉。 */
      int only_need_pcrel;

      r_symndx = ELFNN_R_SYM (rel->r_info);
      r_type = ELFNN_R_TYPE (rel->r_info);

      if (r_symndx >= NUM_SHDR_ENTRIES (symtab_hdr))
	{
	  _bfd_error_handler
	    (_("%pB: bad symbol index: %d"), abfd, r_symndx);
	  return FALSE;
	}

      if (r_symndx < symtab_hdr->sh_info)
	{
	  /* A local symbol.  */
	  isym = bfd_sym_from_r_symndx (&htab->sym_cache, abfd, r_symndx);
	  if (isym == NULL)
	    return FALSE;

	  if (ELF_ST_TYPE (isym->st_info) == STT_GNU_IFUNC)
	    {
	      h = elfNN_loongarch_get_local_sym_hash (htab, abfd, rel, TRUE);
	      if (h == NULL)
		return FALSE;

	      h->type = STT_GNU_IFUNC;
	      h->ref_regular = 1;
	    }
	  else
	    h = NULL;
	}
      else
	{
	  h = sym_hashes[r_symndx - symtab_hdr->sh_info];
	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;
	}

      if (h && h->type == STT_GNU_IFUNC)
	{
	  if (htab->elf.dynobj == NULL)
	    htab->elf.dynobj = abfd;

	  if (!htab->elf.splt
	      && !_bfd_elf_create_ifunc_sections (htab->elf.dynobj, info))
	    /* If '.plt' not represent, create '.iplt' to deal with ifunc. */
	    return FALSE;

	  if (h->plt.refcount < 0)
	    h->plt.refcount = 0;
	  h->plt.refcount++;
	  h->needs_plt = 1;

	  elf_tdata (info->output_bfd)->has_gnu_symbols
	    |= elf_gnu_symbol_ifunc;
	}

      need_dynreloc = 0;
      only_need_pcrel = 0;
      switch (r_type)
	{
	case R_LARCH_SOP_PUSH_GPREL:
	  if (!loongarch_elf_record_tls_and_got_reference
		 (abfd, info, h, r_symndx, GOT_NORMAL))
	    return FALSE;
	  break;

	case R_LARCH_SOP_PUSH_TLS_GD:
	  if (!loongarch_elf_record_tls_and_got_reference
		 (abfd, info, h, r_symndx, GOT_TLS_GD))
	    return FALSE;
	  break;

	case R_LARCH_SOP_PUSH_TLS_GOT:
	  if (bfd_link_pic (info))
	    /* may fail for lazy-bind */
	    info->flags |= DF_STATIC_TLS;

	  if (!loongarch_elf_record_tls_and_got_reference
		 (abfd, info, h, r_symndx, GOT_TLS_IE))
	    return FALSE;
	  break;

	case R_LARCH_SOP_PUSH_TLS_TPREL:
	  if (!bfd_link_executable (info))
	    return FALSE;

	  info->flags |= DF_STATIC_TLS;

	  if (!loongarch_elf_record_tls_and_got_reference
                 (abfd, info, h, r_symndx, GOT_TLS_LE))
	    return FALSE;
	  break;

	case R_LARCH_SOP_PUSH_ABSOLUTE:
	  if (h != NULL)
	    /* If this reloc is in a read-only section, we might
	       need a copy reloc.  We can't check reliably at this
	       stage whether the section is read-only, as input
	       sections have not yet been mapped to output sections.
	       Tentatively set the flag for now, and correct in
	       adjust_dynamic_symbol.  */
	    /* 这个flag的本质是关注对一个符号的引用能否被动态连接器改变。
	       比如la.pcrel，在连接时会将符号的pc相对偏移量写入指令立即数；
	       而代码段是只读的，动态连接器无法改动指令，这时，那个la只能引用
	       local的那个符号的定义了，无法被动态连接器改变。
	       而使用got表的话，因为got entry可以被动态连接器改变，因此可以改变
	       la到底哪个模块中的符号。
	       动态库里的符号定义可能被可执行文件中的符号定义覆盖，由此，动态库
	       中对符号的引用必须可以被动态连接器改变；
	       而如果在可执行文件中la.pcrel一个动态库中的对象，按常理来说，如果
	       不走got表，这个引用是错误的。但如果我们真的把这个符号定义在
	       可执行文件中，而将动态库中对象的初始值复制到可执行文件中
	       （R_LARCH_COPY），这其实等效于引用动态库中的对象了。
	       由此，如果某个重定位一旦可能不被动态链接器控制，这个flag被置位，
	       接下来的处理会根据情况加上R_LARCH_COPY重定位。这样，我们也只能
	       在可执行文件中做这件事；动态库中的R_LARCH_COPY是很奇怪的。 */
	    h->non_got_ref = 1;
	  break;

	case R_LARCH_SOP_PUSH_PCREL:
	  if (h != NULL)
	    {
	      h->non_got_ref = 1;

	      /* We try to create PLT stub for all non-local function.  */
	      if (h->plt.refcount < 0)
		h->plt.refcount = 0;
	      h->plt.refcount++;
	    }
	  break;

	case R_LARCH_SOP_PUSH_PLT_PCREL:
	  /* This symbol requires a procedure linkage table entry.  We
	     actually build the entry in adjust_dynamic_symbol,
	     because this might be a case of linking PIC code without
	     linking in any dynamic objects, in which case we don't
	     need to generate a procedure linkage table after all.  */
	  if (h != NULL)
	    {
	      h->needs_plt = 1;
	      if (h->plt.refcount < 0)
		h->plt.refcount = 0;
	      h->plt.refcount++;
	    }
	  break;

	case R_LARCH_TLS_DTPREL32:
	case R_LARCH_TLS_DTPREL64:
	  need_dynreloc = 1;
	  only_need_pcrel = 1;
	  break;

	case R_LARCH_JUMP_SLOT:
	case R_LARCH_32:
	case R_LARCH_64:
	  need_dynreloc = 1;

	  /* If resolved symbol is defined in this object,
	       1. Under pie, the symbol is known. We convert it
		  into R_LARCH_RELATIVE and need load-addr still.
	       2. Under pde, the symbol is known and we can discard R_LARCH_NN.
	       3. Under dll, R_LARCH_NN can't be changed normally, since
		  its defination could be covered by the one in executable.
		  For symbolic, we convert it into R_LARCH_RELATIVE.
	     Thus, only under pde, it needs pcrel only. We discard it. */
	  only_need_pcrel = bfd_link_pde (info);

	  if (h != NULL)
	    h->non_got_ref = 1;
	  break;

	case R_LARCH_GNU_VTINHERIT:
	  if (!bfd_elf_gc_record_vtinherit (abfd, sec, h, rel->r_offset))
	    return FALSE;
	  break;

	case R_LARCH_GNU_VTENTRY:
	  if (!bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_addend))
	    return FALSE;
	  break;

	default:
	  break;
	}

      /* Record some info for sizing and allocating dynamic entry */
      if (need_dynreloc && (sec->flags & SEC_ALLOC))
	{
	  /* When creating a shared object, we must copy these
	     relocs into the output file.  We create a reloc
	     section in dynobj and make room for the reloc.  */
	  struct elf_dyn_relocs *p;
	  struct elf_dyn_relocs **head;

	  if (sreloc == NULL)
	    {
	      sreloc = _bfd_elf_make_dynamic_reloc_section
			 (sec, htab->elf.dynobj, LARCH_ELF_LOG_WORD_BYTES,
			  abfd, /*rela?*/ TRUE);

	      if (sreloc == NULL)
		return FALSE;
	    }

	  /* If this is a global symbol, we count the number of
	     relocations we need for this symbol.  */
	  if (h != NULL)
	    head = &((struct loongarch_elf_link_hash_entry *) h)->dyn_relocs;
	  else
	    {
	      /* Track dynamic relocs needed for local syms too.
		 We really need local syms available to do this
		 easily.  Oh well.  */

	      asection *s;
	      void *vpp;

	      s = bfd_section_from_elf_index (abfd, isym->st_shndx);
	      if (s == NULL)
		s = sec;

	      vpp = &elf_section_data (s)->local_dynrel;
	      head = (struct elf_dyn_relocs **) vpp;
	    }

	  p = *head;
	  if (p == NULL || p->sec != sec)
	    {
	      bfd_size_type amt = sizeof *p;
	      p = (struct elf_dyn_relocs *) bfd_alloc (htab->elf.dynobj, amt);
	      if (p == NULL)
		return FALSE;
	      p->next = *head;
	      *head = p;
	      p->sec = sec;
	      p->count = 0;
	      p->pc_count = 0;
	    }

	  p->count++;
	  p->pc_count += only_need_pcrel;
	}
    }

  return TRUE;
}

/* Find dynamic relocs for H that apply to read-only sections.  */

static asection *
readonly_dynrelocs (struct elf_link_hash_entry *h)
{
  struct elf_dyn_relocs *p;

  for (p = loongarch_elf_hash_entry (h)->dyn_relocs; p != NULL; p = p->next)
    {
      asection *s = p->sec->output_section;

      if (s != NULL && (s->flags & SEC_READONLY) != 0)
	return p->sec;
    }
  return NULL;
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.  */
static bfd_boolean
loongarch_elf_adjust_dynamic_symbol (struct bfd_link_info *info,
				     struct elf_link_hash_entry *h)
{
  struct loongarch_elf_link_hash_table *htab;
  struct loongarch_elf_link_hash_entry * eh;
  bfd *dynobj;
  asection *s, *srel;

  htab = loongarch_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);

  dynobj = htab->elf.dynobj;

  /* Make sure we know what is going on here.  */
  BFD_ASSERT (dynobj != NULL
	      && (h->needs_plt
		  || h->type == STT_GNU_IFUNC
		  || h->is_weakalias
		  || (h->def_dynamic
		      && h->ref_regular
		      && !h->def_regular)));

  /* If this is a function, put it in the procedure linkage table.  We
     will fill in the contents of the procedure linkage table later
     (although we could actually do it here).  */
  if (h->type == STT_FUNC || h->type == STT_GNU_IFUNC || h->needs_plt)
    {
      if (h->plt.refcount < 0
	  || (h->type != STT_GNU_IFUNC
	      && (SYMBOL_REFERENCES_LOCAL (info, h)
		  || (ELF_ST_VISIBILITY (h->other) != STV_DEFAULT
		      && h->root.type == bfd_link_hash_undefweak))))
	{
	  /* This case can occur if we saw a R_LARCH_SOP_PUSH_PLT_PCREL reloc
	     in an input file, but the symbol was never referred to by a
	     dynamic object, or if all references were garbage collected.
	     In such a case, we don't actually need to build a PLT entry.  */
	  h->plt.offset = MINUS_ONE;
	  h->needs_plt = 0;
	}
      else
	h->needs_plt = 1;

      return TRUE;
    }
  else
    h->plt.offset = MINUS_ONE;

  /* If this is a weak symbol, and there is a real definition, the
     processor independent code will have arranged for us to see the
     real definition first, and we can just use the same value.  */
  if (h->is_weakalias)
    {
      struct elf_link_hash_entry *def = weakdef (h);
      BFD_ASSERT (def->root.type == bfd_link_hash_defined);
      h->root.u.def.section = def->root.u.def.section;
      h->root.u.def.value = def->root.u.def.value;
      return TRUE;
    }

  /* This is a reference to a symbol defined by a dynamic object which
     is not a function.  */

  /* If we are creating a shared library, we must presume that the
     only references to the symbol are via the global offset table.
     For such cases we need not do anything here; the relocations will
     be handled correctly by relocate_section.  */
  if (bfd_link_dll (info))
    return TRUE;

  /* If there are no references to this symbol that do not use the
     GOT, we don't need to generate a copy reloc.  */
  if (!h->non_got_ref)
    return TRUE;

  /* If -z nocopyreloc was given, we won't generate them either.  */
  if (info->nocopyreloc)
    {
      h->non_got_ref = 0;
      return TRUE;
    }

  /* If we don't find any dynamic relocs in read-only sections, then
     we'll be keeping the dynamic relocs and avoiding the copy reloc.  */
  if (!readonly_dynrelocs (h))
    {
      h->non_got_ref = 0;
      return TRUE;
    }

  /* We must allocate the symbol in our .dynbss section, which will
     become part of the .bss section of the executable.  There will be
     an entry for this symbol in the .dynsym section.  The dynamic
     object will contain position independent code, so all references
     from the dynamic object to this symbol will go through the global
     offset table.  The dynamic linker will use the .dynsym entry to
     determine the address it must put in the global offset table, so
     both the dynamic object and the regular object will refer to the
     same memory location for the variable.  */

  /* We must generate a R_LARCH_COPY reloc to tell the dynamic linker
     to copy the initial value out of the dynamic object and into the
     runtime process image.  We need to remember the offset into the
     .rel.bss section we are going to use.  */
  eh = (struct loongarch_elf_link_hash_entry *) h;
  if (eh->tls_type & ~GOT_NORMAL)
    {
      s = htab->sdyntdata;
      srel = htab->elf.srelbss;
    }
  else
    if ((h->root.u.def.section->flags & SEC_READONLY) != 0)
      {
	s = htab->elf.sdynrelro;
	srel = htab->elf.sreldynrelro;
      }
    else
      {
	s = htab->elf.sdynbss;
	srel = htab->elf.srelbss;
      }
  if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0)
    {
      srel->size += sizeof (ElfNN_External_Rela);
      h->needs_copy = 1;
    }

  return _bfd_elf_adjust_dynamic_copy (info, h, s);
}


/* Allocate space in .plt, .got and associated reloc sections for
   dynamic relocs.  */

static bfd_boolean
allocate_dynrelocs (struct elf_link_hash_entry *h, void *inf)
{
  struct bfd_link_info *info;
  struct loongarch_elf_link_hash_table *htab;
  struct loongarch_elf_link_hash_entry *eh;
  struct elf_dyn_relocs *p;

  if (h->root.type == bfd_link_hash_indirect)
    return TRUE;

  eh = (struct loongarch_elf_link_hash_entry *) h;
  info = (struct bfd_link_info *) inf;
  htab = loongarch_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);

  /* 在这里针对符号对.got .iplt .plt的扩充和后续elf_finish_dynamic_symbol补充
     内容对照；WILL_CALL_FINISH_DYNAMIC_SYMBOL似乎指的是这个符号在将来会不会被
     finish_dynamic_symbol调用。
     a. 对于非IFUNC符号，被allocate_dynrelocs照顾到的符号h要保证在链接后期被
     elf_finish_dynamic_symbol调用
     b. STT_GNU_IFUNC符号一定走plt，但是对于那些local转化为h的符号，默认是不会
     被调用allocate_dynrelocs和elf_finish_dynamic_symbol的，要手动遍历
     这些符号来调用这两个函数，从而为它们分配plt stub；
     而WILL_CALL_FINISH_DYNAMIC_SYMBOL返回false，因此下面的逻辑都是
     WILL_CALL_FINISH_DYNAMIC_SYMBOL和对IFUNC的判断配合起来。  */

  do
    {
      asection *plt, *gotplt, *relplt;

      if (!h->needs_plt)
	break;

      h->needs_plt = 0;

      if (htab->elf.splt)
	{
	  if (h->dynindx == -1 && !h->forced_local
	      && !bfd_elf_link_record_dynamic_symbol (info, h))
	    return FALSE;

	  if (!WILL_CALL_FINISH_DYNAMIC_SYMBOL (1, bfd_link_pic (info), h)
	      && h->type != STT_GNU_IFUNC)
	    break;

	  plt = htab->elf.splt;
	  gotplt = htab->elf.sgotplt;
	  relplt = htab->elf.srelplt;
	}
      else if (htab->elf.iplt)
	{
	  /* .iplt only for IFUNC */
	  if (h->type != STT_GNU_IFUNC)
	    break;

	  plt = htab->elf.iplt;
	  gotplt = htab->elf.igotplt;
	  relplt = htab->elf.irelplt;
	}
      else
	break;

      if (plt->size == 0)
	plt->size = PLT_HEADER_SIZE;

      h->plt.offset = plt->size;
      plt->size += PLT_ENTRY_SIZE;
      gotplt->size += GOT_ENTRY_SIZE;
      relplt->size += sizeof (ElfNN_External_Rela);

      h->needs_plt = 1;
    }
  while (0);

  if (!h->needs_plt)
    h->plt.offset = MINUS_ONE;

  if (0 < h->got.refcount)
    {
      asection *s;
      bfd_boolean dyn;
      int tls_type = loongarch_elf_hash_entry (h)->tls_type;

      /* Make sure this symbol is output as a dynamic symbol.
	 Undefined weak syms won't yet be marked as dynamic.  */
      if (h->dynindx == -1 && !h->forced_local
	  && !bfd_elf_link_record_dynamic_symbol (info, h))
	return FALSE;

      s = htab->elf.sgot;
      h->got.offset = s->size;
      dyn = htab->elf.dynamic_sections_created;
      if (tls_type & (GOT_TLS_GD | GOT_TLS_IE))
	{
	  /* TLS_GD needs two dynamic relocs and two GOT slots.  */
	  if (tls_type & GOT_TLS_GD)
	    {
	      s->size += 2 * GOT_ENTRY_SIZE;
	      htab->elf.srelgot->size += 2 * sizeof (ElfNN_External_Rela);
	    }

	  /* TLS_IE needs one dynamic reloc and one GOT slot.  */
	  if (tls_type & GOT_TLS_IE)
	    {
	      s->size += GOT_ENTRY_SIZE;
	      htab->elf.srelgot->size += sizeof (ElfNN_External_Rela);
	    }
	}
      else
	{
	  s->size += GOT_ENTRY_SIZE;
	  if ((WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, bfd_link_pic (info), h)
	       && !UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
	      || h->type == STT_GNU_IFUNC)
	    htab->elf.srelgot->size += sizeof (ElfNN_External_Rela);
	}
    }
  else
    h->got.offset = MINUS_ONE;

  if (eh->dyn_relocs == NULL)
    return TRUE;

  /* 如果某些函数未被定义，SYMBOL_CALLS_LOCAL返回1；
     而SYMBOL_REFERENCES_LOCAL返回0。
     似乎是因为未定义的函数可以有plt从而将其转化为local的。 */
  if (SYMBOL_REFERENCES_LOCAL (info, h))
    {
      struct elf_dyn_relocs **pp;

      for (pp = &eh->dyn_relocs; (p = *pp) != NULL; )
	{
	  p->count -= p->pc_count;
	  p->pc_count = 0;
	  if (p->count == 0)
	    *pp = p->next;
	  else
	    pp = &p->next;
	}
    }

  if (h->root.type == bfd_link_hash_undefweak)
    {
      if (UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
	eh->dyn_relocs = NULL;
      else if (h->dynindx == -1 && !h->forced_local
	       /* Make sure this symbol is output as a dynamic symbol.
		  Undefined weak syms won't yet be marked as dynamic.  */
	       && !bfd_elf_link_record_dynamic_symbol (info, h))
	return FALSE;
    }

  for (p = eh->dyn_relocs; p != NULL; p = p->next)
    {
      asection *sreloc = elf_section_data (p->sec)->sreloc;
      sreloc->size += p->count * sizeof (ElfNN_External_Rela);
    }

  return TRUE;
}

static bfd_boolean
elfNN_loongarch_allocate_local_dynrelocs (void **slot, void *inf)
{
  struct elf_link_hash_entry *h
    = (struct elf_link_hash_entry *) *slot;

  if (!h->def_regular
      || !h->ref_regular
      || !h->forced_local
      || h->root.type != bfd_link_hash_defined)
    abort ();

  return allocate_dynrelocs (h, inf);
}

/* Set DF_TEXTREL if we find any dynamic relocs that apply to
   read-only sections.  */

static bfd_boolean
maybe_set_textrel (struct elf_link_hash_entry *h, void *info_p)
{
  asection *sec;

  if (h->root.type == bfd_link_hash_indirect)
    return TRUE;

  sec = readonly_dynrelocs (h);
  if (sec != NULL)
    {
      struct bfd_link_info *info = (struct bfd_link_info *) info_p;

      info->flags |= DF_TEXTREL;
      info->callbacks->minfo (
	_("%pB: dynamic relocation against `%pT' in read-only section `%pA'\n"),
	sec->owner, h->root.root.string, sec);

      /* Not an error, just cut short the traversal.  */
      return FALSE;
    }
  return TRUE;
}

static bfd_boolean
loongarch_elf_size_dynamic_sections (bfd *output_bfd,
				     struct bfd_link_info *info)
{
  struct loongarch_elf_link_hash_table *htab;
  bfd *dynobj;
  asection *s;
  bfd *ibfd;

  htab = loongarch_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);
  dynobj = htab->elf.dynobj;
  BFD_ASSERT (dynobj != NULL);

  if (htab->elf.dynamic_sections_created)
    {
      /* Set the contents of the .interp section to the interpreter.  */
      if (bfd_link_executable (info) && !info->nointerp)
	{
	  const char *interpreter;
	  flagword flags = elf_elfheader (output_bfd)->e_flags;
	  s = bfd_get_linker_section (dynobj, ".interp");
	  BFD_ASSERT (s != NULL);
	  if ((flags & EF_LARCH_ABI) == EF_LARCH_ABI_LP32)
	    interpreter = "/lib32/ld.so.1";
	  else if ((flags & EF_LARCH_ABI) == EF_LARCH_ABI_LP64)
	    interpreter = "/lib64/ld.so.1";
	  else
	    interpreter = "/lib/ld.so.1";
	  s->contents = (unsigned char *) interpreter;
	  s->size = strlen (interpreter) + 1;
	}
    }

  /* Set up .got offsets for local syms, and space for local dynamic
     relocs.  */
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      bfd_signed_vma *local_got;
      bfd_signed_vma *end_local_got;
      char *local_tls_type;
      bfd_size_type locsymcount;
      Elf_Internal_Shdr *symtab_hdr;
      asection *srel;

      if (!is_loongarch_elf (ibfd))
	continue;

      for (s = ibfd->sections; s != NULL; s = s->next)
	{
	  struct elf_dyn_relocs *p;

	  for (p = elf_section_data (s)->local_dynrel; p != NULL; p = p->next)
	    {
	      p->count -= p->pc_count;
	      if (!bfd_is_abs_section (p->sec)
		  && bfd_is_abs_section (p->sec->output_section))
		{
		  /* Input section has been discarded, either because
		     it is a copy of a linkonce section or due to
		     linker script /DISCARD/, so we'll be discarding
		     the relocs too.  */
		}
	      else if (0 < p->count)
		{
		  srel = elf_section_data (p->sec)->sreloc;
		  srel->size += p->count * sizeof (ElfNN_External_Rela);
		  if ((p->sec->output_section->flags & SEC_READONLY) != 0)
		    info->flags |= DF_TEXTREL;
		}
	    }
	}

      local_got = elf_local_got_refcounts (ibfd);
      if (!local_got)
	continue;

      symtab_hdr = &elf_symtab_hdr (ibfd);
      locsymcount = symtab_hdr->sh_info;
      end_local_got = local_got + locsymcount;
      local_tls_type = _bfd_loongarch_elf_local_got_tls_type (ibfd);
      s = htab->elf.sgot;
      srel = htab->elf.srelgot;
      for (; local_got < end_local_got; ++local_got, ++local_tls_type)
	{
	  if (0 < *local_got)
	    {
	      *local_got = s->size;
	      s->size += GOT_ENTRY_SIZE;

	      if (*local_tls_type & GOT_TLS_GD)
		s->size += GOT_ENTRY_SIZE;

	      if (bfd_link_pic (info) /* R_LARCH_RELATIVE */
		  || (*local_tls_type &
		      (GOT_TLS_GD /* R_LARCH_TLS_DTPRELNN */
		       | GOT_TLS_IE /* R_LARCH_TLS_TPRELNN */)))
		srel->size += sizeof (ElfNN_External_Rela);
	    }
	  else
	    *local_got = MINUS_ONE;
	}
    }

  /* Allocate global sym .plt and .got entries, and space for global
     sym dynamic relocs.  */
  elf_link_hash_traverse (&htab->elf, allocate_dynrelocs, info);
  /* Allocate .plt and .got entries, and space for local ifunc symbols.  */
  htab_traverse (htab->loc_hash_table,
		 elfNN_loongarch_allocate_local_dynrelocs,
		 info);

  /* Don't allocate .got.plt section if there are no PLT.  */
  if (htab->elf.sgotplt
      && htab->elf.sgotplt->size == GOTPLT_HEADER_SIZE
      && (htab->elf.splt == NULL
	  || htab->elf.splt->size == 0))
    htab->elf.sgotplt->size = 0;

  /* The check_relocs and adjust_dynamic_symbol entry points have
     determined the sizes of the various dynamic sections.  Allocate
     memory for them.  */
  for (s = dynobj->sections; s != NULL; s = s->next)
    {
      if ((s->flags & SEC_LINKER_CREATED) == 0)
	continue;

      if (s == htab->elf.splt
	  || s == htab->elf.iplt
	  || s == htab->elf.sgot
	  || s == htab->elf.sgotplt
	  || s == htab->elf.igotplt
	  || s == htab->elf.sdynbss
	  || s == htab->elf.sdynrelro)
	{
	  /* Strip this section if we don't need it; see the
	     comment below.  */
	}
      else if (strncmp (s->name, ".rela", 5) == 0)
	{
	  if (s->size != 0)
	    {
	      /* We use the reloc_count field as a counter if we need
		 to copy relocs into the output file.  */
	      s->reloc_count = 0;
	    }
	}
      else
	{
	  /* It's not one of our sections.  */
	  continue;
	}

      if (s->size == 0)
	{
	  /* If we don't need this section, strip it from the
	     output file.  This is mostly to handle .rela.bss and
	     .rela.plt.  We must create both sections in
	     create_dynamic_sections, because they must be created
	     before the linker maps input sections to output
	     sections.  The linker does that before
	     adjust_dynamic_symbol is called, and it is that
	     function which decides whether anything needs to go
	     into these sections.  */
	  s->flags |= SEC_EXCLUDE;
	  continue;
	}

      if ((s->flags & SEC_HAS_CONTENTS) == 0)
	continue;

      /* Allocate memory for the section contents.  Zero the memory
	 for the benefit of .rela.plt, which has 4 unused entries
	 at the beginning, and we don't want garbage.  */
      s->contents = (bfd_byte *) bfd_zalloc (dynobj, s->size);
      if (s->contents == NULL)
	return FALSE;
    }

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      /* Add some entries to the .dynamic section.  We fill in the
	 values later, in loongarch_elf_finish_dynamic_sections, but we
	 must add the entries now so that we get the correct size for
	 the .dynamic section.  The DT_DEBUG entry is filled in by the
	 dynamic linker and used by the debugger.  */
#define add_dynamic_entry(TAG, VAL) \
      _bfd_elf_add_dynamic_entry (info, TAG, VAL)

      if (bfd_link_executable (info))
	{
	  if (!add_dynamic_entry (DT_DEBUG, 0))
	    return FALSE;
	}

      if (htab->elf.srelplt->size != 0)
	{
	  if (!add_dynamic_entry (DT_PLTGOT, 0)
	      || !add_dynamic_entry (DT_PLTRELSZ, 0)
	      || !add_dynamic_entry (DT_PLTREL, DT_RELA)
	      || !add_dynamic_entry (DT_JMPREL, 0))
	    return FALSE;
	}

      if (!add_dynamic_entry (DT_RELA, 0)
	  || !add_dynamic_entry (DT_RELASZ, 0)
	  || !add_dynamic_entry (DT_RELAENT, sizeof (ElfNN_External_Rela)))
	return FALSE;

      /* If any dynamic relocs apply to a read-only section,
	 then we need a DT_TEXTREL entry.  */
      if ((info->flags & DF_TEXTREL) == 0)
	elf_link_hash_traverse (&htab->elf, maybe_set_textrel, info);

      if (info->flags & DF_TEXTREL)
	{
	  if (!add_dynamic_entry (DT_TEXTREL, 0))
	    return FALSE;
	  /* Clear the DF_TEXTREL flag.  It will be set again if we
             write out an actual text relocation; we may not, because
             at this point we do not know whether e.g. any .eh_frame
             absolute relocations have been converted to PC-relative.  */
	  info->flags &= ~DF_TEXTREL;
	}
    }
#undef add_dynamic_entry

  return TRUE;
}


#define LARCH_LD_STACK_DEPTH 16
static int64_t lisa_opc_stack[LARCH_LD_STACK_DEPTH];
static size_t lisa_stack_top = 0;

static bfd_reloc_status_type
loongarch_push (int64_t val)
{
  if (LARCH_LD_STACK_DEPTH <= lisa_stack_top)
    return bfd_reloc_outofrange;
  lisa_opc_stack[lisa_stack_top++] = val;
  return bfd_reloc_ok;
}

static bfd_reloc_status_type
loongarch_pop (int64_t *val)
{
  if (lisa_stack_top == 0)
    return bfd_reloc_outofrange;
  BFD_ASSERT (val);
  *val = lisa_opc_stack[--lisa_stack_top];
  return bfd_reloc_ok;
}

static bfd_reloc_status_type
loongarch_top (int64_t *val)
{
  if (lisa_stack_top == 0)
    return bfd_reloc_outofrange;
  BFD_ASSERT (val);
  *val = lisa_opc_stack[lisa_stack_top - 1];
  return bfd_reloc_ok;
}

static void
loongarch_elf_append_rela (bfd *abfd, asection *s, Elf_Internal_Rela *rel)
{
  const struct elf_backend_data *bed;
  bfd_byte *loc;

  bed = get_elf_backend_data (abfd);
  loc = s->contents + (s->reloc_count++ * bed->s->sizeof_rela);
  bed->s->swap_reloca_out (abfd, rel, loc);
}

/* Emplace a static relocation.  */

static bfd_reloc_status_type
perform_relocation (const Elf_Internal_Rela *rel,
		    bfd_vma value,
		    bfd *input_bfd,
		    bfd_byte *contents)
{

  uint32_t insn1;
  int64_t opr1, opr2, opr3;
  bfd_reloc_status_type r = bfd_reloc_ok;
  switch (ELFNN_R_TYPE (rel->r_info))
    {
    case R_LARCH_SOP_PUSH_PCREL:
    case R_LARCH_SOP_PUSH_ABSOLUTE:
    case R_LARCH_SOP_PUSH_GPREL:
    case R_LARCH_SOP_PUSH_TLS_TPREL:
    case R_LARCH_SOP_PUSH_TLS_GOT:
    case R_LARCH_SOP_PUSH_TLS_GD:
    case R_LARCH_SOP_PUSH_PLT_PCREL:
      r = loongarch_push (value);
      break;

    case R_LARCH_SOP_PUSH_DUP:
      r = bfd_reloc_outofrange;
      if (loongarch_pop (&opr1) != bfd_reloc_ok
	  || loongarch_push (opr1) != bfd_reloc_ok
	  || loongarch_push (opr1) != bfd_reloc_ok)
	break;
      r = bfd_reloc_ok;
      break;

    case R_LARCH_SOP_ASSERT:
      r = loongarch_pop (&opr1);
      if (r != bfd_reloc_ok && opr1 == FALSE)
	r = bfd_reloc_notsupported;
      break;

    case R_LARCH_SOP_NOT:
      r = bfd_reloc_outofrange;
      if (loongarch_pop (&opr1) != bfd_reloc_ok
	  || loongarch_push (!opr1) != bfd_reloc_ok)
	break;
      r = bfd_reloc_ok;
      break;

    case R_LARCH_SOP_SUB:
      r = bfd_reloc_outofrange;
      if (loongarch_pop (&opr2) != bfd_reloc_ok
	  || loongarch_pop (&opr1) != bfd_reloc_ok
	  || loongarch_push (opr1 - opr2) != bfd_reloc_ok)
	break;
      r = bfd_reloc_ok;
      break;

    case R_LARCH_SOP_SL:
      r = bfd_reloc_outofrange;
      if (loongarch_pop (&opr2) != bfd_reloc_ok
	  || loongarch_pop (&opr1) != bfd_reloc_ok
	  || loongarch_push (opr1 << opr2) != bfd_reloc_ok)
	break;
      r = bfd_reloc_ok;
      break;

    case R_LARCH_SOP_SR:
      r = bfd_reloc_outofrange;
      if (loongarch_pop (&opr2) != bfd_reloc_ok
	  || loongarch_pop (&opr1) != bfd_reloc_ok
	  || loongarch_push (opr1 >> opr2) != bfd_reloc_ok)
	break;
      r = bfd_reloc_ok;
      break;

    case R_LARCH_SOP_AND:
      r = bfd_reloc_outofrange;
      if (loongarch_pop (&opr2) != bfd_reloc_ok
	  || loongarch_pop (&opr1) != bfd_reloc_ok
	  || loongarch_push (opr1 & opr2) != bfd_reloc_ok)
	break;
      r = bfd_reloc_ok;
      break;

    case R_LARCH_SOP_ADD:
      r = bfd_reloc_outofrange;
      if (loongarch_pop (&opr2) != bfd_reloc_ok
	  || loongarch_pop (&opr1) != bfd_reloc_ok
	  || loongarch_push (opr1 + opr2) != bfd_reloc_ok)
	break;
      r = bfd_reloc_ok;
      break;

    case R_LARCH_SOP_IF_ELSE:
      r = bfd_reloc_outofrange;
      if (loongarch_pop (&opr3) != bfd_reloc_ok
	  || loongarch_pop (&opr2) != bfd_reloc_ok
	  || loongarch_pop (&opr1) != bfd_reloc_ok
	  || loongarch_push (opr1 ? opr2 : opr3) != bfd_reloc_ok)
	break;
      r = bfd_reloc_ok;
      break;

    case R_LARCH_SOP_POP_32_S_10_5:
      r = loongarch_pop (&opr1);
      if (r != bfd_reloc_ok)
	break;
      if ((opr1 & ~(uint64_t)0xf) != 0x0
	  && (opr1 & ~(uint64_t)0xf) != ~(uint64_t)0xf)
	r = bfd_reloc_overflow;
      if (r != bfd_reloc_ok)
	break;
      insn1 = bfd_get (32, input_bfd, contents + rel->r_offset);
      insn1 = (insn1 & (~(uint32_t)0x7c00)) | ((opr1 & 0x1f) << 10);
      bfd_put (32, input_bfd, insn1, contents + rel->r_offset);
      break;

    case R_LARCH_SOP_POP_32_U_10_12:
      r = loongarch_pop (&opr1);
      if (r != bfd_reloc_ok)
	break;
      if (opr1 & ~(uint64_t)0xfff)
	r = bfd_reloc_overflow;
      if (r != bfd_reloc_ok)
	break;
      insn1 = bfd_get (32, input_bfd, contents + rel->r_offset);
      insn1 = (insn1 & (~(uint32_t)0x3ffc00)) | ((opr1 & 0xfff) << 10);
      bfd_put (32, input_bfd, insn1, contents + rel->r_offset);
      break;

    case R_LARCH_SOP_POP_32_S_10_12:
      r = loongarch_pop (&opr1);
      if (r != bfd_reloc_ok)
	break;
      if ((opr1 & ~(uint64_t)0x7ff) != 0x0
	  && (opr1 & ~(uint64_t)0x7ff) != ~(uint64_t)0x7ff)
	r = bfd_reloc_overflow;
      if (r != bfd_reloc_ok)
	break;
      insn1 = bfd_get (32, input_bfd, contents + rel->r_offset);
      insn1 = (insn1 & (~(uint32_t)0x3ffc00)) | ((opr1 & 0xfff) << 10);
      bfd_put (32, input_bfd, insn1, contents + rel->r_offset);
      break;

    case R_LARCH_SOP_POP_32_S_10_16:
      r = loongarch_pop (&opr1);
      if (r != bfd_reloc_ok)
	break;
      if ((opr1 & ~(uint64_t)0x7fff) != 0x0
	  && (opr1 & ~(uint64_t)0x7fff) != ~(uint64_t)0x7fff)
	r = bfd_reloc_overflow;
      if (r != bfd_reloc_ok)
	break;
      insn1 = bfd_get (32, input_bfd, contents + rel->r_offset);
      insn1 = (insn1 & 0xfc0003ff) | ((opr1 & 0xffff) << 10);
      bfd_put (32, input_bfd, insn1, contents + rel->r_offset);
      break;

    case R_LARCH_SOP_POP_32_S_10_16_S2:
      r = loongarch_pop (&opr1);
      if (r != bfd_reloc_ok)
	break;
      if ((opr1 & 0x3) != 0)
	r = bfd_reloc_overflow;
      opr1 >>= 2;
      if ((opr1 & ~(uint64_t)0x7fff) != 0x0
	  && (opr1 & ~(uint64_t)0x7fff) != ~(uint64_t)0x7fff)
	r = bfd_reloc_overflow;
      if (r != bfd_reloc_ok)
	break;
      insn1 = bfd_get (32, input_bfd, contents + rel->r_offset);
      insn1 = (insn1 & 0xfc0003ff) | ((opr1 & 0xffff) << 10);
      bfd_put (32, input_bfd, insn1, contents + rel->r_offset);
      break;

    case R_LARCH_SOP_POP_32_S_0_5_10_16_S2:
      r = loongarch_pop (&opr1);
      if (r != bfd_reloc_ok)
	break;
      if ((opr1 & 0x3) != 0)
	r = bfd_reloc_overflow;
      opr1 >>= 2;
      if ((opr1 & ~(uint64_t)0xfffff) != 0x0
	  && (opr1 & ~(uint64_t)0xfffff) != ~(uint64_t)0xfffff)
	r = bfd_reloc_overflow;
      if (r != bfd_reloc_ok)
	break;
      insn1 = bfd_get (32, input_bfd, contents + rel->r_offset);
      insn1 = (insn1 & 0xfc0003e0)
	    | ((opr1 & 0xffff) << 10) | ((opr1 & 0x1f0000) >> 16);
      bfd_put (32, input_bfd, insn1, contents + rel->r_offset);
      break;

    case R_LARCH_SOP_POP_32_S_5_20:
      r = loongarch_pop (&opr1);
      if (r != bfd_reloc_ok)
	break;
      if ((opr1 & ~(uint64_t)0x7ffff) != 0x0
	  && (opr1 & ~(uint64_t)0x7ffff) != ~(uint64_t)0x7ffff)
	r = bfd_reloc_overflow;
      if (r != bfd_reloc_ok)
	break;
      insn1 = bfd_get (32, input_bfd, contents + rel->r_offset);
      insn1 = (insn1 & (~(uint32_t)0x1ffffe0)) | ((opr1 & 0xfffff) << 5);
      bfd_put (32, input_bfd, insn1, contents + rel->r_offset);
      break;

    case R_LARCH_SOP_POP_32_S_0_10_10_16_S2:
      r = loongarch_pop (&opr1);
      if (r != bfd_reloc_ok)
	break;
      if ((opr1 & 0x3) != 0)
	r = bfd_reloc_overflow;
      opr1 >>= 2;
      if ((opr1 & ~(uint64_t)0x1ffffff) != 0x0
	  && (opr1 & ~(uint64_t)0x1ffffff) != ~(uint64_t)0x1ffffff)
	r = bfd_reloc_overflow;
      if (r != bfd_reloc_ok)
	break;
      insn1 = bfd_get (32, input_bfd, contents + rel->r_offset);
      insn1 = (insn1 & 0xfc000000)
	    | ((opr1 & 0xffff) << 10) | ((opr1 & 0x3ff0000) >> 16);
      bfd_put (32, input_bfd, insn1, contents + rel->r_offset);
      break;

    case R_LARCH_SOP_POP_32_U:
      r = loongarch_pop (&opr1);
      if (r != bfd_reloc_ok)
	break;
      if (opr1 & ~(uint64_t)0xffffffff)
	r = bfd_reloc_overflow;
      if (r != bfd_reloc_ok)
	break;
      bfd_put (32, input_bfd, opr1, contents + rel->r_offset);
      break;

    case R_LARCH_TLS_DTPREL32:
    case R_LARCH_32:
      bfd_put (32, input_bfd, value, contents + rel->r_offset);
      break;
    case R_LARCH_TLS_DTPREL64:
    case R_LARCH_64:
      bfd_put (64, input_bfd, value, contents + rel->r_offset);
      break;
    case R_LARCH_ADD8:
      opr1 = bfd_get (8, input_bfd, contents + rel->r_offset);
      bfd_put (8, input_bfd, opr1 + value, contents + rel->r_offset);
      break;
    case R_LARCH_ADD16:
      opr1 = bfd_get (16, input_bfd, contents + rel->r_offset);
      bfd_put (16, input_bfd, opr1 + value, contents + rel->r_offset);
      break;
    case R_LARCH_ADD24:
      opr1 = bfd_get (24, input_bfd, contents + rel->r_offset);
      bfd_put (24, input_bfd, opr1 + value, contents + rel->r_offset);
      break;
    case R_LARCH_ADD32:
      opr1 = bfd_get (32, input_bfd, contents + rel->r_offset);
      bfd_put (32, input_bfd, opr1 + value, contents + rel->r_offset);
      break;
    case R_LARCH_ADD64:
      opr1 = bfd_get (64, input_bfd, contents + rel->r_offset);
      bfd_put (64, input_bfd, opr1 + value, contents + rel->r_offset);
      break;
    case R_LARCH_SUB8:
      opr1 = bfd_get (8, input_bfd, contents + rel->r_offset);
      bfd_put (8, input_bfd, opr1 - value, contents + rel->r_offset);
      break;
    case R_LARCH_SUB16:
      opr1 = bfd_get (16, input_bfd, contents + rel->r_offset);
      bfd_put (16, input_bfd, opr1 - value, contents + rel->r_offset);
      break;
    case R_LARCH_SUB24:
      opr1 = bfd_get (24, input_bfd, contents + rel->r_offset);
      bfd_put (24, input_bfd, opr1 - value, contents + rel->r_offset);
      break;
    case R_LARCH_SUB32:
      opr1 = bfd_get (32, input_bfd, contents + rel->r_offset);
      bfd_put (32, input_bfd, opr1 - value, contents + rel->r_offset);
      break;
    case R_LARCH_SUB64:
      opr1 = bfd_get (64, input_bfd, contents + rel->r_offset);
      bfd_put (64, input_bfd, opr1 - value, contents + rel->r_offset);
      break;

    default:
      r = bfd_reloc_notsupported;
    }
  return r;
}


#define LARCH_RECENT_RELOC_QUEUE_LENGTH 72
static struct
{
  bfd *bfd;
  asection *section;
  bfd_vma r_offset;
  int r_type;
  bfd_vma relocation;
  Elf_Internal_Sym *sym;
  struct elf_link_hash_entry *h;
  bfd_vma addend;
  int64_t top_then;
} lisa_reloc_queue [LARCH_RECENT_RELOC_QUEUE_LENGTH];
static size_t lisa_reloc_queue_head = 0;
static size_t lisa_reloc_queue_tail = 0;

static const char *
loongarch_sym_name (bfd *input_bfd, struct elf_link_hash_entry *h,
		    Elf_Internal_Sym *sym)
{
  const char *ret = NULL;
  if (sym)
    ret = bfd_elf_string_from_elf_section
	    (input_bfd, elf_symtab_hdr (input_bfd).sh_link, sym->st_name);
  else if (h)
    ret = h->root.root.string;

  if (ret == NULL || *ret == '\0')
    ret = "<nameless>";
  return ret;
}

static void
loongarch_record_one_reloc (bfd *abfd, asection *section, int r_type,
			    bfd_vma r_offset, Elf_Internal_Sym *sym,
			    struct elf_link_hash_entry *h, bfd_vma addend)
{
  if ((lisa_reloc_queue_head == 0
       && lisa_reloc_queue_tail == LARCH_RECENT_RELOC_QUEUE_LENGTH - 1)
      || (lisa_reloc_queue_head == lisa_reloc_queue_tail + 1))
    lisa_reloc_queue_head =
      (lisa_reloc_queue_head + 1) % LARCH_RECENT_RELOC_QUEUE_LENGTH;
  lisa_reloc_queue[lisa_reloc_queue_tail].bfd = abfd;
  lisa_reloc_queue[lisa_reloc_queue_tail].section = section;
  lisa_reloc_queue[lisa_reloc_queue_tail].r_offset = r_offset;
  lisa_reloc_queue[lisa_reloc_queue_tail].r_type = r_type;
  lisa_reloc_queue[lisa_reloc_queue_tail].sym = sym;
  lisa_reloc_queue[lisa_reloc_queue_tail].h = h;
  lisa_reloc_queue[lisa_reloc_queue_tail].addend = addend;
  loongarch_top (&lisa_reloc_queue[lisa_reloc_queue_tail].top_then);
  lisa_reloc_queue_tail =
    (lisa_reloc_queue_tail + 1) % LARCH_RECENT_RELOC_QUEUE_LENGTH;
}

static void
loongarch_dump_reloc_record (void (*p) (const char *fmt, ...))
{
  size_t i = lisa_reloc_queue_head;
  bfd *a_bfd = NULL;
  asection *section = NULL;
  bfd_vma r_offset = 0;
  int inited = 0;
  p ("Dump relocate record:\n");
  p ("stack top\t\trelocation name\t\tsymbol");
  while (i != lisa_reloc_queue_tail)
    {
      if (a_bfd != lisa_reloc_queue[i].bfd
	  || section != lisa_reloc_queue[i].section
	  || r_offset != lisa_reloc_queue[i].r_offset)
	{
	  a_bfd = lisa_reloc_queue[i].bfd;
	  section = lisa_reloc_queue[i].section;
	  r_offset = lisa_reloc_queue[i].r_offset;
	  p ("\nat %pB(%pA+0x%v):\n",
	     lisa_reloc_queue[i].bfd,
	     lisa_reloc_queue[i].section,
	     lisa_reloc_queue[i].r_offset);
	}

      if (!inited)
	inited = 1, p ("...\n");

      reloc_howto_type *howto =
	loongarch_elf_rtype_to_howto (lisa_reloc_queue[i].r_type);
      p ("0x%V %s\t`%s'",
	 (bfd_vma) lisa_reloc_queue[i].top_then,
	 howto ? howto->name : "<unknown reloc>",
	 loongarch_sym_name (lisa_reloc_queue[i].bfd,
			     lisa_reloc_queue[i].h,
			     lisa_reloc_queue[i].sym));

      long addend = lisa_reloc_queue[i].addend;
      if (addend < 0)
	p (" - %ld", -addend);
      else if (0 < addend)
	p (" + %ld(0x%v)", addend, lisa_reloc_queue[i].addend);

      p ("\n");
      i = (i + 1) % LARCH_RECENT_RELOC_QUEUE_LENGTH;
    }
  p ("\n" "-- Record dump end --\n\n");
}


static bfd_boolean
loongarch_elf_relocate_section (bfd *output_bfd,
				struct bfd_link_info *info,
				bfd *input_bfd,
				asection *input_section,
				bfd_byte *contents,
				Elf_Internal_Rela *relocs,
				Elf_Internal_Sym *local_syms,
				asection **local_sections)
{
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend;
  bfd_boolean fatal = FALSE;
  asection *sreloc = elf_section_data (input_section)->sreloc;
  struct loongarch_elf_link_hash_table *htab = loongarch_elf_hash_table (info);
  Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr (input_bfd);
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (input_bfd);
  bfd_vma *local_got_offsets = elf_local_got_offsets (input_bfd);
  bfd_boolean is_pic = bfd_link_pic (info);
  bfd_boolean is_dyn = elf_hash_table (info)->dynamic_sections_created;
  asection *plt = htab->elf.splt ? htab->elf.splt : htab->elf.iplt;
  asection *got = htab->elf.sgot;

  relend = relocs + input_section->reloc_count;
  for (rel = relocs; rel < relend; rel++)
    {
      int r_type = ELFNN_R_TYPE (rel->r_info);
      unsigned long r_symndx = ELFNN_R_SYM (rel->r_info);
      bfd_vma pc = sec_addr (input_section) + rel->r_offset;
      reloc_howto_type *howto = loongarch_elf_rtype_to_howto (r_type);
      asection *sec = NULL;
      Elf_Internal_Sym *sym = NULL;
      struct elf_link_hash_entry *h = NULL;
      const char *name;
      bfd_reloc_status_type r = bfd_reloc_ok;
      bfd_boolean is_ie, is_undefweak, unresolved_reloc, defined_local;
      bfd_boolean resolved_local, resolved_dynly, resolved_to_const;
      char tls_type;
      bfd_vma relocation;
      bfd_vma off, ie_off;
      int i, j;

      if (howto == NULL
	  || r_type == R_LARCH_GNU_VTINHERIT
	  || r_type == R_LARCH_GNU_VTENTRY)
	continue;

      /* This is a final link.  */
      if (r_symndx < symtab_hdr->sh_info)
	{
	  is_undefweak = FALSE;
	  unresolved_reloc = FALSE;
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];
	  relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);

	  /* Relocate against local STT_GNU_IFUNC symbol.  */
	  if (!bfd_link_relocatable (info)
	      && ELF_ST_TYPE (sym->st_info) == STT_GNU_IFUNC)
	    {
	      h = elfNN_loongarch_get_local_sym_hash
		    (htab, input_bfd, rel, FALSE);
	      if (h == NULL)
		abort ();

	      /* Set STT_GNU_IFUNC symbol value.  */
	      h->root.u.def.value = sym->st_value;
	      h->root.u.def.section = sec;
	    }
	  defined_local = TRUE;
	  resolved_local = TRUE;
	  resolved_dynly = FALSE;
	  resolved_to_const = FALSE;
	if (bfd_link_relocatable(info)
	    && ELF_ST_TYPE(sym->st_info) == STT_SECTION) {
		rel->r_addend += sec->output_offset;
	}
	}
      else
	{
	  bfd_boolean warned, ignored;

	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation,
				   unresolved_reloc, warned, ignored);
	  /* here means symbol isn't local symbol only and 'h != NULL' */

	  /* 'unresolved_syms_in_objects' specify how to deal with undefined
	     symbol. And 'dynamic_undefined_weak' specify what to do when
	     meeting undefweak.  */

	  if ((is_undefweak = h->root.type == bfd_link_hash_undefweak))
	    {
	      defined_local = FALSE;
	      resolved_local = FALSE;
	      resolved_to_const = !is_dyn || h->dynindx == -1
				|| UNDEFWEAK_NO_DYNAMIC_RELOC (info, h);
	      resolved_dynly = !resolved_local && !resolved_to_const;
	    }
	  else if (warned)
	    {
	      /* Symbol undefined offen means failed already. I don't know why
		 'warned' here but I guess it want to continue relocating as if
		 no error occures to find other errors as more as possible. */

	      /* To avoid generating warning messages about truncated
		 relocations, set the relocation's address to be the same as
		 the start of this section.  */
	      relocation = input_section->output_section
			 ? input_section->output_section->vma : 0;

	      defined_local = relocation != 0;
	      resolved_local = defined_local;
	      resolved_to_const = !resolved_local;
	      resolved_dynly = FALSE;
	    }
	  else
	    {
	      defined_local = !unresolved_reloc && !ignored;
	      resolved_local =
		defined_local && SYMBOL_REFERENCES_LOCAL (info, h);
	      resolved_dynly = !resolved_local;
	      resolved_to_const = !resolved_local && !resolved_dynly;
	    }
	}

      name = loongarch_sym_name (input_bfd, h, sym);

      if (sec != NULL && discarded_section (sec))
	RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					 rel, 1, relend, howto, 0, contents);

      if (bfd_link_relocatable (info))
	continue;

      /* r_symndx will be STN_UNDEF (zero) only for relocs against symbols
	 from removed linkonce sections, or sections discarded by a linker
	 script. Also for R_*_SOP_PUSH_ABSOLUTE and PCREL to specify const.  */
      if (r_symndx == STN_UNDEF || bfd_is_abs_section (sec))
	resolved_dynly = resolved_local = defined_local = FALSE
	  , resolved_to_const = TRUE;

      if (h && h->type == STT_GNU_IFUNC)
	{
	  /* a. 动态连接器可以直接处理STT_GNU_IFUNC，因为动态连接器可以察觉到
	     一个动态符号是STT_GNU_IFUNC，从而在装载时执行resolver；
	     但local符号不行，因为根本没有动态符号，所以要将R_LARCH_64转化为
	     R_LARCH_IRELATIVE，类似的，所有其他重定位类型可能都要针对IFUNC
	     做一些特殊操作，我觉得有点麻烦了。
	     b. 此外，比如代码段的重定位无法动态改变其的引用位置，所以必须走plt
	     来实现IFUNC。
	     c. 因此，为方便实现，我们将plt stub的位置当作IFUNC符号的定义。 */
	  if (h->plt.offset == MINUS_ONE)
	    info->callbacks->info
	      ("%X%pB(%pA+0x%v): error: %s against `%s':\n"
	       "STT_GNU_IFUNC must have PLT stub" "\n",
	       input_bfd, input_section, (bfd_vma) rel->r_offset,
	       howto->name, name);
	  defined_local = TRUE;
	  resolved_local = TRUE;
	  resolved_dynly = FALSE;
	  resolved_to_const = FALSE;
	  relocation = sec_addr (plt) + h->plt.offset;
	}

      unresolved_reloc = resolved_dynly;

      BFD_ASSERT (resolved_local + resolved_dynly + resolved_to_const == 1);

      /* a. 命题 'resolved_dynly' ==> 'h && h->dynindx != -1' 成立。
	 b. 需要动态重定位一个符号当然需要动态符号表。这个断言失败意味着某个
	 动态符号没有执行bfd_elf_link_record_dynamic_symbol。之前的逻辑有问题
	 c. 另外，即使resolved_dynly为真，也不一定真的生成动态重定位表项，因为
	 有时section没有SEC_ALLOC这个flag，当段不需要被加载进内存自然不需要动态
	 重定位。 */
      BFD_ASSERT (!resolved_dynly || (h && h->dynindx != -1));

      BFD_ASSERT (!resolved_local || defined_local);

      is_ie = FALSE;
      switch (r_type)
	{
#define LARCH_ASSERT(cond, bfd_fail_state, message)			\
  ({if (!(cond)) {							\
    r = bfd_fail_state;							\
    switch (r) {							\
    /* 'dangerous' means we do it but can't promise it's ok		\
       'unsupport' means out of ability of relocation type		\
       'undefined' means we can't deal with the undefined symbol  */	\
    case bfd_reloc_undefined:						\
      info->callbacks->undefined_symbol					\
	(info, name, input_bfd, input_section, rel->r_offset, TRUE);	\
    default:								\
      fatal = TRUE;							\
      info->callbacks->info						\
	("%X%pB(%pA+0x%v): error: %s against %s`%s':\n"			\
	 message "\n",							\
	 input_bfd, input_section, (bfd_vma) rel->r_offset,		\
	 howto->name, is_undefweak? "[undefweak] " : "", name);		\
      break;								\
    case bfd_reloc_dangerous:						\
      info->callbacks->info						\
	("%pB(%pA+0x%v): warning: %s against %s`%s':\n"			\
	 message "\n",							\
	 input_bfd, input_section, (bfd_vma) rel->r_offset,		\
	 howto->name, is_undefweak? "[undefweak] " : "", name);		\
      break;								\
    case bfd_reloc_ok:							\
    case bfd_reloc_continue:						\
      info->callbacks->info						\
	("%pB(%pA+0x%v): message: %s against %s`%s':\n"			\
	 message "\n",							\
	 input_bfd, input_section, (bfd_vma) rel->r_offset,		\
	 howto->name, is_undefweak? "[undefweak] " : "", name);		\
      break;								\
    }									\
    if (fatal) break;							\
  }})
	case R_LARCH_MARK_PCREL:
	case R_LARCH_MARK_LA:
	case R_LARCH_NONE:
	  r = bfd_reloc_continue;
	  unresolved_reloc = FALSE;
	  break;

	case R_LARCH_32:
	case R_LARCH_64:
	  if (resolved_dynly || (is_pic && resolved_local))
	    {
	      Elf_Internal_Rela outrel;

	      /* When generating a shared object, these relocations are copied
		 into the output file to be resolved at run time.  */

	      outrel.r_offset =
		_bfd_elf_section_offset (output_bfd, info, input_section,
					 rel->r_offset);

	      unresolved_reloc = !((bfd_vma) -2 <= outrel.r_offset)
			       && (input_section->flags & SEC_ALLOC);

	      outrel.r_offset += sec_addr (input_section);
	      if (resolved_dynly)
		{
		  outrel.r_info = ELFNN_R_INFO (h->dynindx, r_type);
		  outrel.r_addend = rel->r_addend;
		}
	      else
		{
		  outrel.r_info = ELFNN_R_INFO (0, R_LARCH_RELATIVE);
		  outrel.r_addend = relocation + rel->r_addend;
		}

	      if (unresolved_reloc)
		loongarch_elf_append_rela (output_bfd, sreloc, &outrel);
	    }

	  relocation += rel->r_addend;
	  break;

	case R_LARCH_ADD8:
	case R_LARCH_ADD16:
	case R_LARCH_ADD24:
	case R_LARCH_ADD32:
	case R_LARCH_ADD64:
	case R_LARCH_SUB8:
	case R_LARCH_SUB16:
	case R_LARCH_SUB24:
	case R_LARCH_SUB32:
	case R_LARCH_SUB64:
	  LARCH_ASSERT (!resolved_dynly, bfd_reloc_undefined,
"Can't be resolved dynamically. If this procedure is hand-writing assemble,\n"
"there must be something like '.dword sym1 - sym2' to generate these relocs\n"
"and we can't get known link-time address of these symbols.");
	  relocation += rel->r_addend;
	  break;

	case R_LARCH_TLS_DTPREL32:
	case R_LARCH_TLS_DTPREL64:
	  if (resolved_dynly)
	    {
	      Elf_Internal_Rela outrel;

	      outrel.r_offset =
		_bfd_elf_section_offset (output_bfd, info, input_section,
					 rel->r_offset);

	      unresolved_reloc = !((bfd_vma) -2 <= outrel.r_offset)
			       && (input_section->flags & SEC_ALLOC);
	      outrel.r_info = ELFNN_R_INFO (h->dynindx, r_type);
	      outrel.r_offset += sec_addr (input_section);
	      outrel.r_addend = rel->r_addend;
	      if (unresolved_reloc)
		loongarch_elf_append_rela (output_bfd, sreloc, &outrel);
	      break;
	    }

	  LARCH_ASSERT (!resolved_to_const, bfd_reloc_notsupported,
	    "Internal:");

	case R_LARCH_SOP_PUSH_TLS_TPREL:
	  if (resolved_local)
	    {
	      LARCH_ASSERT (elf_hash_table (info)->tls_sec,
		bfd_reloc_notsupported, "TLS section not be created");
	      relocation -= elf_hash_table (info)->tls_sec->vma;
	    }

	  LARCH_ASSERT (resolved_local, bfd_reloc_undefined,
	    "TLS LE just can be resolved local only.");
	  break;

	case R_LARCH_SOP_PUSH_ABSOLUTE:
	  if (is_undefweak)
	    {
	      LARCH_ASSERT (!resolved_dynly, bfd_reloc_dangerous,
"Someone require us to resolve undefweak symbol dynamically.\n"
"But this reloc can't be done. I think I can't throw error for this\n"
"so I resolved it to 0. I suggest to re-compile with '-fpic'.");
	      relocation = 0;
	      unresolved_reloc = FALSE;
	      break;
	    }

	  if (resolved_to_const)
	    {
	      relocation += rel->r_addend;
	      break;
	    }

	  LARCH_ASSERT (!is_pic, bfd_reloc_notsupported,
"Under PIC we don't know load address. Re-compile src with '-fpic'?");

	  if (resolved_dynly)
	    {
	      LARCH_ASSERT (plt && h && h->plt.offset != MINUS_ONE,
			   bfd_reloc_undefined,
"Can't be resolved dynamically. Try to re-compile src with '-fpic'?");

	      LARCH_ASSERT (rel->r_addend == 0, bfd_reloc_notsupported,
		"Shouldn't be with r_addend.");

	      relocation = sec_addr (plt) + h->plt.offset;
	      unresolved_reloc = FALSE;
	      break;
	    }

	  if (resolved_local)
	    {
	      relocation += rel->r_addend;
	      break;
	    }

	  break;

	case R_LARCH_SOP_PUSH_PCREL:
	case R_LARCH_SOP_PUSH_PLT_PCREL:
	  unresolved_reloc = FALSE;

	  if (resolved_to_const)
	    {
	      relocation += rel->r_addend;
	      break;
	    }
	  else if (is_undefweak)
	    {
	      i = 0, j = 0;
	      relocation = 0;
	      if (resolved_dynly)
		{
		  if (h && h->plt.offset != MINUS_ONE)
		    i = 1, j = 2;
		  else
		    LARCH_ASSERT (0, bfd_reloc_dangerous,
"Undefweak need to be resolved dynamically, but PLT stub doesn't represent.");
		}
	    }
	  else
	    {
	      LARCH_ASSERT
		(defined_local || (h && h->plt.offset != MINUS_ONE),
		 bfd_reloc_undefined,
		 "PLT stub does not represent and symbol not defined.");

	      if (resolved_local)
		i = 0, j = 2;
	      else /* if (resolved_dynly) */
		{
		  LARCH_ASSERT
		    (h && h->plt.offset != MINUS_ONE, bfd_reloc_dangerous,
"Internal: PLT stub doesn't represent. Resolve it with pcrel");
		  i = 1, j = 3;
		}
	    }

	  for (; i < j; i++)
	    {
	      if ((i & 1) == 0 && defined_local)
		{
		  relocation -= pc;
		  relocation += rel->r_addend;
		  break;
		}

	      if ((i & 1) && h && h->plt.offset != MINUS_ONE)
		{
		  LARCH_ASSERT (rel->r_addend == 0, bfd_reloc_notsupported,
			       "PLT shouldn't be with r_addend.");
		  relocation = sec_addr (plt) + h->plt.offset - pc;
		  break;
		}
	    }
	  break;

	case R_LARCH_SOP_PUSH_GPREL:
	  unresolved_reloc = FALSE;

	  LARCH_ASSERT (rel->r_addend == 0, bfd_reloc_notsupported,
	    "Shouldn't be with r_addend.");

	  /* 约定在GOT表中写入连接时地址。动态连接器通过_GLOBAL_OFFSET_TABLE_的
	     连接时地址和运行时地址拿到模块的加载地址，拿到连接时地址的办法就是
	     拿到那个got entry。一些体系结构通过.dynamic的段基址拿到模块加载
	     地址，我没有这么做，因为这个段在static-pie下不存在。 */

	  if (h != NULL)
	    {
	      off = h->got.offset;

	      LARCH_ASSERT (off != MINUS_ONE, bfd_reloc_notsupported,
		"Internal: GOT entry doesn't represent.");

	      if (!WILL_CALL_FINISH_DYNAMIC_SYMBOL (is_dyn, is_pic, h)
		  || (is_pic && SYMBOL_REFERENCES_LOCAL (info, h)))
		{
		  /* This is actually a static link, or it is a
		     -Bsymbolic link and the symbol is defined
		     locally, or the symbol was forced to be local
		     because of a version file.  We must initialize
		     this entry in the global offset table.  Since the
		     offset must always be a multiple of the word size,
		     we use the least significant bit to record whether
		     we have initialized it already.

		     When doing a dynamic link, we create a .rela.got
		     relocation entry to initialize the value.  This
		     is done in the finish_dynamic_symbol routine.  */

		  /* 在这里先不用管STT_GNU_IFUNC。elf_finish_dynamic_symbol
		     会单独处理。 */

		  LARCH_ASSERT (!resolved_dynly, bfd_reloc_dangerous,
		    "Internal: here shouldn't dynamic.");
		  LARCH_ASSERT (defined_local || resolved_to_const,
		    bfd_reloc_undefined, "Internal: ");

		  if ((off & 1) != 0)
		    off &= ~1;
		  else
		    {
		      bfd_put_NN (output_bfd, relocation, got->contents + off);
		      h->got.offset |= 1;
		    }
		}
	    }
	  else
	    {
	      LARCH_ASSERT (local_got_offsets, bfd_reloc_notsupported,
		"Internal: local got offsets not reporesent.");

	      off = local_got_offsets[r_symndx];

	      LARCH_ASSERT (off != MINUS_ONE, bfd_reloc_notsupported,
		"Internal: GOT entry doesn't represent.");

	      /* The offset must always be a multiple of the word size.
		 So, we can use the least significant bit to record
		 whether we have already processed this entry.  */
	      if ((off & 1) != 0)
		off &= ~1;
	      else
		{
		  if (is_pic)
		    {
		      asection *s;
		      Elf_Internal_Rela outrel;
		      /* We need to generate a R_LARCH_RELATIVE reloc
			 for the dynamic linker.  */
		      s = htab->elf.srelgot;
		      LARCH_ASSERT (s, bfd_reloc_notsupported,
			"Internal: '.rel.got' not represent");

		      outrel.r_offset = sec_addr (got) + off;
		      outrel.r_info = ELFNN_R_INFO (0, R_LARCH_RELATIVE);
		      outrel.r_addend = relocation; /* link-time addr */
		      loongarch_elf_append_rela (output_bfd, s, &outrel);
		    }

		  bfd_put_NN (output_bfd, relocation, got->contents + off);
		  local_got_offsets[r_symndx] |= 1;
		}
	    }
	  relocation = off;
	  break;

	case R_LARCH_SOP_PUSH_TLS_GOT:
	  is_ie = TRUE;
	case R_LARCH_SOP_PUSH_TLS_GD:
	  unresolved_reloc = FALSE;

	  LARCH_ASSERT (rel->r_addend == 0, bfd_reloc_notsupported,
	    "Shouldn't be with r_addend.");

	  if (resolved_to_const && is_undefweak && h->dynindx != -1)
	    {
	      /* What if undefweak? Let rtld make a decision. */
	      resolved_to_const = resolved_local = FALSE;
	      resolved_dynly = TRUE;
	    }

	  LARCH_ASSERT (!resolved_to_const, bfd_reloc_notsupported,
	    "Internal: Shouldn't be resolved to const.");

	  if (h != NULL)
	    {
	      off = h->got.offset;
	      h->got.offset |= 1;
	    }
	  else
	    {
	      off = local_got_offsets[r_symndx];
	      local_got_offsets[r_symndx] |= 1;
	    }

	  LARCH_ASSERT (off != MINUS_ONE, bfd_reloc_notsupported,
	    "Internal: TLS GOT entry doesn't represent.");

	  tls_type = _bfd_loongarch_elf_tls_type (input_bfd, h, r_symndx);

	  /* If this symbol is referenced by both GD and IE TLS, the IE
	     reference's GOT slot follows the GD reference's slots.  */
	  ie_off = 0;
	  if ((tls_type & GOT_TLS_GD) && (tls_type & GOT_TLS_IE))
	    ie_off = 2 * GOT_ENTRY_SIZE;

	  if ((off & 1) != 0)
	    off &= ~1;
	  else
	    {
	      bfd_vma tls_block_off = 0;
	      Elf_Internal_Rela outrel;

	      if (resolved_local)
		{
		  LARCH_ASSERT
		    (elf_hash_table (info)->tls_sec, bfd_reloc_notsupported,
		     "Internal: TLS sec not represent.");
		  tls_block_off = relocation
				- elf_hash_table (info)->tls_sec->vma;
		}

	      if (tls_type & GOT_TLS_GD)
		{
		  outrel.r_offset = sec_addr (got) + off;
		  outrel.r_addend = 0;
		  bfd_put_NN (output_bfd, 0, got->contents + off);
		  if (resolved_local && bfd_link_executable (info))
		    /* a. 第一个被装载模块的Module ID为1。$glibc/elf/rtld.c中
		       的dl_main有一句'main_map->l_tls_modid = 1'；
		       b. 静态程序的Module ID不重要，但为了省事仍然是1。
		       详见$glibc/csu/libc-tls.c中的init_static_tls。 */
		    bfd_put_NN (output_bfd, 1, got->contents + off);
		  else if (resolved_local/* && !bfd_link_executable (info) */)
		    {
		      outrel.r_info = ELFNN_R_INFO (0, R_LARCH_TLS_DTPMODNN);
		      loongarch_elf_append_rela
			(output_bfd, htab->elf.srelgot, &outrel);
		    }
		  else /* if (resolved_dynly) */
		    {
		      outrel.r_info =
			ELFNN_R_INFO (h->dynindx, R_LARCH_TLS_DTPMODNN);
		      loongarch_elf_append_rela
			(output_bfd, htab->elf.srelgot, &outrel);
		    }

		  outrel.r_offset += GOT_ENTRY_SIZE;
		  bfd_put_NN (output_bfd, tls_block_off,
			      got->contents + off + GOT_ENTRY_SIZE);
		  if (resolved_local)
		    /* DTPREL known */;
		  else /* if (resolved_dynly) */
		    {
		      outrel.r_info =
			ELFNN_R_INFO (h->dynindx, R_LARCH_TLS_DTPRELNN);
		      loongarch_elf_append_rela
			(output_bfd, htab->elf.srelgot, &outrel);
		    }
		}

	      if (tls_type & GOT_TLS_IE)
		{
		  outrel.r_offset = sec_addr (got) + off + ie_off;
		  bfd_put_NN (output_bfd, tls_block_off,
			      got->contents + off + ie_off);
		  if (resolved_local && bfd_link_executable (info))
		    /* TPREL known */;
		  else if (resolved_local/* && !bfd_link_executable (info) */)
		    {
		      outrel.r_info = ELFNN_R_INFO (0, R_LARCH_TLS_TPRELNN);
		      outrel.r_addend = tls_block_off;
		      loongarch_elf_append_rela
			(output_bfd, htab->elf.srelgot, &outrel);
		    }
		  else /* if (resolved_dynly) */
		    {
		      outrel.r_info =
			ELFNN_R_INFO (h->dynindx, R_LARCH_TLS_TPRELNN);
		      outrel.r_addend = 0;
		      loongarch_elf_append_rela
			(output_bfd, htab->elf.srelgot, &outrel);
		    }
		}
	    }

	  relocation = off + (is_ie ? ie_off : 0);
	  break;

	default:
	  break;
	}

      if (fatal)
	break;

      do
	{
	  /* 'unresolved_reloc' means we haven't done it yet.
	     We need help of dynamic linker to fix this memory location up. */
	  if (!unresolved_reloc)
	    break;

	  if (_bfd_elf_section_offset (output_bfd, info, input_section,
				       rel->r_offset) == MINUS_ONE)
	    /* WHY? May because it's invalid so skip checking.
	       But why dynamic reloc a invalid section? */
	    break;

	  if (input_section->output_section->flags & SEC_DEBUGGING)
	    {
	      LARCH_ASSERT  (0, bfd_reloc_dangerous,
		"Seems dynamic linker not process sections 'SEC_DEBUGGING'.");
	      break;
	    }
	  if (!is_dyn)
	    break;

	  if ((info->flags & DF_TEXTREL) == 0)
	    if (input_section->output_section->flags & SEC_READONLY)
	      info->flags |= DF_TEXTREL;
	}
      while (0);
#undef LARCH_ASSERT

      if (fatal)
	break;

      loongarch_record_one_reloc (input_bfd, input_section, r_type,
				  rel->r_offset, sym, h, rel->r_addend);

      if (r != bfd_reloc_continue)
	r = perform_relocation (rel, relocation, input_bfd, contents);

      switch (r)
	{
	case bfd_reloc_dangerous:
	case bfd_reloc_continue:
	case bfd_reloc_ok:
	  continue;

	case bfd_reloc_overflow:
	  /* Overflow value can't be filled in */
	  loongarch_dump_reloc_record (info->callbacks->info);
	  info->callbacks->reloc_overflow
	    (info, (h ? &h->root : NULL), name, howto->name,
	     rel->r_addend, input_bfd, input_section, rel->r_offset);
	  break;

	case bfd_reloc_outofrange:
	  /* Stack state incorrect */
	  loongarch_dump_reloc_record (info->callbacks->info);
	  info->callbacks->info
	    ("%X%H: Internal stack state is incorrect.\n"
	     "Want to push to full stack or pop from empty stack?\n",
	     input_bfd, input_section, rel->r_offset);
	  break;

	case bfd_reloc_notsupported:
	  info->callbacks->info
	    ("%X%H: Unknown relocation type.\n",
	     input_bfd, input_section, rel->r_offset);
	  break;

	default:
	  info->callbacks->info
	    ("%X%H: Internal: unknown error.\n",
	     input_bfd, input_section, rel->r_offset);
	  break;
	}

      fatal = TRUE;
      break;
    }

  return !fatal;
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static bfd_boolean
loongarch_elf_finish_dynamic_symbol (bfd *output_bfd,
				     struct bfd_link_info *info,
				     struct elf_link_hash_entry *h,
				     Elf_Internal_Sym *sym)
{
  struct loongarch_elf_link_hash_table *htab = loongarch_elf_hash_table (info);
  const struct elf_backend_data *bed = get_elf_backend_data (output_bfd);
  asection *plt = NULL;

  if (h->plt.offset != MINUS_ONE)
    {
      size_t i, plt_idx;
      asection *gotplt, *relplt;
      bfd_vma got_address;
      uint32_t plt_entry[PLT_ENTRY_INSNS];
      bfd_byte *loc;
      Elf_Internal_Rela rela;

      plt_idx = (h->plt.offset - PLT_HEADER_SIZE) / PLT_ENTRY_SIZE;

      /* one of '.plt' and '.iplt' represents */
      BFD_ASSERT (!!htab->elf.splt ^ !!htab->elf.iplt);

      if (htab->elf.splt)
	{
	  BFD_ASSERT ((h->type == STT_GNU_IFUNC
		       && SYMBOL_REFERENCES_LOCAL (info, h))
		      || h->dynindx != -1);

	  plt = htab->elf.splt;
	  gotplt = htab->elf.sgotplt;
	  relplt = htab->elf.srelplt;
	  got_address = sec_addr (gotplt) + GOTPLT_HEADER_SIZE
		      + plt_idx * GOT_ENTRY_SIZE;
	}
      else /* if (htab->elf.iplt) */
	{
	  BFD_ASSERT (h->type == STT_GNU_IFUNC
		      && SYMBOL_REFERENCES_LOCAL (info, h));

	  plt = htab->elf.iplt;
	  gotplt = htab->elf.igotplt;
	  relplt = htab->elf.irelplt;
	  got_address = sec_addr (gotplt)
		      + plt_idx * GOT_ENTRY_SIZE;
	}

      /* Find out where the .plt entry should go.  */
      loc = plt->contents + h->plt.offset;

      /* Fill in the PLT entry itself.  */
      loongarch_make_plt_entry
	(got_address, sec_addr (plt) + h->plt.offset, plt_entry);
      for (i = 0; i < PLT_ENTRY_INSNS; i++)
	bfd_put_32 (output_bfd, plt_entry[i], loc + 4 * i);

      /* Fill in the initial value of the .got.plt entry.  */
      loc = gotplt->contents + (got_address - sec_addr (gotplt));
      bfd_put_NN (output_bfd, sec_addr (plt), loc);

      rela.r_offset = got_address;
      if (h->type == STT_GNU_IFUNC && SYMBOL_REFERENCES_LOCAL (info, h))
	{
	  rela.r_info = ELFNN_R_INFO (0, R_LARCH_IRELATIVE);
	  rela.r_addend = h->root.u.def.value
			+ h->root.u.def.section->output_section->vma
			+ h->root.u.def.section->output_offset;
	}
      else
	{
	  /* Fill in the entry in the .rela.plt section.  */
	  rela.r_info = ELFNN_R_INFO (h->dynindx, R_LARCH_JUMP_SLOT);
	  rela.r_addend = 0;
	}

      loc = relplt->contents + plt_idx * sizeof (ElfNN_External_Rela);
      bed->s->swap_reloca_out (output_bfd, &rela, loc);

      if (!h->def_regular)
	{
	  /* Mark the symbol as undefined, rather than as defined in
	     the .plt section.  Leave the value alone.  */
	  sym->st_shndx = SHN_UNDEF;
	  /* If the symbol is weak, we do need to clear the value.
	     Otherwise, the PLT entry would provide a definition for
	     the symbol even if the symbol wasn't defined anywhere,
	     and so the symbol would never be NULL.  */
	  if (!h->ref_regular_nonweak)
	    sym->st_value = 0;
	}
    }

  if (h->got.offset != MINUS_ONE

      && /* TLS got entry have been handled in elf_relocate_section */
	 !(loongarch_elf_hash_entry (h)->tls_type & (GOT_TLS_GD | GOT_TLS_IE))

      && /* have allocated got entry but not allocated rela before */
	 !UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
    {
      asection *sgot, *srela;
      Elf_Internal_Rela rela;
      bfd_vma off = h->got.offset & ~(bfd_vma) 1;

      /* This symbol has an entry in the GOT.  Set it up.  */

      sgot = htab->elf.sgot;
      srela = htab->elf.srelgot;
      BFD_ASSERT (sgot && srela);

      rela.r_offset = sec_addr (sgot) + off;

      if (h->type == STT_GNU_IFUNC)
	{
	  if (/* 加入这个条件的原因是，对于静态链接，IRELATIVE重定位类型在
		 __libc_start_main中调用apply_irel，通过链接脚本提供的
		 __rela_iplt_start和__rela_iplt_end遍历.rela.iplt中的动态重定位
		 表项，来调用各个resolver并将返回结果写入.igot.plt中。
		 问题是照顾不到.rela.iplt之外的IRELATIVE重定位，因此我们在静态
		 连接的情况下绝对不将IRELATIVE写入.igot.plt之外。这样做在运行时
		 可能会有一些性能影响，毕竟ifunc函数都走plt，需要load两次
		 got entry。没什么好的解决方法，未来可以搞.iplt2用于延迟调用
		 resolver。 */
	      elf_hash_table (info)->dynamic_sections_created
	      
	      && SYMBOL_REFERENCES_LOCAL (info, h))
	    {
	      asection *sec = h->root.u.def.section;
	      rela.r_info = ELFNN_R_INFO (0, R_LARCH_IRELATIVE);
	      rela.r_addend = h->root.u.def.value
			    + sec->output_section->vma
			    + sec->output_offset;
	      bfd_put_NN (output_bfd, 0, sgot->contents + off);
	    }
	  else
	    {
	      BFD_ASSERT (plt);
	      rela.r_info =
		ELFNN_R_INFO
		  (0, bfd_link_pic (info) ? R_LARCH_RELATIVE : R_LARCH_NONE);
	      rela.r_addend = plt->output_section->vma
			    + plt->output_offset
			    + h->plt.offset;
	      bfd_put_NN (output_bfd, rela.r_addend, sgot->contents + off);
	    }
	}
      else if (bfd_link_pic (info) && SYMBOL_REFERENCES_LOCAL (info, h))
	{
	  BFD_ASSERT (h->got.offset & 1/* has been filled in addr */);
	  asection *sec = h->root.u.def.section;
	  rela.r_info = ELFNN_R_INFO (0, R_LARCH_RELATIVE);
	  rela.r_addend = h->root.u.def.value
			+ sec->output_section->vma
			+ sec->output_offset;
	}
      else
	{
	  BFD_ASSERT ((h->got.offset & 1) == 0);
	  BFD_ASSERT (h->dynindx != -1);
	  rela.r_info = ELFNN_R_INFO (h->dynindx, R_LARCH_NN);
	  rela.r_addend = 0;
	}

      loongarch_elf_append_rela (output_bfd, srela, &rela);
    }

  if (h->needs_copy)
    {
      Elf_Internal_Rela rela;
      asection *s;

      /* This symbols needs a copy reloc.  Set it up.  */
      BFD_ASSERT (h->dynindx != -1);

      rela.r_offset = sec_addr (h->root.u.def.section) + h->root.u.def.value;
      rela.r_info = ELFNN_R_INFO (h->dynindx, R_LARCH_COPY);
      rela.r_addend = 0;
      if (h->root.u.def.section == htab->elf.sdynrelro)
	s = htab->elf.sreldynrelro;
      else
	s = htab->elf.srelbss;
      loongarch_elf_append_rela (output_bfd, s, &rela);
    }

  /* Mark some specially defined symbols as absolute.  */
  if (h == htab->elf.hdynamic || h == htab->elf.hgot || h == htab->elf.hplt)
    sym->st_shndx = SHN_ABS;

  return TRUE;
}

/* Finish up the dynamic sections.  */

static bfd_boolean
loongarch_finish_dyn (bfd *output_bfd, struct bfd_link_info *info,
		      bfd *dynobj, asection *sdyn)
{
  struct loongarch_elf_link_hash_table *htab = loongarch_elf_hash_table (info);
  const struct elf_backend_data *bed = get_elf_backend_data (output_bfd);
  size_t dynsize = bed->s->sizeof_dyn, skipped_size = 0;
  bfd_byte *dyncon, *dynconend;

  dynconend = sdyn->contents + sdyn->size;
  for (dyncon = sdyn->contents; dyncon < dynconend; dyncon += dynsize)
    {
      Elf_Internal_Dyn dyn;
      asection *s;
      int skipped = 0;

      bed->s->swap_dyn_in (dynobj, dyncon, &dyn);

      switch (dyn.d_tag)
	{
	case DT_PLTGOT:
	  s = htab->elf.sgotplt;
	  dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
	  break;
	case DT_JMPREL:
	  s = htab->elf.srelplt;
	  dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
	  break;
	case DT_PLTRELSZ:
	  s = htab->elf.srelplt;
	  dyn.d_un.d_val = s->size;
	  break;
	case DT_TEXTREL:
	  if ((info->flags & DF_TEXTREL) == 0)
	    skipped = 1;
	  break;
	case DT_FLAGS:
	  if ((info->flags & DF_TEXTREL) == 0)
	    dyn.d_un.d_val &= ~DF_TEXTREL;
	  break;
	}
      if (skipped)
	skipped_size += dynsize;
      else
	bed->s->swap_dyn_out (output_bfd, &dyn, dyncon - skipped_size);
    }
  /* Wipe out any trailing entries if we shifted down a dynamic tag.  */
  memset (dyncon - skipped_size, 0, skipped_size);
  return TRUE;
}

/* Finish up local dynamic symbol handling.  We set the contents of
   various dynamic sections here.  */

static bfd_boolean
elfNN_loongarch_finish_local_dynamic_symbol (void **slot, void *inf)
{
  struct elf_link_hash_entry *h = (struct elf_link_hash_entry *) *slot;
  struct bfd_link_info *info = (struct bfd_link_info *) inf;

  return loongarch_elf_finish_dynamic_symbol (info->output_bfd, info, h, NULL);
}

static bfd_boolean
loongarch_elf_finish_dynamic_sections (bfd *output_bfd,
				       struct bfd_link_info *info)
{
  bfd *dynobj;
  asection *sdyn, *plt, *gotplt;
  struct loongarch_elf_link_hash_table *htab;

  htab = loongarch_elf_hash_table (info);
  BFD_ASSERT (htab);
  dynobj = htab->elf.dynobj;
  sdyn = bfd_get_linker_section (dynobj, ".dynamic");

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      BFD_ASSERT (htab->elf.splt && sdyn);

      if (!loongarch_finish_dyn (output_bfd, info, dynobj, sdyn))
	return FALSE;
    }

  if ((plt = htab->elf.splt))
    gotplt = htab->elf.sgotplt;
  else if ((plt = htab->elf.iplt))
    gotplt = htab->elf.igotplt;

  if (plt && 0 < plt->size)
    {
      size_t i;
      uint32_t plt_header[PLT_HEADER_INSNS];
      loongarch_make_plt_header (sec_addr (gotplt), sec_addr (plt), plt_header);
      for (i = 0; i < PLT_HEADER_INSNS; i++)
	bfd_put_32 (output_bfd, plt_header[i], plt->contents + 4 * i);

      elf_section_data (plt->output_section)->this_hdr.sh_entsize
	= PLT_ENTRY_SIZE;
    }

  if (htab->elf.sgotplt)
    {
      asection *output_section = htab->elf.sgotplt->output_section;

      if (bfd_is_abs_section (output_section))
	{
	  _bfd_error_handler
	    (_("discarded output section: `%pA'"), htab->elf.sgotplt);
	  return FALSE;
	}

      if (0 < htab->elf.sgotplt->size)
	{
	  /* Write the first two entries in .got.plt, needed for the dynamic
	     linker.  */
	  bfd_put_NN (output_bfd, MINUS_ONE, htab->elf.sgotplt->contents);

	  /* 第二项非0时动态连接器认为它是plt header的地址，从而影响到所有
	     R_LARCH_JUMP_SLOT。这似乎是为了prelink预留的。 */
	  bfd_put_NN (output_bfd, (bfd_vma) 0,
		      htab->elf.sgotplt->contents + GOT_ENTRY_SIZE);
	}

      elf_section_data (output_section)->this_hdr.sh_entsize = GOT_ENTRY_SIZE;
    }

  if (htab->elf.sgot)
    {
      asection *output_section = htab->elf.sgot->output_section;

      if (0 < htab->elf.sgot->size)
	{
	  /* Set the first entry in the global offset table to the address of
	     the dynamic section.  */
	  bfd_vma val = sdyn ? sec_addr (sdyn) : 0;
	  bfd_put_NN (output_bfd, val, htab->elf.sgot->contents);
	}

      elf_section_data (output_section)->this_hdr.sh_entsize = GOT_ENTRY_SIZE;
    }

  /* Fill PLT and GOT entries for local STT_GNU_IFUNC symbols.  */
  htab_traverse
    (htab->loc_hash_table, elfNN_loongarch_finish_local_dynamic_symbol, info);

  return TRUE;
}

/* Return address for Ith PLT stub in section PLT, for relocation REL
   or (bfd_vma) -1 if it should not be included.  */

static bfd_vma
loongarch_elf_plt_sym_val (bfd_vma i, const asection *plt,
		       const arelent *rel ATTRIBUTE_UNUSED)
{
  return plt->vma + PLT_HEADER_SIZE + i * PLT_ENTRY_SIZE;
}

static enum elf_reloc_type_class
loongarch_reloc_type_class (const struct bfd_link_info *info ATTRIBUTE_UNUSED,
			    const asection *rel_sec ATTRIBUTE_UNUSED,
			    const Elf_Internal_Rela *rela)
{
  struct loongarch_elf_link_hash_table *htab;
  htab = loongarch_elf_hash_table (info);

  if (htab->elf.dynsym != NULL
      && htab->elf.dynsym->contents != NULL)
    {
      /* Check relocation against STT_GNU_IFUNC symbol if there are
	 dynamic symbols.
	 一定要保证先完成非IFUNC重定位。因为如果IFUNC的resolover尚未完成
	 重定位，那么调用它返回的结果是错误的。非IFUNC重定位类型，比如R_LARCH_64
	 也可以携带IFUNC符号信息。我们在elf_machine_rela中可以察觉到一个符号是
	 IFUNC，而在动态重定位时调用resolver。但八成这个resolver也需要一个
	 R_LARCH_64重定位，可能还未完成，这时就会出问题。
	 在这里识别出来和STT_GNU_IFUNC相关的重定位，将他们往后排。 */
      bfd *abfd = info->output_bfd;
      const struct elf_backend_data *bed = get_elf_backend_data (abfd);
      unsigned long r_symndx = ELFNN_R_SYM (rela->r_info);
      if (r_symndx != STN_UNDEF)
	{
	  Elf_Internal_Sym sym;
	  if (!bed->s->swap_symbol_in (abfd,
		 htab->elf.dynsym->contents + r_symndx * bed->s->sizeof_sym,
		 0, &sym))
	    {
	      /* xgettext:c-format */
	      _bfd_error_handler (_("%pB symbol number %lu references"
				    " nonexistent SHT_SYMTAB_SHNDX section"),
				    abfd, r_symndx);
	      /* Ideally an error class should be returned here.  */
	    }
	  else if (ELF_ST_TYPE (sym.st_info) == STT_GNU_IFUNC)
	    return reloc_class_ifunc;
	}
    }

  switch (ELFNN_R_TYPE (rela->r_info))
    {
    case R_LARCH_IRELATIVE:
      return reloc_class_ifunc;
    case R_LARCH_RELATIVE:
      return reloc_class_relative;
    case R_LARCH_JUMP_SLOT:
      return reloc_class_plt;
    case R_LARCH_COPY:
      return reloc_class_copy;
    default:
      return reloc_class_normal;
    }
}


/* Copy the extra info we tack onto an elf_link_hash_entry.  */

static void
loongarch_elf_copy_indirect_symbol (struct bfd_link_info *info,
				    struct elf_link_hash_entry *dir,
				    struct elf_link_hash_entry *ind)
{
  struct loongarch_elf_link_hash_entry *edir, *eind;

  edir = (struct loongarch_elf_link_hash_entry *) dir;
  eind = (struct loongarch_elf_link_hash_entry *) ind;

  if (eind->dyn_relocs != NULL)
    {
      if (edir->dyn_relocs != NULL)
	{
	  struct elf_dyn_relocs **pp;
	  struct elf_dyn_relocs *p;

	  /* Add reloc counts against the indirect sym to the direct sym
	     list.  Merge any entries against the same section.  */
	  for (pp = &eind->dyn_relocs; (p = *pp) != NULL; )
	    {
	      struct elf_dyn_relocs *q;

	      for (q = edir->dyn_relocs; q != NULL; q = q->next)
		if (q->sec == p->sec)
		  {
		    q->pc_count += p->pc_count;
		    q->count += p->count;
		    *pp = p->next;
		    break;
		  }
	      if (q == NULL)
		pp = &p->next;
	    }
	  *pp = edir->dyn_relocs;
	}

      edir->dyn_relocs = eind->dyn_relocs;
      eind->dyn_relocs = NULL;
    }

  if (ind->root.type == bfd_link_hash_indirect
      && dir->got.refcount < 0)
    {
      edir->tls_type = eind->tls_type;
      eind->tls_type = GOT_UNKNOWN;
    }
  _bfd_elf_link_hash_copy_indirect (info, dir, ind);
}

//#if ARCH_SIZE == 32
//# define PRSTATUS_SIZE		0 /* FIXME */
//# define PRSTATUS_OFFSET_PR_CURSIG	0
//# define PRSTATUS_OFFSET_PR_PID	0
//# define PRSTATUS_OFFSET_PR_REG	0
//# define ELF_GREGSET_T_SIZE		264
//# define PRPSINFO_SIZE		0
//# define PRPSINFO_OFFSET_PR_PID	0
//# define PRPSINFO_OFFSET_PR_FNAME	0
//# define PRPSINFO_OFFSET_PR_PSARGS	0
//#else
#define PRSTATUS_SIZE			384
#define PRSTATUS_OFFSET_PR_CURSIG	12
#define PRSTATUS_OFFSET_PR_PID		32
#define PRSTATUS_OFFSET_PR_REG		112
#define ELF_GREGSET_T_SIZE		264

#define PRPSINFO_SIZE			144
#define PRPSINFO_OFFSET_PR_PID		32
#define PRPSINFO_OFFSET_PR_FNAME	48
#define PRPSINFO_OFFSET_PR_PSARGS	64
#define PRPSINFO_SIZE_PR_FNAMW		16
#define PRPSINFO_SIZE_PR_PSARGS		80
//#endif

/* Support for core dump NOTE sections.  */

static bfd_boolean
loongarch_elf_grok_prstatus (bfd *abfd, Elf_Internal_Note *note)
{
  switch (note->descsz)
    {
    default:
      return FALSE;

    case PRSTATUS_SIZE:  /* sizeof(struct elf_prstatus) on Linux/Loongarch.  */
      /* pr_cursig */
      elf_tdata (abfd)->core->signal
	= bfd_get_16 (abfd, note->descdata + PRSTATUS_OFFSET_PR_CURSIG);

      /* pr_pid */
      elf_tdata (abfd)->core->lwpid
	= bfd_get_32 (abfd, note->descdata + PRSTATUS_OFFSET_PR_PID);
      break;
    }

  /* Make a ".reg/999" section.  */
  return _bfd_elfcore_make_pseudosection (abfd, ".reg", ELF_GREGSET_T_SIZE,
					  note->descpos + PRSTATUS_OFFSET_PR_REG);
}

static bfd_boolean
loongarch_elf_grok_psinfo (bfd *abfd, Elf_Internal_Note *note)
{
  switch (note->descsz)
    {
    default:
      return FALSE;

    case PRPSINFO_SIZE: /* sizeof(struct elf_prpsinfo) on Linux/Loongarch.  */
      /* pr_pid */
      elf_tdata (abfd)->core->pid
	= bfd_get_32 (abfd, note->descdata + PRPSINFO_OFFSET_PR_PID);

      /* pr_fname */
      elf_tdata (abfd)->core->program = _bfd_elfcore_strndup
	(abfd, note->descdata + PRPSINFO_OFFSET_PR_FNAME, PRPSINFO_OFFSET_PR_FNAME);

      /* pr_psargs */
      elf_tdata (abfd)->core->command = _bfd_elfcore_strndup
	(abfd, note->descdata + PRPSINFO_OFFSET_PR_PSARGS, PRPSINFO_SIZE_PR_PSARGS);
      break;
    }

  /* Note that for some reason, a spurious space is tacked
     onto the end of the args in some (at least one anyway)
     implementations, so strip it off if it exists.  */

    {
      char *command = elf_tdata (abfd)->core->command;
      int n = strlen (command);

      if (0 < n && command[n - 1] == ' ')
	command[n - 1] = '\0';
    }

  return TRUE;
}

/* Set the right mach type.  */
static bfd_boolean
loongarch_elf_object_p (bfd *abfd)
{
  /* There are only two mach types in Loongarch currently.  */
  if (strcmp (abfd->xvec->name, "elf64-loongarch") == 0)
    bfd_default_set_arch_mach (abfd, bfd_arch_loongarch, bfd_mach_loongarch64);
  else
    bfd_default_set_arch_mach (abfd, bfd_arch_loongarch, bfd_mach_loongarch32);
  return TRUE;
}

static asection *
loongarch_elf_gc_mark_hook (asection *sec,
			    struct bfd_link_info *info,
			    Elf_Internal_Rela *rel,
			    struct elf_link_hash_entry *h,
			    Elf_Internal_Sym *sym)
{
  if (h != NULL)
    switch (ELFNN_R_TYPE (rel->r_info))
      {
      case R_LARCH_GNU_VTINHERIT:
      case R_LARCH_GNU_VTENTRY:
	return NULL;
      }

  return _bfd_elf_gc_mark_hook (sec, info, rel, h, sym);
}

static bfd_boolean
_loongarch_bfd_set_section_contents(bfd *abfd,
					sec_ptr section,
					const void *location,
					file_ptr offset,
					bfd_size_type conut)

{
	if (elf_elfheader(abfd)->e_flags ==0)
	   if(abfd->arch_info->arch == bfd_arch_loongarch)
		if (abfd->arch_info->mach ==bfd_mach_loongarch32)
			elf_elfheader(abfd)->e_flags = EF_LARCH_ABI_LP32;	
		else if (abfd->arch_info->mach ==bfd_mach_loongarch64)
		      elf_elfheader(abfd)->e_flags = EF_LARCH_ABI_LP64;	
		else 
		      return FALSE;
	return _bfd_elf_set_section_contents(abfd,section,location,offset,conut);
}



#define TARGET_LITTLE_SYM		loongarch_elfNN_vec
#define TARGET_LITTLE_NAME		"elfNN-loongarch"
#define ELF_ARCH			bfd_arch_loongarch
#define ELF_TARGET_ID			LARCH_ELF_DATA
#define ELF_MACHINE_CODE		EM_LOONGARCH
#define ELF_MAXPAGESIZE			0x4000
#define bfd_elfNN_bfd_reloc_type_lookup loongarch_reloc_type_lookup
#define bfd_elfNN_bfd_link_hash_table_create loongarch_elf_link_hash_table_create
#define bfd_elfNN_bfd_reloc_name_lookup loongarch_reloc_name_lookup
#define elf_info_to_howto_rel		NULL /* fall through to elf_info_to_howto */
#define elf_info_to_howto		loongarch_info_to_howto_rela
#define bfd_elfNN_bfd_merge_private_bfd_data \
  _bfd_loongarch_elf_merge_private_bfd_data

#define bfd_elfNN_set_section_contents       _loongarch_bfd_set_section_contents 


#define elf_backend_reloc_type_class	     loongarch_reloc_type_class
#define elf_backend_copy_indirect_symbol     loongarch_elf_copy_indirect_symbol
#define elf_backend_create_dynamic_sections  loongarch_elf_create_dynamic_sections
#define elf_backend_check_relocs	     loongarch_elf_check_relocs
#define elf_backend_adjust_dynamic_symbol    loongarch_elf_adjust_dynamic_symbol
#define elf_backend_size_dynamic_sections    loongarch_elf_size_dynamic_sections
#define elf_backend_relocate_section	     loongarch_elf_relocate_section
#define elf_backend_finish_dynamic_symbol    loongarch_elf_finish_dynamic_symbol
#define elf_backend_finish_dynamic_sections  loongarch_elf_finish_dynamic_sections
#define elf_backend_object_p		     loongarch_elf_object_p
#define elf_backend_gc_mark_hook	     loongarch_elf_gc_mark_hook
#define elf_backend_plt_sym_val		     loongarch_elf_plt_sym_val
#define elf_backend_grok_prstatus	     loongarch_elf_grok_prstatus
#define elf_backend_grok_psinfo		     loongarch_elf_grok_psinfo

#include "elfNN-target.h"
