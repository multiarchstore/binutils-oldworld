## Process this file with automake to generate Makefile.in
#
#   Copyright (C) 2012-2018 Free Software Foundation, Inc.
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING3.  If not see
# <http://www.gnu.org/licenses/>.
#

AUTOMAKE_OPTIONS = dejagnu foreign no-dist subdir-objects
ACLOCAL_AMFLAGS = -I .. -I ../config -I ../bfd

SUBDIRS = doc po

tooldir = $(exec_prefix)/$(target_alias)

# This is where we get zlib from.  zlibdir is -L../zlib and zlibinc is
# -I../zlib, unless we were configured with --with-system-zlib, in which
# case both are empty.
ZLIBINC = @zlibinc@

YACC = `if [ -f ../bison/bison ] ; then echo ../bison/bison -y -L../bison/bison ; else echo @YACC@ ; fi`
LEX = `if [ -f ../flex/flex ] ; then echo ../flex/flex ; else echo @LEX@ ; fi`

# Automake 1.10+ disables lex and yacc output file regeneration if
# maintainer mode is disabled.  Avoid this.
am__skiplex =
am__skipyacc =

WARN_CFLAGS = @WARN_CFLAGS@ @WARN_WRITE_STRINGS@
NO_WERROR = @NO_WERROR@
AM_CFLAGS = $(WARN_CFLAGS) $(ZLIBINC)

TARG_CPU = @target_cpu_type@
TARG_CPU_C = $(srcdir)/config/tc-@target_cpu_type@.c
TARG_CPU_O = config/tc-@target_cpu_type@.@OBJEXT@
TARG_CPU_H = $(srcdir)/config/tc-@target_cpu_type@.h
OBJ_FORMAT_C = $(srcdir)/config/obj-@obj_format@.c
OBJ_FORMAT_O = config/obj-@obj_format@.@OBJEXT@
OBJ_FORMAT_H = $(srcdir)/config/obj-@obj_format@.h
TARG_ENV_H = $(srcdir)/config/te-@te_file@.h
ATOF_TARG_C = $(srcdir)/config/atof-@atof@.c
ATOF_TARG_O = config/atof-@atof@.@OBJEXT@

# use @target_cpu_type@ for refering to configured target name
IT_HDRS=itbl-parse.h $(srcdir)/itbl-ops.h
IT_SRCS=itbl-parse.c itbl-lex-wrapper.c $(srcdir)/itbl-ops.c
IT_DEPS=$(srcdir)/itbl-parse.y $(srcdir)/itbl-lex.l $(srcdir)/config/itbl-@target_cpu_type@.h
IT_OBJS=itbl-parse.@OBJEXT@ itbl-lex.@OBJEXT@ itbl-ops.@OBJEXT@


# Regular source files.

GAS_CFILES = \
	app.c \
	as.c \
	atof-generic.c \
	compress-debug.c \
	cond.c \
	depend.c \
	dwarf2dbg.c \
	dw2gencfi.c \
	ecoff.c \
	ehopt.c \
	expr.c \
	flonum-copy.c \
	flonum-konst.c \
	flonum-mult.c \
	frags.c \
	hash.c \
	input-file.c \
	input-scrub.c \
	listing.c \
	literal.c \
	macro.c \
	messages.c \
	output-file.c \
	read.c \
	remap.c \
	sb.c \
	stabs.c \
	subsegs.c \
	symbols.c \
	write.c

CFILES = $(GAS_CFILES) itbl-ops.c cgen.c

HFILES = \
	as.h \
	asintl.h \
	bignum.h \
	bit_fix.h \
	cgen.h \
	compress-debug.h \
	dwarf2dbg.h \
	dw2gencfi.h \
	ecoff.h \
	emul-target.h \
	emul.h \
	expr.h \
	flonum.h \
	frags.h \
	hash.h \
	input-file.h \
	itbl-lex.h \
	itbl-ops.h \
	listing.h \
	macro.h \
	obj.h \
	output-file.h \
	read.h \
	sb.h \
	struc-symbol.h \
	subsegs.h \
	symbols.h \
	tc.h \
	write.h

# CPU files in config.

TARGET_CPU_CFILES = \
	config/tc-aarch64.c \
	config/tc-alpha.c \
	config/tc-arc.c \
	config/tc-arm.c \
	config/tc-avr.c \
	config/tc-bfin.c \
	config/tc-cr16.c \
	config/tc-cris.c \
	config/tc-crx.c \
	config/tc-d10v.c \
	config/tc-d30v.c \
	config/tc-dlx.c \
	config/tc-epiphany.c \
	config/tc-fr30.c \
	config/tc-frv.c \
	config/tc-ft32.c \
	config/tc-h8300.c \
	config/tc-hppa.c \
	config/tc-ia64.c \
	config/tc-i386.c \
	config/tc-ip2k.c \
	config/tc-iq2000.c \
	config/tc-lm32.c \
	config/tc-loongarch.c \
	config/tc-m32c.c \
	config/tc-m32r.c \
	config/tc-m68hc11.c \
	config/tc-m68k.c \
	config/tc-s12z.c \
	config/tc-mcore.c \
	config/tc-mep.c \
	config/tc-metag.c \
	config/tc-microblaze.c \
	config/tc-mips.c \
	config/tc-mmix.c \
	config/tc-mn10200.c \
	config/tc-mn10300.c \
	config/tc-moxie.c \
	config/tc-msp430.c \
	config/tc-mt.c \
	config/tc-nds32.c \
	config/tc-nios2.c \
	config/tc-ns32k.c \
	config/tc-or1k.c \
	config/tc-pdp11.c \
	config/tc-pj.c \
	config/tc-ppc.c \
	config/tc-pru.c \
	config/tc-riscv.c \
	config/tc-rl78.c \
	config/tc-rx.c \
	config/tc-s390.c \
	config/tc-score.c \
	config/tc-sh.c \
	config/tc-sparc.c \
	config/tc-spu.c \
	config/tc-tic30.c \
	config/tc-tic4x.c \
	config/tc-tic54x.c \
	config/tc-tic6x.c \
	config/tc-tilegx.c \
	config/tc-tilepro.c \
	config/tc-v850.c \
	config/tc-vax.c \
	config/tc-visium.c \
	config/tc-wasm32.c \
	config/tc-xstormy16.c \
	config/tc-xc16x.c \
	config/tc-xgate.c \
	config/tc-xtensa.c \
	config/tc-z80.c \
	config/tc-z8k.c \
	config/xtensa-relax.c

TARGET_CPU_HFILES = \
	config/tc-aarch64.h \
	config/tc-alpha.h \
	config/tc-arc.h \
	config/tc-arm.h \
	config/tc-avr.h \
	config/tc-bfin.h \
	config/tc-cr16.h \
	config/tc-cris.h \
	config/tc-crx.h \
	config/tc-d10v.h \
	config/tc-d30v.h \
	config/tc-dlx.h \
	config/tc-epiphany.h \
	config/tc-fr30.h \
	config/tc-frv.h \
	config/tc-ft32.h \
	config/tc-h8300.h \
	config/tc-hppa.h \
	config/tc-ia64.h \
	config/tc-i386.h \
	config/tc-ip2k.h \
	config/tc-iq2000.h \
	config/tc-lm32.h \
	config/tc-m32c.h \
	config/tc-m32r.h \
	config/tc-m68hc11.h \
	config/tc-m68k.h \
	config/tc-s12z.h \
	config/tc-mcore.h \
	config/tc-mep.h \
	config/tc-metag.h \
	config/tc-microblaze.h \
	config/tc-mips.h \
	config/tc-mmix.h \
	config/tc-mn10200.h \
	config/tc-mn10300.h \
	config/tc-msp430.h \
	config/tc-mt.h \
	config/tc-nds32.h \
	config/tc-nios2.h \
	config/tc-ns32k.h \
	config/tc-or1k.h \
	config/tc-pdp11.h \
	config/tc-pj.h \
	config/tc-ppc.h \
	config/tc-pru.h \
	config/tc-riscv.h \
	config/tc-rl78.h \
	config/tc-rx.h \
	config/tc-s390.h \
	config/tc-score.h \
	config/tc-sh.h \
	config/tc-sparc.h \
	config/tc-spu.h \
	config/tc-tic30.h \
	config/tc-tic4x.h \
	config/tc-tic54x.h \
	config/tc-tic6x.h \
	config/tc-tilegx.h \
	config/tc-tilepro.h \
	config/tc-v850.h \
	config/tc-vax.h \
	config/tc-visium.h \
	config/tc-wasm32.h \
	config/tc-xstormy16.h \
	config/tc-xc16x.h \
	config/tc-xgate.h \
	config/tc-xtensa.h \
	config/tc-z80.h \
	config/tc-z8k.h \
	config/xtensa-relax.h

# OBJ files in config

OBJ_FORMAT_CFILES = \
	config/obj-aout.c \
	config/obj-coff.c \
	config/obj-ecoff.c \
	config/obj-elf.c \
	config/obj-evax.c \
	config/obj-fdpicelf.c \
	config/obj-macho.c \
	config/obj-multi.c \
	config/obj-som.c

OBJ_FORMAT_HFILES = \
	config/obj-aout.h \
	config/obj-coff.h \
	config/obj-ecoff.h \
	config/obj-elf.h \
	config/obj-evax.h \
	config/obj-fdpicelf.h \
	config/obj-macho.h \
	config/obj-multi.h \
	config/obj-som.h

# Emulation header files in config

TARG_ENV_HFILES = \
	config/te-386bsd.h \
	config/te-aix5.h \
	config/te-armeabi.h \
	config/te-armfbsdeabi.h \
	config/te-armfbsdvfp.h \
	config/te-armlinuxeabi.h \
	config/te-freebsd.h \
	config/te-generic.h \
	config/te-gnu.h \
	config/te-go32.h \
	config/te-hppa.h \
	config/te-hppa64.h \
	config/te-hppalinux64.h \
	config/te-ia64aix.h \
	config/te-interix.h \
	config/te-lynx.h \
	config/te-macos.h \
	config/te-nbsd.h \
	config/te-nbsd532.h \
	config/te-pc532mach.h \
	config/te-pe.h \
	config/te-solaris.h \
	config/te-svr4.h \
	config/te-symbian.h \
	config/te-tmips.h \
	config/te-vxworks.h \
	config/te-wince-pe.h

TARG_ENV_CFILES = \
	config/te-vms.c

# Multi files in config

MULTI_CFILES = \
	config/e-crisaout.c \
	config/e-criself.c \
	config/e-i386aout.c \
	config/e-i386coff.c \
	config/e-i386elf.c \
	config/e-mipself.c

CONFIG_ATOF_CFILES = \
	config/atof-ieee.c \
	config/atof-vax.c

POTFILES = $(MULTI_CFILES) $(CONFIG_ATOF_CFILES) \
	$(TARG_ENV_HFILES) $(TARG_ENV_CFILES) $(OBJ_FORMAT_HFILES) \
	$(OBJ_FORMAT_CFILES) $(TARGET_CPU_HFILES) $(TARGET_CPU_CFILES) \
	$(HFILES) $(CFILES)
po/POTFILES.in: @MAINT@ Makefile
	for f in $(POTFILES); do echo $$f; done | LC_ALL=C sort > tmp \
	  && mv tmp $(srcdir)/po/POTFILES.in

# Note: GASP is now deprecated and has been removed.  It is still
# available in the CVS archive or older binutils releases if it is needed.
noinst_PROGRAMS = as-new
noinst_SCRIPTS = $(GDBINIT)
EXTRA_SCRIPTS = .gdbinit

EXTRA_DIST = m68k-parse.c itbl-parse.c itbl-parse.h itbl-lex.c \
	bfin-parse.c bfin-parse.h bfin-lex.c \
	rl78-parse.c rl78-parse.h \
	rx-parse.c rx-parse.h \
	loongarch-parse.c loongarch-parse.h loongarch-lex.c

diststuff: $(EXTRA_DIST) info

DISTCLEANFILES = targ-cpu.h obj-format.h targ-env.h itbl-cpu.h cgen-desc.h

# Now figure out from those variables how to compile and link.

BASEDIR = $(srcdir)/..
BFDDIR = $(BASEDIR)/bfd
INCDIR = $(BASEDIR)/include

# This is the variable actually used when we compile.
# Specify the directories to be searched for header files.
# Both . and srcdir are used, in that order,
# so that tm.h and config.h will be found in the compilation
# subdirectory rather than in the source directory.
AM_CPPFLAGS = -I. -I$(srcdir) -I../bfd -I$(srcdir)/config \
	-I$(INCDIR) -I$(srcdir)/.. -I$(BFDDIR) @INCINTL@ \
	-DLOCALEDIR="\"$(datadir)/locale\""

# How to link with both our special library facilities
# and the system's installed libraries.

GASLIBS = @OPCODES_LIB@ ../bfd/libbfd.la ../libiberty/libiberty.a

# Files to be copied away after each stage in building.
STAGESTUFF = *.@OBJEXT@ $(noinst_PROGRAMS)

as_new_SOURCES = $(GAS_CFILES)
as_new_LDADD = $(TARG_CPU_O) $(OBJ_FORMAT_O) $(ATOF_TARG_O) \
	$(extra_objects) $(GASLIBS) $(LIBINTL) $(LIBM)
as_new_DEPENDENCIES = $(TARG_CPU_O) $(OBJ_FORMAT_O) $(ATOF_TARG_O) \
	$(extra_objects) $(GASLIBS) $(LIBINTL_DEP)
EXTRA_as_new_SOURCES = $(CFILES) $(HFILES) $(TARGET_CPU_CFILES) \
	$(TARGET_CPU_HFILES) $(OBJ_FORMAT_CFILES) $(OBJ_FORMAT_HFILES) \
	$(TARG_ENV_CFILES) $(CONFIG_ATOF_CFILES) $(MULTI_CFILES)

EXPECT = expect
RUNTEST = runtest
RUNTESTFLAGS=

check-DEJAGNU: site.exp
	if [ -d testsuite ]; then \
	  true; \
	else \
	  mkdir testsuite; \
	fi
	rm -f testsuite/site.exp
	cp site.exp testsuite/site.exp
	rootme=`pwd`; export rootme; \
	srcdir=`cd ${srcdir}; pwd` ; export srcdir ; \
	LC_ALL=C; export LC_ALL; \
	EXPECT=${EXPECT} ; export EXPECT ; \
	runtest=$(RUNTEST); \
	cd testsuite; \
	if $(SHELL) -c "$$runtest --version" > /dev/null 2>&1; then \
	  $$runtest --tool $(DEJATOOL) --srcdir $${srcdir}/testsuite \
		$(RUNTESTFLAGS); \
	else echo "WARNING: could not find \`runtest'" 1>&2; :;\
	fi

# The m68k operand parser.

EXTRA_as_new_SOURCES += config/m68k-parse.y

# If m68k-parse.y is in a different directory, then ylwrap will use an
# absolute path when it invokes yacc, which will cause yacc to put the
# absolute path into the generated file.  That's a pain when it comes
# to generating snapshots, because it introduces spurious diffs.
# Since when we make the snapshots $(srcdir) = ".", we check for that
# case and handle it differently.  This means that anybody who
# configures with $(srcdir) = "." will have to set their path in the
# debugger if they want to debug m68k-parse.y.  This is bad, but on
# the other hand it's good that people who use the prebuilt
# m68k-parse.c don't get a spurious absolute path.
m68k-parse.c: $(srcdir)/config/m68k-parse.y
	f=$(srcdir)/config/m68k-parse.y; \
	if [ $$f = "./config/m68k-parse.y" ]; then \
	  ln -s config/m68k-parse.y . > /dev/null 2>/dev/null || \
	   ln config/m68k-parse.y . > /dev/null 2>/dev/null || \
	   cp config/m68k-parse.y . >/dev/null 2>/dev/null; \
	  f=m68k-parse.y; \
	else true; fi; \
	$(SHELL) $(YLWRAP) $$f y.tab.c m68k-parse.c -- $(YACCCOMPILE); \
	if [ $$f = "m68k-parse.y" ]; then \
	  rm -f m68k-parse.y; \
	else true; fi
# Disable -Werror, if it has been enabled, since old versions of bison/
# yacc will produce working code which contain compile time warnings.
m68k-parse.@OBJEXT@: m68k-parse.c
if am__fastdepCC
	$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ `test -f m68k-parse.c || echo $(srcdir)/`m68k-parse.c $(NO_WERROR)
	mv -f $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
else
if AMDEP
	source='m68k-parse.c' object='$@' libtool=no @AMDEPBACKSLASH@
	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
endif
	$(COMPILE) -c `test -f m68k-parse.c || echo $(srcdir)/`m68k-parse.c $(NO_WERROR)
endif

# Don't let the .y.h rule clobber m68k-parse.h.
m68k-parse.h: ; @true
$(srcdir)/config/m68k-parse.h: ; @true

EXTRA_as_new_SOURCES += config/bfin-parse.y
bfin-parse.c: $(srcdir)/config/bfin-parse.y
	$(SHELL) $(YLWRAP) $(srcdir)/config/bfin-parse.y y.tab.c bfin-parse.c y.tab.h bfin-parse.h -- $(YACCCOMPILE) -d ;
bfin-parse.h: bfin-parse.c
bfin-parse.h: ; @true
$(srcdir)/config/bfin-parse.h: ; @true

bfin-lex.c: $(srcdir)/config/bfin-lex.l
	$(SHELL) $(YLWRAP) $(srcdir)/config/bfin-lex.l lex.yy.c bfin-lex.c -- $(LEXCOMPILE)
bfin-lex-wrapper.@OBJEXT@: $(srcdir)/config/bfin-lex-wrapper.c bfin-lex.c bfin-parse.h $(srcdir)/config/bfin-defs.h
if am__fastdepCC
	$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $(srcdir)/config/bfin-lex-wrapper.c $(NO_WERROR)
	mv -f $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
else
if AMDEP
	source='bfin-lex-wrapper.c' object='$@' libtool=no @AMDEPBACKSLASH@
	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
endif
	$(COMPILE) -c $(srcdir)/config/bfin-lex-wrapper.c $(NO_WERROR)
endif

EXTRA_as_new_SOURCES += config/rl78-parse.y
rl78-parse.c: $(srcdir)/config/rl78-parse.y
	$(SHELL) $(YLWRAP) $(srcdir)/config/rl78-parse.y y.tab.c rl78-parse.c y.tab.h rl78-parse.h -- $(YACCCOMPILE) -d ;
rl78-parse.h: rl78-parse.c
rl78-defs.h: ; @true
$(srcdir)/config/rl78-defs.h: ; @true

EXTRA_as_new_SOURCES += config/rx-parse.y
rx-parse.c: $(srcdir)/config/rx-parse.y
	$(SHELL) $(YLWRAP) $(srcdir)/config/rx-parse.y y.tab.c rx-parse.c y.tab.h rx-parse.h -- $(YACCCOMPILE) -d ;
rx-parse.h: rx-parse.c
rx-defs.h: ; @true
$(srcdir)/config/rx-defs.h: ; @true

EXTRA_as_new_SOURCES += config/loongarch-parse.y
loongarch-parse.c: $(srcdir)/config/loongarch-parse.y
	$(SHELL) $(YLWRAP) $(srcdir)/config/loongarch-parse.y y.tab.c loongarch-parse.c y.tab.h loongarch-parse.h -- $(YACCCOMPILE) -d ;
loongarch-parse.h: loongarch-parse.c
loongarch-parse.h: ; @true
$(srcdir)/config/loongarch-parse.h: ; @true

loongarch-lex.c: $(srcdir)/config/loongarch-lex.l
	$(SHELL) $(YLWRAP) $(srcdir)/config/loongarch-lex.l lex.yy.c loongarch-lex.c -- $(LEXCOMPILE)
loongarch-lex-wrapper.@OBJEXT@: $(srcdir)/config/loongarch-lex-wrapper.c loongarch-lex.c loongarch-parse.h
if am__fastdepCC
	$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $(srcdir)/config/loongarch-lex-wrapper.c $(NO_WERROR)
	mv -f $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
else
if AMDEP
	source='loongarch-lex-wrapper.c' object='$@' libtool=no @AMDEPBACKSLASH@
	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
endif
	$(COMPILE) -c $(srcdir)/config/loongarch-lex-wrapper.c $(NO_WERROR)
endif

# The instruction table specification lexical analyzer and parser.

# Disable -Werror, if it has been enabled, since old versions of bison/
# yacc will produce working code which contain compile time warnings.
itbl-lex-wrapper.@OBJEXT@: itbl-lex-wrapper.c itbl-lex.c itbl-parse.h
if am__fastdepCC
	$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $(srcdir)/itbl-lex-wrapper.c $(NO_WERROR)
	mv -f $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
else
if AMDEP
	source='itbl-lex-wrapper.c' object='$@' libtool=no @AMDEPBACKSLASH@
	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
endif
	$(COMPILE) -c $(srcdir)/itbl-lex-wrapper.c $(NO_WERROR)
endif

# Disable -Werror, if it has been enabled, since old versions of bison/
# yacc will produce working code which contain compile time warnings.
itbl-parse.@OBJEXT@: itbl-parse.c
if am__fastdepCC
	$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ `test -f itbl-parse.c || echo $(srcdir)/`itbl-parse.c $(NO_WERROR)
	mv -f $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
else
if AMDEP
	source='itbl-parse.c' object='$@' libtool=no @AMDEPBACKSLASH@
	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
endif
	$(COMPILE) -c `test -f itbl-parse.c || echo $(srcdir)/`itbl-parse.c $(NO_WERROR)
endif

itbl-parse.c: $(srcdir)/itbl-parse.y
	$(SHELL) $(YLWRAP) $(srcdir)/itbl-parse.y y.tab.c itbl-parse.c y.tab.h itbl-parse.h -- $(YACCCOMPILE) -d

itbl-parse.h: itbl-parse.c ; @true

itbl-ops.@OBJEXT@: itbl-parse.h

# stand-alone itbl assembler & disassembler

EXTRA_PROGRAMS = itbl-test
itbl_test_SOURCES = itbl-parse.y itbl-lex.l
itbl_test_LDADD = itbl-tops.@OBJEXT@ itbl-test.@OBJEXT@ $(GASLIBS) @LEXLIB@

itbl-tops.@OBJEXT@: itbl-ops.c itbl-parse.h
if am__fastdepCC
	$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -o $@ -c -DSTAND_ALONE $(srcdir)/itbl-ops.c
	mv -f $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
else
if AMDEP
	source='itbl-ops.c' object='$@' libtool=no @AMDEPBACKSLASH@
	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
endif
	$(COMPILE) -o $@ -DSTAND_ALONE -c $(srcdir)/itbl-ops.c
endif

itbl-test.@OBJEXT@: $(srcdir)/testsuite/gas/all/itbl-test.c
if am__fastdepCC
	$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ -DSTAND_ALONE $(srcdir)/testsuite/gas/all/itbl-test.c
	mv -f $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
else
if AMDEP
	source='itbl-test.c' object='$@' libtool=no @AMDEPBACKSLASH@
	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
endif
	$(COMPILE) -c -DSTAND_ALONE $(srcdir)/testsuite/gas/all/itbl-test.c
endif

# CGEN interface.

CGEN_CPU_PREFIX = @cgen_cpu_prefix@

cgen.@OBJEXT@: cgen.c cgen.h cgen-desc.h subsegs.h \
	$(INCDIR)/obstack.h $(INCDIR)/opcode/cgen.h \
	$(srcdir)/../opcodes/$(CGEN_CPU_PREFIX)-desc.h \
	$(srcdir)/../opcodes/$(CGEN_CPU_PREFIX)-opc.h

# Remake the info files.

MOSTLYCLEANFILES = $(STAGESTUFF) core \
	testsuite/*.@OBJEXT@ testsuite/*.out testsuite/gas.log testsuite/gas.sum \
	testsuite/site.exp site.bak site.exp stage stage1 stage2

.PHONY: install-exec-local install-data-local
.PHONY: install-exec-bindir install-exec-tooldir

install-exec-local: install-exec-bindir @install_tooldir@

install-exec-bindir: $(noinst_PROGRAMS)
	$(mkinstalldirs) $(DESTDIR)$(bindir)
	@list='$(noinst_PROGRAMS)'; for p in $$list; do \
	  if test -f $$p; then \
	    echo " $(INSTALL_PROGRAM_ENV) $(LIBTOOL)  --mode=install $(INSTALL_PROGRAM) $$p $(bindir)/`echo $$p|sed -e 's/$(EXEEXT)$$//' -e 's/-new//'|sed '$(transform)'|sed 's/$$/$(EXEEXT)/'`"; \
	    $(INSTALL_PROGRAM_ENV) $(LIBTOOL)  --mode=install $(INSTALL_PROGRAM) $$p $(DESTDIR)$(bindir)/`echo $$p|sed -e 's/$(EXEEXT)$$//' -e 's/-new//'|sed '$(transform)'|sed 's/$$/$(EXEEXT)/'`; \
	  else :; fi; \
	done

install-exec-tooldir: install-exec-bindir $(noinst_PROGRAMS)
	$(mkinstalldirs) $(DESTDIR)$(tooldir)/bin
	n=`echo as | sed '$(transform)'`; \
	if [ "$(bindir)/$$n$(EXEEXT)" != "$(tooldir)/bin/as$(EXEEXT)" ]; then \
	  rm -f $(DESTDIR)$(tooldir)/bin/as$(EXEEXT); \
	  ln $(DESTDIR)$(bindir)/$$n$(EXEEXT) $(DESTDIR)$(tooldir)/bin/as$(EXEEXT) >/dev/null 2>/dev/null \
	    || $(INSTALL_PROGRAM_ENV) $(LIBTOOL) --mode=install $(INSTALL_PROGRAM) as-new$(EXEEXT) $(DESTDIR)$(tooldir)/bin/as$(EXEEXT); \
	else \
	  true ; \
	fi

# These exist for maintenance purposes.

.PHONY: bootstrap bootstrap2 bootstrap3 stage1 stage2 stage3 comparison

bootstrap: as-new$(EXEEXT)
	$(MAKE) stage1
	rm -f stage && ln -s stage1 stage
	$(MAKE) CC="$(CC)" CFLAGS="-O -Bstage/ $(CFLAGS)" libdir=$(libdir) ALLOCA= $(noinst_PROGRAMS)
	$(MAKE) stage2
	rm -f stage && ln -s stage2 stage
	$(MAKE) CC="$(CC)" CFLAGS="-O -Bstage/ $(CFLAGS)" libdir=$(libdir) ALLOCA= $(noinst_PROGRAMS)
	$(MAKE) comparison against=stage2

bootstrap2:
	rm -f stage && ln -s stage1 stage
	$(MAKE) CC="$(CC)" CFLAGS="-O -Bstage/ $(CFLAGS)" libdir=$(libdir) ALLOCA= $(noinst_PROGRAMS)
	$(MAKE) stage2
	rm -f stage && ln -s stage2 stage
	$(MAKE) CC="$(CC)" CFLAGS="-O -Bstage/ $(CFLAGS)" libdir=$(libdir) ALLOCA= $(noinst_PROGRAMS)
	$(MAKE) comparison against=stage2

bootstrap3:
	rm -f stage && ln -s stage2 stage
	$(MAKE) CC="$(CC)" CFLAGS="-O -Bstage/ $(CFLAGS)" libdir=$(libdir) ALLOCA= $(noinst_PROGRAMS)
	$(MAKE) comparison against=stage2

# Copy the object files from a particular stage into a subdirectory.
stage1:
	-mkdir stage1
	-mv $(STAGESTUFF) stage1
	if [ -f stage1/as-new$(EXEEXT) -a ! -f stage1/as$(EXEEXT) ] ; then (cd stage1 ; ln -s as-new$(EXEEXT) as$(EXEEXT)) ; fi

stage2:
	-mkdir stage2
	-mv $(STAGESTUFF) stage2
	if [ -f stage2/as-new$(EXEEXT) -a ! -f stage2/as$(EXEEXT) ] ; then (cd stage2 ; ln -s as-new$(EXEEXT) as$(EXEEXT)) ; fi

stage3:
	-mkdir stage3
	-mv $(STAGESTUFF) stage3
	if [ -f stage3/as-new$(EXEEXT) -a ! -f stage3/as$(EXEEXT) ] ; then (cd stage3 ; ln -s as-new as$(EXEEXT)) ; fi

against=stage2

comparison:
	x=0 ; \
	for file in *.@OBJEXT@ ; do \
	  f1=./$$file; f2=${against}/$$file; \
	  $(do_compare) > /dev/null 2>&1; \
	  if test $$? -ne 0; then \
	    echo $$file differs ; \
	    x=1 ; \
	  fi ; \
	done ; \
	exit $$x
	-rm -f tmp-foo*

.PHONY: de-stage1 de-stage2 de-stage3

de-stage1:
	- (cd stage1 ; rm -f as$(EXEEXT) ; mv -f * ..)
	- rmdir stage1

de-stage2:
	- (cd stage2 ; rm -f as$(EXEEXT) ; mv -f * ..)
	- rmdir stage2

de-stage3:
	- (cd stage3 ; rm -f as$(EXEEXT) ; mv -f * ..)
	- rmdir stage3

# Reconfigure if configure.tgt changes.
# development.sh is used to determine -Werror default.
CONFIG_STATUS_DEPENDENCIES = $(srcdir)/configure.tgt $(BFDDIR)/development.sh
