include $(BASEDIR)/Rules.mk

CFLAGS += -I$(BASEDIR)/UnitTest

obj-y += AllTests.o
obj-y += common_func_for_test.o
obj-y += f_sra_make_enc_part.o
obj-y += f_sra_set_image.o
obj-y += f_sra_get_image.o
obj-y += f_sra_set_mbb.o
obj-y += f_sra_get_sp.o
obj-y += f_sra_set_sp.o

include $(BASEDIR)/Post.mk

# Object file contains changeset and compiler information.
#kernel.o: $(BASEDIR)/include/xen/compile.h
