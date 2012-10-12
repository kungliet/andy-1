include $(BASEDIR)/Rules.mk

CFLAGS += -I$(BASEDIR)/UnitTest

obj-y += AllTests.o
obj-y += assertTest.o

include $(BASEDIR)/Post.mk

# Object file contains changeset and compiler information.
#kernel.o: $(BASEDIR)/include/xen/compile.h
