include $(BASEDIR)/Rules.mk

CFLAGS += -I$(BASEDIR)/UnitTest

obj-y += AssertImpl.o
obj-y += RepeatedTest.o
obj-y += stdImpl.o
obj-y += TestCaller.o
obj-y += TestCase.o
obj-y += TestResult.o
obj-y += TestRunner.o
obj-y += TestSuite.o
obj-y += TextUIRunner.o
obj-y += TextOutputter.o
obj-y += XMLOutputter.o

include $(BASEDIR)/Post.mk

# Object file contains changeset and compiler information.
#kernel.o: $(BASEDIR)/include/xen/compile.h
