#include <embUnit/embUnit.h>
#include <embUnit/XMLOutputter.h>

extern TestRef assertTest_tests(void);

int embunit_test_example(void)
{
	TextUIRunner_setOutputter(XMLOutputter_outputter());
	XMLOutputter_setFileName("XenassertTest");

	TextUIRunner_start();
		TextUIRunner_runTest(assertTest_tests());
	TextUIRunner_end();
	return 0;
}
