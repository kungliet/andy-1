#include <embUnit/embUnit.h>

static void setUp(void)
{
}

static void tearDown(void)
{
}

static void assert_equal_string_runTest(void)
{
	TEST_ASSERT_EQUAL_STRING("123","123");
}

static void assert_equal_int_runTest(void)
{
	TEST_ASSERT_EQUAL_INT(123,123)
}

static void assert_null_runTest(void)
{
	char *p=NULL;
	TEST_ASSERT_NULL(p);
}

static void assert_not_null_runTest(void)
{
	char *p=NULL;
	TEST_ASSERT_NOT_NULL(p);
}

static void assert_message_runTest(void)
{
	TEST_ASSERT_MESSAGE(0,"0");
}

static void assert_runTest(void)
{
	TEST_ASSERT(1);
}

static void verify(TestCaseRef test)
{
	TestResult result = new_TestResult(NULL);

	test->isa->run(test,&result);

	if (result.failureCount == 0) {
		TEST_FAIL("fail");
	}
}

static void testASSERT_EQUAL_STRING(void)
{
	TestCase tcase = new_TestCase("assert_equal_string",setUp,tearDown,
		assert_equal_string_runTest);
	verify(&tcase);
}

TestRef assertTest_tests(void)
{
	EMB_UNIT_TESTFIXTURES(fixtures) {
		new_TestFixture("testASSERT_EQUAL_STRING",assert_equal_string_runTest),
		new_TestFixture("testASSERT_EQUAL_STRING2",testASSERT_EQUAL_STRING),
		new_TestFixture("testASSERT_EQUAL_INT",assert_equal_string_runTest),
		new_TestFixture("testASSERT_NULL",assert_null_runTest),
		new_TestFixture("testASSERT_NOT_NULL",assert_not_null_runTest),
		new_TestFixture("testASSERT_MESSAGE",assert_message_runTest),
		new_TestFixture("testASSERT",assert_runTest),
	};
	EMB_UNIT_TESTCALLER(AssertTest,"AssertTest",setUp,tearDown,fixtures);

	return (TestRef)&AssertTest;
}
