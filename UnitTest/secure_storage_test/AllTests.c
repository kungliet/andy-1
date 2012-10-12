#include <embUnit/embUnit.h>

/*embunit:extern=+ */
extern TestRef f_sra_make_enc_part_tests(void);
extern TestRef f_sra_set_image_tests(void);
extern TestRef f_sra_get_image_tests(void);
extern TestRef f_sra_set_mbb_tests(void);
extern TestRef f_sra_get_sp_tests(void);
extern TestRef f_sra_set_sp_tests(void);
/*embunit:extern=- */

int xen_sra_func_test(void)
{
	TestRunner_start();
	/*embunit:run=+ */
		TestRunner_runTest(f_sra_make_enc_part_tests());
		TestRunner_runTest(f_sra_set_image_tests());
		TestRunner_runTest(f_sra_get_image_tests());
		TestRunner_runTest(f_sra_set_mbb_tests());
		TestRunner_runTest(f_sra_get_sp_tests());
		TestRunner_runTest(f_sra_set_sp_tests());
	/*embunit:run=- */
	TestRunner_end();
	return 0;
}
