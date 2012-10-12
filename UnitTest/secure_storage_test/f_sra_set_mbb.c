#include <embUnit/embUnit.h>

/*embunit:include=+ */
/*embunit:include=- */
#include "common_func_for_test.h"

static ssb_master_boot_block_t mbb1, *mbb2;

static void setUp(void)
{
  init_part_var(PART_MBB);

  /* initialize */
  memset(&mbb1, 0, sizeof(mbb1));

  mbb1.psize = 4;
  mbb1.mtd_part[0].ptype = PART_MBB;
  mbb1.mtd_part[0].mtd_tb_num = 1;
  mbb1.mtd_part[0].offset = MBB_OFFSET;
  mbb1.mtd_part[0].size = 0;
  mbb1.mtd_part[0].max_size = MBB_SIZE;
  mbb1.mtd_part[0].mask_flags = -1;

  mbb1.mtd_part[1].ptype = PART_SP1;
  mbb1.mtd_part[1].mtd_tb_num = 2;
  mbb1.mtd_part[1].offset = SP1_OFFSET;
  mbb1.mtd_part[1].size = 0;
  mbb1.mtd_part[1].max_size = SP1_SIZE;
  mbb1.mtd_part[1].mask_flags = -2;

  mbb1.mtd_part[2].ptype = PART_OS_IMAGE;
  mbb1.mtd_part[2].mtd_tb_num = 5;
  mbb1.mtd_part[2].offset = OSIP_OFFSET;
  mbb1.mtd_part[2].size = 0;
  mbb1.mtd_part[2].max_size = OSIP_SIZE;
  mbb1.mtd_part[2].mask_flags = -3;

  mbb1.mtd_part[3].ptype = PART_SUB_VMM_IMAGE;
  mbb1.mtd_part[3].mtd_tb_num = 2;
  mbb1.mtd_part[3].offset = VMM_OFFSET-SP1_OFFSET;
  mbb1.mtd_part[3].size = 0;
  mbb1.mtd_part[3].max_size = VMM_SIZE;
  mbb1.mtd_part[3].mask_flags = -4;
}

static void tearDown(void)
{
	/* terminate */
}

/*embunit:impl=+ */
static void sra_set_mbb_success_16(void)
{
  int rc = SUCCESS;

  if (sra_set_mbb(&mbb1) != 0) TEST_EXIT(FAIL);
  mbb2 = sra_get_mbb();
  if (mbb2 == NULL) TEST_EXIT(FAIL);
  TEST_ASSERT(test_equal_mbb(&mbb1, mbb2));

 out:
  TEST_ASSERT(rc);
}

static void sra_set_mbb_fail_17(void)
{
  TEST_ASSERT(sra_set_mbb(NULL) == -EINVAL);
}

/*embunit:impl=- */
TestRef f_sra_set_mbb_tests(void)
{
	EMB_UNIT_TESTFIXTURES(fixtures) {
	/*embunit:fixtures=+ */
		new_TestFixture("sra_set_mbb_success_16",sra_set_mbb_success_16),
		new_TestFixture("sra_set_mbb_fail_17",sra_set_mbb_fail_17),
	/*embunit:fixtures=- */
	};
	EMB_UNIT_TESTCALLER(f_sra_set_mbb,"f_sra_set_mbb",setUp,tearDown,fixtures);
	return (TestRef)&f_sra_set_mbb;
};
