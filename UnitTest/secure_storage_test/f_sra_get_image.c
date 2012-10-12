#include <embUnit/embUnit.h>

/*embunit:include=+ */
/*embunit:include=- */

#include "common_func_for_test.h"

static ssb_master_boot_block_t mbb1;
static ssb_image_container_t sp11;
static ssb_image_container_t osip1;

static void setUp(void)
{
  init_part_var(PART_MBB);
  init_part_var(PART_SP1);
  init_part_var(PART_OS_IMAGE);

  /* initialize */
  memset(&mbb1, 0, sizeof(mbb1));
  memset(&sp11, 0, sizeof(sp11));

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

  if (sra_set_mbb(&mbb1) < 0) {
    printf("[%s]: sra_set_mbb() ERROR !!\n", __FUNCTION__);
    return;
  }

  /* SPx test */
  sp11.images_size = 2;
  sp11.image[0].type = CERTM_IMG;
  sp11.image[0].u.ptr = "CERTM image";
  sp11.image[0].size = strlen(sp11.image[0].u.ptr) + 1;
  sp11.image[1].type = XEN_ARM_SIGNED_HASH;
  sp11.image[1].u.ptr = "xen-arm signed hash value";
  sp11.image[1].size = strlen(sp11.image[1].u.ptr) + 1;

  if (sra_set_sp(&sp11, PART_SP1) != 0) {
    printf("[%s]: sra_set_sp(PART_SP1) error\n", __FUNCTION__);
    return;
  }

  /* osip test */
  osip1.images_size = 2;
  osip1.image[0].type = SECURE_DOM_IMG;
  osip1.image[0].u.ptr = "Secure domain key";
  osip1.image[0].size = strlen(osip1.image[0].u.ptr) + 1;
  osip1.image[1].type = NORMAL_DOM1_IMG;
  osip1.image[1].u.ptr = "Secure domain signed hash";
  osip1.image[1].size = strlen(osip1.image[1].u.ptr) + 1;
  if (sra_set_sp(&osip1, PART_OS_IMAGE) != 0) {
    printf("[%s]: sra_set_sp(PART_OS_IMAGE) error\n", __FUNCTION__);
    return;
  }
}

static void tearDown(void)
{
	/* terminate */
}

/*embunit:impl=+ */
static void sra_get_image_success_13(void)
{
  int rc = SUCCESS;

  default_struct_t *pds = NULL;
  
  pds = sra_get_image(PART_SP1, XEN_ARM_SIGNED_HASH);
  if (pds == NULL) TEST_EXIT(FAIL);
  if (pds->type != sp11.image[1].type) TEST_EXIT(FAIL);
  if (pds->size != sp11.image[1].size) TEST_EXIT(FAIL);
  if (memcmp(pds->u.ptr, sp11.image[1].u.ptr, pds->size) != 0) TEST_EXIT(FAIL);

  pds = sra_get_image(PART_END, SECURE_DOM_IMG);
  if (pds == NULL) TEST_EXIT(FAIL);
  if (pds->type != osip1.image[0].type) TEST_EXIT(FAIL);
  if (pds->size != osip1.image[0].size) TEST_EXIT(FAIL);
  if (memcmp(pds->u.ptr, osip1.image[0].u.ptr, pds->size) != 0) TEST_EXIT(FAIL);

 out:
  TEST_ASSERT(rc);
}

static void sra_get_image_fail_14(void)
{
  TEST_ASSERT(sra_get_image(0x2354245, XEN_ARM_IMG) == NULL);
}

static void sra_get_image_fail_15(void)
{
  TEST_ASSERT(sra_get_image(PART_SP1, SECURE_DOM_KEY) == NULL);
}

/*embunit:impl=- */
TestRef f_sra_get_image_tests(void)
{
	EMB_UNIT_TESTFIXTURES(fixtures) {
	/*embunit:fixtures=+ */
		new_TestFixture("sra_get_image_success_13",sra_get_image_success_13),
		new_TestFixture("sra_get_image_fail_14",sra_get_image_fail_14),
		new_TestFixture("sra_get_image_fail_15",sra_get_image_fail_15),
	/*embunit:fixtures=- */
	};
	EMB_UNIT_TESTCALLER(f_sra_get_image,"f_sra_get_image",setUp,tearDown,fixtures);
	return (TestRef)&f_sra_get_image;
};
