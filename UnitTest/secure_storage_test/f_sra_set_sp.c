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

  /* osip test */
  osip1.images_size = 2;
  osip1.image[0].type = SECURE_DOM_KEY;
  osip1.image[0].u.ptr = "Secure domain key";
  osip1.image[0].size = strlen(osip1.image[0].u.ptr) + 1;
  osip1.image[1].type = SECURE_DOM_SIGNED_HASH;
  osip1.image[1].u.ptr = "Secure domain signed hash";
  osip1.image[1].size = strlen(osip1.image[1].u.ptr) + 1;
}

static void tearDown(void)
{
	/* terminate */
}

/*embunit:impl=+ */
static void sra_set_sp_success_20(void)
{
  int rc = SUCCESS;
  int i;
  ssb_image_container_t *pic=NULL;

  if (sra_set_sp(&sp11, PART_SP1) != 0) TEST_EXIT(FAIL);
  pic = sra_get_sp(PART_SP1);
  if (pic == NULL) TEST_EXIT(FAIL);
  if (!test_equal_sp(0, pic, &sp11)) TEST_EXIT(FAIL);

  if (sra_set_sp(&osip1, PART_OS_IMAGE) != 0) TEST_EXIT(FAIL);
  pic = sra_get_sp(PART_OS_IMAGE);
  if (pic == NULL) TEST_EXIT(FAIL);
  if (pic->images_size != osip1.images_size) TEST_EXIT(FAIL);
  for (i=0; i<pic->images_size; i++){
    if (pic->image[i].type != osip1.image[i].type) TEST_EXIT(FAIL);
    if (pic->image[i].size != osip1.image[i].size) TEST_EXIT(FAIL);
    if (pic->image[i].u.pos != osip1.image[i].u.pos) TEST_EXIT(FAIL);
  }

 out:
  TEST_ASSERT(rc);
}

static void sra_set_sp_fail_21(void)
{
  TEST_ASSERT(sra_set_sp(&sp11, 0x234f32) == -EINVAL);
}

static void sra_set_sp_fail_22(void)
{
  TEST_ASSERT(sra_set_sp(NULL, PART_SP2) == -EINVAL);
}

/*embunit:impl=- */
TestRef f_sra_set_sp_tests(void)
{
	EMB_UNIT_TESTFIXTURES(fixtures) {
	/*embunit:fixtures=+ */
		new_TestFixture("sra_set_sp_success_20",sra_set_sp_success_20),
		new_TestFixture("sra_set_sp_fail_21",sra_set_sp_fail_21),
		new_TestFixture("sra_set_sp_fail_22",sra_set_sp_fail_22),
	/*embunit:fixtures=- */
	};
	EMB_UNIT_TESTCALLER(f_sra_set_sp,"f_sra_set_sp",setUp,tearDown,fixtures);
	return (TestRef)&f_sra_set_sp;
};
