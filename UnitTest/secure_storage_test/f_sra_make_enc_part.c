#include <embUnit/embUnit.h>

/*embunit:include=+ */
#include "xen/sra_func.h"
/*embunit:include=- */

#include "common_func_for_test.h"

static ssb_master_boot_block_t mbb1;
static ssb_image_container_t sp11;
static ssb_image_container_t osip1;
static default_struct_t vmm1;

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
  osip1.image[0].type = SECURE_DOM_KEY;
  osip1.image[0].u.ptr = "Secure domain key";
  osip1.image[0].size = strlen(osip1.image[0].u.ptr) + 1;
  osip1.image[1].type = SECURE_DOM_SIGNED_HASH;
  osip1.image[1].u.ptr = "Secure domain signed hash";
  osip1.image[1].size = strlen(osip1.image[1].u.ptr) + 1;
  if (sra_set_sp(&osip1, PART_OS_IMAGE) != 0) {
    printf("[%s]: sra_set_sp(PART_OS_IMAGE) error\n", __FUNCTION__);
    return;
  }

  /* VMM test */
  vmm1.type = XEN_ARM_IMG;
  vmm1.u.ptr = "(void*)0xc0008000";
  vmm1.size = strlen(vmm1.u.ptr);
}

static void tearDown(void)
{
	/* terminate */
}

/*embunit:impl=+ */
static void sra_make_enc_part_success_1(void)
{
  int rc = SUCCESS;
  transfer_struct_t ts;
  int enc_size = 0;
  char *to_mem = NULL, *src = NULL;
  ssb_master_boot_block_t *pmbb = NULL;

  ts = sra_get_bin(PART_MBB);
  to_mem = _page_alloc(NULL, ts.size+sizeof(ssb_master_boot_block_header_t));

  /* from input data */
  enc_size = sra_make_enc_part(to_mem, ts.size+sizeof(ssb_master_boot_block_header_t), ts.ptr, ts.size, PART_MBB);
  if (enc_size< 0) {
    TEST_EXIT(FAIL);
  }

  src = to_mem;
  to_mem = _page_alloc(NULL, ts.size + sizeof(ssb_master_boot_block_t));
  if (test_dec_part(to_mem, src, enc_size, PART_MBB) < 0) {
    TEST_EXIT(FAIL);
  }

  pmbb = (ssb_master_boot_block_t *)to_mem;
  if (test_equal_mbb(pmbb, &mbb1) == FAIL) {
    TEST_EXIT(FAIL);
  }


  /* from global data */
  memcpy(&enc_size, src-sizeof(u_int32_t), sizeof(u_int32_t));
  memset(src-sizeof(u_int32_t), 0, enc_size);
  memcpy(&enc_size, to_mem-sizeof(u_int32_t), sizeof(u_int32_t));
  memset(to_mem-sizeof(u_int32_t), 0, enc_size);

  enc_size = sra_make_enc_part(src, ts.size+sizeof(ssb_master_boot_block_header_t), NULL, 0, PART_MBB);
  if (enc_size < 0) {
    TEST_EXIT(FAIL);
  }

  if (test_dec_part(to_mem, src, enc_size, PART_MBB) < 0) {
    TEST_EXIT(FAIL);
  }

  pmbb = (ssb_master_boot_block_t *)to_mem;
  if (test_equal_mbb(pmbb, &mbb1) == FAIL) {
    TEST_EXIT(FAIL);
  }

 out:
  _page_alloc(src, 0);
  _page_alloc(to_mem, 0);
  TEST_ASSERT(rc);
}

static void sra_make_enc_part_success_2(void)
{
  int rc = SUCCESS;
  int enc_size = 0;
  transfer_struct_t ts;
  char *to_mem = NULL, *src = NULL;
  ssb_image_container_t *pic = NULL;

  ts = sra_get_bin(PART_SP1);
  to_mem = _page_alloc(NULL, ts.size);

  /* from input data */
  enc_size = sra_make_enc_part(to_mem, ts.size, ts.ptr, ts.size, PART_SP1);
  if (enc_size < 0) {
    TEST_EXIT(FAIL);
  }

  src = to_mem;
  to_mem = _page_alloc(NULL, ts.size + sizeof(ssb_image_container_t));
  if (test_dec_part(to_mem, src, enc_size, PART_SP1) < 0) {
    TEST_EXIT(FAIL);
  }

  pic = (ssb_image_container_t *)to_mem;
  if (test_equal_sp(0, pic, &sp11) == FAIL) {
    TEST_EXIT(FAIL);
  }

  /* from global data */
  memcpy(&enc_size, src-sizeof(u_int32_t), sizeof(u_int32_t));
  memset(src-sizeof(u_int32_t), 0, enc_size);
  memcpy(&enc_size, to_mem-sizeof(u_int32_t), sizeof(u_int32_t));
  memset(to_mem-sizeof(u_int32_t), 0, enc_size);

  enc_size = sra_make_enc_part(to_mem, ts.size, NULL, 0, PART_SP1);
  if (enc_size < 0) {
    TEST_EXIT(FAIL);
  }

  src = to_mem;
  to_mem = _page_alloc(NULL, ts.size + sizeof(ssb_image_container_t));
  if (test_dec_part(to_mem, src, enc_size, PART_SP1) < 0) {
    TEST_EXIT(FAIL);
  }

  pic = (ssb_image_container_t *)to_mem;
  if (test_equal_sp(0, pic, &sp11) == FAIL) {
    TEST_EXIT(FAIL);
  }

 out:
  _page_alloc(src, 0);
  _page_alloc(to_mem, 0);
  TEST_ASSERT(rc);
}

static void sra_make_enc_part_success_3(void)
{
  int rc = SUCCESS;
  int enc_size = 0;
  transfer_struct_t ts;
  char *to_mem = NULL, *src = NULL;
  ssb_image_container_t *pic = NULL;

  ts = sra_get_bin(PART_OS_IMAGE);
  to_mem = _page_alloc(NULL, ts.size);

  /* from input data */
  enc_size = sra_make_enc_part(to_mem, ts.size, ts.ptr, ts.size, PART_OS_IMAGE);
  if (enc_size < 0) {
    TEST_EXIT(FAIL);
  }

  src = to_mem;
  to_mem = _page_alloc(NULL, ts.size + sizeof(ssb_image_container_t));
  if (test_dec_part(to_mem, src, enc_size, PART_OS_IMAGE) < 0) {
    TEST_EXIT(FAIL);
  }

  pic = (ssb_image_container_t *)to_mem;
  if (pic->images_size != osip1.images_size) TEST_EXIT(FAIL);
  for (enc_size=0; enc_size<pic->images_size; enc_size++){
    if (pic->image[enc_size].type != osip1.image[enc_size].type) TEST_EXIT(FAIL);
    if (pic->image[enc_size].size != osip1.image[enc_size].size) TEST_EXIT(FAIL);
    if (pic->image[enc_size].u.pos != osip1.image[enc_size].u.pos) TEST_EXIT(FAIL);
  }

  /* from global data */
  memcpy(&enc_size, src-sizeof(u_int32_t), sizeof(u_int32_t));
  memset(src-sizeof(u_int32_t), 0, enc_size);
  memcpy(&enc_size, to_mem-sizeof(u_int32_t), sizeof(u_int32_t));
  memset(to_mem-sizeof(u_int32_t), 0, enc_size);

  enc_size = sra_make_enc_part(to_mem, ts.size, NULL, 0, PART_OS_IMAGE);
  if (enc_size < 0) {
    TEST_EXIT(FAIL);
  }

  src = to_mem;
  to_mem = _page_alloc(NULL, ts.size + sizeof(ssb_image_container_t));
  if (test_dec_part(to_mem, src, enc_size, PART_OS_IMAGE) < 0) {
    TEST_EXIT(FAIL);
  }

  pic = (ssb_image_container_t *)to_mem;
  if (pic->images_size != osip1.images_size) TEST_EXIT(FAIL);
  for (enc_size=0; enc_size<pic->images_size; enc_size++){
    if (pic->image[enc_size].type != osip1.image[enc_size].type) TEST_EXIT(FAIL);
    if (pic->image[enc_size].size != osip1.image[enc_size].size) TEST_EXIT(FAIL);
    if (pic->image[enc_size].u.pos != osip1.image[enc_size].u.pos) TEST_EXIT(FAIL);
  }

 out:
  _page_alloc(src, 0);
  _page_alloc(to_mem, 0);
  TEST_ASSERT(rc);
}

static void sra_make_enc_part_success_4(void)
{
  int rc = SUCCESS;
  int enc_size = 0;
  char *to_mem = NULL, *src = NULL;

  to_mem = _page_alloc(NULL, vmm1.size);

  /* from input data */
  enc_size = sra_make_enc_part(to_mem, vmm1.size, vmm1.u.ptr, vmm1.size, PART_SUB_VMM_IMAGE);
  if (enc_size < 0) {
    TEST_EXIT(FAIL);
  }

  src = to_mem;
  to_mem = _page_alloc(NULL, vmm1.size + sizeof(default_struct_t));
  if (test_dec_part(to_mem, src, enc_size, PART_SUB_VMM_IMAGE) < 0) {
    TEST_EXIT(FAIL);
  }

  if(memcmp(to_mem, vmm1.u.ptr, vmm1.size) != 0) TEST_EXIT(FAIL);
  
 out:
  _page_alloc(src, 0);
  _page_alloc(to_mem, 0);
  TEST_ASSERT(rc);
}

static void sra_make_enc_part_fail_5(void)
{
  int rc = SUCCESS;
  char *to_mem = NULL;

  to_mem = _page_alloc(NULL, vmm1.size);

  /* from global data */
  rc = sra_make_enc_part(to_mem, vmm1.size, NULL, 0, PART_SUB_VMM_IMAGE);

  _page_alloc(to_mem, 0);
  TEST_ASSERT(rc == -EINVAL);
}

static void sra_make_enc_part_fail_6(void)
{
  TEST_ASSERT(sra_make_enc_part(NULL, 0, vmm1.u.ptr, vmm1.size, PART_SUB_VMM_IMAGE) == -EINVAL);
}

static void sra_make_enc_part_fail_7(void)
{
  int rc = SUCCESS;
  char *to_mem = NULL;

  to_mem = _page_alloc(NULL, 10);
  rc = sra_make_enc_part(to_mem, 10, vmm1.u.ptr, vmm1.size, PART_SUB_VMM_IMAGE);
  _page_alloc(to_mem, 0);
  TEST_ASSERT(rc == -EMSGSIZE);
}

static void sra_make_enc_part_fail_8(void)
{
  int rc = SUCCESS;
  char *to_mem = NULL;

  to_mem = _page_alloc(NULL, vmm1.size);
  rc = sra_make_enc_part(to_mem, vmm1.size, vmm1.u.ptr, vmm1.size, 0xff0f9e8f);
  _page_alloc(to_mem, 0);
  TEST_ASSERT(rc == -EINVAL);
}

/*embunit:impl=- */
TestRef f_sra_make_enc_part_tests(void)
{
	EMB_UNIT_TESTFIXTURES(fixtures) {
	/*embunit:fixtures=+ */
		new_TestFixture("sra_make_enc_part_success_1",sra_make_enc_part_success_1),
		new_TestFixture("sra_make_enc_part_success_2",sra_make_enc_part_success_2),
		new_TestFixture("sra_make_enc_part_success_3",sra_make_enc_part_success_3),
		new_TestFixture("sra_make_enc_part_success_4",sra_make_enc_part_success_4),
		new_TestFixture("sra_make_enc_part_fail_5",sra_make_enc_part_fail_5),
		new_TestFixture("sra_make_enc_part_fail_6",sra_make_enc_part_fail_6),
		new_TestFixture("sra_make_enc_part_fail_7",sra_make_enc_part_fail_7),
		new_TestFixture("sra_make_enc_part_fail_8",sra_make_enc_part_fail_8),
	/*embunit:fixtures=- */
	};
	EMB_UNIT_TESTCALLER(f_sra_make_enc_part,"f_sra_make_enc_part",setUp,tearDown,fixtures);
	return (TestRef)&f_sra_make_enc_part;
};
