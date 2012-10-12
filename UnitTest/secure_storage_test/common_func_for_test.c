#include "common_func_for_test.h"

int test_equal_mbb(ssb_master_boot_block_t *mbb1, ssb_master_boot_block_t *mbb2)
{
  int i;

  if (mbb1->psize != mbb2->psize) return FAIL;
  for (i=0; i<mbb1->psize; i++) {
    if (mbb1->mtd_part[i].ptype != mbb2->mtd_part[i].ptype) return FAIL;
    if (mbb1->mtd_part[i].offset != mbb2->mtd_part[i].offset) return FAIL;
    if (mbb1->mtd_part[i].mtd_tb_num != mbb2->mtd_part[i].mtd_tb_num) return FAIL;
    if (mbb1->mtd_part[i].max_size != mbb2->mtd_part[i].max_size) return FAIL;
    if (mbb1->mtd_part[i].mask_flags != mbb2->mtd_part[i].mask_flags) return FAIL;
  }
  return SUCCESS;
}

int test_equal_sp(unsigned long mbb_sp_base, ssb_image_container_t *sp1, ssb_image_container_t *sp2)
{
  int i;

  if (sp1->images_size != sp2->images_size) return FAIL;
  for (i=0; i<sp1->images_size; i++) {
    if (sp1->image[i].type != sp2->image[i].type) return FAIL;
    if (sp1->image[i].size != sp2->image[i].size) return FAIL;
    if (sp1->image[i].u.ptr < (char*)0xc0000000) {
      if (memcmp(sp1->image[i].u.ptr + mbb_sp_base, 
		 sp2->image[i].u.ptr + mbb_sp_base,
		 sp1->image[i].size) != 0) return FAIL;
    } else {
      if (memcmp(sp1->image[i].u.ptr, sp2->image[i].u.ptr,
		 sp1->image[i].size) != 0) return FAIL;
    }
  }
  return SUCCESS;
}

int test_equal_image(default_struct_t *ds1, default_struct_t *ds2)
{
  if (ds1->type != ds2->type) return FAIL;
  if (ds1->size != ds2->size) return FAIL;
  if (memcmp(ds1->u.ptr, ds2->u.ptr, ds1->size)) return FAIL;

  return SUCCESS;
}

int test_dec_part(void *to_ptr, void *from_ptr, u_int32_t from_size, partition_type_t ptype)
{
  int ivar32;

  CrUINT8 *lbuf_ptr=NULL;
  u_int32_t max_buf_size, to_size;
  ssb_image_container_t *pic=NULL;
  ssb_master_boot_block_t *pmbb=NULL;
  ssb_master_boot_block_header_t mbbh;

  if (to_ptr == NULL || from_ptr == NULL) return -EINVAL;

  if (ptype == PART_MBB) {
    memcpy(&mbbh, from_ptr, sizeof(mbbh));
    if (mbbh.magic != MAGIC_MBB) return -EINVAL;
    pmbb = to_ptr;
    lbuf_ptr = to_ptr + sizeof(ssb_master_boot_block_t);
    from_size = mbbh.size;
    from_ptr += sizeof(mbbh);
    to_size = max_buf_size = from_size + sizeof(ssb_master_boot_block_t);

  } else if (ptype == PART_SP1 || ptype == PART_SP2 || ptype == PART_SP3 ||
	     ptype == PART_OS_IMAGE) {
    pic = to_ptr;
    lbuf_ptr = to_ptr + sizeof(ssb_image_container_t);
    to_size = max_buf_size = from_size + sizeof(ssb_image_container_t);

  } else if (ptype == PART_SUB_VMM_IMAGE) {
    lbuf_ptr = to_ptr;
    to_size = max_buf_size = from_size;

  } else {
    return -EINVAL;
  }

  /* decrypt encrypted data */

  ivar32 = crypto_decrypt_data(from_ptr, from_size, &lbuf_ptr, &max_buf_size);
  if (ivar32 < 0) {
    printk("** dec_part: ptype(%d) decryption error\n", ptype);
    return -ENOEXEC;
  }

  /* Master Boot Block, SP1, SP2, SP3 unserialization */
  if (ptype != PART_SUB_VMM_IMAGE)
    if (_sra_unserialize(to_ptr, to_size, lbuf_ptr, max_buf_size, ptype, NOCOPY) < 0) {
      printk("** MBB, SP1, SP2, SP3 unserialize error: !\n");
      return -ENOEXEC;
    }

  return 0;
}
