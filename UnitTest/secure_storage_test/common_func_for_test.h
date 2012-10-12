#include <xen/string.h>
#include <xen/errno.h>
#include <xen/lib.h>
#include <public/secure_storage_struct.h>
#include <xen/sra_func.h>
#include <security/crypto/TlsCrApiRoot.h>
#include <security/crypto/crypto.h>

#define SUCCESS 1
#define FAIL 0

int test_equal_mbb(ssb_master_boot_block_t *mbb1, ssb_master_boot_block_t *mbb2);
int test_equal_sp(unsigned long mbb_sp_base, ssb_image_container_t *sp1, ssb_image_container_t *sp2);
int test_equal_image(default_struct_t *ds1, default_struct_t *ds2);
int test_dec_part(void *to_ptr, void *from_ptr, u_int32_t from_size, partition_type_t ptype);


#define UBOOT_OFFSET 0x0
#define MBB_OFFSET 0x100000
#define SP1_OFFSET 0x140000
#define VMM_OFFSET 0x180000
#define SP2_OFFSET 0x240000
#define SP3_OFFSET 0x2C0000
#define OSIP_OFFSET 0x300000
#define DRV_RFS_OFFSET 0x1000000
#define DOM0_RFS_OFFSET 0x0
#define DOM1_RFS_OFFSET 0x0

#define UBOOT_SIZE MBB_OFFSET
#define MBB_SIZE SP1_OFFSET-MBB_OFFSET
#define SP1_SIZE SP2_OFFSET-SP1_OFFSET
#define VMM_SIZE SP2_OFFSET-VMM_OFFSET
#define SP2_SIZE SP3_OFFSET-SP2_OFFSET
#define SP3_SIZE OSIP_OFFSET-SP3_OFFSET
#define OSIP_SIZE DRV_RFS_OFFSET-OSIP_OFFSET
#define DRV_RFS_SIZE 0x1000000
#define DOM0_RFS_SIZE 0x2000000
#define DOM1_RFS_SIZE 0x2000000

#define MBB_SP_BASE (0xc2800000) /* NOR flash memory address */

#define SUCCESS 1
#define FAIL 0
#define TEST_EXIT(_errno)                                                       \
  do {                                                                          \
    if ((_errno) == 0) {                                                        \
      printk("Failure in %s: error %d, line %d\n",	                \
	     __func__, (_errno), __LINE__);         \
    }                                                                           \
    rc = (_errno);						                \
    goto out;								        \
  } while ( 0 )

