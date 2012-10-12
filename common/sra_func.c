/*
 * (C) Copyright 2007
 * Samsung Software Labs., sd.mo@samsung.com
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

/*
 * secure storage - related information support
 */

#include <xen/lib.h>
#include <xen/mm.h>
#include <asm/mm.h>
#include <xen/console.h>
#include <asm/memmap.h>
#include <asm/page.h>
#include <public/version.h>
#include <xen/sra_func.h>
#include <security/crypto/TlsCrApiRoot.h>
#include <security/crypto/crypto.h>

#ifdef CONFIG_VMM_SECURITY
static sym_key_t *gpSym=NULL;
static ssb_master_boot_block_t *gpMbb=NULL;
static ssb_image_container_t *gpSp1=NULL;
static ssb_image_container_t *gpSp2=NULL;
static ssb_image_container_t *gpSp3=NULL;
static ssb_image_container_t *gpOsip = NULL;
#endif

extern unsigned long sra_info_ptr;
int xen_sra_func_test(void);

void init_part_var(partition_type_t ptype)
{
#ifdef CONFIG_VMM_SECURITY
  switch(ptype) {
  case PART_MBB:
    _page_alloc(gpMbb, 0);
    gpMbb = NULL;
    break;

  case PART_SP1:
    _page_alloc(gpSp1, 0);
    gpSp1 = NULL;
    break;

  case PART_SP2:
    _page_alloc(gpSp2, 0);
    gpSp2 = NULL;
    break;

  case PART_SP3:
    _page_alloc(gpSp3, 0);
    gpSp3 = NULL;
    break;

  case PART_OS_IMAGE:
    _page_alloc(gpOsip, 0);
    gpOsip = NULL;
    break;

  case PART_SUB_VMM_IMAGE:
    printk("there is no VMM data inside Xen-on-Arm\n");
    break;

  default:
    return;
  }
#endif
}

int sra_init(void)
{
  int rc = 0;
#ifdef CONFIG_VMM_SECURITY
  int i;
  ssb_transfer_container_t *ssb_tc = (ssb_transfer_container_t *)sra_info_ptr;

  /* symmetric key initialization */
  if (_init_master_key(ssb_tc) != 0) {
    printk( "** sra_init error: no symmetric key\n");
    ERROR_EXIT(-1);
  }

  /* Master Boot Block & Secure Partition loading */
  if (_load_part(ssb_tc, PART_MBB) < 0) {
    printk( "** sra_init error: MBB loading error !\n");
    ERROR_EXIT(-2);
  }

  if (_load_part(ssb_tc, PART_SP1) < 0) {
    printk( "** sra_init error: Secure Partition #1 loading error !\n");
    ERROR_EXIT(-3);
  }

  if (_load_part(ssb_tc, PART_SP2) < 0) {
    printk( "** sra_init error: Secure Partition #2 loading error !\n");
    ERROR_EXIT(-4);
  }

  if (_load_part(ssb_tc, PART_SP3) < 0) {
    printk( "** sra_init error: Secure Partition #3 loading error !\n");
  }

  if (_load_part(ssb_tc, PART_OS_IMAGE) < 0) {
    printk( "** sra_init error: Kernel informations in OS image partition !\n");
  }

  if (crypto_init() < 0) {
    printk( "** sra_init error: cryptographic library initialization error !\n");
  }
  

#ifdef UNIT_TEST
  /* Unit Test codes */
  if (ssb_tc->image[MAX_IMAGE_STRUCT_SIZE-1].type == PART_END) {
    if (strcmp(ssb_tc->image[MAX_IMAGE_STRUCT_SIZE-1].ptr, "UnitTest") == 0) {
      printk("****************************************************\n");
      printk("** Starting Unit Tests on Secure Storage function **\n");
      printk("****************************************************\n");
      xen_sra_func_test();
      printk("****************************************************\n");
      printk("*** Ended Unit Tests on Secure Storage function ****\n");
      printk("****************************************************\n");
      ERROR_EXIT(-EPERM);
    }
  }
#endif

  /* clear u-boot memory range */
  for (i=0; i<ssb_tc->images_size; i++)
    memset(ssb_tc->image[i].ptr, 0, ssb_tc->image[i].size);
  
 out:
#endif
  return rc;
}


/* master key initialization */
int _init_master_key(ssb_transfer_container_t *tc)
{
  int rc = 0;
#ifdef CONFIG_VMM_SECURITY
  sym_key_t *psk;
  u_int32_t size = 0;
  char *dest;
  transfer_struct_t *ts = _find_transfer_image(tc, TRANSFER_MASTER_KEY);

  if (ts == NULL) {
    printf("init_master_key: no symmetric key\n");
    ERROR_EXIT(-ENODATA);
  }

  psk = (sym_key_t *)(ts->ptr);

  /* symmetric key initialization */
  size += sizeof(crypto_kind_of_t);
  size += sizeof(TLSBulkCipherEnum);
  size += sizeof(CrUINT16);
  size += sizeof(CrUINT16);
  size += psk->key_size;
  size += psk->init_vec_size;

  dest = _page_alloc(NULL, size);
  if (dest == NULL) ERROR_EXIT(-ENOMEM);

  gpSym = (sym_key_t *)dest;

  gpSym->type.kind_of = psk->type.kind_of;
  gpSym->type.u.sym = psk->type.u.sym;
  gpSym->key_size = psk->key_size;

  gpSym->key = (dest + sizeof(sym_key_t));
  memcpy(gpSym->key, psk->key, gpSym->key_size);
  gpSym->init_vec_size = psk->init_vec_size;
  gpSym->init_vec = (gpSym->key + gpSym->key_size);
  memcpy(gpSym->init_vec, psk->init_vec, gpSym->init_vec_size);

 out:
#endif
  return rc;
}

/* memory allocation per page */
void *_page_alloc(void *ptr, u_int32_t bytes)
{
#ifdef CONFIG_VMM_SECURITY
  u_int32_t org_size=0;
  u_int32_t use_size = 0;
  u_int32_t order = 0;

  if (ptr != NULL) {
    memcpy(&org_size, (ptr - sizeof(u_int32_t)), sizeof(u_int32_t));
    use_size = org_size - sizeof(u_int32_t);
  }

  if (bytes == 0) {
    if (org_size != 0)
      free_xenheap_pages((ptr-sizeof(u_int32_t)),
			 get_order_from_bytes(org_size));
    return NULL;
      
  }

  if (use_size >= bytes) {
    return ptr;

  }

  if (ptr != NULL)
    free_xenheap_pages((ptr-sizeof(u_int32_t)),
		       get_order_from_bytes(org_size));
  order = get_order_from_bytes(bytes+sizeof(u_int32_t));
  ptr = alloc_xenheap_pages(order);
  if (ptr == NULL) return NULL;

  org_size = (1 << (order + PAGE_SHIFT));
  memcpy(ptr, &org_size, sizeof(u_int32_t));

  return (ptr + sizeof(u_int32_t));
#else
  return NULL;
#endif
}

/* load MBB, SP, or OS Image partition : input parition type*/
int _load_part(ssb_transfer_container_t *tc, partition_type_t ptype)
{
  int rc = 0;
#ifdef CONFIG_VMM_SECURITY
  void *dest=NULL;
  u_int32_t dest_size;
  transfer_struct_t *ts = _find_transfer_image(tc, ptype);

  if (ts == NULL) return -ENODATA;

  switch(ptype) {
  case PART_MBB:
    dest_size = sizeof(ssb_master_boot_block_t) + ts->size;
    break;

  case PART_SP1:
  case PART_SP2:
  case PART_SP3:
  case PART_OS_IMAGE:
    dest_size = sizeof(ssb_image_container_t) + ts->size;
    break;

  default:
    printk( "load_part: unknown partition type: %d\n", ptype);
    ERROR_EXIT(-EINVAL);
  }

  /* Master Boot Block, SP1, SP2, SP3 unserialization */

  dest = _page_alloc(NULL, dest_size);
  if (dest == NULL) ERROR_EXIT(-ENOMEM);
  if (_sra_unserialize(dest, dest_size, ts->ptr, ts->size, ptype, COPY) != 0) {
    printk( "load_part: MBB, SP1, SP3, SP3 unserialize error: !\n");
    ERROR_EXIT(-EFAULT);
  }

  switch(ptype) {
  case PART_MBB:
    gpMbb = (ssb_master_boot_block_t *)dest;
    break;

  case PART_SP1:
    gpSp1 = (ssb_image_container_t *)dest;
    break;

  case PART_SP2:
    gpSp2 = (ssb_image_container_t *)dest;
    break;

  case PART_SP3:
    gpSp3 = (ssb_image_container_t *)dest;
    break;

  case PART_OS_IMAGE:
    gpOsip = (ssb_image_container_t *)dest;
    break;

  default:
    printk( "load_part: unknown partition type: %d\n", ptype);
    ERROR_EXIT(-EINVAL);
  }

 out:
  if (dest != NULL && rc != 0)
    _page_alloc(dest, 0);
#endif
  return rc;
}

/* make encrypted MBB, SP, or OS Image partition for flashing to flash memory */
int sra_make_enc_part(void *to_mem, u_int32_t to_size, void *from_bin, u_int32_t bin_size, partition_type_t ptype)
{
  int rc = 0;
#ifdef CONFIG_VMM_SECURITY
  int ivar32, out_len;
  void *lbuf_ptr = NULL;
  ssb_master_boot_block_header_t ssb_mbbh;
  ssb_mtd_partition_t lssb_mp;

  if (to_mem == NULL || 
      (ptype != PART_MBB && ptype != PART_SP1 && ptype != PART_SUB_VMM_IMAGE &&
       ptype != PART_SP2 && ptype != PART_SP3 && ptype != PART_OS_IMAGE))
    return -EINVAL;
  if (to_size < bin_size) return -EMSGSIZE;

  if (from_bin == NULL) {
    bin_size = sizeof(u_int32_t) + sizeof(unsigned long);

    switch (ptype) {
    case PART_MBB:
      from_bin = (void*)gpMbb + sizeof(ssb_master_boot_block_t);
      bin_size += sizeof(ssb_master_boot_block_t);
      break;

    case PART_SP1:
      from_bin = (void*)gpSp1 + sizeof(ssb_image_container_t);
      bin_size += _get_part_size(gpSp1);
      break;

    case PART_SUB_VMM_IMAGE:
      printk( "sra_make_enc_part: source pointer(for VMM image) is NULL\n");
      ERROR_EXIT(-EINVAL);
      break;

    case PART_SP2:
      from_bin = (void*)gpSp2 + sizeof(ssb_image_container_t);
      bin_size += _get_part_size(gpSp2);
      break;

    case PART_SP3:
      from_bin = (void*)gpSp3 + sizeof(ssb_image_container_t);
      bin_size += _get_part_size(gpSp3);
      break;

    case PART_OS_IMAGE:
      from_bin = (void*)gpOsip + sizeof(ssb_image_container_t);
      bin_size += sizeof(ssb_image_container_t);
      break;

    default:
      printk( "sra_make_enc_part: unknown partition type: %d\n", ptype);
      ERROR_EXIT(-EINVAL);
    }
  }

  /* if MBB, remain header space */
  if (ptype == PART_MBB) {
    lbuf_ptr = to_mem + sizeof(ssb_master_boot_block_header_t); /* MBB header information space*/
    out_len = to_size - sizeof(ssb_master_boot_block_header_t);

  } else {
    lbuf_ptr = to_mem;
    lssb_mp.ptype = ptype;
    if(_get_mtd_partition(&lssb_mp) != 0) {
      printk( "sra_make_enc_part: cannot append partition (%d) in MBB\n", ptype);
      ERROR_EXIT(-ENOEXEC);
    }
    out_len = to_size;
  }

  /* encrypt data */

  ivar32 = crypto_encrypt_data(from_bin, bin_size, (unsigned char**)&lbuf_ptr, &out_len);

  if (ivar32 < 0) {
    printk( "sra_make_enc_part: ptype(%d) encryption error\n", ptype);
    ERROR_EXIT(-ENOEXEC);
  }
  
  bin_size = out_len;

  /* if MBB, write header information */
  if (ptype == PART_MBB) {
    ssb_mbbh.magic = MAGIC_MBB;
    ssb_mbbh.size = bin_size;
    memcpy(to_mem, &ssb_mbbh, sizeof(ssb_master_boot_block_header_t));
    bin_size += sizeof(ssb_master_boot_block_header_t);    
  } else {
    if (lssb_mp.size != bin_size) {
      lssb_mp.size = bin_size;
      if(_set_mtd_partition(&lssb_mp) != 0) {
	printk( "sra_make_enc_part: cannot set ptype(%d) partition info into MBB\n", lssb_mp.ptype);
	ERROR_EXIT(-ENOEXEC);
      }
    }
  }

  return bin_size;

 out:
#endif
  return rc;
}


/* MBB & SP data unserialization */
int _sra_unserialize(void *to_con, u_int32_t to_size, void *from_bin, u_int32_t from_size, 
		     partition_type_t ptype, int copy)
{
  int rc = 0;
#ifdef CONFIG_VMM_SECURITY
  u_int32_t lcrc32, vcrc32, magic_num;
  char *lptr = NULL;
  ssb_image_container_t *pSp = NULL;

  switch (ptype) {
  case PART_MBB:
    magic_num = MAGIC_MBB;
    break;

  case PART_SP1:
    magic_num = MAGIC_SP1;
    break;

  case PART_SP2:
    magic_num = MAGIC_SP2;
    break;

  case PART_SP3:
    magic_num = MAGIC_SP3;
    break;

  case PART_OS_IMAGE:
    magic_num = MAGIC_OSIP;
    break;

  default:
    printk( "_sra_unserialize: unknown partition type: %d\n", ptype);
    ERROR_EXIT(-EINVAL);
  }

  if (to_con == NULL || from_bin == NULL) {
    printk( "_sra_unserialize: parameter error!\n");
    ERROR_EXIT(-EINVAL);
  }

  /* verify magic number */
  memcpy(&vcrc32, from_bin, sizeof(u_int32_t));
  if (vcrc32 != magic_num) {
    printk( "_sra_unserialize: loaded image is not ptype(%d) binary\n", ptype);
    ERROR_EXIT(-EINVAL);
  }

  /* read & cheack CRC32 */
  memcpy((void*)&vcrc32, (from_bin+sizeof(u_int32_t)), sizeof(unsigned long));

  lcrc32 = crc32(0, (from_bin+sizeof(u_int32_t)+sizeof(unsigned long)), 
		     (from_size-(sizeof(u_int32_t)+sizeof(unsigned long))));
  if (lcrc32 != vcrc32) {
    printk( "_sra_unserialize: bad CRC32 error (readed:0x%X != caculated:0x%X)\n", vcrc32, lcrc32);
    ERROR_EXIT(-ENOEXEC);
  }

  /* needed size calculation & check to_con buffer's size */
  if (ptype == PART_MBB) {
    lcrc32 = sizeof(ssb_master_boot_block_t); /* header size */
  } else {
    lcrc32 = sizeof(ssb_image_container_t);
  }
  vcrc32 = lcrc32;
  if (copy)
    vcrc32 += from_size;

  if (to_size < vcrc32) {
    printk( "_sra_unserialize: parameter error!\n");
    ERROR_EXIT(-EMSGSIZE);
  }

  if (copy) {
    lptr = to_con+lcrc32;
    memcpy(lptr, from_bin, from_size);
    lptr += ((sizeof(u_int32_t) + sizeof(unsigned long)));
  } else {
    lptr = from_bin + (sizeof(u_int32_t) + sizeof(unsigned long));
  }


  /* unserialization */

  if (ptype == PART_MBB) {
    *((ssb_master_boot_block_t *)to_con) = *((ssb_master_boot_block_t *)lptr);

  } else if (ptype == PART_OS_IMAGE) {
    *((ssb_image_container_t *)to_con) = *((ssb_image_container_t *)lptr);

  } else {
    pSp = (ssb_image_container_t *)(to_con);
    memcpy(&vcrc32, lptr, sizeof(u_int32_t));
    lptr += sizeof(u_int32_t);

    if (vcrc32 > MAX_IMAGE_STRUCT_SIZE) {
      printk( "_sra_unserialize: too many image structures:max=%d, but current=%d\n"
	      "\tadjusting size = %d\n",
	      MAX_IMAGE_STRUCT_SIZE, pSp->images_size, MAX_IMAGE_STRUCT_SIZE);
      vcrc32 = MAX_IMAGE_STRUCT_SIZE;
    }

    pSp->images_size = vcrc32;
    for (lcrc32=0; lcrc32<vcrc32; lcrc32++) {
      memcpy(&(pSp->image[lcrc32].type), lptr, sizeof(image_type_t));
      lptr +=  sizeof(image_type_t);

      memcpy(&(pSp->image[lcrc32].size), lptr, sizeof(u_int32_t));
      lptr += sizeof(u_int32_t);

      pSp->image[lcrc32].u.ptr = lptr;
      lptr += pSp->image[lcrc32].size;
    }
  }

 out:
#endif
  return rc;
}

/* MBB & SP data serialization : never mind 'copy' parameter, always copy*/
int _sra_serialize(void *to_bin, u_int32_t to_size, void *from_con, u_int32_t from_size, 
		   partition_type_t ptype, int copy)
{
  int rc = 0;
#ifdef CONFIG_VMM_SECURITY
  u_int32_t vcrc32, magic_num, data_size;
  char *lptr = NULL;
  ssb_image_container_t *pSp = NULL;

  if (to_bin == NULL || from_con == NULL) {
    printk( "_sra_serialize: parameter error!\n");
    ERROR_EXIT(-EINVAL);
  }

  if (to_size < (from_size+sizeof(u_int32_t)+sizeof(unsigned long))) {
    printk( "_sra_serialize: parameter error!\n");
    ERROR_EXIT(-EMSGSIZE);
  }

  lptr = to_bin + (sizeof(u_int32_t)+sizeof(unsigned long));

  switch (ptype) {
  case PART_MBB:
    magic_num = MAGIC_MBB;
    break;

  case PART_SP1:
    magic_num = MAGIC_SP1;
    break;

  case PART_SP2:
    magic_num = MAGIC_SP2;
    break;

  case PART_SP3:
    magic_num = MAGIC_SP3;
    break;

  case PART_OS_IMAGE:
    magic_num = MAGIC_OSIP;
    break;

  default:
    printk( "_sra_serialize: unknown partition type: %d\n", ptype);
    ERROR_EXIT(-EINVAL);
  }


  /* SP or OS image partition serialization */
  if (ptype == PART_MBB) {
    *((ssb_master_boot_block_t *)lptr) = *((ssb_master_boot_block_t *)from_con);
    data_size = sizeof(ssb_master_boot_block_t);

  } else if (ptype == PART_OS_IMAGE) {
    *((ssb_image_container_t *)lptr) = *((ssb_image_container_t *)from_con);
    data_size = sizeof(ssb_image_container_t);

  } else {
    pSp = (ssb_image_container_t *)from_con;

    memcpy(lptr, &(pSp->images_size), sizeof(u_int32_t));
    lptr += sizeof(u_int32_t);
    for (vcrc32=0; vcrc32<pSp->images_size; vcrc32++) {
      memcpy(lptr, &(pSp->image[vcrc32].type), sizeof(image_type_t));
      memcpy((lptr+sizeof(image_type_t)), &(pSp->image[vcrc32].size), sizeof(u_int32_t));
      memcpy((lptr+sizeof(image_type_t)+sizeof(u_int32_t)), pSp->image[vcrc32].u.ptr, pSp->image[vcrc32].size);

      lptr += (sizeof(image_type_t) + sizeof(u_int32_t) + pSp->image[vcrc32].size);
    }

    data_size = _get_part_size(pSp);
  }

  /* write magic number */
  memcpy(to_bin, &magic_num, sizeof(u_int32_t));
  lptr = to_bin + sizeof(u_int32_t);

  /* calculate & write CRC32 */
  vcrc32 = crc32(0, (lptr+sizeof(unsigned long)), data_size); 
  memcpy(lptr, &vcrc32, sizeof(unsigned long));

 out:
#endif
  return rc;
}

transfer_struct_t sra_get_bin(partition_type_t ptype)
{
  transfer_struct_t ts;
#ifdef CONFIG_VMM_SECURITY

  ts.type = ptype;
  ts.size = sizeof(u_int32_t) + sizeof(unsigned long);

  switch (ptype) {
  case PART_MBB:
    ts.ptr = (void *)gpMbb+sizeof(ssb_master_boot_block_t);
    ts.size += sizeof(ssb_master_boot_block_t);
    return ts;

  case PART_SP1:
    ts.ptr = (void *)gpSp1+sizeof(ssb_image_container_t);
    ts.size += _get_part_size(gpSp1);
    return ts;

  case PART_SP2:
    ts.ptr = (void *)gpSp2+sizeof(ssb_image_container_t);
    ts.size += _get_part_size(gpSp2);
    return ts;

  case PART_SP3:
    ts.ptr = (void *)gpSp3+sizeof(ssb_image_container_t);
    ts.size += _get_part_size(gpSp3);
    return ts;

  case PART_OS_IMAGE:
    ts.ptr = (void *)gpOsip+sizeof(ssb_image_container_t);
    ts.size += sizeof(ssb_image_container_t);
    return ts;

  default:
    printk( "sra_get_bin: unknown partition type: %d\n", ptype);
    ts.type = PART_END;
    ts.size = 0;
    ts.ptr = NULL;
  }
#endif
  return ts;
}


/* get MBB information pointer */
ssb_master_boot_block_t *sra_get_mbb(void)
{
#ifdef CONFIG_VMM_SECURITY
  return gpMbb;
#else
  return NULL;
#endif
}

/* write MBB to local DB */
int sra_set_mbb(ssb_master_boot_block_t *pmbb) {
  int rc = 0;
#ifdef CONFIG_VMM_SECURITY
  static spinlock_t sra_set_mbb_lock = SPIN_LOCK_UNLOCKED;

  spin_lock(&sra_set_mbb_lock);

  if (pmbb == NULL) {
    printk( "ssb_set_mbb: error! input data is NULL.\n");
    ERROR_EXIT(-EINVAL);
  }

  if (gpMbb == NULL) {
    gpMbb = (ssb_master_boot_block_t *)_page_alloc(NULL, 
			sizeof(ssb_master_boot_block_t)*2 +
			sizeof(u_int32_t)+sizeof(unsigned long));
    if (gpMbb == NULL) return -ENOMEM;
  }

  (*gpMbb) = (*pmbb);

  if(_sra_serialize(((void*)gpMbb + sizeof(ssb_master_boot_block_t)), 
		    sizeof(ssb_master_boot_block_t)+sizeof(u_int32_t)+sizeof(unsigned long),
		    gpMbb, sizeof(ssb_master_boot_block_t), PART_MBB, COPY) != 0) {
    printk( "sra_set_mbb: _sra_serialize error\n");
    ERROR_EXIT(-ENOEXEC);
  }

 out:
  spin_unlock(&sra_set_mbb_lock);
#endif
  return rc;
}

/* get SP information */
ssb_image_container_t *sra_get_sp(partition_type_t ptype)
{
#ifdef CONFIG_VMM_SECURITY
  switch (ptype) {
  case PART_SP1:
    return gpSp1;

  case PART_SP2:
    return gpSp2;

  case PART_SP3:
    return gpSp3;

  case PART_OS_IMAGE:  /* for internal use only */
    return gpOsip;
   
  default:
    printk( "sra_get_sp: unknown partition type: %d\n", ptype);
    return NULL;
  }
#else
  return NULL;
#endif
}

/* write SP information to */
int sra_set_sp(ssb_image_container_t *sp, partition_type_t ptype)
{
  int rc = 0;
#ifdef CONFIG_VMM_SECURITY
  u_int32_t i, src_size, bin_size;
  void **ppSp = NULL;
  ssb_image_container_t *ptemp=NULL;
  static spinlock_t sra_set_sp_lock = SPIN_LOCK_UNLOCKED;

  if (sp == NULL) ERROR_EXIT(-EINVAL);

  spin_lock(&sra_set_sp_lock);


  switch (ptype) {
  case PART_SP1:
    ppSp = (void*)&gpSp1;
    break;

  case PART_SP2:
    ppSp = (void*)&gpSp2;
    break;

  case PART_SP3:
    ppSp = (void*)&gpSp3;
    break;

  case PART_OS_IMAGE:
    ppSp = (void*)&gpOsip;
    break;

  default:
    printk( "sra_set_sp: unknown partition type: %d\n", ptype);
    ERROR_EXIT(-EINVAL);
  }

  if (sp == (*ppSp)) {
    ptemp = (*ppSp);
    (*ppSp) = NULL;
  }

  bin_size = sizeof(u_int32_t) + sizeof(unsigned long);
  if (ptype == PART_OS_IMAGE) {
    src_size = sizeof(ssb_image_container_t);
  } else {
    src_size = _get_part_size(sp);
  }
  bin_size += src_size;

  i = bin_size + sizeof(ssb_image_container_t);

  (*ppSp) = _page_alloc((*ppSp), i);

  if(_sra_serialize((*ppSp + sizeof(ssb_image_container_t)), 
		    bin_size, sp, src_size, ptype, COPY) != 0) {
    printk( "sra_set_sp: _sra_serialize error\n");
    ERROR_EXIT(-ENOEXEC);
  }

  if(_sra_unserialize((*ppSp), i, ((*ppSp) + sizeof(ssb_image_container_t)), bin_size, 
		      ptype, NOCOPY) != 0) {
    printk( "sra_set_sp: _sra_unserialize error\n");
    ERROR_EXIT(-ENOEXEC);
  }

 out:
  if (ptemp != NULL)
    _page_alloc(ptemp, 0);
  spin_unlock(&sra_set_sp_lock);
#endif
  return rc;
}

/* appending or changing image data */
int sra_set_image(default_struct_t *img, partition_type_t ptype)
{
  int rc = 0;
#ifdef CONFIG_VMM_SECURITY
  int i, src_size, serial_src_size=0;
  void **ppSp = NULL;
  ssb_image_container_t *pSp=NULL;
  ssb_image_container_t *ptemp=NULL;
  static spinlock_t sra_set_image_lock = SPIN_LOCK_UNLOCKED;

  spin_lock(&sra_set_image_lock);

  if (img == NULL) {
    printk( "sra_set_image: img parameter is NULL\n");
    ERROR_EXIT(-EINVAL);
  }

  switch (ptype) {
  case PART_SP1:
    if (gpSp1 == NULL) {
      gpSp1 = _page_alloc(NULL, sizeof(ssb_image_container_t));
      memset(gpSp1, 0, sizeof(ssb_image_container_t));
    }
    pSp = gpSp1;
    ppSp = (void**)&gpSp1;
    break;

  case PART_SP2:
    if (gpSp2 == NULL) {
      gpSp2 = _page_alloc(NULL, sizeof(ssb_image_container_t));
      memset(gpSp2, 0, sizeof(ssb_image_container_t));
    }
    pSp = gpSp2;
    ppSp = (void**)&gpSp2;
    break;

  case PART_SP3:
    if (gpSp3 == NULL) {
      gpSp3 = _page_alloc(NULL, sizeof(ssb_image_container_t));
      memset(gpSp3, 0, sizeof(ssb_image_container_t));
    }
    pSp = gpSp3;
    ppSp = (void**)&gpSp3;
    break;

  case PART_OS_IMAGE:
    if (gpOsip == NULL) {
      gpOsip = _page_alloc(NULL, sizeof(ssb_image_container_t));
      memset(gpOsip, 0, sizeof(ssb_image_container_t));
    }
    pSp = gpOsip;
    ppSp = (void**)&gpOsip;
    break;

  default:
    printk( "sra_set_image: unknown partition type (%d)\n", ptype);
    ERROR_EXIT(-EINVAL);
  }

  src_size = sizeof(u_int32_t) + sizeof(unsigned long);
  if (ptype == PART_OS_IMAGE) {
    src_size += sizeof(ssb_image_container_t);
  } else {
    src_size += (_get_part_size(pSp) + img->size); /* new image size */
  }

  for (i=0; i<pSp->images_size; i++) {
    if(pSp->image[i].type == img->type) {
      if (ptype != PART_OS_IMAGE)
	src_size -= pSp->image[i].size; /* old image size */
      break;
    }
  }

  /* total partition size overflow */
  if ((src_size+sizeof(ssb_image_container_t)) > MAX_PART_SIZE) {
    ERROR_EXIT(-EMSGSIZE);
  }

  if (i < MAX_IMAGE_STRUCT_SIZE) {
    if (i >= pSp->images_size) (pSp->images_size)++;
    pSp->image[i] = (*img);
  } else {
    ERROR_EXIT(-ENOMEM);
  }
  ptemp = pSp;
  (*ppSp) = NULL;
  (*ppSp) = _page_alloc((*ppSp), (src_size+sizeof(ssb_image_container_t)));
  if ((*ppSp) == NULL) {
    ERROR_EXIT(-ENOMEM);
  }

  if (ptype == PART_OS_IMAGE)
    serial_src_size = sizeof(ssb_image_container_t);
  else
    serial_src_size = _get_part_size(ptemp);
  if(_sra_serialize((*ppSp + sizeof(ssb_image_container_t)), 
		    src_size, ptemp, serial_src_size, ptype, COPY) != 0) {
    printk( "sra_set_image: _sra_serialize error\n");
    ERROR_EXIT(-ENOEXEC);
  }

  if(_sra_unserialize((*ppSp), src_size+sizeof(ssb_image_container_t), 
		      ((*ppSp) + sizeof(ssb_image_container_t)), src_size, 
		      ptype, NOCOPY) != 0) {
    printk( "sra_set_image: _sra_unserialize error\n");
    ERROR_EXIT(-ENOEXEC);
  }

 out:
  _page_alloc(ptemp, 0);
  spin_unlock(&sra_set_image_lock);
#endif
  return rc;
}

/* read the img->type data */
default_struct_t *sra_get_image(partition_type_t ptype, image_type_t itype)
{
#ifdef CONFIG_VMM_SECURITY
  int i;
  ssb_image_container_t *pSp;

  switch (ptype) {
  case PART_END:
  case PART_SP1:
    pSp = gpSp1;
    break;

  case PART_SP2:
    pSp = gpSp2;
    break;

  case PART_SP3:
    pSp = gpSp3;
    break;

  case PART_OS_IMAGE:
    pSp = gpOsip;
    break;

  default:
    printk( "sra_get_image: unknown partition type (%d)\n", ptype);
    return NULL;
  }

  if (pSp != NULL) {
    for (i=0; i<pSp->images_size; i++) {
      if(pSp->image[i].type == itype) {
	return &(pSp->image[i]);
      }
    }
  }

  if (ptype == PART_END) {
    if (gpSp2 != NULL) {
      for (i=0; i<gpSp2->images_size; i++) {
	if(gpSp2->image[i].type == itype) {
	  return &(gpSp2->image[i]);
	}
      }
    }
    if (gpSp3 != NULL) {
      for (i=0; i<gpSp3->images_size; i++) {
	if(gpSp3->image[i].type == itype) {
	  return &(gpSp3->image[i]);
	}
      }
    }
    if (gpOsip != NULL) {
      for (i=0; i<gpOsip->images_size; i++) {
	if(gpOsip->image[i].type == itype) {
	  return &(gpOsip->image[i]);
	}
      }
    }
  }
#endif
  return NULL;
}

/* get ssb_mtd_partition_t data for ptype */
int _get_mtd_partition(ssb_mtd_partition_t *psmp)
{
  int rc = 0;
#ifdef CONFIG_VMM_SECURITY
  int i;

  if (psmp == NULL) {
    printk( "_get_mtd_partition: ssb_mtd_partition_t param is NULL !\n");
    ERROR_EXIT(-EINVAL);
  }

  if (gpMbb == NULL)   {
    printk( "_get_mtd_partition: MBB is NULL !\n");
    ERROR_EXIT(-ENODATA);
  }

  for (i=0; i<gpMbb->psize; i++) {
    if (gpMbb->mtd_part[i].ptype == psmp->ptype) {
      (*psmp) = (gpMbb->mtd_part[i]);
      break;
    }
  }

  if (i == gpMbb->psize) {
    printk("_get_mtd_partition: cannot %d part type information\n", psmp->ptype);
    ERROR_EXIT(-ENODATA);
  }

 out:
#endif
  return rc;
}

/* set ssb_mtd_partition_t data for ptype */
int _set_mtd_partition(ssb_mtd_partition_t *psmp)
{
  int rc = 0;
#ifdef CONFIG_VMM_SECURITY
  int i;

  if (psmp == NULL) {
    printk( "_get_mtd_partition: ssb_mtd_partition_t param is NULL !\n");
    ERROR_EXIT(-EINVAL);
  }

  if (gpMbb == NULL)   {
    printk( "_get_mtd_partition: MBB is NULL !\n");
    ERROR_EXIT(-ENODATA);
  }

  for (i=0; i<gpMbb->psize; i++) {
    if (gpMbb->mtd_part[i].ptype == psmp->ptype) {
      gpMbb->mtd_part[i] = (*psmp);
      return 0;
    }
  }
  if (i < MAX_MTD_PARTITION) {
    (gpMbb->psize)++;
    gpMbb->mtd_part[i] = (*psmp);
    if(_sra_serialize((gpMbb + sizeof(ssb_master_boot_block_t)), 
		      sizeof(ssb_master_boot_block_t)+sizeof(u_int32_t)+sizeof(unsigned long),
		      gpMbb, sizeof(ssb_master_boot_block_t), PART_MBB, COPY) != 0) {
      printk( "_set_mtd_partition: _sra_serialize error\n");
      ERROR_EXIT(-ENOEXEC);
    }
  }

 out:
#endif
  return rc;
}

/* find image structure */
transfer_struct_t *_find_transfer_image(ssb_transfer_container_t *tc, partition_type_t ptype)
{
#ifdef CONFIG_VMM_SECURITY
  int i;

  if (tc == NULL) return NULL;
  for (i=0; i<tc->images_size; i++)
    if (tc->image[i].type == ptype) break;
  if (i >= tc->images_size) return NULL;
  
  return &(tc->image[i]);
#else
  return NULL;
#endif
}

#if 0
default_struct_t *_find_default_image(ssb_image_container_t *ic, image_type_t itype)
{
  int i;
  
  if (ic == NULL) return NULL;
  for (i=0; i<ic->images_size; i++)
    if (ic->image[i].type == itype) break;
  if (i >= ic->images_size) return NULL;
  
  return &(ic->image[i]);
}
#endif

/* calculate partition size from structure*/
u_int32_t _get_part_size(ssb_image_container_t *ic)
{
  u_int32_t total = 0;
#ifdef CONFIG_VMM_SECURITY
  int i;

  total += sizeof(ssb_image_container_t);
  for (i=0; i<ic->images_size; i++) {
    total += ic->image[i].size;
  }

#endif
  return total;
}


/**********************************************/
/**********************************************/
/**********************************************/
/**********************************************/
/**********************************************/

#if SRA_DEBUG == 1
#if 0
char *to_mem;
void test_func(void)
{
  int r_mbb, r_sp, r_osip, r_copy;

  to_mem = _page_alloc(to_mem, 128*1024);

  r_mbb = test_mbb();
  if (r_mbb == 0) {
    printk( "\ntest_func: MBB-related function test OK!\n");
    printk( "****************************************\n");
  }
  r_sp = test_sp_osip();
  if (r_sp == 0) {
    printk( "\ntest_func: Secure Partition-related function test OK!\n");
    printk( "****************************************\n");
  }

  if (r_mbb == 0 && r_sp == 0 && r_osip == 0 && r_copy == 0) 
    printk( "test_func: all tests are OK!\n");
}

int test_mbb(void) 
{

  ssb_master_boot_block_t mbb1, *mbb2;

  memset(&mbb1, 0, sizeof(mbb1));

  mbb1.psize = 4;

  mbb1.mtd_part[0].ptype = PART_SP1;
  mbb1.mtd_part[0].offset = 0xC2050000;
  mbb1.mtd_part[0].size = 0;

  mbb1.mtd_part[1].ptype = PART_SP2;
  mbb1.mtd_part[1].offset = 0xC2150000;
  mbb1.mtd_part[1].size = 0;

  mbb1.mtd_part[2].ptype = PART_SP3;
  mbb1.mtd_part[2].offset = 0XC2200000;
  mbb1.mtd_part[2].size = 0;

  mbb1.mtd_part[3].ptype = PART_OS_IMAGE;
  mbb1.mtd_part[3].offset = 0XC2300000;
  mbb1.mtd_part[3].size = 0;

  /* ssb_write_mbb/ssb_read_mbb test */
  if (sra_set_mbb(&mbb1) != 0) {
    printk( "test_mbb: ssb_write_mbb() error\n");
    return -1;
  }
  mbb2 = sra_get_mbb();
  if (mbb2 == NULL) {
    printk( "test_mbb: ssb_read_mbb() error\n");
    return -1;
  }
  if (!test_equal_mbb(&mbb1, mbb2)) {
    printk( "test_mbb: mbb1 and mbb2 are different !!\n");
    return -1;
  }
  if (sra_make_enc_part(to_mem, 1024*1024, NULL, 0, PART_MBB) < 0) {
    printk( "test_mbb: make_enc_part(PART_MBB) ERROR !!\n");
    return -1;
  }

  if (!test_equal_mbb(&mbb1, gpMbb)) {
    printk( "test_mbb: mbb1 and gpMbb are different !!\n");
    return -1;
  }

  printk( "test_mbb: mbb comparison ok!\n");

  return 0;
}

int test_sp_osip(void) {
  ssb_image_container_t sp11, *sp12;
  ssb_image_container_t sp21, *sp22;
  ssb_image_container_t sp31, *sp32;
  ssb_image_container_t osi1, osi2;
  default_struct_t ds[3], *pds;


  sp11.images_size = 3;
  sp11.image[0].type = CERTM_IMG;
  sp11.image[0].u.ptr = "CERTM image";
  sp11.image[0].size = strlen(sp11.image[0].u.ptr) + 1;
  sp11.image[1].type = XEN_ARM_IMG;
  sp11.image[1].u.ptr = "XEN_ARM image";
  sp11.image[1].size = strlen(sp11.image[1].u.ptr) + 1;
  sp11.image[2].type = XEN_ARM_SIGNED_HASH;
  sp11.image[2].u.ptr = "xen-arm signed hash value";
  sp11.image[2].size = strlen(sp11.image[2].u.ptr) + 1;

  sp21.images_size = 2;
  sp21.image[0].type = XEN_AC_POLICY_1;
  sp21.image[0].u.ptr = "Security policy #1 for xen-arm vmm internal";
  sp21.image[0].size = strlen(sp21.image[0].u.ptr) + 1;
  sp21.image[1].type = XEN_AC_POLICY_2;
  sp21.image[1].u.ptr = "Security policy #2 for XEN-ARM VMM";
  sp21.image[1].size = strlen(sp21.image[1].u.ptr) + 1;

  sp31.images_size = 2;
  sp31.image[0].type = SECURE_DOM_KEY;
  sp31.image[0].u.ptr = "Secure domain key";
  sp31.image[0].size = strlen(sp31.image[0].u.ptr) + 1;
  sp31.image[1].type = SECURE_DOM_SIGNED_HASH;
  sp31.image[1].u.ptr = "Secure domain signed hash";
  sp31.image[1].size = strlen(sp31.image[1].u.ptr) + 1;

  /* sra_set_sp/sra_get_sp test */
  if (sra_set_sp(&sp11, PART_SP1) != 0) {
    printk( "test_sp: sra_set_sp(PART_SP1) error\n");
    return -1;
  }
  sp12 = sra_get_sp(PART_SP1);
  if (sp12 == NULL) {
    printk( "test_sp: sra_get_sp(PART_SP1) error\n");
    return -1;
  }
  if (!test_equal_sp(&sp11, sp12)) {
    printk( "test_sp: sp11 and sp22 are different !!\n");
    return -1;
  }

  if (sra_make_enc_part(to_mem, 1024*1024, NULL, 0, PART_SP1) < 0) {
    printk( "test_sp: make_enc_part(PART_SP1) ERROR !!\n");
    return -1;
  }

  if (!test_equal_sp(&sp11, gpSp1)) {
    printk( "test_sp: sp11 and gpSp1 are different !!\n");
    return -1;
  }
  printk( "test_sp: sp1 comparison ok!\n");

  /****/
  if (sra_set_sp(&sp21, PART_SP2) != 0) {
    printk( "test_sp: sra_set_sp(PART_SP2) error\n");
    return -1;
  }
  sp22 = sra_get_sp(PART_SP2);
  if (sp22 == NULL) {
    printk( "test_sp: sra_get_sp(PART_SP2) error\n");
    return -1;
  }
  if (!test_equal_sp(&sp21, sp22)) {
    printk( "test_sp: sp21 and sp22 are different !!\n");
    return -1;
  }
  if (sra_make_enc_part(to_mem, 1024*1024, NULL, 0, PART_SP2) < 0) {
    printk( "test_sp: make_enc_part(PART_SP2) ERROR !!\n");
    return -1;
  }
  if (!test_equal_sp(&sp21, gpSp2)) {
    printk( "test_sp: sp21 and gSp2 are different !!\n");
    return -1;
  }
  printk( "test_sp: sp2 comparison ok!\n");

  /****/
  if (sra_set_sp(&sp31, PART_SP3) != 0) {
    printk( "test_sp: sra_set_sp(PART_SP3) error\n");
    return -1;
  }
  sp32 = sra_get_sp(PART_SP3);
  if (sp32 == NULL) {
    printk( "test_sp: sra_get_sp(PART_SP3) error\n");
    return -1;
  }
  if (!test_equal_sp(&sp31, sp32)) {
    printk( "test_sp: sp31 and sp32 are different !!\n");
    return -1;
  }
  if (sra_make_enc_part(to_mem, 1024*1204, NULL, 0, PART_SP3) < 0) {
    printk( "test_sp: make_enc_part(PART_SP3) ERROR !!\n");
    return -1;
  }
  if (!test_equal_sp(&sp31, gpSp3)) {
    printk( "test_sp: sp31 and gSp3 are different !!\n");
    return -1;
  }
  printk( "test_sp: sp3 comparison ok!\n");

  /****OSIP*/
  ds[0].type = DRIVER_DOM_IMG;
  ds[0].u.pos = 0xC2400000;
  ds[0].size = 100*1024;
  if (sra_set_image(&(ds[0]), PART_OS_IMAGE) != 0) {
    printk( "test_sp: sra_set_image(PART_OS_IMAGE) error\n");
    return -1;
  }

  ds[1].type = SECURE_DOM_IMG;
  ds[1].u.pos = 0xC2800000;
  ds[1].size = 200*1024;
  if (sra_set_image(&(ds[1]), PART_OS_IMAGE) != 0) {
    printk( "test_sp: sra_set_image(PART_OS_IMAGE) error\n");
    return -1;
  }

  ds[2].type = NORMAL_DOM1_IMG;
  ds[2].u.pos = 0xC2C00000;
  ds[2].size = 300*1024;
  if (sra_set_image(&(ds[2]), PART_OS_IMAGE) != 0) {
    printk( "test_sp: sra_set_image(PART_OS_IMAGE) error\n");
    return -1;
  }

  osi1 = *(gpOsip);
  osi2.images_size = 3;

  pds = sra_get_image(PART_OS_IMAGE, DRIVER_DOM_IMG);
  if (pds == NULL) {
    printk( "test_sp: sra_get_image(PART_OS_IMAGE, DRIVER_DOM_IMG) error\n");
    return -1;
  }
  osi2.image[0] = *pds;

  pds = sra_get_image(PART_OS_IMAGE, SECURE_DOM_IMG);
  if (pds == NULL) {
    printk( "test_sp: sra_get_image(PART_OS_IMAGE, SECURE_DOM_IMG) error\n");
    return -1;
  }
  osi2.image[1] = *pds;

  pds = sra_get_image(PART_OS_IMAGE, NORMAL_DOM1_IMG);
  if (pds == NULL) {
    printk( "test_sp: sra_get_image(PART_OS_IMAGE, NORMAL_DOM1_IMG) error\n");
    return -1;
  }
  osi2.image[2] = *pds;

  if (!test_equal_sp(&osi1, &osi2)) {
    printk( "test_sp: osi1 and osi2 are different !!\n");
    return -1;
  }
  if (sra_make_enc_part(to_mem, 1024*1204, NULL, 0, PART_OS_IMAGE) < 0) {
    printk( "test_sp: make_enc_part(PART_OS_IMAGE) ERROR !!\n");
    return -1;
  }
  if (!test_equal_sp(&osi1, gpOsip)) {
    printk("test_sp: osi1 and gpOsip are different !!\n");
    return -1;
  }
  printk("test_sp: OS image part comparison ok!\n");


  return 0;
}
#endif /* if 0 */
#endif /* SBOOT_DEBUG 1 */
