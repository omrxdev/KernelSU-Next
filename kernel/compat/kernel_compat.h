#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/fs.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/task_work.h>
#include "ss/policydb.h"
#include "linux/key.h"

#ifndef ksu_access_ok
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
    #define ksu_access_ok(ptr, size) access_ok(ptr, size)
#else
    #define ksu_access_ok(ptr, size) access_ok(VERIFY_READ, ptr, size)
#endif
#endif

#ifndef ksu_access_ok_write
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
    #define ksu_access_ok_write(ptr, size) access_ok(ptr, size)
#else
    #define ksu_access_ok_write(ptr, size) access_ok(VERIFY_WRITE, ptr, size)
#endif
#endif

/*
 * Adapt to Huawei HISI kernel without affecting other kernels ,
 * Huawei Hisi Kernel EBITMAP Enable or Disable Flag ,
 * From ss/ebitmap.h
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)) &&                         \
		(LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)) ||             \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)) &&                    \
		(LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0))
#ifdef HISI_SELINUX_EBITMAP_RO
#define CONFIG_IS_HW_HISI
#endif
#endif

// Checks for UH, KDP and RKP
#ifdef SAMSUNG_UH_DRIVER_EXIST
#if defined(CONFIG_UH) || defined(CONFIG_KDP) || defined(CONFIG_RKP)
#error "CONFIG_UH, CONFIG_KDP and CONFIG_RKP is enabled! Please disable or remove it before compile a kernel with KernelSU!"
#endif
#endif

extern ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
				      loff_t *pos);
extern ssize_t ksu_kernel_write_compat(struct file *p, const void *buf,
				       size_t count, loff_t *pos);
extern int path_mount(const char *dev_name, struct path *path, const char *type_page, unsigned long flags,
                      void *data_page);

extern long copy_from_user_nofault(void *dst, const void __user *src, size_t size);
extern long copy_to_user_nofault(void __user *dst, const void *src, size_t size);
extern long copy_to_kernel_nofault(void *dst, const void *src, size_t size);
extern long copy_from_kernel_nofault(void *dst, const void *src, size_t size);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||                           \
	defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
extern struct key *init_session_keyring;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static inline void *ksu_kvmalloc(size_t size, gfp_t flags)
{
// https://elixir.bootlin.com/linux/v4.4.302/source/security/apparmor/lib.c#L79
	void *buffer = NULL;

	if (size == 0)
		return NULL;

	/* do not attempt kmalloc if we need more than 16 pages at once */
	if (size <= (16 * PAGE_SIZE))
		buffer = kmalloc(size, flags | GFP_NOIO | __GFP_NOWARN);
	if (!buffer) {
		if (flags & __GFP_ZERO)
			buffer = vzalloc(size);
		else
			buffer = vmalloc(size);
	}
	return buffer;
}

static inline void ksu_kvfree(const void *buf)
{
	if (is_vmalloc_addr(buf))
		vfree(buf);
	else
		kfree(buf);
}
#define kvmalloc ksu_kvmalloc
#define kvfree ksu_kvfree
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 222)
extern ssize_t strscpy_pad(char *dest, const char *src, size_t count);
#endif

#ifndef KSU_OPTIONAL_STRNCPY
extern long strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr,
				   long count);
#endif // #ifndef KSU_OPTIONAL_STRNCPY

// Linux >= 5.7
// task_work_add (struct, struct, enum)
// Linux pre-5.7
// task_work_add (struct, struct, bool)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#ifndef TWA_RESUME
#define TWA_RESUME true
#endif
#endif

// https://github.com/torvalds/linux/blob/v5.4/arch/arm64/include/asm/pgtable.h#L61
#ifndef PTE_ADDR_LOW
#define PTE_ADDR_LOW (((_AT(pteval_t, 1) << (48 - PAGE_SHIFT)) - 1) << PAGE_SHIFT)
#endif

#ifndef PTE_ADDR_MASK
#define PTE_ADDR_MASK PTE_ADDR_LOW
#endif

#ifndef __pte_to_phys
#define __pte_to_phys(pte) (pte_val(pte) & PTE_ADDR_MASK)
#endif

#ifndef __pud_to_phys
#define __pud_to_phys(pud) __pte_to_phys(pud_pte(pud))
#endif

#ifndef __pmd_to_phys
#define __pmd_to_phys(pmd) __pte_to_phys(pmd_pte(pmd))
#endif

extern void __flush_icache_range(unsigned long start, unsigned long end);

#endif // #ifndef __KSU_H_KERNEL_COMPAT
