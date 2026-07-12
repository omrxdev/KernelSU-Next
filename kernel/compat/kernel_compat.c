#include <linux/version.h>
#include <linux/fs.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/task.h>
#else
#include <linux/sched.h>
#endif
#include <linux/uaccess.h>
#include <linux/fdtable.h>
#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"

ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
			       loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) ||                          \
	defined(KSU_OPTIONAL_KERNEL_WRITE)
	return kernel_read(p, buf, count, pos);
#else
	loff_t offset = pos ? *pos : 0;
	ssize_t result = kernel_read(p, offset, (char *)buf, count);
	if (pos && result > 0) {
		*pos = offset + result;
	}
	return result;
#endif
}

ssize_t ksu_kernel_write_compat(struct file *p, const void *buf, size_t count,
				loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) ||                          \
	defined(KSU_OPTIONAL_KERNEL_WRITE)
	return kernel_write(p, buf, count, pos);
#else
	loff_t offset = pos ? *pos : 0;
	ssize_t result = kernel_write(p, buf, count, offset);
	if (pos && result > 0) {
		*pos = offset + result;
	}
	return result;
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
__weak int path_mount(const char *dev_name, struct path *path, const char *type_page, unsigned long flags,
                      void *data_page)
{
    // 384 is enough
    char buf[384] = { 0 };
    mm_segment_t old_fs;
    long ret;

    // -1 on the size as implicit null termination
    // as we zero init the thing
    char *realpath = d_path(path, buf, sizeof(buf) - 1);
    if (!(realpath && realpath != buf))
        return -ENOENT;

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    ret = do_mount(dev_name, (const char __user *)realpath, type_page, flags, data_page);
    set_fs(old_fs);
    return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
__weak long copy_from_user_nofault(void *dst, const void __user *src, size_t size)
{
    long ret = -EFAULT;
    mm_segment_t old_fs = get_fs();

	set_fs(USER_DS);
    if (ksu_access_ok(src, size)) {
        pagefault_disable();
        ret = __copy_from_user_inatomic(dst, src, size);
        pagefault_enable();
    }
    set_fs(old_fs);

    return ret ? -EFAULT : 0;
}

__weak long copy_to_user_nofault(void __user *dst, const void *src, size_t size)
{
    long ret = -EFAULT;
    mm_segment_t old_fs = get_fs();

	set_fs(USER_DS);
    if (ksu_access_ok_write(dst, size)) {
        pagefault_disable();
        ret = __copy_to_user_inatomic(dst, src, size);
        pagefault_enable();
    }
    set_fs(old_fs);

    return ret ? -EFAULT : 0;
}

__weak long copy_to_kernel_nofault(void *dst, const void *src, size_t size)
{
    long ret;
    mm_segment_t old_fs = get_fs();

    set_fs(KERNEL_DS);
    pagefault_disable();
    ret = __copy_to_user_inatomic((__force void __user *)dst, src, size);
    pagefault_enable();
    set_fs(old_fs);

    return ret ? -EFAULT : 0;
}

__weak long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
{
    long ret;
    mm_segment_t old_fs = get_fs();

    set_fs(KERNEL_DS);
    pagefault_disable();
    ret = __copy_from_user_inatomic(dst, (__force const void __user *)src, size);
    pagefault_enable();
    set_fs(old_fs);

    return ret ? -EFAULT : 0;
}
#endif // < 5.8.0

#ifndef KSU_OPTIONAL_STRNCPY
long strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr,
				   long count)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
	return strncpy_from_unsafe_user(dst, unsafe_addr, count);
#else
	mm_segment_t old_fs = get_fs();
	long ret;

	if (unlikely(count <= 0))
		return 0;

	set_fs(USER_DS);
	pagefault_disable();
	ret = strncpy_from_user(dst, unsafe_addr, count);
	pagefault_enable();
	set_fs(old_fs);

	if (ret >= count) {
		ret = count;
		dst[ret - 1] = '\0';
	} else if (ret > 0) {
		ret++;
	}

	return ret;
#endif
}
#endif // #ifndef KSU_OPTIONAL_STRNCPY

// https://elixir.bootlin.com/linux/v4.14.222/source/lib/string.c#L282
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 222)
__weak ssize_t strscpy_pad(char *dest, const char *src, size_t count)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
    ssize_t res = strscpy(dest, src, count);
    if (res >= 0 && (size_t)res < count) {
        memset(dest + res, 0, count - res);
    }
    return res;
#else
    if (count == 0)
        return -E2BIG;

    strncpy(dest, src, count);
    dest[count - 1] = '\0';
    return strlen(dest);
#endif
}
#endif // KERNEL_VERSION < 4.14.222

// https://github.com/torvalds/linux/commit/3b8c9f1cdfc506e94e992ae66b68bbe416f89610
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
__weak void __flush_icache_range(unsigned long start, unsigned long end)
{
    flush_icache_range(start, end);
}
#endif
