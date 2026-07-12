#include <linux/file.h>
#include <linux/namei.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/compiler_types.h>
#endif
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/mm.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/pgtable.h>
#else
#include <asm/pgtable.h>
#endif
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/types.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#else
#include <linux/sched.h>
#endif
#include <linux/ptrace.h>

#include "arch.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "runtime/ksud.h"
#include "feature/sucompat.h"
#include "policy/app_profile.h"
#include "selinux/selinux.h"
#include "compat/kernel_compat.h"
#ifdef CONFIG_KSU_KPROBES_HOOK
#include "hook/syscall_hook.h"
#else
#include "feature/adb_root.h"
#endif
#include "sulog/event.h"
#include "ksu.h"
#include "util.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

bool ksu_su_compat_enabled __read_mostly = true;

static int su_compat_feature_get(u64 *value)
{
	*value = ksu_su_compat_enabled ? 1 : 0;
	return 0;
}

static int su_compat_feature_set(u64 value)
{
	bool enable = value != 0;
	ksu_su_compat_enabled = enable;
	pr_info("su_compat: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
	.feature_id = KSU_FEATURE_SU_COMPAT,
	.name = "su_compat",
	.get_handler = su_compat_feature_get,
	.set_handler = su_compat_feature_set,
};

#ifdef CONFIG_KSU_KPROBES_HOOK
static const char su_path[] = SU_PATH;

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	// To avoid having to mmap a page in userspace, just write below the stack
	// pointer.
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *ksud_user_path(void)
{
	static const char ksud_path[] = KSUD_PATH;

	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

static char __user *empty_user_path(void)
{
	return userspace_stack_buffer("", sizeof(""));
}

static bool is_ksud_exists()
{
	struct path path;

	if (kern_path(KSUD_PATH, 0, &path) < 0) {
		return false;
	}
	path_put(&path);
	return true;
}

long ksu_handle_faccessat_sucompat(int orig_nr, struct pt_regs *regs)
{
	const char __user **filename_user, *orig_filename;
	long ret;
	const struct cred *old_cred;

	if (!ksu_is_allow_uid_for_current(current_uid().val)) {
		goto do_orig_facessat;
	}

	filename_user = (const char __user **)&PT_REGS_PARM2(regs);

	char path[sizeof(su_path) + 1];
	memset(path, 0, sizeof(path));
	strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
		old_cred = override_creds(ksu_cred);
		if (is_ksud_exists()) {
			ksu_compat_sulog('a');
			pr_info("faccessat su->ksud!\n");
			orig_filename = *filename_user;
			*filename_user = ksud_user_path();
			ret = ksu_syscall_table[orig_nr](regs);
			revert_creds(old_cred);
			*filename_user = orig_filename;
			return ret;
		} else {
			revert_creds(old_cred);
		}
	}

do_orig_facessat:
	return ksu_syscall_table[orig_nr](regs);
}

long ksu_handle_stat_sucompat(int orig_nr, struct pt_regs *regs)
{
	const char __user **filename_user, *orig_filename;
	long ret;
	const struct cred *old_cred;

	if (!ksu_is_allow_uid_for_current(current_uid().val)) {
		goto do_orig_stat;
	}

	filename_user = (const char __user **)&PT_REGS_PARM2(regs);

	char path[sizeof(su_path) + 1];
	memset(path, 0, sizeof(path));
	strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
		old_cred = override_creds(ksu_cred);
		if (is_ksud_exists()) {
			ksu_compat_sulog('s');
			pr_info("newfstatat su->ksud!\n");
			orig_filename = *filename_user;
			*filename_user = ksud_user_path();
			ret = ksu_syscall_table[orig_nr](regs);
			revert_creds(old_cred);
			*filename_user = orig_filename;
			return ret;
		} else {
			revert_creds(old_cred);
		}
	}

do_orig_stat:
	return ksu_syscall_table[orig_nr](regs);
}

long ksu_handle_execve_sucompat(const char __user **filename_user, int orig_nr, struct pt_regs *regs)
{
	const char __user *fn;
	const char __user *const __user *argv_user = (const char __user *const __user *)PT_REGS_PARM2(regs);
	struct ksu_sulog_pending_event *pending_sucompat = NULL;
	char path[sizeof(su_path) + 1];
	long ret, orig_regs[5];
	unsigned long addr;
	int tmp_fd;
	struct file *ksud_file;
	const struct cred *old_cred;

	if (unlikely(!filename_user))
		goto do_orig_execve;

	if (!ksu_is_allow_uid_for_current(current_uid().val))
		goto do_orig_execve;

	addr = untagged_addr((unsigned long)*filename_user);
	fn = (const char __user *)addr;
	memset(path, 0, sizeof(path));
	ret = strncpy_from_user(path, fn, sizeof(path));

	if (ret < 0) {
		pr_warn("Access filename when execve failed: %ld", ret);
		goto do_orig_execve;
	}

	if (likely(memcmp(path, su_path, sizeof(su_path))))
		goto do_orig_execve;

	ksu_compat_sulog('x');
	pr_info("sys_execve su found\n");

	tmp_fd = get_unused_fd_flags(O_CLOEXEC);
	if (tmp_fd < 0) {
		pr_err("alloc tmp fd err: %d\n", tmp_fd);
		goto do_orig_execve;
	}

	old_cred = override_creds(ksu_cred);
	ksud_file = filp_open(KSUD_PATH, O_PATH, 0);
	revert_creds(old_cred);
	if (IS_ERR(ksud_file)) {
		pr_err("open ksud err: %ld\n", PTR_ERR(ksud_file));
		put_unused_fd(tmp_fd);
		goto do_orig_execve;
	}

	fd_install(tmp_fd, ksud_file);

	pending_sucompat = ksu_sulog_capture_sucompat(*filename_user, argv_user, GFP_KERNEL);
	// execve(file, argv, environ)
	// execveat(fd, file, argv, environ, flags)
	orig_regs[0] = regs->__PT_PARM1_REG;
	orig_regs[1] = regs->__PT_PARM2_REG;
	orig_regs[2] = regs->__PT_PARM3_REG;
	orig_regs[3] = regs->__PT_SYSCALL_PARM4_REG;
	orig_regs[4] = regs->__PT_PARM5_REG;
	regs->__PT_PARM5_REG = AT_EMPTY_PATH;
	regs->__PT_SYSCALL_PARM4_REG = regs->__PT_PARM3_REG;
	regs->__PT_PARM3_REG = regs->__PT_PARM2_REG;
	regs->__PT_PARM2_REG = empty_user_path();
	regs->__PT_PARM1_REG = tmp_fd;

	ret = escape_with_root_profile();
	if (ret) {
		pr_err("escape_with_root_profile failed: %ld\n", ret);
	}
	ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);

	ret = ksu_syscall_table[__NR_execveat](regs);
	if (ret < 0) {
		ksu_close_fd(tmp_fd);
		regs->__PT_PARM1_REG = orig_regs[0];
		regs->__PT_PARM2_REG = orig_regs[1];
		regs->__PT_PARM3_REG = orig_regs[2];
		regs->__PT_SYSCALL_PARM4_REG = orig_regs[3];
		regs->__PT_PARM5_REG = orig_regs[4];
	}
	return ret;

do_orig_execve:
	return ksu_syscall_table[orig_nr](regs);
}

#else // CONFIG_KSU_MANUAL_HOOK

extern bool ksud_execve_key;

static inline int do_ksu_handle_execveat_sucompat(int *fd, const char *filename, void *argv)
{
	struct path kpath;
	bool is_allowed = ksu_is_allow_uid_for_current(current_uid().val);

	(void)fd;
	(void)argv;

	if (!ksu_su_compat_enabled)
		return 0;
	if (!is_allowed)
		return 0;
	if (likely(memcmp(filename, SU_PATH, sizeof(SU_PATH))))
		return 0;

	ksu_compat_sulog('x');
	pr_info("do_execveat_common su found\n");
	escape_with_root_profile();

	if (kern_path(KSUD_PATH, LOOKUP_FOLLOW, &kpath)) {
		pr_info("sucompat: /data/adb/ksud not found, fallback to /system/bin/sh");
		memcpy((void *)filename, SH_PATH, sizeof(SH_PATH));
	} else {
		path_put(&kpath);
		memcpy((void *)filename, KSUD_PATH, sizeof(KSUD_PATH));
	}

	return 0;
}

int ksu_handle_execve(int *fd, const char *filename, void *argv, void *envp, int *flags)
{
	long ret;

	(void)flags;

	if (current->pid != 1 && is_init(current_cred())) {
		if (unlikely(strcmp(filename, KSUD_PATH) == 0)) {
			pr_info("hook_manager: escape to root for init executing ksud\n");
			escape_to_root_for_init();
		}

		ret = ksu_adb_root_handle_execve(filename, (struct user_arg_ptr *)envp);
		if (ret)
			pr_err("adb root failed: %ld\n", ret);
	}

	if (unlikely(ksud_execve_key)) {
		ksu_handle_execveat_ksud(filename, (struct user_arg_ptr *)argv);
	}

	if (current_uid().val == 0) {
		ksu_compat_sulog('x');
	}

	return do_ksu_handle_execveat_sucompat(fd, filename, argv);
}

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)
{
	if (IS_ERR(*filename_ptr))
		return 0;

	return ksu_handle_execve(fd, (*filename_ptr)->name, argv, envp, flags);
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *__never_use_argv, void *__never_use_envp,
				 int *__never_use_flags)
{
	return ksu_handle_execveat(fd, filename_ptr, __never_use_argv, __never_use_envp,
				   __never_use_flags);
}

#endif // CONFIG_KSU_MANUAL_HOOK

// sucompat: permitted process can execute 'su' to gain root access.
void __init ksu_sucompat_init()
{
	if (ksu_register_feature_handler(&su_compat_handler)) {
		pr_err("Failed to register su_compat feature handler\n");
	}
}

void __exit ksu_sucompat_exit()
{
	ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
