#include "selinux_hide.h"
#include "infra/symbol_resolver.h"
#include "linux/jump_label.h"
#include "selinux/sepolicy.h"
#include <linux/cred.h>
#include <linux/cpu.h>
#include <linux/memory.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <asm-generic/errno-base.h>
#include <net/genetlink.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/version.h>

#include <security.h>
#include <ss/context.h>
#include <ss/services.h>
#include <ss/mls.h>
#include <ss/conditional.h>
#include "avc.h"
#include "klog.h"
#include "linux/kallsyms.h"
#include "objsec.h"
#include "hook/patch_memory.h"
#include "ksu.h"
#include "policy/feature.h"
#include "compat/kernel_compat.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include "hook/lsm_hook.h"
#endif

static DEFINE_MUTEX(selinux_hide_mutex);
static bool ksu_selinux_hide_enabled __read_mostly = false;
static bool ksu_selinux_hide_running __read_mostly = false;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
static inline void *ksu_symtab_search(struct symtab *s, const char *name) {
    return hashtab_search(s->table, (void *)name);
}
#else
#define ksu_symtab_search(s, name) symtab_search(s, name)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    #define ksu_mls_compute_context_len(pol, ctx) mls_compute_context_len(pol, ctx)
    #define ksu_mls_sid_to_context(pol, ctx, ptr) mls_sid_to_context(pol, ctx, ptr)
    #define ksu_mls_context_to_sid(pol, oldc, ptr, ctx, sidtab, def) mls_context_to_sid(pol, oldc, ptr, ctx, sidtab, def)
#else
    #define ksu_mls_compute_context_len(pol, ctx) mls_compute_context_len(ctx)
    #define ksu_mls_sid_to_context(pol, ctx, ptr) mls_sid_to_context(ctx, ptr)
    #define ksu_mls_context_to_sid(pol, oldc, ptr, ctx, sidtab, def) mls_context_to_sid(oldc, ptr, ctx, sidtab, def)
#endif

extern struct policydb *backup_policydb;
extern struct sidtab *backup_sidtab;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
extern struct selinux_policy *backup_sepolicy;
#endif

static struct mutex *ksu_selinux_status_lock_ptr = NULL;
static struct page **ksu_selinux_status_page_ptr = NULL;

static inline struct mutex *ksu_get_status_lock(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0) || defined(KSU_COMPAT_SELINUX_STATUS_VAR_IN_SELINUX_STATE)
    return &selinux_state.status_lock;
#else
    if (!ksu_selinux_status_lock_ptr) {
        ksu_selinux_status_lock_ptr = (struct mutex *)find_kernel_symbol_exact("selinux_status_lock");
    }
    return ksu_selinux_status_lock_ptr;
#endif
}

static inline struct page *ksu_get_status_page(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0) || defined(KSU_COMPAT_SELINUX_STATUS_VAR_IN_SELINUX_STATE)
    return selinux_state.status_page;
#else
    if (!ksu_selinux_status_page_ptr) {
        ksu_selinux_status_page_ptr = (struct page **)find_kernel_symbol_exact("selinux_status_page");
    }
    return ksu_selinux_status_page_ptr ? *ksu_selinux_status_page_ptr : NULL;
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int security_context_to_sid_with_policy(struct selinux_policy *policy, const char *scontext, u32 scontext_len, u32 *sid, u32 def_sid, gfp_t gfp_flags);
static int security_sid_to_context_with_policy(struct selinux_policy *policy, u32 sid, char **scontext, u32 *scontext_len);
static void security_compute_av_user_with_policy(struct selinux_policy *policy, u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd);

#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
static struct selinux_state fake_state;

#else
static void context_struct_compute_av(struct context *scontext, struct context *tcontext, u16 tclass, struct av_decision *avd, struct extended_perms *xperms);
static int constraint_expr_eval(struct context *scontext, struct context *tcontext, struct context *xcontext, struct constraint_expr *cexpr);
static void type_attribute_bounds_av(struct context *scontext, struct context *tcontext, u16 tclass, struct av_decision *avd);
static void avd_init(struct av_decision *avd);
static int string_to_context_struct(struct policydb *pol, struct sidtab *sidtabp, char *scontext, u32 scontext_len, struct context *ctx, u32 def_sid);
static int ksu_security_context_to_sid(const char *scontext, u32 scontext_len, u32 *sid, gfp_t gfp_flags);
static int ksu_security_context_str_to_sid(const char *scontext, u32 *sid, gfp_t gfp);
static int ksu_security_sid_to_context(u32 sid, char **scontext, u32 *scontext_len);
static void ksu_security_compute_av_user(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd);

static inline u32 current_sid(void) {
    const struct task_security_struct *tsec = current_security();
    return tsec->sid;
}
#endif

enum sel_inos {
    SEL_ROOT_INO = 2, SEL_LOAD, SEL_ENFORCE, SEL_CONTEXT, SEL_ACCESS, SEL_CREATE, SEL_RELABEL,
    SEL_USER, SEL_POLICYVERS, SEL_COMMIT_BOOLS, SEL_MLS, SEL_DISABLE,
    SEL_MEMBER, SEL_CHECKREQPROT, SEL_COMPAT_NET, SEL_REJECT_UNKNOWN,
    SEL_DENY_UNKNOWN, SEL_STATUS, SEL_POLICY, SEL_VALIDATE_TRANS, SEL_INO_NEXT,
};

typedef ssize_t (*write_op_fn)(struct file *, char *, size_t);
static write_op_fn *selinux_write_op;
static write_op_fn *context_write, *access_write;
static write_op_fn orig_context_write, orig_access_write;

static struct page *fake_status = NULL;

static void initialize_fake_status(void)
{
    struct mutex *status_lock = ksu_get_status_lock();
    struct page *status_page = ksu_get_status_page();

    if (!status_lock) return;

    mutex_lock(status_lock);
    if (fake_status || !status_page) goto out;

    struct selinux_kernel_status *status = page_address(status_page);
    if (!status->enforcing && !ksu_late_loaded) goto out;

    struct page *new_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!new_page) goto out;

    struct selinux_kernel_status *new_status = page_address(new_page);
    memcpy(new_status, status, sizeof(*status));
    
    if (ksu_late_loaded && !new_status->enforcing) {
        new_status->enforcing = 1;
        new_status->sequence = new_status->policyload ? 4 : 0;
    }

    fake_status = new_page;
out:
    mutex_unlock(status_lock);
}

typedef int (*sel_open_handle_status_fn)(struct inode *inode, struct file *filp);
static sel_open_handle_status_fn orig_sel_open_handle_status, *sel_open_handle_status_slot;

static int my_sel_open_handle_status(struct inode *inode, struct file *filp)
{
    if (likely(current_uid().val >= 10000 && ksu_selinux_hide_enabled)) {
        struct mutex *status_lock = ksu_get_status_lock();
        void *data;
        
        if (status_lock) {
            mutex_lock(status_lock);
            data = fake_status;
            mutex_unlock(status_lock);
            
            if (data) {
                filp->private_data = data;
                return 0;
            }
        }
    }

    int ret = orig_sel_open_handle_status(inode, filp);
    if (!ret && !fake_status) {
        initialize_fake_status();
    }
    return ret;
}

static void hook_selinux_status_open(void)
{
    if (orig_sel_open_handle_status) return;
    if (!sel_open_handle_status_slot) {
#ifdef CONFIG_KALLSYMS_ALL
        struct file_operations *ops = (struct file_operations *)find_kernel_symbol_exact("sel_handle_status_ops");
#else
        extern struct file_operations sel_handle_status_ops;
        struct file_operations *ops = &sel_handle_status_ops;
#endif
        if (!ops) {
            pr_err("selinux_hide: sel_handle_status_ops not found\n");
            return;
        }
        sel_open_handle_status_slot = &ops->open;
    }
    
    sel_open_handle_status_fn new_fn = my_sel_open_handle_status;
    orig_sel_open_handle_status = *sel_open_handle_status_slot;
    int ret = ksu_patch_text(sel_open_handle_status_slot, &new_fn, sizeof(new_fn), KSU_PATCH_TEXT_FLUSH_DCACHE);
    if (ret) {
        pr_err("selinux_hide: patch sel_open_handle_status err: %d\n", ret);
        orig_sel_open_handle_status = NULL;
    }
}

static ssize_t my_write_context(struct file *file, char *buf, size_t size)
{
    if (likely(current_uid().val < 10000)) {
        return orig_context_write(file, buf, size);
    }
    char *canon = NULL;
    u32 sid, len;
    ssize_t length;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    length = avc_has_perm(current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__CHECK_CONTEXT, NULL);
    if (length) goto out;
    length = security_context_to_sid_with_policy(backup_sepolicy, buf, size, &sid, SECSID_NULL, GFP_KERNEL);
    if (length) goto out;
    length = security_sid_to_context_with_policy(backup_sepolicy, sid, &canon, &len);

#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
    length = avc_has_perm(&selinux_state, current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__CHECK_CONTEXT, NULL);
    if (length) goto out;
    length = security_context_to_sid(&fake_state, buf, size, &sid, GFP_KERNEL);
    if (length) goto out;
    length = security_sid_to_context(&fake_state, sid, &canon, &len);

#else
    length = avc_has_perm(current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__CHECK_CONTEXT, NULL);
    if (length) goto out;
    length = ksu_security_context_to_sid(buf, size, &sid, GFP_KERNEL);
    if (length) goto out;
    length = ksu_security_sid_to_context(sid, &canon, &len);
#endif

    if (length) goto out;

    length = -ERANGE;
    if (len > SIMPLE_TRANSACTION_LIMIT) {
        pr_err("SELinux: my_write_context: context size exceeds limit\n");
        goto out;
    }

    memcpy(buf, canon, len);
    length = len;
out:
    kfree(canon);
    return length;
}

static ssize_t my_write_access(struct file *file, char *buf, size_t size)
{
    if (likely(current_uid().val < 10000)) {
        return orig_access_write(file, buf, size);
    }
    char *scon = NULL, *tcon = NULL;
    u32 ssid, tsid;
    u16 tclass;
    struct av_decision avd;
    ssize_t length;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    length = avc_has_perm(current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__COMPUTE_AV, NULL);
#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
    length = avc_has_perm(&selinux_state, current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__COMPUTE_AV, NULL);
#else
    length = avc_has_perm(current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__COMPUTE_AV, NULL);
#endif
    if (length) goto out;

    length = -ENOMEM;
    scon = kzalloc(size + 1, GFP_KERNEL);
    tcon = kzalloc(size + 1, GFP_KERNEL);
    if (!scon || !tcon) goto out;

    length = -EINVAL;
    if (sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3) goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    length = security_context_to_sid_with_policy(backup_sepolicy, scon, strlen(scon), &ssid, SECSID_NULL, GFP_KERNEL);
    if (length) goto out;
    length = security_context_to_sid_with_policy(backup_sepolicy, tcon, strlen(tcon), &tsid, SECSID_NULL, GFP_KERNEL);
    if (length) goto out;
    security_compute_av_user_with_policy(backup_sepolicy, ssid, tsid, tclass, &avd);

#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
    length = security_context_str_to_sid(&fake_state, scon, &ssid, GFP_KERNEL);
    if (length) goto out;
    length = security_context_str_to_sid(&fake_state, tcon, &tsid, GFP_KERNEL);
    if (length) goto out;
    security_compute_av_user(&fake_state, ssid, tsid, tclass, &avd);

#else
    length = ksu_security_context_str_to_sid(scon, &ssid, GFP_KERNEL);
    if (length) goto out;
    length = ksu_security_context_str_to_sid(tcon, &tsid, GFP_KERNEL);
    if (length) goto out;
    ksu_security_compute_av_user(ssid, tsid, tclass, &avd);
#endif

    length = scnprintf(buf, SIMPLE_TRANSACTION_LIMIT, "%x %x %x %x %u %x", 
                       avd.allowed, 0xffffffff, avd.auditallow, avd.auditdeny, avd.seqno, avd.flags);
out:
    kfree(tcon);
    kfree(scon);
    return length;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) || defined(KSU_COMPAT_SETPROCATTR_USE_NEW_PROTOTYPE)
typedef int (*setprocattr_fn)(const char *name, void *value, size_t size);
int ksu_handle_selinux_setprocattr(const char *name, void *value, size_t size);
#else
typedef int (*setprocattr_fn)(struct task_struct *p, char *name, void *value, size_t size);
int ksu_handle_selinux_setprocattr(struct task_struct *p, char *name, void *value, size_t size);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
struct ksu_lsm_hook selinux_setprocattr_hook = KSU_LSM_HOOK_INIT(setprocattr, "selinux_setprocattr", ksu_handle_selinux_setprocattr, 0);
#else
static setprocattr_fn ksu_orig_setprocattr;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) || defined(KSU_COMPAT_SETPROCATTR_USE_NEW_PROTOTYPE)
int __nocfi ksu_handle_selinux_setprocattr(const char *name, void *value, size_t size)
#else
int __nocfi ksu_handle_selinux_setprocattr(struct task_struct *p, char *name, void *value, size_t size)
#endif
{
    int error;
    u32 mysid, sid;
    char *str = value;
    
    if (likely(current_uid().val < 10000)) goto call_orig;
    if (strcmp(name, "current")) goto call_orig;
    
    mysid = current_sid();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    error = avc_has_perm(mysid, mysid, SECCLASS_PROCESS, PROCESS__SETCURRENT, NULL);
#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
    error = avc_has_perm(&selinux_state, mysid, mysid, SECCLASS_PROCESS, PROCESS__SETCURRENT, NULL);
#else
    error = avc_has_perm(mysid, mysid, SECCLASS_PROCESS, PROCESS__SETCURRENT, NULL);
#endif
    if (error) return error;

    if (size && str[0] && str[0] != '\n') {
        if (str[size - 1] == '\n') {
            str[size - 1] = 0;
            size--;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
        error = security_context_to_sid_with_policy(backup_sepolicy, str, size, &sid, SECSID_NULL, GFP_KERNEL);
#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
        error = security_context_to_sid(&fake_state, str, size, &sid, GFP_KERNEL);
#else
        error = ksu_security_context_to_sid(str, size, &sid, GFP_KERNEL);
#endif
        if (error) return error;
    }

call_orig:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    return ((setprocattr_fn)selinux_setprocattr_hook.original)(name, value, size);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) || defined(KSU_COMPAT_SETPROCATTR_USE_NEW_PROTOTYPE)
    return ksu_orig_setprocattr(name, value, size);
#else
    return ksu_orig_setprocattr(p, name, value, size);
#endif
}

static void hook_legacy_setprocattr(void) 
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    struct security_hook_list *hp;
    hlist_for_each_entry(hp, &security_hook_heads.setprocattr, list) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
        if (strcmp("selinux", hp->lsm)) continue;
#endif
        ksu_orig_setprocattr = hp->hook.setprocattr;
        setprocattr_fn my_setprocattr = ksu_handle_selinux_setprocattr;
        ksu_patch_text(&hp->hook.setprocattr, &my_setprocattr, sizeof(my_setprocattr), KSU_PATCH_TEXT_FLUSH_DCACHE);
        break;
    }
#endif
}

static void ksu_selinux_hide_unhook(void)
{
    int ret;
    if (orig_context_write) {
        ret = ksu_patch_text(context_write, &orig_context_write, sizeof(orig_context_write), KSU_PATCH_TEXT_FLUSH_DCACHE);
        if (ret) pr_err("selinux_hide: exit: patch_text context_write err: %d\n", ret);
        orig_context_write = NULL;
    }
    if (orig_access_write) {
        ret = ksu_patch_text(access_write, &orig_access_write, sizeof(orig_access_write), KSU_PATCH_TEXT_FLUSH_DCACHE);
        if (ret) pr_err("selinux_hide: exit: patch_text access_write err: %d\n", ret);
        orig_access_write = NULL;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    ksu_lsm_unhook(&selinux_setprocattr_hook);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
    if (ksu_orig_setprocattr) {
        struct security_hook_list *hp;
        hlist_for_each_entry(hp, &security_hook_heads.setprocattr, list) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
            if (strcmp("selinux", hp->lsm)) continue;
#endif
            ret = ksu_patch_text(&hp->hook.setprocattr, &ksu_orig_setprocattr, sizeof(ksu_orig_setprocattr), KSU_PATCH_TEXT_FLUSH_DCACHE);
            if (ret) pr_err("selinux_hide: exit: patch_text setprocattr err: %d\n", ret);
            ksu_orig_setprocattr = NULL;
            break;
        }
    }
#endif
}

static int ksu_selinux_hide_enable(void)
{
    int ret;
    pr_info("selinux_hide: init selinux hide\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
    if (!backup_sepolicy) return -EAGAIN;
#else
    if (!backup_policydb || !backup_sidtab) return -EAGAIN;
#endif

    hook_selinux_status_open();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) && !defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
    fake_state.initialized = true;
    fake_state.ss = kzalloc(sizeof(*fake_state.ss), GFP_KERNEL);
    if (!fake_state.ss) return -ENOMEM;
    fake_state.ss->sidtab = kzalloc(sizeof(struct sidtab), GFP_KERNEL);
    if (!fake_state.ss->sidtab) { kfree(fake_state.ss); return -ENOMEM; }
    
    fake_state.ss->latest_granting = 1;
    rwlock_init(&(fake_state.ss->policy_rwlock));
    memcpy(&fake_state.ss->policydb, backup_policydb, sizeof(struct policydb));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
    memcpy(fake_state.ss->sidtab, backup_sidtab, sizeof(struct sidtab));
#else
    memcpy(&fake_state.ss->sidtab, backup_sidtab, sizeof(struct sidtab));
#endif
    kfree(backup_policydb); kfree(backup_sidtab);
    backup_policydb = NULL; backup_sidtab = NULL;
#endif

#ifdef CONFIG_KALLSYMS_ALL
    selinux_write_op = (write_op_fn *)find_kernel_symbol_exact("write_op");
#else
    extern ssize_t (*const write_op[])(struct file *, char *, size_t);
    selinux_write_op = (write_op_fn *)&write_op;
#endif
    if (!selinux_write_op) return -ENOSYS;

    context_write = &selinux_write_op[SEL_CONTEXT];
    orig_context_write = *context_write;
    write_op_fn my_ctx = my_write_context;
    ret = ksu_patch_text(context_write, &my_ctx, sizeof(my_ctx), KSU_PATCH_TEXT_FLUSH_DCACHE);
    if (ret) goto unhook;

    access_write = &selinux_write_op[SEL_ACCESS];
    orig_access_write = *access_write;
    write_op_fn my_acc = my_write_access;
    ret = ksu_patch_text(access_write, &my_acc, sizeof(my_acc), KSU_PATCH_TEXT_FLUSH_DCACHE);
    if (ret) goto unhook;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    ret = ksu_lsm_hook(&selinux_setprocattr_hook);
    if (ret) goto unhook;
#else
    hook_legacy_setprocattr();
#endif

    return 0;

unhook:
    ksu_selinux_hide_unhook();
    return -ENOSYS;
}

static void ksu_selinux_hide_disable(void)
{
    pr_info("selinux_hide: exit selinux hide\n");
    ksu_selinux_hide_unhook();
}

static int selinux_hide_feature_get(u64 *value)
{
    *value = ksu_selinux_hide_enabled ? 1 : 0;
    return 0;
}

static int selinux_hide_feature_set(u64 value)
{
    bool enable = value != 0;
    int ret = 0;
    
    mutex_lock(&selinux_hide_mutex);
    ksu_selinux_hide_enabled = enable;
    if (enable) {
        if (!ksu_selinux_hide_running) {
            ret = ksu_selinux_hide_enable();
            if (!ret) ksu_selinux_hide_running = true;
        }
    } else {
        if (ksu_selinux_hide_running) {
            ksu_selinux_hide_disable();
            ksu_selinux_hide_running = false;
        }
    }
    mutex_unlock(&selinux_hide_mutex);
    return ret;
}

static const struct ksu_feature_handler selinux_hide_handler = {
    .feature_id = KSU_FEATURE_SELINUX_HIDE,
    .name = "selinux_hide",
    .get_handler = selinux_hide_feature_get,
    .set_handler = selinux_hide_feature_set,
};

void ksu_selinux_hide_handle_second_stage(void) { initialize_fake_status(); }
void ksu_selinux_hide_handle_post_fs_data(void) { }

void __init ksu_selinux_hide_init(void)
{
    ksu_register_feature_handler(&selinux_hide_handler);
    if (ksu_late_loaded) initialize_fake_status();
}

void __exit ksu_selinux_hide_exit(void)
{
    mutex_lock(&selinux_hide_mutex);
    if (ksu_selinux_hide_running) {
        ksu_selinux_hide_disable();
        ksu_selinux_hide_running = false;
    }
    mutex_unlock(&selinux_hide_mutex);
    ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_HIDE);
    
    struct mutex *status_lock = ksu_get_status_lock();
    if (status_lock) {
        mutex_lock(status_lock);
        if (fake_status) __free_page(fake_status);
        fake_status = NULL;
        mutex_unlock(status_lock);
    }
}

void ksu_selinux_hide_drop_backup_if_unused(void)
{
    mutex_lock(&selinux_hide_mutex);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
    if (!ksu_selinux_hide_running && backup_sepolicy) {
        sidtab_destroy(backup_sepolicy->sidtab);
        kfree(backup_sepolicy->sidtab);
        ksu_destroy_sepolicy(backup_sepolicy);
        backup_sepolicy = NULL;
    }
#else
    if (!ksu_selinux_hide_running && backup_policydb && backup_sidtab) {
        sidtab_destroy(backup_sidtab);
        kfree(backup_sidtab);
        policydb_destroy(backup_policydb);
        kfree(backup_policydb);
        backup_policydb = NULL;
        backup_sidtab = NULL;
    }
#endif
    mutex_unlock(&selinux_hide_mutex);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0) && !defined(KSU_COMPAT_USE_SELINUX_STATE)

static int constraint_expr_eval(struct context *scontext, struct context *tcontext, struct context *xcontext, struct constraint_expr *cexpr)
{
    u32 val1, val2;
    struct context *c;
    struct role_datum *r1, *r2;
    struct mls_level *l1, *l2;
    struct constraint_expr *e;
    int s[CEXPR_MAXDEPTH];
    int sp = -1;

    for (e = cexpr; e; e = e->next) {
        switch (e->expr_type) {
        case CEXPR_NOT:
            BUG_ON(sp < 0);
            s[sp] = !s[sp];
            break;
        case CEXPR_AND:
            BUG_ON(sp < 1);
            sp--;
            s[sp] &= s[sp + 1];
            break;
        case CEXPR_OR:
            BUG_ON(sp < 1);
            sp--;
            s[sp] |= s[sp + 1];
            break;
        case CEXPR_ATTR:
            if (sp == (CEXPR_MAXDEPTH - 1)) return 0;
            switch (e->attr) {
            case CEXPR_USER:
                val1 = scontext->user; val2 = tcontext->user; break;
            case CEXPR_TYPE:
                val1 = scontext->type; val2 = tcontext->type; break;
            case CEXPR_ROLE:
                val1 = scontext->role; val2 = tcontext->role;
                r1 = backup_policydb->role_val_to_struct[val1 - 1];
                r2 = backup_policydb->role_val_to_struct[val2 - 1];
                switch (e->op) {
                case CEXPR_DOM: s[++sp] = ebitmap_get_bit(&r1->dominates, val2 - 1); continue;
                case CEXPR_DOMBY: s[++sp] = ebitmap_get_bit(&r2->dominates, val1 - 1); continue;
                case CEXPR_INCOMP: s[++sp] = (!ebitmap_get_bit(&r1->dominates, val2 - 1) && !ebitmap_get_bit(&r2->dominates, val1 - 1)); continue;
                default: break;
                }
                break;
            case CEXPR_L1L2: l1 = &(scontext->range.level[0]); l2 = &(tcontext->range.level[0]); goto mls_ops;
            case CEXPR_L1H2: l1 = &(scontext->range.level[0]); l2 = &(tcontext->range.level[1]); goto mls_ops;
            case CEXPR_H1L2: l1 = &(scontext->range.level[1]); l2 = &(tcontext->range.level[0]); goto mls_ops;
            case CEXPR_H1H2: l1 = &(scontext->range.level[1]); l2 = &(tcontext->range.level[1]); goto mls_ops;
            case CEXPR_L1H1: l1 = &(scontext->range.level[0]); l2 = &(scontext->range.level[1]); goto mls_ops;
            case CEXPR_L2H2: l1 = &(tcontext->range.level[0]); l2 = &(tcontext->range.level[1]); goto mls_ops;
            mls_ops:
                switch (e->op) {
                case CEXPR_EQ: s[++sp] = mls_level_eq(l1, l2); continue;
                case CEXPR_NEQ: s[++sp] = !mls_level_eq(l1, l2); continue;
                case CEXPR_DOM: s[++sp] = mls_level_dom(l1, l2); continue;
                case CEXPR_DOMBY: s[++sp] = mls_level_dom(l2, l1); continue;
                case CEXPR_INCOMP: s[++sp] = mls_level_incomp(l2, l1); continue;
                default: BUG(); return 0;
                }
                break;
            default: BUG(); return 0;
            }

            switch (e->op) {
            case CEXPR_EQ: s[++sp] = (val1 == val2); break;
            case CEXPR_NEQ: s[++sp] = (val1 != val2); break;
            default: BUG(); return 0;
            }
            break;
        case CEXPR_NAMES:
            if (sp == (CEXPR_MAXDEPTH - 1)) return 0;
            c = scontext;
            if (e->attr & CEXPR_TARGET) c = tcontext;
            else if (e->attr & CEXPR_XTARGET) { c = xcontext; if (!c) { BUG(); return 0; } }
            if (e->attr & CEXPR_USER) val1 = c->user;
            else if (e->attr & CEXPR_ROLE) val1 = c->role;
            else if (e->attr & CEXPR_TYPE) val1 = c->type;
            else { BUG(); return 0; }

            switch (e->op) {
            case CEXPR_EQ: s[++sp] = ebitmap_get_bit(&e->names, val1 - 1); break;
            case CEXPR_NEQ: s[++sp] = !ebitmap_get_bit(&e->names, val1 - 1); break;
            default: BUG(); return 0;
            }
            break;
        default: BUG(); return 0;
        }
    }
    BUG_ON(sp != 0);
    return s[0];
}

static void type_attribute_bounds_av(struct context *scontext, struct context *tcontext, u16 tclass, struct av_decision *avd)
{
    struct context lo_scontext, lo_tcontext, *tcontextp = tcontext;
    struct av_decision lo_avd;
    struct type_datum *source, *target;
    u32 masked = 0;

    source = flex_array_get_ptr(backup_policydb->type_val_to_struct_array, scontext->type - 1);
    target = flex_array_get_ptr(backup_policydb->type_val_to_struct_array, tcontext->type - 1);

    if (!source || !source->bounds || !target) return;

    memset(&lo_avd, 0, sizeof(lo_avd));
    memcpy(&lo_scontext, scontext, sizeof(lo_scontext));
    lo_scontext.type = source->bounds;

    if (target->bounds) {
        memcpy(&lo_tcontext, tcontext, sizeof(lo_tcontext));
        lo_tcontext.type = target->bounds;
        tcontextp = &lo_tcontext;
    }

    context_struct_compute_av(&lo_scontext, tcontextp, tclass, &lo_avd, NULL);

    masked = ~lo_avd.allowed & avd->allowed;
    if (likely(!masked)) return;

    avd->allowed &= ~masked;
}

static void context_struct_compute_av(struct context *scontext, struct context *tcontext, u16 tclass, struct av_decision *avd, struct extended_perms *xperms)
{
    struct constraint_node *constraint;
    struct role_allow *ra;
    struct avtab_key avkey;
    struct avtab_node *node;
    struct class_datum *tclass_datum;
    struct ebitmap *sattr, *tattr;
    struct ebitmap_node *snode, *tnode;
    unsigned int i, j;

    avd->allowed = 0; avd->auditallow = 0; avd->auditdeny = 0xffffffff;
    if (xperms) { memset(&xperms->drivers, 0, sizeof(xperms->drivers)); xperms->len = 0; }

    if (unlikely(!tclass || tclass > backup_policydb->p_classes.nprim)) return;

    tclass_datum = backup_policydb->class_val_to_struct[tclass - 1];
    avkey.target_class = tclass;
    avkey.specified = AVTAB_AV | AVTAB_XPERMS;

    sattr = flex_array_get(backup_policydb->type_attr_map_array, scontext->type - 1);
    tattr = flex_array_get(backup_policydb->type_attr_map_array, tcontext->type - 1);

    ebitmap_for_each_positive_bit(sattr, snode, i) {
        ebitmap_for_each_positive_bit(tattr, tnode, j) {
            avkey.source_type = i + 1;
            avkey.target_type = j + 1;
            for (node = avtab_search_node(&backup_policydb->te_avtab, &avkey); node; node = avtab_search_node_next(node, avkey.specified)) {
                if (node->key.specified == AVTAB_ALLOWED) avd->allowed |= node->datum.u.data;
                else if (node->key.specified == AVTAB_AUDITALLOW) avd->auditallow |= node->datum.u.data;
                else if (node->key.specified == AVTAB_AUDITDENY) avd->auditdeny &= node->datum.u.data;
                else if (xperms && (node->key.specified & AVTAB_XPERMS)) services_compute_xperms_drivers(xperms, node);
            }
            cond_compute_av(&backup_policydb->te_cond_avtab, &avkey, avd, xperms);
        }
    }

    constraint = tclass_datum->constraints;
    while (constraint) {
        if ((constraint->permissions & (avd->allowed)) && !constraint_expr_eval(scontext, tcontext, NULL, constraint->expr)) {
            avd->allowed &= ~(constraint->permissions);
        }
        constraint = constraint->next;
    }

    if (tclass == backup_policydb->process_class && (avd->allowed & backup_policydb->process_trans_perms) && scontext->role != tcontext->role) {
        for (ra = backup_policydb->role_allow; ra; ra = ra->next) {
            if (scontext->role == ra->role && tcontext->role == ra->new_role) break;
        }
        if (!ra) avd->allowed &= ~backup_policydb->process_trans_perms;
    }

    type_attribute_bounds_av(scontext, tcontext, tclass, avd);
}

static int string_to_context_struct(struct policydb *pol, struct sidtab *sidtabp, char *scontext, u32 scontext_len, struct context *ctx, u32 def_sid)
{
    struct role_datum *role;
    struct type_datum *typdatum;
    struct user_datum *usrdatum;
    char *scontextp, *p, oldc;
    int rc = -EINVAL;

    context_init(ctx);
    scontextp = scontext;

    p = scontextp;
    while (*p && *p != ':') p++;
    if (*p == 0) goto out;
    *p++ = 0;

    usrdatum = ksu_symtab_search(&pol->p_users, scontextp);
    if (!usrdatum) goto out;
    ctx->user = usrdatum->value;

    scontextp = p;
    while (*p && *p != ':') p++;
    if (*p == 0) goto out;
    *p++ = 0;

    role = ksu_symtab_search(&pol->p_roles, scontextp);
    if (!role) goto out;
    ctx->role = role->value;

    scontextp = p;
    while (*p && *p != ':') p++;
    oldc = *p;
    *p++ = 0;

    typdatum = ksu_symtab_search(&pol->p_types, scontextp);
    if (!typdatum || typdatum->attribute) goto out;
    ctx->type = typdatum->value;

    rc = ksu_mls_context_to_sid(pol, oldc, &p, ctx, sidtabp, def_sid);
    if (rc) goto out;

    rc = -EINVAL;
    if ((p - scontext) < scontext_len) goto out;
    if (!policydb_context_isvalid(pol, ctx)) goto out;
    rc = 0;
out:
    if (rc) context_destroy(ctx);
    return rc;
}

static int ksu_security_context_to_sid(const char *scontext, u32 scontext_len, u32 *sid, gfp_t gfp_flags)
{
    char *scontext2;
    struct context context;
    int rc = 0;

    if (!scontext_len) return -EINVAL;
    *sid = SECSID_NULL;

    scontext2 = kmalloc(scontext_len + 1, gfp_flags);
    if (!scontext2) return -ENOMEM;
    memcpy(scontext2, scontext, scontext_len);
    scontext2[scontext_len] = 0;

    rc = string_to_context_struct(backup_policydb, backup_sidtab, scontext2, scontext_len, &context, SECSID_NULL);
    if (rc == 0) {
        rc = sidtab_context_to_sid(backup_sidtab, &context, sid);
        context_destroy(&context);
    }
    kfree(scontext2);
    return rc;
}

static int ksu_security_context_str_to_sid(const char *scontext, u32 *sid, gfp_t gfp)
{
    return ksu_security_context_to_sid(scontext, strlen(scontext), sid, gfp);
}

static int ksu_security_sid_to_context(u32 sid, char **scontext, u32 *scontext_len)
{
    struct context *context;
    char *scontextp;

    if (scontext) *scontext = NULL;
    *scontext_len = 0;

    context = sidtab_search(backup_sidtab, sid);
    if (!context) return -EINVAL;

    if (context->len) {
        *scontext_len = context->len;
        if (scontext) {
            *scontext = kstrdup(context->str, GFP_ATOMIC);
            if (!(*scontext)) return -ENOMEM;
        }
        return 0;
    }

    *scontext_len += strlen(sym_name(backup_policydb, SYM_USERS, context->user - 1)) + 1;
    *scontext_len += strlen(sym_name(backup_policydb, SYM_ROLES, context->role - 1)) + 1;
    *scontext_len += strlen(sym_name(backup_policydb, SYM_TYPES, context->type - 1)) + 1;
    *scontext_len += ksu_mls_compute_context_len(backup_policydb, context);

    if (!scontext) return 0;

    scontextp = kmalloc(*scontext_len, GFP_ATOMIC);
    if (!scontextp) return -ENOMEM;
    *scontext = scontextp;

    scontextp += sprintf(scontextp, "%s:%s:%s", sym_name(backup_policydb, SYM_USERS, context->user - 1),
                         sym_name(backup_policydb, SYM_ROLES, context->role - 1), sym_name(backup_policydb, SYM_TYPES, context->type - 1));

    ksu_mls_sid_to_context(backup_policydb, context, &scontextp);
    *scontextp = 0;
    return 0;
}

static void ksu_security_compute_av_user(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd)
{
    struct context *scontext = NULL, *tcontext = NULL;
    avd_init(avd);

    scontext = sidtab_search(backup_sidtab, ssid);
    tcontext = sidtab_search(backup_sidtab, tsid);
    if (!scontext || !tcontext) return;

    if (ebitmap_get_bit(&backup_policydb->permissive_map, scontext->type)) avd->flags |= AVD_FLAGS_PERMISSIVE;

    if (unlikely(!tclass)) {
        if (backup_policydb->allow_unknown) avd->allowed = 0xffffffff;
        return;
    }

    context_struct_compute_av(scontext, tcontext, tclass, avd, NULL);
}

static void avd_init(struct av_decision *avd)
{
    avd->allowed = 0;
    avd->auditallow = 0;
    avd->auditdeny = 0xffffffff;
    avd->seqno = 1;
    avd->flags = 0;
}
#endif
