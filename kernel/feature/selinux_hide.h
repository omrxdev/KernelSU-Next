#ifndef __KSU_H_SELINUX_HIDE
#define __KSU_H_SELINUX_HIDE

#include <linux/types.h>
#include <linux/mutex.h>

void ksu_selinux_hide_init(void);
void ksu_selinux_hide_exit(void);

int sepol_expected_argc(u32 cmd);

// types
// :type1:\0:type2:\0:type3:\0
extern char *ksu_hide_type_list;
extern size_t ksu_hide_type_len;

// rules
// :src1:\0:tgt1:\0:src2:\0:tgt2:\0:src3:\0:tgt3:\0
extern char *ksu_hide_rule_list;
extern size_t ksu_hide_rule_len;

extern struct mutex selinux_hide_list_mutex;

void ksu_add_probe_to_list(u32 cmd, const char *args[]);
void ksu_hide_notify_reload(bool ksu_triggered);

#endif