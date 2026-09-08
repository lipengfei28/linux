/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TRACE_STACKMAP_H
#define _TRACE_STACKMAP_H

#include <linux/types.h>
#include <linux/atomic.h>

#define FTRACE_STACKMAP_MAX_DEPTH	64

/* The cookie contains the generation in its high half and the slot below. */
#define FTRACE_STACKMAP_COOKIE_GEN_SHIFT	32

#define FTRACE_STACKMAP_BIN_MAGIC	0x46534D42	/* 'FSMB' */
#define FTRACE_STACKMAP_BIN_VERSION	1

struct ftrace_stackmap_bin_header {
	u32 magic;
	u32 version;
	u32 nr_stacks;
	u32 generation;
};

struct ftrace_stackmap_bin_entry {
	u32 stack_id;
	u32 nr;
	u32 ref_count;
	u32 reserved;
	u64 ips[];		/* nr entries follow the header */
};

struct trace_array;

#ifdef CONFIG_FTRACE_STACKMAP

struct ftrace_stackmap;

int ftrace_stackmap_alloc(struct trace_array *tr);
int ftrace_stackmap_get_cookie(struct ftrace_stackmap *smap,
			       unsigned long *ips, unsigned int nr_entries,
			       u64 *cookie);

extern const struct file_operations ftrace_stackmap_fops;
extern const struct file_operations ftrace_stackmap_stat_fops;
extern const struct file_operations ftrace_stackmap_bin_fops;

#else

struct ftrace_stackmap;
static inline int ftrace_stackmap_alloc(struct trace_array *tr)
{ return -EOPNOTSUPP; }
static inline int ftrace_stackmap_get_cookie(struct ftrace_stackmap *s,
					     unsigned long *ips,
					     unsigned int n, u64 *cookie)
{ return -EOPNOTSUPP; }

#endif
#endif /* _TRACE_STACKMAP_H */
