/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TRACE_STACKMAP_H
#define _TRACE_STACKMAP_H

#include <linux/types.h>
#include <linux/atomic.h>

#define FTRACE_STACKMAP_MAX_DEPTH	64

/* The cookie contains the generation in its high half and the slot below. */
#define FTRACE_STACKMAP_COOKIE_GEN_SHIFT	32

struct trace_array;

#ifdef CONFIG_FTRACE_STACKMAP

struct ftrace_stackmap;

int ftrace_stackmap_alloc(struct trace_array *tr);
int ftrace_stackmap_get_cookie(struct ftrace_stackmap *smap,
			       unsigned long *ips, unsigned int nr_entries,
			       u64 *cookie);

extern const struct file_operations ftrace_stackmap_fops;
extern const struct file_operations ftrace_stackmap_stat_fops;

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
