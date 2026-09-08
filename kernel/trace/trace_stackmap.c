// SPDX-License-Identifier: GPL-2.0
/*
 * Lock-free stack trace deduplication for ftrace.
 *
 * The map uses preallocated storage and cmpxchg-based linear probing.
 * A 64-bit cookie combines the map generation with the hash-table slot.
 *
 * Reset clears only the map; it does not touch the ring buffer. An open
 * tracefs file holds a reference to the map it opened.
 *
 * The map is allocated when the stackmap option is first enabled and
 * released on request.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/vmalloc.h>
#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/log2.h>
#include <linux/refcount.h>
#include <asm/local.h>

#include "trace.h"
#include "trace_stackmap.h"

/*
 * Keep misses bounded even after pool exhaustion leaves claimed-but-empty
 * slots in the table.
 */
#define FTRACE_STACKMAP_MAX_PROBE	64

struct stackmap_elt {
	u32		nr;
	atomic_t	ref_count;
	unsigned long	ips[FTRACE_STACKMAP_MAX_DEPTH];
};

struct stackmap_entry {
	u32			key;
	struct stackmap_elt	*val;
};

static struct stackmap_elt *stackmap_load_elt(struct stackmap_entry *entry)
{
	/* Pairs with smp_store_release() after elt initialization. */
	return smp_load_acquire(&entry->val);
}

struct ftrace_stackmap {
	struct trace_array	*tr;		/* owning trace_array */
	unsigned int		map_bits;
	unsigned int		map_size;	/* 1 << (map_bits + 1) */
	unsigned int		max_elts;	/* 1 << map_bits */
	u32			hash_seed;	/* per-instance jhash seed */
	atomic_t		next_elt;	/* index into elts pool */
	struct stackmap_entry	*entries;	/* hash table */
	struct stackmap_elt	*elts;		/* flat element pool */
	atomic_t		resetting;
	u64			generation;	/* high half of cookies */
	atomic_long_t __percpu	*successes;	/* hits and inserts */
	atomic_long_t __percpu	*drops;
	refcount_t		ref;		/* trace array + open files */
};

/* Held for writing while map storage changes under tracefs readers. */
static DECLARE_RWSEM(stackmap_rwsem);

/* A free waits here for the files that still hold the map. */
static DECLARE_WAIT_QUEUE_HEAD(stackmap_free_wq);

/* Generation of the next map. Zero is reserved as an invalid generation. */
static u64 stackmap_next_gen = 1;

/* The table is 2x the preallocated element pool. */
#define FTRACE_STACKMAP_BITS		14

/* --- Element pool --- */

static struct stackmap_elt *stackmap_get_elt(struct ftrace_stackmap *smap)
{
	int idx;

	if (atomic_read(&smap->next_elt) >= smap->max_elts)
		return NULL;

	idx = atomic_fetch_add_unless(&smap->next_elt, 1, smap->max_elts);
	if (idx < smap->max_elts)
		return &smap->elts[idx];
	return NULL;
}

/* --- Create / Destroy / Reset --- */

static void ftrace_stackmap_destroy(struct ftrace_stackmap *smap)
{
	free_percpu(smap->drops);
	free_percpu(smap->successes);
	vfree(smap->elts);
	vfree(smap->entries);
	kfree(smap);
}

static struct ftrace_stackmap *ftrace_stackmap_create(struct trace_array *tr)
{
	struct ftrace_stackmap *smap;
	unsigned int bits = FTRACE_STACKMAP_BITS;

	smap = kzalloc_obj(*smap, GFP_KERNEL);
	if (!smap)
		return ERR_PTR(-ENOMEM);

	smap->tr = tr;
	smap->map_bits = bits;
	smap->max_elts = 1U << bits;
	smap->map_size = 1U << (bits + 1);	/* 2x over-provision */

	/* Fail rather than invoke the OOM killer, as the ring buffer does. */
	smap->entries = __vcalloc(smap->map_size, sizeof(*smap->entries),
				  GFP_KERNEL | __GFP_RETRY_MAYFAIL | __GFP_NOWARN);
	if (!smap->entries)
		goto fail;

	smap->elts = __vcalloc(smap->max_elts, sizeof(*smap->elts),
			       GFP_KERNEL | __GFP_RETRY_MAYFAIL | __GFP_NOWARN);
	if (!smap->elts)
		goto fail;

	smap->successes = alloc_percpu(atomic_long_t);
	if (!smap->successes)
		goto fail;
	smap->drops = alloc_percpu(atomic_long_t);
	if (!smap->drops)
		goto fail;

	smap->hash_seed = get_random_u32();
	atomic_set(&smap->next_elt, 0);
	atomic_set(&smap->resetting, 0);
	smap->generation = stackmap_next_gen;
	refcount_set(&smap->ref, 1);

	return smap;

fail:
	ftrace_stackmap_destroy(smap);
	return ERR_PTR(-ENOMEM);
}

/* Cover both RCU-watching and RCU-not-watching tracing contexts. */
static void stackmap_drain_users(void)
{
	synchronize_rcu_tasks_rude();
	synchronize_rcu();
}

/**
 * ftrace_stackmap_alloc - allocate and publish the stackmap of @tr
 * @tr: the trace array
 *
 * Returns 0 if the map exists or was allocated, or -ENOMEM.
 * The caller holds trace_types_lock.
 */
int ftrace_stackmap_alloc(struct trace_array *tr)
{
	struct ftrace_stackmap *smap;

	lockdep_assert_held(&trace_types_lock);

	if (tr->stackmap)
		return 0;

	smap = ftrace_stackmap_create(tr);
	if (IS_ERR(smap))
		return PTR_ERR(smap);

	/* Pairs with smp_load_acquire() by the users of tr->stackmap. */
	smp_store_release(&tr->stackmap, smap);
	return 0;
}

/* Pin the current map, if any, for an open tracefs file. */
static struct ftrace_stackmap *stackmap_get(struct trace_array *tr)
{
	struct ftrace_stackmap *smap;

	guard(mutex)(&trace_types_lock);
	smap = tr->stackmap;
	if (smap)
		refcount_inc(&smap->ref);
	return smap;
}

static void stackmap_put(struct ftrace_stackmap *smap)
{
	if (!smap)
		return;
	if (refcount_dec_and_test(&smap->ref))
		ftrace_stackmap_destroy(smap);
	else
		wake_up(&stackmap_free_wq);
}

/*
 * Clear all entries. The ring buffer is not cleared; cookies from before
 * the reset are invalidated by the generation change.
 *
 * @resetting excludes new hot-path users, the grace periods drain admitted
 * ones, and stackmap_rwsem excludes tracefs readers while storage is
 * cleared. The caller holds trace_types_lock.
 */
static void stackmap_reset(struct trace_array *tr)
{
	struct ftrace_stackmap *smap = tr->stackmap;
	int cpu;

	lockdep_assert_held(&trace_types_lock);

	if (!smap)
		return;

	atomic_set(&smap->resetting, 1);
	stackmap_drain_users();

	down_write(&stackmap_rwsem);

	memset(smap->entries, 0, sizeof(*smap->entries) * smap->map_size);
	memset(smap->elts, 0, sizeof(*smap->elts) * (size_t)smap->max_elts);

	atomic_set(&smap->next_elt, 0);
	for_each_possible_cpu(cpu) {
		atomic_long_set(per_cpu_ptr(smap->successes, cpu), 0);
		atomic_long_set(per_cpu_ptr(smap->drops, cpu), 0);
	}

	smap->generation++;

	up_write(&stackmap_rwsem);

	/* Release resetting=0 so new get_cookie() observes a cleared map. */
	atomic_set_release(&smap->resetting, 0);
}

/*
 * Release the map. Refused while the option is enabled. Hot-path users
 * are drained, then the free waits until every file that opened the map
 * is closed. @self is the map held by the writing file, if any.
 */
static int stackmap_free(struct trace_array *tr, struct ftrace_stackmap *self)
{
	struct ftrace_stackmap *smap;
	int ret;

	scoped_guard(mutex, &trace_types_lock) {
		if (tr->trace_flags & TRACE_ITER(STACKMAP))
			return -EBUSY;
		smap = tr->stackmap;
		if (!smap)
			return 0;

		WRITE_ONCE(tr->stackmap, NULL);
		stackmap_drain_users();
		/* Continue the generation so old cookies do not match a new map. */
		stackmap_next_gen = smap->generation + 1;
	}

	/* Closing a file calls trace_array_put(), so wait without the lock. */
	ret = wait_event_killable(stackmap_free_wq,
				  refcount_read(&smap->ref) == 1 + (self == smap));
	stackmap_put(smap);
	return ret;
}

/* --- Core: get_cookie (lock-free, NMI-safe) --- */

/* The generation is sampled while the caller's RCU read-side section holds. */
static inline u64 stackmap_make_cookie(struct ftrace_stackmap *smap, u32 idx)
{
	/* 32 bits only tell resets apart; wrapping after 2^32 is harmless. */
	u32 gen = (u32)READ_ONCE(smap->generation);

	/* Do not pair a new generation with an old slot. */
	return ((u64)gen << FTRACE_STACKMAP_COOKIE_GEN_SHIFT) | idx;
}

int ftrace_stackmap_get_cookie(struct ftrace_stackmap *smap,
			       unsigned long *ips, unsigned int nr_entries,
			       u64 *cookie)
{
	u32 key_hash, idx, test_key, trace_len;
	struct stackmap_entry *entry;
	struct stackmap_elt *val;
	int probes = 0;
	int ret;

	if (!smap || !nr_entries)
		return -EINVAL;
	/* Do not merge distinct stacks by silently truncating the input. */
	if (nr_entries > FTRACE_STACKMAP_MAX_DEPTH)
		return -E2BIG;

	/* Enter before checking resetting so reset can drain admitted callers. */
	rcu_read_lock_sched_notrace();
	/* Pair with reset's release store before touching map storage. */
	if (atomic_read_acquire(&smap->resetting)) {
		ret = -EINVAL;
		goto out;
	}

	trace_len = nr_entries * sizeof(unsigned long);
	/* jhash2() consumes u32 words; ips is naturally u32-aligned. */
	key_hash = jhash2((const u32 *)ips, trace_len / sizeof(u32),
			  smap->hash_seed);
	if (key_hash == 0)
		key_hash = 1;	/* 0 means free slot */

	idx = key_hash >> (32 - (smap->map_bits + 1));

	while (probes < FTRACE_STACKMAP_MAX_PROBE) {
		idx &= (smap->map_size - 1);
		entry = &smap->entries[idx];
		/*
		 * READ_ONCE() to avoid LKMM data race with concurrent
		 * cmpxchg(&entry->key, 0, key_hash) on this slot.
		 */
		test_key = READ_ONCE(entry->key);

		if (test_key == key_hash) {
			val = stackmap_load_elt(entry);
			/*
			 * An insert with this hash has not published its
			 * element. Do not wait, as from NMI it may be the
			 * interrupted context, and do not add a second entry:
			 * let the caller record this stack in full.
			 */
			if (!val) {
				ret = -EBUSY;
				goto out;
			}
			if (READ_ONCE(val->nr) == nr_entries &&
			    memcmp(val->ips, ips, trace_len) == 0) {
				atomic_add_unless(&val->ref_count, 1, INT_MAX);
				atomic_long_add_unless(
					this_cpu_ptr(smap->successes), 1, LONG_MAX);
				*cookie = stackmap_make_cookie(smap, idx);
				ret = 0;
				goto out;
			}
		} else if (!test_key) {
			/* Do not claim a slot that cannot get an element. */
			if (atomic_read(&smap->next_elt) >= smap->max_elts)
				break;
			/* Lost the race: re-read the slot, it may be this stack. */
			if (cmpxchg(&entry->key, 0, key_hash) != 0)
				continue;

			val = stackmap_get_elt(smap);
			if (!val) {
				/*
				 * A racing insert took the last element. Keep
				 * the claimed slot as a bounded gravestone.
				 */
				atomic_long_add_unless(this_cpu_ptr(smap->drops),
						       1, LONG_MAX);
				ret = -ENOSPC;
				goto out;
			}

			val->nr = nr_entries;
			atomic_set(&val->ref_count, 1);
			memcpy(val->ips, ips, trace_len);

			/* Publish the fully initialized element. */
			smp_store_release(&entry->val, val);
			atomic_long_add_unless(this_cpu_ptr(smap->successes),
					       1, LONG_MAX);
			*cookie = stackmap_make_cookie(smap, idx);
			ret = 0;
			goto out;
		}

		idx++;
		probes++;
	}

	atomic_long_add_unless(this_cpu_ptr(smap->drops), 1, LONG_MAX);
	ret = -ENOSPC;
out:
	rcu_read_unlock_sched_notrace();
	return ret;
}

/* --- Text export: /sys/kernel/tracing/stack_map --- */

struct stackmap_seq_private {
	struct trace_array	*tr;
	struct ftrace_stackmap	*smap;	/* pinned at open(), may be NULL */
};

static struct stackmap_entry *stackmap_seq_seek(struct ftrace_stackmap *smap,
						 loff_t *pos)
{
	loff_t i;

	for (i = *pos; i < smap->map_size; i++) {
		if (READ_ONCE(smap->entries[i].key) &&
		    stackmap_load_elt(&smap->entries[i])) {
			*pos = i;
			return &smap->entries[i];
		}
	}
	/* Advance past the end or seq_read() repeats the last entry. */
	*pos = smap->map_size;
	return NULL;
}

static void *stackmap_seq_start(struct seq_file *m, loff_t *pos)
{
	struct stackmap_seq_private *priv = m->private;

	down_read(&stackmap_rwsem);
	if (!priv->smap)
		return NULL;
	return stackmap_seq_seek(priv->smap, pos);
}

static void *stackmap_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct stackmap_seq_private *priv = m->private;
	struct ftrace_stackmap *smap = priv->smap;

	if (!smap)
		return NULL;
	(*pos)++;
	return stackmap_seq_seek(smap, pos);
}

static void stackmap_seq_stop(struct seq_file *m, void *v)
{
	/* seq_file calls stop() even when start() returned NULL. */
	up_read(&stackmap_rwsem);
}

static int stackmap_seq_show(struct seq_file *m, void *v)
{
	struct stackmap_entry *entry = v;
	struct stackmap_seq_private *priv = m->private;
	struct stackmap_elt *elt;
	u32 idx = entry - priv->smap->entries;
	u32 i, nr;

	elt = stackmap_load_elt(entry);
	if (!elt)
		return 0;

	nr = READ_ONCE(elt->nr);
	if (nr > FTRACE_STACKMAP_MAX_DEPTH)
		nr = FTRACE_STACKMAP_MAX_DEPTH;

	seq_printf(m, "stack_id %u gen %u [ref %u, depth %u]\n",
		   idx, (u32)READ_ONCE(priv->smap->generation),
		   atomic_read(&elt->ref_count), nr);
	for (i = 0; i < nr; i++) {
		unsigned long ip = elt->ips[i];

		if (ip == FTRACE_TRAMPOLINE_MARKER) {
			seq_printf(m, "  [%u] [FTRACE TRAMPOLINE]\n", i);
			continue;
		}
		seq_printf(m, "  [%u] %pS\n", i,
			   (void *)trace_adjust_address(priv->smap->tr, ip));
	}
	seq_putc(m, '\n');
	return 0;
}

static const struct seq_operations stackmap_seq_ops = {
	.start	= stackmap_seq_start,
	.next	= stackmap_seq_next,
	.stop	= stackmap_seq_stop,
	.show	= stackmap_seq_show,
};

static int stackmap_open(struct inode *inode, struct file *file)
{
	struct trace_array *tr = inode->i_private;
	struct stackmap_seq_private *priv;
	struct seq_file *m;
	int ret;

	ret = tracing_check_open_get_tr(tr);
	if (ret)
		return ret;

	ret = seq_open_private(file, &stackmap_seq_ops,
			       sizeof(struct stackmap_seq_private));
	if (ret) {
		trace_array_put(tr);
		return ret;
	}

	m = file->private_data;
	priv = m->private;
	priv->tr = tr;
	/* A reader keeps the map it opened until it closes the file. */
	if (file->f_mode & FMODE_READ)
		priv->smap = stackmap_get(tr);
	return 0;
}

static int stackmap_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;
	struct stackmap_seq_private *priv = m->private;
	struct ftrace_stackmap *smap = priv->smap;
	struct trace_array *tr = priv->tr;
	int ret;

	ret = seq_release_private(inode, file);
	stackmap_put(smap);
	trace_array_put(tr);
	return ret;
}

/* Commands are matched exactly, with an optional trailing newline. */
static ssize_t stackmap_write(struct file *file, const char __user *ubuf,
			      size_t count, loff_t *ppos)
{
	struct seq_file *m = file->private_data;
	struct stackmap_seq_private *priv = m->private;
	char buf[8];
	size_t n = min(count, sizeof(buf) - 1);
	int ret = 0;

	if (n == 0)
		return -EINVAL;
	if (copy_from_user(buf, ubuf, n))
		return -EFAULT;
	buf[n] = '\0';
	if (buf[n - 1] == '\n')
		buf[--n] = '\0';

	if (!strcmp(buf, "0") || !strcmp(buf, "reset")) {
		guard(mutex)(&trace_types_lock);
		stackmap_reset(priv->tr);
	} else if (!strcmp(buf, "free")) {
		ret = stackmap_free(priv->tr, priv->smap);
	} else {
		ret = -EINVAL;
	}

	return ret ? ret : count;
}

const struct file_operations ftrace_stackmap_fops = {
	.open		= stackmap_open,
	.read		= seq_read,
	.write		= stackmap_write,
	.llseek		= seq_lseek,
	.release	= stackmap_release,
};
