// SPDX-License-Identifier: GPL-2.0
/* Test stack_map_bin generation handling across read() calls. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static ssize_t read_nointr(int fd, void *buf, size_t count)
{
	ssize_t n;

	do {
		n = read(fd, buf, count);
	} while (n < 0 && errno == EINTR);

	return n;
}

static ssize_t snapshot_size(const char *path)
{
	char buf[4096];
	ssize_t len = 0;
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	while ((n = read_nointr(fd, buf, sizeof(buf))) > 0)
		len += n;
	if (n < 0)
		len = -1;
	close(fd);
	return len;
}

static int load_snapshot(const char *path, unsigned char **snapshot,
			 size_t *snapshot_len)
{
	unsigned char extra;
	unsigned char *data;
	ssize_t measured;
	ssize_t n;
	size_t offset = 0;
	int saved_errno;
	int fd;

	measured = snapshot_size(path);
	if (measured < 0)
		return -1;
	data = malloc(measured ? (size_t)measured : 1);
	if (!data)
		return -1;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto err_free;
	while (offset < (size_t)measured) {
		n = read_nointr(fd, data + offset, (size_t)measured - offset);
		if (n <= 0) {
			if (!n)
				errno = EIO;
			goto err_close;
		}
		offset += n;
	}
	n = read_nointr(fd, &extra, 1);
	if (n != 0) {
		if (n > 0)
			errno = EIO;
		goto err_close;
	}
	if (close(fd))
		goto err_free;
	*snapshot = data;
	*snapshot_len = offset;
	return 0;

err_close:
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
err_free:
	saved_errno = errno;
	free(data);
	errno = saved_errno;
	return -1;
}

static int write_control(const char *path, const char *value)
{
	ssize_t len = strlen(value);
	ssize_t n;
	int saved_errno;
	int fd;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	do {
		n = write(fd, value, len);
	} while (n < 0 && errno == EINTR);
	if (n != len) {
		if (n >= 0)
			errno = EIO;
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	return close(fd);
}

static int reset_map(const char *path)
{
	return write_control(path, "0\n");
}

enum old_export_result {
	OLD_EXPORT_INVALID,
	OLD_EXPORT_COMPLETE,
	OLD_EXPORT_STALE,
};

static enum old_export_result
validate_old_export(const unsigned char *snapshot, size_t snapshot_len,
		    const unsigned char *old_export, size_t old_export_len,
		    ssize_t n, int read_errno)
{
	if (snapshot_len <= 1 || old_export_len < 1 ||
	    old_export_len > snapshot_len ||
	    memcmp(snapshot, old_export, old_export_len))
		return OLD_EXPORT_INVALID;
	if (n == 0 && old_export_len == snapshot_len)
		return OLD_EXPORT_COMPLETE;
	if (n == -1 && read_errno == ESTALE &&
	    old_export_len < snapshot_len)
		return OLD_EXPORT_STALE;
	return OLD_EXPORT_INVALID;
}

static int run_selftests(void)
{
	static const unsigned char snapshot[] = { 0x46, 0x53, 0x4d, 0x42 };
	static const unsigned char mixed_complete[] = { 0x46, 0x00, 0x00, 0x00 };
	static const unsigned char mixed_short[] = { 0x46, 0x00 };
	static const unsigned char too_long[] = {
		0x46, 0x53, 0x4d, 0x42, 0x00
	};
	int failures = 0;

	if (validate_old_export(snapshot, sizeof(snapshot), mixed_complete,
				sizeof(mixed_complete), 0, 0) !=
	    OLD_EXPORT_INVALID) {
		fprintf(stderr, "mixed complete export was not INVALID\n");
		failures++;
	}
	if (validate_old_export(snapshot, sizeof(snapshot), mixed_short,
				sizeof(mixed_short), -1, ESTALE) !=
	    OLD_EXPORT_INVALID) {
		fprintf(stderr, "mixed short export was not INVALID\n");
		failures++;
	}
	if (validate_old_export(snapshot, sizeof(snapshot), snapshot, 1,
				-1, ESTALE) != OLD_EXPORT_STALE) {
		fprintf(stderr, "zero additional bytes plus ESTALE was not STALE\n");
		failures++;
	}
	if (validate_old_export(snapshot, sizeof(snapshot), snapshot,
				sizeof(snapshot), 0, 0) != OLD_EXPORT_COMPLETE ||
	    validate_old_export(snapshot, sizeof(snapshot), snapshot, 2,
				-1, ESTALE) != OLD_EXPORT_STALE ||
	    validate_old_export(snapshot, sizeof(snapshot), snapshot, 2,
				0, 0) != OLD_EXPORT_INVALID ||
	    validate_old_export(snapshot, sizeof(snapshot), snapshot,
				sizeof(snapshot), -1, ESTALE) !=
	    OLD_EXPORT_INVALID ||
	    validate_old_export(snapshot, sizeof(snapshot), too_long,
				sizeof(too_long), 0, 0) != OLD_EXPORT_INVALID) {
		fprintf(stderr, "old export terminal validation selftest failed\n");
		failures++;
	}
	if (failures)
		return 1;
	printf("old export validation selftests passed\n");
	return 0;
}

int main(int argc, char **argv)
{
	char buf[64];
	unsigned char empty[17];
	unsigned char *old_export;
	unsigned char *snapshot;
	enum old_export_result result;
	size_t old_export_len;
	size_t snapshot_len;
	size_t read_len;
	ssize_t total, n;
	uint32_t nr_stacks;
	int read_errno;
	int disable_errno;
	int fd;
	int i;

	if (argc == 2 && !strcmp(argv[1], "--selftest"))
		return run_selftests();
	if (argc != 4) {
		fprintf(stderr, "Usage: %s STACK_MAP_BIN STACK_MAP TRACING_ON\n",
			argv[0]);
		return 1;
	}

	if (load_snapshot(argv[1], &snapshot, &snapshot_len)) {
		perror("snapshot stack_map_bin");
		return 1;
	}
	if (snapshot_len <= 16) {
		fprintf(stderr, "stack_map_bin has no records: %zu bytes\n",
			snapshot_len);
		free(snapshot);
		return 1;
	}
	if (snapshot_len == SIZE_MAX) {
		fprintf(stderr, "stack_map_bin snapshot is too large\n");
		free(snapshot);
		return 1;
	}
	old_export = malloc(snapshot_len + 1);
	if (!old_export) {
		perror("allocate old stack_map_bin export");
		free(snapshot);
		return 1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open stack_map_bin");
		free(old_export);
		free(snapshot);
		return 1;
	}
	n = read_nointr(fd, old_export, 1);
	if (n != 1) {
		if (n < 0)
			perror("initial stack_map_bin read");
		else
			fprintf(stderr, "short initial stack_map_bin read: %zd\n", n);
		close(fd);
		free(old_export);
		free(snapshot);
		return 1;
	}
	if (old_export[0] != snapshot[0]) {
		fprintf(stderr, "initial stack_map_bin byte differs from snapshot\n");
		close(fd);
		free(old_export);
		free(snapshot);
		return 1;
	}
	if (reset_map(argv[2])) {
		perror("reset stack_map");
		close(fd);
		free(old_export);
		free(snapshot);
		return 1;
	}

	old_export_len = 1;
	for (;;) {
		read_len = snapshot_len + 1 - old_export_len;
		if (read_len > sizeof(buf))
			read_len = sizeof(buf);
		errno = 0;
		n = read_nointr(fd, old_export + old_export_len, read_len);
		if (n <= 0)
			break;
		old_export_len += n;
		if (old_export_len > snapshot_len)
			break;
	}
	read_errno = errno;
	result = validate_old_export(snapshot, snapshot_len, old_export,
				     old_export_len, n, read_errno);
	if (result == OLD_EXPORT_COMPLETE) {
		printf("old fd completed snapshot: consumed=%zu EOF\n",
		       old_export_len);
	} else if (result == OLD_EXPORT_STALE) {
		printf("old fd stopped at snapshot prefix: consumed=%zu ESTALE\n",
		       old_export_len);
	} else {
		fprintf(stderr,
			"invalid old fd result: snapshot=%zu consumed=%zu n=%zd errno=%d\n",
			snapshot_len, old_export_len, n, read_errno);
		close(fd);
		free(old_export);
		free(snapshot);
		return 1;
	}
	close(fd);
	free(old_export);
	free(snapshot);

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("reopen stack_map_bin");
		return 1;
	}
	n = read_nointr(fd, empty, sizeof(empty));
	if (n != 16) {
		fprintf(stderr, "bad empty export size: %zd\n", n);
		close(fd);
		return 1;
	}
	memcpy(&nr_stacks, empty + 8, sizeof(nr_stacks));
	n = read_nointr(fd, buf, 1);
	if (nr_stacks != 0 || n != 0) {
		fprintf(stderr, "bad empty export: nr_stacks=%u next_read=%zd\n",
			nr_stacks, n);
		close(fd);
		return 1;
	}
	close(fd);

	/*
	 * Open an empty export, then populate the map without resetting it.
	 * The old fd must retain its open-time empty record set even though a
	 * fresh open sees entries from the same generation.
	 */
	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open empty membership snapshot");
		return 1;
	}
	if (write_control(argv[3], "1\n")) {
		perror("enable tracing");
		close(fd);
		return 1;
	}
	for (i = 0; i < 500; i++) {
		total = snapshot_size(argv[1]);
		if (total > 16)
			break;
		usleep(10000);
	}
	if (write_control(argv[3], "0\n")) {
		disable_errno = errno;
		/* Best effort: a transient write failure must not leak tracing on. */
		if (write_control(argv[3], "0\n"))
			perror("retry disable tracing");
		errno = disable_errno;
		perror("disable tracing");
		close(fd);
		return 1;
	}
	if (total <= 16) {
		fprintf(stderr, "map did not refill for membership test: %zd bytes\n",
			total);
		close(fd);
		return 1;
	}
	n = read_nointr(fd, empty, sizeof(empty));
	if (n != 16) {
		fprintf(stderr, "old fd exported post-open records: %zd bytes\n", n);
		close(fd);
		return 1;
	}
	memcpy(&nr_stacks, empty + 8, sizeof(nr_stacks));
	n = read_nointr(fd, buf, 1);
	if (nr_stacks != 0 || n != 0) {
		fprintf(stderr,
			"old fd record set changed: nr_stacks=%u next_read=%zd\n",
			nr_stacks, n);
		close(fd);
		return 1;
	}
	close(fd);

	printf("stack_map_bin generation and membership tests passed\n");
	return 0;
}
