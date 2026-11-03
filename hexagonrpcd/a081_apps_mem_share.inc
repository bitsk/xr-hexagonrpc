/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included only by the private hexagonrpcd apps_mem.c overlay.
 * REA DSP ELF0x63a8: method4, in8 {fd,size}, out16 {vapps,vadsp}.
 * REA DSP ELF0x6458: method5, in16 {vadsp64,size32,padding32}.
 */
#include <errno.h>
#include <stdatomic.h>
#include <sys/mman.h>

struct a081_shared_map {
	struct a081_shared_map *next;
	int fd;
	uint32_t size;
	void *host;
	uint64_t remote;
};

/* Same-process plugin checks actual callback completion, not only DSP deinit's
 * return value: qvr_dsp_driver_common_deinit ignores share_unmap errors. */
static _Atomic uint64_t a081_share_maps, a081_share_unmaps, a081_share_live, a081_share_errors;
void a081_apps_mem_counters(uint64_t out[4])
{
	out[0] = atomic_load(&a081_share_maps);
	out[1] = atomic_load(&a081_share_unmaps);
	out[2] = atomic_load(&a081_share_live);
	out[3] = atomic_load(&a081_share_errors);
}

static uint32_t a081_apps_mem_share_map(void *data,
		const struct fastrpc_io_buffer *in, struct fastrpc_io_buffer *out)
{
	struct apps_mem_ctx *ctx = data;
	struct a081_shared_map *map;
	struct fastrpc_mem_map req = { 0 };
	int fd, size, ret, saved;
	uint64_t reply[2];

	if (in[0].s < 8 || out[0].s < 16)
		return AEE_EBADPARM;
	memcpy(&fd, in[0].p, 4);
	memcpy(&size, (char *)in[0].p + 4, 4);
	if (fd < 0 || size <= 0)
		return AEE_EBADPARM;
	map = calloc(1, sizeof(*map));
	if (!map)
		return AEE_ENOMEMORY;
	map->host = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map->host == MAP_FAILED) {
		saved = errno;
		fprintf(stderr, "stage=share_map_mmap fd=%d length=%d rc=-1 errno=%d\n", fd, size, saved);
		atomic_fetch_add(&a081_share_errors, 1);
		free(map);
		return AEE_EFAILED;
	}
	/* Legacy FASTRPC_IOCTL_MMAP rejects flags0/user pages in mainline.
	 * MEM_MAP sends init method10 and returns the immediate DSP VA. */
	req.fd = fd;
	req.flags = FASTRPC_MAP_STATIC;
	req.vaddrin = (uintptr_t)map->host;
	req.length = size;
	errno = 0;
	ret = ioctl(ctx->fd, FASTRPC_IOCTL_MEM_MAP, &req);
	saved = ret == -1 ? errno : 0;
	fprintf(stderr, "stage=share_map fd=%d length=%d rc=%d errno=%d vadsp=0x%" PRIx64 "\n",
		fd, size, ret, saved, (uint64_t)req.vaddrout);
	if (ret) {
		atomic_fetch_add(&a081_share_errors, 1);
		munmap(map->host, size);
		free(map);
		return ret > 0 ? (uint32_t)ret : AEE_EFAILED;
	}
	map->fd = fd; /* Borrowed: plugin must retain it until DSP share_unmap. */
	map->size = size;
	map->remote = req.vaddrout;
	map->next = ctx->shared_maps;
	ctx->shared_maps = map;
	reply[0] = (uintptr_t)map->host;
	reply[1] = map->remote;
	memcpy(out[0].p, reply, sizeof(reply));
	atomic_fetch_add(&a081_share_maps, 1);
	atomic_fetch_add(&a081_share_live, 1);
	return 0;
}

static int a081_unmap_one(struct apps_mem_ctx *ctx, struct a081_shared_map *map)
{
	struct fastrpc_mem_unmap req = { 0 };
	int ret, saved;
	req.fd = map->fd;
	req.vaddr = map->remote;
	req.length = map->size;
	errno = 0;
	ret = ioctl(ctx->fd, FASTRPC_IOCTL_MEM_UNMAP, &req);
	saved = ret == -1 ? errno : 0;
	fprintf(stderr, "stage=share_unmap fd=%d length=%u rc=%d errno=%d vadsp=0x%" PRIx64 "\n",
		map->fd, map->size, ret, saved, map->remote);
	if (ret) {
		atomic_fetch_add(&a081_share_errors, 1);
		return ret;
	}
	errno = 0;
	ret = munmap(map->host, map->size);
	saved = ret == -1 ? errno : 0;
	fprintf(stderr, "stage=share_unmap_host fd=%d length=%u rc=%d errno=%d\n",
		map->fd, map->size, ret, saved);
	if (ret) atomic_fetch_add(&a081_share_errors, 1);
	atomic_fetch_add(&a081_share_unmaps, 1);
	atomic_fetch_sub(&a081_share_live, 1);
	return 0;
}

static uint32_t a081_apps_mem_share_unmap(void *data,
		const struct fastrpc_io_buffer *in, struct fastrpc_io_buffer *out)
{
	struct apps_mem_ctx *ctx = data;
	struct a081_shared_map **at, *map;
	uint64_t remote;
	int size, ret;
	(void)out;
	if (in[0].s < 12) return AEE_EBADPARM;
	memcpy(&remote, in[0].p, 8);
	memcpy(&size, (char *)in[0].p + 8, 4);
	for (at = &ctx->shared_maps; *at; at = &(*at)->next) {
		map = *at;
		if (map->remote != remote || size <= 0 || map->size != (uint32_t)size)
			continue;
		ret = a081_unmap_one(ctx, map);
		if (ret) return ret > 0 ? (uint32_t)ret : AEE_EFAILED;
		*at = map->next;
		free(map);
		return 0;
	}
	atomic_fetch_add(&a081_share_errors, 1);
	fprintf(stderr, "stage=share_unmap_lookup length=%d vadsp=0x%" PRIx64 " rc=%d\n",
		size, remote, AEE_EBADPARM);
	return AEE_EBADPARM;
}

static void a081_apps_mem_cleanup(struct apps_mem_ctx *ctx)
{
	struct a081_shared_map *map;
	while ((map = ctx->shared_maps)) {
		ctx->shared_maps = map->next;
		if (a081_unmap_one(ctx, map))
			munmap(map->host, map->size);
		free(map);
	}
	fprintf(stderr, "stage=apps_mem_cleanup maps=%" PRIu64 " unmaps=%" PRIu64
		" live=%" PRIu64 " errors=%" PRIu64 "\n",
		atomic_load(&a081_share_maps), atomic_load(&a081_share_unmaps),
		atomic_load(&a081_share_live), atomic_load(&a081_share_errors));
}
