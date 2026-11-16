/*
 * FastRPC Example
 *
 * Copyright (C) 2023 The Sensor Shell Contributors
 *
 * This file is part of sensh.
 *
 * Sensh is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <dlfcn.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <libhexagonrpc/error.h>
#include <libhexagonrpc/handle.h>
#include <libhexagonrpc/interface/remotectl.h>
#include <libhexagonrpc/session.h>
#include <misc/fastrpc.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "apps_mem.h"
#include "apps_std.h"
#include "hexagonfs.h"
#include "interface/adsp_default_listener.h"
#include "listener.h"
#include "localctl.h"
#include "rpcd_builder.h"

/* Private -P mode owns a single session. The plugin executes in a thread so
 * its DMA-buf fd numbers are valid in the reverse-call listener's fd table. */
extern void a081_apps_mem_counters(uint64_t out[4]);
struct plugin_client { void *library; int (*entry)(void); };
static void *plugin_thread(void *arg)
{
	struct plugin_client *client = arg;
	int rc = client->entry();
	uint64_t counts[4];
	a081_apps_mem_counters(counts);
	fprintf(stderr, "stage=plugin_exit rc=%d share_maps=%llu share_unmaps=%llu live=%llu errors=%llu\n",
		rc, (unsigned long long)counts[0], (unsigned long long)counts[1],
		(unsigned long long)counts[2], (unsigned long long)counts[3]);
	/* Exit this private process, releasing its FastRPC session. No other
	 * clients are allowed in -P mode. The system sensor daemon is separate. */
	exit(rc == 0 ? 0 : 1);
	return NULL;
}
static int start_plugin(const char *path)
{
	struct plugin_client *client = calloc(1, sizeof(*client));
	pthread_t thread;
	int rc;
	void *symbol;
	int (*synchronous_signals)(void) = NULL;
	if (!client) return 1;
	client->library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!client->library) {
		fprintf(stderr, "stage=plugin_load error=%s\n", dlerror());
		free(client);
		return 1;
	}
	symbol = dlsym(client->library, "a081_qvr_client_main");
	memcpy(&client->entry, &symbol, sizeof(client->entry));
	if (!client->entry) {
		fprintf(stderr, "stage=plugin_symbol error=%s\n", dlerror());
		dlclose(client->library);
		free(client);
		return 1;
	}
	/* Opt-in contract: the plugin consumes SIGTERM/SIGINT through signalfd.
	 * Block them before creating any plugin workers and before next2. A signal
	 * must not restart an in-flight FastRPC ioctl as a second DSP request.
	 * Older head/controller plugins retain their existing signal contract. */
	symbol = dlsym(client->library, "a081_qvr_client_synchronous_signals");
	memcpy(&synchronous_signals, &symbol, sizeof(synchronous_signals));
	if (synchronous_signals) {
		sigset_t blocked;
		sigemptyset(&blocked);
		sigaddset(&blocked, SIGTERM);
		sigaddset(&blocked, SIGINT);
		rc = synchronous_signals() == 1 ?
			pthread_sigmask(SIG_BLOCK, &blocked, NULL) : EINVAL;
		if (rc) {
			fprintf(stderr, "stage=plugin_signal_contract rc=%d\n", rc);
			dlclose(client->library);
			free(client);
			return 1;
		}
		fprintf(stderr, "stage=plugin_signal_contract mode=signalfd\n");
	}
	rc = pthread_create(&thread, NULL, plugin_thread, client);
	if (rc) {
		fprintf(stderr, "stage=plugin_thread rc=%d\n", rc);
		dlclose(client->library);
		free(client);
		return 1;
	}
	pthread_detach(thread);
	return 0;
}

static int register_fastrpc_listener(int fd)
{
	const char *name = "adsp_default_listener";
	uint32_t hdl = 0, dlerr = 0;
	char err[256] = {0};
	int ret, close_ret, saved_errno;

	/* Keep the transport and remote loader results separate. The convenience
	 * open wrapper reduces both to -1, losing the DSP error needed here. */
	ret = remotectl_open(fd, strlen(name) + 1, name, &hdl,
			     sizeof(err), err, &dlerr);
	saved_errno = ret == -1 ? errno : 0;
	err[sizeof(err) - 1] = '\0';
	if (ret || dlerr) {
		fprintf(stderr, "stage=listener_open rc=%d rc_hex=0x%08x errno=%d loader_rc=0x%08x message=%s loader_message=%s\n",
			ret, (unsigned int)ret, saved_errno, dlerr,
			hexagonrpc_strerror(ret), err);
		return ret ? ret : 1;
	}

	ret = adsp_default_listener_register(fd, hdl);
	saved_errno = ret == -1 ? errno : 0;
	fprintf(stderr, "stage=listener_register handle=0x%08x rc=%d rc_hex=0x%08x errno=%d message=%s\n",
		hdl, ret, (unsigned int)ret, saved_errno, hexagonrpc_strerror(ret));

	dlerr = 0;
	close_ret = remotectl_close(fd, hdl, 0, NULL, &dlerr);
	saved_errno = close_ret == -1 ? errno : 0;
	if (close_ret || dlerr)
		fprintf(stderr, "stage=listener_close handle=0x%08x rc=%d rc_hex=0x%08x errno=%d loader_rc=0x%08x message=%s\n",
			hdl, close_ret, (unsigned int)close_ret, saved_errno, dlerr,
			hexagonrpc_strerror(close_ret));
	return ret;
}

static void print_usage(const char *argv0)
{
	printf("Usage: %s [options] -f DEVICE\n\n", argv0);
	printf("Server for FastRPC remote procedure calls from Qualcomm DSPs\n\n"
	       "Options:\n"
	       "\t-c SHELL\t\tCreate a new pd running the specified ELF\n"
	       "\t-d DSP\t\tDSP name (default: "")\n"
	       "\t-f DEVICE\tFastRPC device node to attach to\n"
	       "\t-p PROGRAM\tRun client program with shared file descriptor\n"
	       "\t-P PLUGIN\tRun one in-process A081 client plugin; exit when it returns\n"
	       "\t-R DIR\t\tRoot directory of served files (default: /usr/share/qcom/)\n"
	       "\t-s\t\tAttach to sensorspd\n"
	       "\t-h\t\tPrint help and exit\n");
}

static int create_shell_pd(int fd, const char *create_shell)
{
	char *buf;
	int shellfd, ret;
	struct stat stats;
	struct fastrpc_alloc_dma_buf dmabuf;
	long page_size;
	struct fastrpc_init_create init = {
		.attrs = getenv("XR_FASTRPC_UNSIGNED_PD") && !strcmp(getenv("XR_FASTRPC_UNSIGNED_PD"), "1") ? FASTRPC_MODE_UNSIGNED_MODULE : 0,
		.siglen = 0,
	};

	if (init.attrs) {
		const char *last = strrchr(create_shell, '/');
		if (strcmp(last ? last + 1 : create_shell, "fastrpc_shell_unsigned_3")) return -1;
		fprintf(stderr, "stage=private_pd attrs=0x%x shell=%s\n", init.attrs, create_shell);
	}
	shellfd = open(create_shell, O_RDONLY);
	if (shellfd == -1) {
		fprintf(stderr, "Could not open %s: %s\n",
			create_shell, strerror(errno));
		return -1;
	}

	ret = fstat(shellfd, &stats);
	if (ret == -1)
		goto err_close_fd;

	page_size = sysconf(_SC_PAGE_SIZE);
	dmabuf.size = (stats.st_size + page_size - 1) & ~(page_size - 1);
	dmabuf.flags = 0;

	ret = ioctl(fd, FASTRPC_IOCTL_ALLOC_DMA_BUFF, &dmabuf);
	if (ret)
		goto err_close_fd;

	buf = mmap(NULL, dmabuf.size, PROT_WRITE, MAP_SHARED, dmabuf.fd, 0);
	if (buf == MAP_FAILED) {
		ret = -1;
		goto err_close_dmabuf;
	}

	read(shellfd, buf, stats.st_size);

	init.file = (__u64) buf;
	init.filefd = dmabuf.fd;
	init.filelen = stats.st_size;

	ret = ioctl(fd, FASTRPC_IOCTL_INIT_CREATE, &init);

	munmap(buf, dmabuf.size);
err_close_dmabuf:
	close(dmabuf.fd);
err_close_fd:
	close(shellfd);

	return ret;
}

static int setup_environment(int fd)
{
	char *buf;
	int ret;

	buf = malloc(256);
	if (buf == NULL) {
		perror("Could not format file descriptor");
		return 1;
	}

	snprintf(buf, 256, "%d", fd);
	buf[255] = '\0';

	ret = setenv("HEXAGONRPC_FD", buf, 1);

	free(buf);

	return ret;
}

static int terminate_clients(size_t n_pids, const pid_t *pids)
{
	size_t i;

	for (i = 0; i < n_pids; i++) {
		kill(pids[i], SIGTERM);
	}

	return 0;
}

static int start_clients(size_t n_progs, const char **progs, pid_t *pids)
{
	size_t i;

	for (i = 0; i < n_progs; i++) {
		pids[i] = fork();
		if (pids[i] == -1) {
			perror("Could not fork process");
			terminate_clients(i, pids);
			return 1;
		}

		if (pids[i] == 0) {
			execl("/usr/bin/env", "/usr/bin/env", progs[i], (const char *) NULL);
			exit(1);
		}
	}

	return 0;
}

static void *start_reverse_tunnel(int fd, const char *device_dir, const char *dsp,
				  const char *plugin)
{
	struct fastrpc_interface **ifaces;
	struct hexagonfs_dirent *root_dir;
	size_t n_ifaces = 3;
	int ret;

	ifaces = malloc(sizeof(struct fastrpc_interface) * n_ifaces);
	if (ifaces == NULL)
		return NULL;

#ifdef HEXAGONRPC_VERBOSE
	fprintf(stderr, "stage=reverse_fs prefix=%s dsp=%s library_root=%s/dsp/%s\n",
		device_dir, dsp, device_dir, dsp);
#endif
	root_dir = construct_root_dir(device_dir, dsp);

	/*
	 * The apps_remotectl interface patiently waits for this function to
	 * fully populate the ifaces array as long as it receives a pointer to
	 * it.
	 */
	ifaces[REMOTECTL] = fastrpc_localctl_init(n_ifaces, ifaces);

	// Dynamic interfaces with no hardcoded handle
	ifaces[1] = fastrpc_apps_std_init(root_dir);
	ifaces[2] = fastrpc_apps_mem_init(fd);

	ret = register_fastrpc_listener(fd);
	if (ret)
		goto err;

	ret = init_fastrpc_listener(fd);
	if (ret)
		goto err;

	/* The plugin publishes its socket from entry(). Its endpoint must not
	 * become visible until reverse calls can be received. Starting it before
	 * init2 lets a warm client open a DSP module against an absent listener. */
	if (plugin && start_plugin(plugin))
		goto err;

	ret = run_fastrpc_listener(fd, n_ifaces, ifaces);
	if (plugin) {
		/* The detached plugin can still be using mapped DMA. A failed reverse
		 * listener cannot coordinate its stop/unmap calls. End the private
		 * process as one unit; never unmap beneath a live plugin thread. */
		fprintf(stderr, "stage=listener_exit rc=%d message=private_session_abort_without_host_unmap\n", ret);
		_exit(4);
	}

err:
	fastrpc_apps_mem_deinit(ifaces[2]);
	fastrpc_localctl_deinit(ifaces[REMOTECTL]);

	free(ifaces);

	return NULL;
}

static char *read_sysfs_file(const char *path, struct stat *file_stat)
{
	char *contents = NULL;
	int fd, res, n_bytes;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return NULL;

	res = fstat(fd, file_stat);
	if (res)
		goto close_fd;

	contents = malloc(file_stat->st_size);
	if (contents == NULL)
		goto close_fd;

	n_bytes = read(fd, contents, file_stat->st_size);
	if (n_bytes != file_stat->st_size) {
		free(contents);
		contents = NULL;
	}

close_fd:
	close(fd);

	return contents;
}

/*
 * Guesses the device's HexagonFS directory from the model and compatible
 * properties in the device-tree.
 *
 * The vendor name is guessed by splitting the model property at the first
 * space to preserve the canonical capitalization of the name.
 *
 * The SoC name is assumed to be part of the first property in the compatible
 * list that starts with "qcom,".
 *
 * Finally, all compatible entries are split at the first , and the all
 * right-hand sides of the entry considered as the codename.
 *
 * It returns the first guessed combination of all 3 for which a path exists
 * at /usr/share/qcom/{soc}/{vendor}/{codename}.
 * If no match is found, a null pointer is returned.
 */
static char *guess_device_directory_from_compatible(void)
{
	char *compatible_ptr, *device_name, *model_ptr, *orig_compatible_ptr,
		*end_of_vendor_name, *vendor_name;
	char *chipset_name = NULL;
	char *ret = NULL;
	struct stat compatible_stat, model_stat;

	compatible_ptr = read_sysfs_file("/proc/device-tree/compatible",
					 &compatible_stat);
	if (compatible_ptr == NULL)
		return NULL;
	orig_compatible_ptr = compatible_ptr;

	model_ptr = read_sysfs_file("/proc/device-tree/model", &model_stat);
	if (model_ptr == NULL)
		goto free_compatible;

	end_of_vendor_name = strchr(model_ptr, ' ');
	if (end_of_vendor_name == NULL)
		end_of_vendor_name = model_ptr + model_stat.st_size - 1;
	vendor_name = strndup(model_ptr, end_of_vendor_name - model_ptr);
	if (vendor_name == NULL)
		goto free_model;

	while (compatible_ptr < orig_compatible_ptr + compatible_stat.st_size) {
		if (strncmp("qcom,", compatible_ptr, sizeof("qcom,") - 1) == 0) {
			chipset_name = compatible_ptr + sizeof("qcom,") - 1;
			break;
		}

		compatible_ptr += strlen(compatible_ptr) + 1;
	}

	if (chipset_name == NULL)
		goto free_model;

	compatible_ptr = orig_compatible_ptr;
	while (compatible_ptr < orig_compatible_ptr + compatible_stat.st_size) {
		char *try_path = NULL;

		device_name = strchr(compatible_ptr, ',');
		if (device_name == NULL)
			continue;
		device_name += 1;

		if (asprintf(&try_path, "/usr/share/qcom/%s/%s/%s",
			     chipset_name, vendor_name, device_name) < 0)
			goto free_model;

		if (!access(try_path, R_OK)) {
			ret = try_path;
			break;
		}

		free(try_path);

		compatible_ptr += strlen(compatible_ptr) + 1;
	}

free_model:
	free(model_ptr);
free_compatible:
	free(orig_compatible_ptr);

	return ret;
}

int main(int argc, char* argv[])
{
	char *fastrpc_node = NULL;
	const char *device_dir = "/usr/share/qcom/";
	const char *dsp = "";
	const char *create_shell = NULL;
	const char *plugin = NULL;
	const char *guessed_device_dir;
	const char **progs;
	pid_t *pids;
	size_t n_progs = 0;
	int fd, ret, opt;
	bool attach_sns = false;
#ifdef HEXAGONRPC_VERBOSE
	/* Preserve successful file-open/read traces when a timeout kills us. */
	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(stderr, NULL, _IOLBF, 0);
#endif

	progs = malloc(sizeof(const char *) * argc);
	if (progs == NULL) {
		perror("Could not list client programs");
		return 1;
	}

	pids = malloc(sizeof(pid_t) * argc);
	if (pids == NULL) {
		perror("Could not list client PIDs");
		goto err_free_progs;
	}

	guessed_device_dir = guess_device_directory_from_compatible();
	if (guessed_device_dir != NULL)
		device_dir = guessed_device_dir;

	while ((opt = getopt(argc, argv, "c:d:f:p:P:R:sh")) != -1) {
		switch (opt) {
			case 'c':
				create_shell = optarg;
				break;
			case 'd':
				dsp = optarg;
				break;
			case 'f':
				fastrpc_node = optarg;
				break;
			case 'p':
				progs[n_progs] = optarg;
				n_progs++;
				break;
			case 'P':
				plugin = optarg;
				break;
			case 'R':
				device_dir = optarg;
				break;
			case 's':
				attach_sns = true;
				break;
			case 'h':
				print_usage(argv[0]);
				goto free_pids;
				break;
			default:
				print_usage(argv[0]);
				goto err_free_pids;
		}
	}

	if (plugin && n_progs != 0) {
		fprintf(stderr, "-P cannot be combined with -p\n");
		goto err_free_pids;
	}

	if (!fastrpc_node) {
		print_usage(argv[0]);
		goto err_free_pids;
	}

	printf("Starting %s (%s) on %s\n", argv[0], attach_sns? "INIT_ATTACH_SNS": "INIT_ATTACH", fastrpc_node);

	fd = open(fastrpc_node, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Could not open FastRPC node (%s): %s\n", fastrpc_node, strerror(errno));
		goto err_free_pids;
	}

	if (attach_sns)
		ret = ioctl(fd, FASTRPC_IOCTL_INIT_ATTACH_SNS, NULL);
	else if (create_shell != NULL)
		ret = create_shell_pd(fd, create_shell);
	else
		ret = ioctl(fd, FASTRPC_IOCTL_INIT_ATTACH, NULL);
	if (ret) {
		fprintf(stderr, "Could not attach to FastRPC node: %s\n", strerror(errno));
		goto err_close_dev;
	}

	ret = setup_environment(fd);
	if (ret) {
		perror("Could not setup environment variables");
		goto err_close_dev;
	}

	ret = start_clients(n_progs, progs, pids);
	if (ret)
		goto err_close_dev;

	start_reverse_tunnel(fd, device_dir, dsp, plugin);

	/* Successful -P completion exits from plugin_thread after all cleanup. */
	if (plugin) {
		fprintf(stderr, "stage=listener_exit rc=1 message=listener_ended_before_plugin\n");
		goto err_close_dev;
	}

	terminate_clients(n_progs, pids);

	close(fd);
free_pids:
	free(pids);
	free(progs);

	return 0;

err_close_dev:
	close(fd);
err_free_pids:
	free(pids);
err_free_progs:
	free(progs);
	return 4;
}
