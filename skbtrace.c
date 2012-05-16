/*
 * socket buffer tracing application
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright (C) 2012 Li Yu <bingtian.ly@taobao.com>
 *
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <locale.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <pcap.h>

#include "list.h"
#include "linux/skbtrace_api.h"

#define DEBUGFS_TYPE		(0x64626720)

#define SKBTRACE_CONF		"/skbtrace.conf"
#define SKBTRACE_ENABLED_PATH	"/skbtrace/enabled"
#define SKBTRACE_FILTERS_PATH	"/skbtrace/filters"
#define SKBTRACE_VERSION_PATH	"/skbtrace/version"
#define SKBTRACE_DROPPED_PATH	"/skbtrace/dropped"
#define SKBTRACE_SUBBUF_NR_PATH	"/skbtrace/subbuf_nr"
#define SKBTRACE_SUBBUF_SIZE_PATH	"/skbtrace/subbuf_size"

#define SKBTRACE_HARDIRQ_PATH	"/skbtrace/trace.hardirq.cpu"
#define SKBTRACE_SOFTIRQ_PATH	"/skbtrace/trace.softirq.cpu"
#define SKBTRACE_SYSCALL_PATH	"/skbtrace/trace.syscall.cpu"

#define SKBTRACE_VERSION	"0.1.0"
#define SKBTRACE_K_VERSION	"1"
#define OPTSTRING		"r:D:w:b:n:c:C:p:e:F:fslvVh"
#define USAGE_STR \
	"\t-r ARG Path to mounted debugfs, defaults to /sys/kernel/debug\n" \
	"\t-D ARG Directory to prepend to output file names\n" \
	"\t-w ARG Stop after defined time, in seconds\n" \
	"\t-b ARG Sub buffer size in bytes\n" \
	"\t-n ARG Number of sub buffers\n" \
	"\t-c ARG Search path for configuration file skbtrace.conf, default is to enable all tracepoints\n" \
	"\t-C CHANNEL_LIST Given channel list to specifiy what are channels which skbtrace can receive from\n" \
	"\t\tCHANNEL_LIST\t\tAvailable channels are syscall, softirq, hardirq\n" \
	"\t-p PROCESSOR_LIST Given a processors list to specifiy what are processors which skbtrace can receive from\n" \
	"\t-e EVENT[,OPTIONS_LIST] Specifiy an interesting trace event, this can be used multiple times\n" \
	"\t\tEVENT\t\tOne of available trace events, please refer the output of -l option\n" \
	"\t\tOPTIONS_LIST\tThe optional parameters of the trace event, the format is option1=val1,option2=val2,...\n" \
	"\t-F ARG Specify filter for sk_buff and sockets\n" \
	"\t-f Overwrite existed result files\n" \
	"\t-s Write result data on stdandard output\n" \
	"\t-l List all available trace events, and channels\n" \
	"\t-V Show actual configuration details\n" \
	"\t-v Print program version info\n\n"

static char *Conf_pathlist = "./:/etc/skbtrace/";
static char *Debugfs_path = "/sys/kernel/debug";
static char *Output_path = "./skbtrace.results";
static int Stop_timeout = 0;
static long Nr_processors;
static int Subbuf_size = SKBTRACE_DEF_SUBBUF_SIZE;
static int Subbuf_nr = SKBTRACE_DEF_SUBBUF_NR;
static int Overwrite_existed_results = O_EXCL;
static struct bpf_program Def_bpf_program;
static int Verbose;
static int On_stdout;
static unsigned int Channels_mask= -1;	 /* receive data from all channels, default */
static int *Processors_mask;
static char **Cmd_line;
static pthread_spinlock_t Stdout_lock;
static pthread_mutex_t Done_lock = PTHREAD_MUTEX_INITIALIZER;
static int Tracing_stop;
static pthread_t *Tracing_threads;

struct available_event {
	char *name;
	char *options;
	struct available_event *next;
};

static struct available_event *Available_events;

static LIST_HEAD(Enabled_event_list);
struct event {
	struct list_head list;
	char *options;
	char name[];
};

static void *append_data(const char *dir, const char *fn, void *data, int nr_bytes);
static char *read_one_line(const char *dir, const char *fn, FILE **fp, char **line, size_t *len);
static char *append_one_line(const char *dir, const char *fn, char *line);
static int add_one_event(char *event_spec);

static void bpf_dumpbin(const struct bpf_program *fp)
{
	struct bpf_insn *insn;
	int i;
	int n = fp->bf_len;

	fprintf(stderr, "BPF instructions\n");
	insn = fp->bf_insns;
	for (i = 0; i < n; ++insn, ++i) {
		fprintf(stderr, "\t%s\n", bpf_image(insn, i));
		fprintf(stderr, "\t\t{ 0x%x, %d, %d, 0x%08x },\n",
		       insn->code, insn->jt, insn->jf, insn->k);
	}
}

static int bpf_compile(char *bpf_string, int linktype)
{
	pcap_t *handle;
	int ret;

	handle = pcap_open_dead(linktype, 100);
	ret = pcap_compile(handle, &Def_bpf_program, bpf_string, 1, 0);
	if (ret < 0) {
		pcap_perror(handle, "invalid filter: ");
		exit(1);
	}
	pcap_close(handle);
	return 0;
}

static inline void *skbtrace_filters_enable(void)
{
	return append_data(Debugfs_path, SKBTRACE_FILTERS_PATH,
			&Def_bpf_program, sizeof(struct bpf_program));
}

static inline char *skbtrace_enable_default(char *spec)
{
	return append_one_line(Debugfs_path, SKBTRACE_ENABLED_PATH, spec);
}

static inline char *skbtrace_enable(struct event *e)
{
	char spec[4096];

	if (e) {
		if (e->options)
			snprintf(spec, 4096, "%s,%s", e->name, e->options);
		else
			snprintf(spec, 4096, "%s", e->name);
	} else {
		strcpy(spec, "-*");
	}

	return append_one_line(Debugfs_path, SKBTRACE_ENABLED_PATH, spec);
}

static inline char *skbtrace_dropped_reset(void)
{
	return append_one_line(Debugfs_path, SKBTRACE_DROPPED_PATH, "0 0 0");
}

static inline char *skbtrace_version(void)
{
	FILE *fp = NULL;
	char *line = NULL;
	size_t len = 0;

	read_one_line(Debugfs_path, SKBTRACE_VERSION_PATH, &fp, &line, &len);
	if (fp)
		fclose(fp); /* only care first line */
	return line;
}

static inline char *skbtrace_dropped(void)
{
	FILE *fp = NULL;
	char *line = NULL;
	size_t len = 0;

	read_one_line(Debugfs_path, SKBTRACE_DROPPED_PATH, &fp, &line, &len);
	if (fp)
		fclose(fp); /* only care first line */
	return line;
}

static char *read_one_line(const char *dir, const char *fn, FILE **fp, char **line, size_t *len)
{
	char *path;

	if (!*fp) {
		*line = NULL;
		path = malloc(strlen(dir) + strlen(fn) + 2);
		if (!path)
			return NULL;
		sprintf(path, "%s/%s", dir, fn);
		*fp = fopen(path, "r");
		free(path);
		if (!*fp)
			return NULL;
	}

	if (-1 == getline(line, len, *fp)) {
		fclose(*fp);
		*fp = NULL;
		return NULL;
	}
	(*line)[strlen(*line) - 1] = '\x0'; /* remove tailing '\n' */
	return *line;
}

static void *append_data(const char *dir, const char *fn, void *data, int nr_bytes)
{
	char *path;
	int fd;

	path = malloc(strlen(dir) + strlen(fn) + 2);
	if (!path)
		return NULL;
	sprintf(path, "%s/%s", dir, fn);
	fd = open(path, O_WRONLY|O_APPEND);
	free(path);
	if (fd < 0)
		return NULL;

	if (nr_bytes != write(fd, data, nr_bytes)) {
		close(fd);
		return NULL;
	}

	close(fd);
	return data;
}

static char *append_one_line(const char *dir, const char *fn, char *line)
{
	int nr_bytes;

	nr_bytes = strlen(line);
	return append_data(dir, fn, line, nr_bytes);
}

/* This assumes that we enabled trace events support in kernel */
static int load_available_events(void)
{
	char *line = NULL, *end;
	FILE * fp = NULL;
	size_t len = 0;

	Available_events = NULL;

	while (read_one_line(Debugfs_path, SKBTRACE_ENABLED_PATH, &fp, &line, &len)) {
		struct available_event *e;

		e = malloc(sizeof(struct available_event));
		if (!e)
			return -ENOMEM;
		end = strchr(line, ' ');
		if (!end)
			continue;
		*end = '\x0';
		end = strchr(++end, ' '); /* skip "enabled:X " */
		if (end)
			end++;
		e->name = strdup(line);
		if (!e->name)
			return -ENOMEM;
		if (end) {
			e->options = strdup(end);
			if (!e->options)
				return -ENOMEM;
		} else
			e->options = "none";
		e->next = Available_events;
		Available_events = e;
	}
	if (line)
		free(line);
	return 0;
}

static void show_available_events(void)
{
	struct available_event *avail_e;

	fprintf(stderr, "Available events and options:\n");
	avail_e = Available_events;
	while (avail_e) {
		fprintf(stderr, "\t%s\n", avail_e->name);
		fprintf(stderr, "\t\tOptions: %s\n",
			avail_e->options);
		avail_e = avail_e->next;
	}
}

static void show_version(char *argv[])
{
	fprintf(stderr, "Version: %s %s\n", argv[0], SKBTRACE_VERSION);
	exit(0);
}

static void show_usage(char *argv[])
{
	fprintf(stderr, "Usage: %s %s\n%s", argv[0], SKBTRACE_VERSION, USAGE_STR);
	exit(0);
}

static void check_debugfs(void)
{
	struct statfs stfs;

	if (statfs(Debugfs_path, &stfs) < 0 || stfs.f_type != (long)DEBUGFS_TYPE) {
		fprintf(stderr, "Invalid debug path %s\n", Debugfs_path);
		exit(1);
	}

	if (load_available_events()) {
		fprintf(stderr, "Failed to load available events\n");
		exit(1);
	}
}

static void show_skbtrace_events(void)
{
	check_debugfs();
	show_available_events();
	exit(0);
}

static int handle_channel_arg(char *channels_list)
{
	char *cur;

	Channels_mask = 0;
	cur = strsep(&channels_list, ",");
	while (cur) {
		if (!strcmp("syscall", cur))
			Channels_mask |= (1<<SC);
		else if (!strcmp("softirq", cur))
			Channels_mask |= (1<<SI);
		else if (!strcmp("hardirq", cur))
			Channels_mask |= (1<<HW);
		else
			return -EINVAL;
		cur = strsep(&channels_list, ",");
	}
	return 0;
}

static int handle_processor_arg(char *processors_list)
{
	char *cur;
	int start, end;

	cur = strsep(&processors_list, ",");
	while (cur) {
		int n = sscanf(cur, "%d-%d", &start, &end);
		if (n <= 0)
			return -EINVAL;
		if (start >= Nr_processors || start < 0)
			return -EINVAL;
		if (1 == n)
			end = start;
		else if (end >= Nr_processors || end < 0 || end < start)
			return -EINVAL;
		for (; start <= end; start++)
			Processors_mask[start] = 1;
		cur = strsep(&processors_list, ",");
	}
	return 0;
}

static void handle_args(int argc, char *argv[])
{
	int opt;
	int has_p = 0;

	while ((opt = getopt(argc, argv, OPTSTRING)) != -1) {
	switch (opt) {
	case 'v':
		show_version(argv);	/* exit here */
	case 'l':
		show_skbtrace_events();	/* exit here */
	case 'f':
		Overwrite_existed_results = 0;
		break;
	case 's':
		On_stdout = 1;
		pthread_spin_init(&Stdout_lock, PTHREAD_PROCESS_PRIVATE);
		break;
	case 'h':
	default:
		show_usage(argv);
	case 'e':
		if (add_one_event(optarg)) {
			fprintf(stderr, "failed to add event '%s'\n", optarg);
			exit(1);
		}
		break;
	case 'F':
		bpf_compile(optarg, DLT_RAW);
		break;
	case 'c':
		Conf_pathlist = optarg;
		break;
	case 'C':
		if (handle_channel_arg(optarg)) {
			fprintf(stderr, "Invalid channels list\n");
			exit(1);
		}
		break;
	case 'p':
		if (handle_processor_arg(optarg)) {
			fprintf(stderr, "Invalid processors list\n");
			exit(1);
		}
		has_p = 1;
		break;
	case 'r':
		Debugfs_path = optarg;
		break;
	case 'D':
		Output_path = optarg;
		break;
	case 'w':
		Stop_timeout = atoi(optarg);
		if (Stop_timeout <= 0) {
			fprintf(stderr, "Invalid tracing time length, must be > 0\n");
			exit(1);
		}
		break;
	case 'V':
		++Verbose;
		break;
	case 'b':
		Subbuf_size = atoi(optarg);
		break;
	case 'n':
		Subbuf_nr = atoi(optarg);
		break;
	}
	}

	if (!has_p) {
		int i;

		for (i=0; i<Nr_processors; i++)
			Processors_mask[i] = 1;
	}

	if (optind < argc) {
		int i, nr = argc - optind;

		if (Stop_timeout) {
			fprintf(stderr, "Unknown option: %s\n", argv[optind]);
			exit(1);
		}

		Cmd_line = malloc(sizeof(char *) * (1 + nr));
		if (!Cmd_line) {
			fprintf(stderr, "Failed to allocate memory\n");
			exit(1);
		}
		memset(Cmd_line, 0, sizeof(char *) * nr);
		for (i = 0; i < nr; i++)
			Cmd_line[i] = argv[optind+i];
	}

	if (!Verbose)
		return;

	fprintf(stderr, "Search path for skbtrace.conf = %s\n", Conf_pathlist);
	fprintf(stderr, "Debugfs mount path = %s\n", Debugfs_path);
	fprintf(stderr, "Results output path = %s\n", Output_path);
	fprintf(stderr, "Tracing during time = %d secs\n", Stop_timeout);
	fprintf(stderr, "Relayfs subbuf size = %d Bytes\n", Subbuf_size);
	fprintf(stderr, "Relayfs subbuf count = %d\n", Subbuf_nr);
	if (!Stop_timeout)
		fprintf(stderr, "Tracing go on until you press <Ctrl-C>\n");
	else
		fprintf(stderr, "Tracing time length = %d secs\n", Stop_timeout);
}

static int is_available_event(const char *event_name)
{
	struct available_event *avail_e;

	avail_e = Available_events;
	while (avail_e) {
		if (!strcmp(avail_e->name, event_name))
			return 1;
		avail_e = avail_e->next;
	}
	return 0;
}

static int validate_events(void)
{
	struct event *e;

	list_for_each_entry(e, &Enabled_event_list, list) {
		if (!is_available_event(e->name)) {
			fprintf(stderr, "%s is not an available event.\n", e->name);
			return 0;
		}
	}

	return 1;
}

static int add_one_event(char *event_spec)
{
	int sz;
	char *name, *options;
	struct event *e;

	if (!event_spec)
		return -EINVAL;

	sz = strlen(event_spec) + 1;
	name = event_spec;
	options = strchr(event_spec, ',');
	if (options) {
		*options = '\x0';
		options++;
		if ('\x0' == *options)
			options = NULL;
	}

	list_for_each_entry(e, &Enabled_event_list, list) {
		if (!strcmp(e->name, name))
			return -EEXIST;
	}

	e = malloc(sizeof(struct event) + sz);
	if (!e) {
		fprintf(stderr, "Need more memory\n");
		exit(1);
	}

	INIT_LIST_HEAD(&e->list);
	memcpy((char*)e->name, event_spec, sz);
	e->options = options;
	list_add_tail(&e->list, &Enabled_event_list);
	return 0;
}

static void load_one_conf(const char *dir)
{
	char *line = NULL;
	FILE * fp = NULL;
	size_t len = 0;

	while (read_one_line(dir, SKBTRACE_CONF, &fp, &line, &len)) {
		if (add_one_event(line)) {
			fprintf(stderr, "failed to add event '%s'\n", line);
			break;
		}
	}
	if (line)
		free(line);
}

static void load_conf(void)
{
	char *dir_list, *dir;

	if (!list_empty(&Enabled_event_list))
		/* Use any -e option will bypass configration */
		return;

	dir_list = strdup(Conf_pathlist);
	dir = strtok(dir_list, ":");
	while (dir) {
		load_one_conf(dir);
		dir = strtok(NULL, ":");
	}
	free(dir_list);
}

static void skbtrace_subbuf_setup(void)
{
	char buf[24];

	sprintf(buf, "%d", Subbuf_size);
	if (!append_one_line(Debugfs_path, SKBTRACE_SUBBUF_SIZE_PATH, buf)) {
		fprintf(stderr, "Failed to setup subbuf_size=%s: %s\n", buf, strerror(errno));
		exit(1);
	}

	sprintf(buf, "%d", Subbuf_nr);
	if (!append_one_line(Debugfs_path, SKBTRACE_SUBBUF_NR_PATH, buf)) {
		fprintf(stderr, "Failed to setup subbuf_nr=%s: %s\n", buf, strerror(errno));
		exit(1);
	}
}

static void enable_skbtrace(void)
{
	char *line;
	struct available_event *avail_e;
	struct event *e;

	line = skbtrace_version();
	if (!line || strcmp(line, SKBTRACE_K_VERSION)) {
		if (line)
			free(line);
		fprintf(stderr, "Requires skbtrace kernel API version " SKBTRACE_K_VERSION "\n");
		exit(1);
	}

	free(line);

	skbtrace_enable(NULL);
	skbtrace_enable(NULL);
	skbtrace_dropped_reset();
	skbtrace_subbuf_setup();

	if (Def_bpf_program.bf_len > 0) {
		if (Verbose > 1)
			bpf_dumpbin(&Def_bpf_program);
		skbtrace_filters_enable();
	}

	if (Verbose)
		fprintf(stderr, "Enabled event list:\n");

	list_for_each_entry(e, &Enabled_event_list, list) {
		if (Verbose)
			fprintf(stderr, "\t%s %s\n", (char*)e->name, e->options ? : "");
		if (!skbtrace_enable(e)) {
			fprintf(stderr, "Failed to enable event '%s' with option(s) '%s', use -l option list available events\n",
				       (char*)e->name, e->options ? : "");
			exit(1);
		}
	}

	if (!list_empty(&Enabled_event_list))
		goto quit;

	avail_e = Available_events;
	while (avail_e) {
		if (Verbose)
			fprintf(stderr, "\t%s\n", avail_e->name);
		skbtrace_enable_default(avail_e->name);
		avail_e = avail_e->next;
	}
quit:
	pthread_mutex_lock(&Done_lock);
}

static void disable_skbtrace(void)
{
	char *dropped;
	unsigned long sc, si, hw;
	long cpu;

	skbtrace_enable(NULL); /* stop tracing */
	Tracing_stop = 1;
	for (cpu = 0; cpu < Nr_processors; cpu++) {
		char *msg;

		pthread_join(Tracing_threads[cpu], (void**)&msg);
		if (msg)
			fprintf(stderr, "Thread-%ld: %s\n", cpu, msg);
	}

	skbtrace_enable(NULL); /* delete channels */
	dropped = skbtrace_dropped();
	skbtrace_dropped_reset();
	if (!dropped)
		goto quit;
	sscanf(dropped, "%lu %lu %lu", &hw, &si, &sc);
	fprintf(stderr, "Dropped: hardirq/%lu softirq/%lu syscall/%lu\n",
							hw, si, sc);
quit:
	pthread_mutex_unlock(&Done_lock);
}

static void handle_sigint(__attribute__((__unused__)) int sig)
{
	disable_skbtrace();
	exit(0);
}

static void* err_msg(char *source)
{
	char *msg;
	int saved_errno;

	saved_errno = errno;
	msg = malloc(strlen(source) + 256);
	if (!msg)
		return source;
	if (saved_errno)
		sprintf(msg, "%s failed: %s", source, strerror(saved_errno));
	else
		sprintf(msg, "%s failed: Unknown reason", source);
		
	return msg;
}

static void* lock_on_cpu(long cpu)
{
	cpu_set_t cpu_mask;

	CPU_ZERO(&cpu_mask);
	CPU_SET((int)cpu, &cpu_mask);
	if (sched_setaffinity(0, sizeof(cpu_mask), &cpu_mask) < 0)
		return err_msg("sched_setaffinity()");

	return NULL;
}

static void clearup_tracing(int fd[NR_CHANNELS*2])
{
	unsigned int i;

	for (i = 0; i < sizeof(fd)/sizeof(int); i++) {
		if (On_stdout && i >= NR_CHANNELS)
			continue;
		if (fd[i] >= 0)
			close(fd[i]);
	}
}

static void* __setup_tracing_fd(char *prefix, char *fn, long cpu,
						int fd[NR_CHANNELS*2], int idx)
{
	char *path, *filename;
	int flags;
	mode_t mode;

	if (!Processors_mask[cpu]) {
		fd[idx] = -1;
		return NULL;
	}

	if (On_stdout && idx >= NR_CHANNELS) {
		fd[idx] = STDOUT_FILENO;
		return NULL;
	}

	if (!(Channels_mask & (1<<idx))) {
		fd[idx] = -1;
		return NULL;
	}

	/* +6 :
	 * +2, reserve for inserting "/" and tailing '\x0'
	 * +4, for max 9999 CPUs
	 */
	path = malloc(strlen(prefix) + strlen(fn) + 6);
	if (!path)
		return err_msg("malloc()");

	filename = (idx >= NR_CHANNELS) ? basename(fn) : fn;
	sprintf(path, "%s/%s%ld", prefix, filename, cpu);

	if (idx >= NR_CHANNELS)
		flags = O_RDWR | O_CREAT | O_TRUNC | Overwrite_existed_results;
	else
		flags = O_NONBLOCK | O_RDONLY;
	mode = (idx >= NR_CHANNELS) ? (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) : 0;

	fd[idx] = open(path, flags, mode);
	if (fd[idx] < 0) {
		char *msg;

		msg = malloc(strlen(path) + 32);
		if (!msg)
			return err_msg((idx >= NR_CHANNELS) ? "open(OUTPUT-DIR/trace.*.cpu*)" : "open(DEBUGFS/trace.*.cpu*)");
		if (idx >= NR_CHANNELS)
			sprintf(msg, "open '%s' for writing", path);
		else
			sprintf(msg, "open '%s' for reading", path);
		return err_msg(msg);
	}
	free(path);
	return NULL;
}

static void* setup_tracing(long cpu, int fd[NR_CHANNELS*2])
{
	char *msg;
	unsigned int i;

	for (i = 0; i < sizeof(fd)/sizeof(int); i++)
		fd[i] = -1;

#define setup_tracing_fd(prefix, fn, cpu, idx)\
	msg = __setup_tracing_fd(prefix, fn, cpu, fd, idx);\
	if (msg)\
		goto quit;

	setup_tracing_fd(Debugfs_path, SKBTRACE_SYSCALL_PATH, cpu, SC);
	setup_tracing_fd(Debugfs_path, SKBTRACE_SOFTIRQ_PATH, cpu, SI);
	setup_tracing_fd(Debugfs_path, SKBTRACE_HARDIRQ_PATH, cpu, HW);

	setup_tracing_fd(Output_path, SKBTRACE_SYSCALL_PATH, cpu, SC + NR_CHANNELS);
	setup_tracing_fd(Output_path, SKBTRACE_SOFTIRQ_PATH, cpu, SI + NR_CHANNELS);
	setup_tracing_fd(Output_path, SKBTRACE_HARDIRQ_PATH, cpu, HW + NR_CHANNELS);
#undef setup_tracing_fd
	return NULL;
quit:
	clearup_tracing(fd);
	return msg;
}

typedef struct {
	int ifd, ofd;
	void *buf;
	ssize_t size;
	long channel;
} tracing_t;

static void* do_tracing_targeted_file(int epfd, long cpu)
{
	tracing_t *tracing;
	struct epoll_event events[NR_CHANNELS];
	int nr_events, last_round = 0;
	ssize_t done;

	while ((nr_events = epoll_wait(epfd, (struct epoll_event*)events, NR_CHANNELS, 100)) >= 0) {

if (Verbose > 1 && nr_events) {
	fprintf(stderr, "epoll_wait() return with %d events\n", nr_events);
}

		while (--nr_events >= 0) {
			ssize_t total, offset;
 			
			if (events[nr_events].events & EPOLLERR)
				return err_msg("epoll_wait()");
			tracing = (tracing_t*)events[nr_events].data.ptr;
			total = Subbuf_size*Subbuf_nr;
			do {
				if (tracing->buf)
					munmap(tracing->buf, total + getpagesize());
				offset = tracing->size & (~(getpagesize() - 1));
				if (ftruncate(tracing->ofd, tracing->size + total + getpagesize()) < 0)
					return err_msg("ftruncate()");
				tracing->buf = mmap(NULL, total + getpagesize(), PROT_WRITE, MAP_SHARED,
							tracing->ofd, offset);
				if (MAP_FAILED == tracing->buf)
					return err_msg("mmap()");
				done = read(tracing->ifd, tracing->buf + tracing->size - offset, total);
				if (done > 0)
					tracing->size += done;
				else if (!done || EAGAIN == errno)
					break;
				else
					return err_msg("read()");
if (Verbose > 1)
{
				fprintf(stderr, "cpu=%ld ifd=%d ofd=%d offset=%ld read=%ld size=%ld\n",
						cpu, tracing->ifd, tracing->ofd,
						offset, done,tracing->size + (done > 0 ? done : 0));
}
			} while (1);
		}
		if (Tracing_stop) {
			if (!last_round) {
				last_round = 1;
				continue;
			} else if (done <= 0)
				break;
		}

	}

	return Tracing_stop ? NULL : err_msg("epoll_wait()");
}

static void* do_tracing_targeted_stdout(int epfd, long cpu)
{
	tracing_t *tracing;
	struct epoll_event events[NR_CHANNELS];
	int nr_events, last_round = 0;
	char *buf;
	ssize_t done;

	buf = malloc(Subbuf_size*Subbuf_nr);
	if (!buf)
		return "Need more memory";

	while ((nr_events = epoll_wait(epfd, (struct epoll_event*)events, NR_CHANNELS, 100)) >= 0) {

if (Verbose > 1 && nr_events) {
	fprintf(stderr, "epoll_wait() return with %d events\n", nr_events);
}
		while (--nr_events >= 0) {
			if (events[nr_events].events & EPOLLERR)
				return err_msg("epoll_wait()");
			tracing = (tracing_t*)events[nr_events].data.ptr;
			do {
				done = read(tracing->ifd, buf, Subbuf_size*Subbuf_nr);
				if (done > 0) {
					pthread_spin_lock(&Stdout_lock);
					write(STDOUT_FILENO, &cpu, sizeof(long));
					write(STDOUT_FILENO, &tracing->channel, sizeof(long));
					write(STDOUT_FILENO, &done, sizeof(ssize_t));
					write(STDOUT_FILENO, buf, done);
					pthread_spin_unlock(&Stdout_lock);
if (Verbose > 1)
{
				fprintf(stderr, "cpu=%ld ifd=%d ofd=1 read=%ld\n",
						cpu, tracing->ifd, done);
}
					continue;
				} else if (!done || EAGAIN != errno)
					break;
				else
					return err_msg("read()");
			} while (1);
		}
		if (Tracing_stop) {
			if (!last_round) {
				last_round = 1;
				continue;
			} else if (done <= 0)
				break;
		}
	}

	return NULL;
}

static void* do_tracing(long cpu, int fd[NR_CHANNELS*2])
{
	int epfd;
	unsigned int i;
	struct epoll_event event;
	tracing_t tracing_array[NR_CHANNELS];
	void *msg;

	epfd = epoll_create(NR_CHANNELS);
	if (epfd < 0)
		return err_msg("epoll_create()");

	for (i = 0; i < NR_CHANNELS; i++) {
		if (fd[i] < 0 || fd[i + NR_CHANNELS] < 0)
			continue;
		tracing_array[i].ifd = fd[i];
		tracing_array[i].ofd = fd[i + NR_CHANNELS];
		tracing_array[i].buf = NULL;
		tracing_array[i].size = 0UL;
		tracing_array[i].channel = i;
		event.events = EPOLLIN|EPOLLET;
		event.data.ptr = (void*)(&tracing_array[i]);
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd[i], &event) < 0)
			return err_msg("epoll_ctl()");
	}

	if (!On_stdout)
		msg = do_tracing_targeted_file(epfd, cpu);
	else
		msg = do_tracing_targeted_stdout(epfd, cpu);

	for (i = 0; !On_stdout && i < NR_CHANNELS; i++)
		ftruncate(tracing_array[i].ofd, tracing_array[i].size);

	close(epfd);
	return msg;
}

static void *tracing(void *p_cpu)
{
	long cpu = (long)p_cpu;
	int fd[NR_CHANNELS*2]; /* first half are input fds, last half are output fds */
	void *msg;

	msg = lock_on_cpu(cpu);
	if (msg) {
		fprintf(stderr, "Thread-%ld: %s\n", cpu, (char*)msg);
		msg = NULL;
		kill(getpid(), SIGINT);
		goto quit;
	}

	msg = setup_tracing(cpu, fd);
	if (msg) {
		fprintf(stderr, "Thread-%ld: %s\n", cpu, (char*)msg);
		msg = NULL;
		kill(getpid(), SIGINT);
		goto quit;
	}

	msg = do_tracing(cpu, fd);
	if (msg)
		goto quit;

	clearup_tracing(fd);
quit:
	pthread_exit(msg);
}

static void start_tracing(void)
{
	pid_t pid;
	long cpu;

	if (!validate_events())
		return;

        setlocale(LC_NUMERIC, "en_US");

	Tracing_threads = malloc(sizeof(pthread_t) * Nr_processors);
	if (!Tracing_threads) {
		fprintf(stderr, "Need more memory\n");
		return;
	}

        signal(SIGINT, handle_sigint);
        signal(SIGHUP, handle_sigint);
        signal(SIGTERM, handle_sigint);
        signal(SIGALRM, handle_sigint);
        signal(SIGPIPE, SIG_IGN);

	enable_skbtrace();

	if (Cmd_line) {
		pid = fork();
		if (pid < 0) {
			fprintf(stderr, "fork() failed: %s\n", strerror(errno));
			exit(1);
		} else if (0 == pid) {
			execvp(Cmd_line[0], Cmd_line);
			exit(1);
		}
	}

	for (cpu = 0; cpu < Nr_processors; cpu++) {
		if (pthread_create(Tracing_threads+cpu, NULL, tracing, (void*)cpu))
			break;
	}
	
	if (Stop_timeout > 0) {
		sleep(Stop_timeout);
		disable_skbtrace();
	} else if (Cmd_line) {
		waitpid(pid, NULL, 0);
		disable_skbtrace();
	}

	/* Wait for disable_skbtrace() finished */
	pthread_mutex_lock(&Done_lock);
}

static void processors_mask_init(void)
{
	int i;

        Nr_processors = sysconf(_SC_NPROCESSORS_ONLN);
        if (Nr_processors < 0) {
                fprintf(stderr, "sysconf(_SC_NPROCESSORS_ONLN) failed %d/%s\n",
                        errno, strerror(errno));
		exit(1);
        }
	Processors_mask = malloc(sizeof(int)*Nr_processors);
	if (!Processors_mask) {
                fprintf(stderr, "need more memory\n");
		exit(1);
	}
	for (i=0; i<Nr_processors; i++)
		Processors_mask[i] = 0;
}

int main(int argc, char *argv[])
{
	system("/sbin/modprobe skbtrace >/dev/null 2>&1");
	processors_mask_init();
	handle_args(argc, argv);
	check_debugfs();
	load_conf();

	start_tracing();
	return 0;
}
