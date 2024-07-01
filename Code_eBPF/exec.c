#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <string.h>
#include "msg.h"  
#include "ringbuf.skel.h"  
#include <time.h>
#define LOG_FILE_PATH "/home/hieu/Desktop/eBPF/j.txt"


static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur   = RLIM_INFINITY,
        .rlim_max   = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

static int handle_msg(void *ctx, void *data, size_t sz)
{   
    FILE *log_file = fopen(LOG_FILE_PATH, "a");
    const struct my_msg *msg = data;
    time_t current_time;
    struct tm *time_info;
    char timeString[9];
    time(&current_time);
    time_info = localtime(&current_time);
    strftime(timeString, sizeof(timeString), "%H:%M:%S", time_info);

    if (msg->pathname && strncmp(msg->pathname, "/etc/init.d", 10) == 0){
        fprintf(log_file, "\nTime: %s\n", timeString);
        fprintf(log_file, "PID %d, command: %s, path: %s\n", msg->pid, msg->command, msg->pathname);}


    fclose(log_file);
    return 0;
}

int main(void)
{
    bump_memlock_rlimit();

    struct ringbuf *skel = ringbuf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    if (ringbuf__load(skel)) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        
    }

    if (ringbuf__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_msg, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        
    }

    while (1) {
        ring_buffer__poll(rb, 1000);  // Poll every 1000 microseconds (1 millisecond)
    }


    return 0;
}
