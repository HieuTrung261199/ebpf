#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <string.h>
#include "msg.h"
#include "ringbuf.skel.h"  
#include <time.h>
#define LOG_FILE_PATH "/home/hieu/Desktop/eBPF/log.txt" 


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

/*
static int handle_open(void *ctx, void *data, size_t sz)
{   
    FILE *log_file = fopen(LOG_FILE_PATH, "a");
    const struct add_file *msg = data;
    
    time_t current_time;
    struct tm *time_info;
    char timeString[9];
    time(&current_time);
    time_info = localtime(&current_time);
    strftime(timeString, sizeof(timeString), "%H:%M:%S", time_info);
    //if (msg->pathname && strncmp(msg->pathname, "/home/hieu/Desktop/eBPF/log.txt", 30) != 0){}
    
    if (msg->pathname && strncmp(msg->pathname, "/etc/init.d", 10) == 0){
        fprintf(stdout, "\nTime: %s\n", timeString);
        fprintf(stdout, "PID %d, command: %s, path: %s\n", msg->pid, msg->command, msg->pathname);}
    fclose(log_file);
    return 0;
}*/


static int handle_exec(void *ctx, void *data, size_t sz)
{   
    FILE *log_file = fopen(LOG_FILE_PATH, "a");
    const struct execve *msg = data;

    time_t current_time;
    struct tm *time_info;
    char timeString[9];
    time(&current_time);
    time_info = localtime(&current_time);
    strftime(timeString, sizeof(timeString), "%H:%M:%S", time_info);

    if (msg->command && strncmp(msg->command, "cpuUsage.sh", 10) != 0){
        fprintf(log_file, "\nTime: %s\n", timeString);
        fprintf(log_file, "PID %d, command: %s, path: %s\n", msg->pid, msg->command, msg->filename);}


    fclose(log_file);
    return 0;
}


static int handle_content_evt(void *ctx, void *data, size_t sz)
{
    const struct content *msg = data;
    FILE *log_file = fopen(LOG_FILE_PATH, "a");
    time_t current_time;
    struct tm *time_info;
    char timeString[9];
    time(&current_time);
    time_info = localtime(&current_time);
    strftime(timeString, sizeof(timeString), "%H:%M:%S", time_info);
    fprintf(log_file, "\nTime: %s\n", timeString);
    fprintf(log_file, "sys_enter_pwrite64: fd=%lld,  count=%lld, pos=%lld\n",msg -> fd, msg -> count, msg ->  pos);
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

    struct ring_buffer *rb_exec = ring_buffer__new(bpf_map__fd(skel->maps.rb_exec), handle_exec, NULL, NULL);
    //struct ring_buffer *rb_open = ring_buffer__new(bpf_map__fd(skel->maps.rb_open), handle_open, NULL, NULL);
    struct ring_buffer *rb_content = ring_buffer__new(bpf_map__fd(skel->maps.rb_content), handle_content_evt, NULL, NULL);

    while (1) {
        ring_buffer__poll(rb_exec, 1000);  // Poll every 1000 microseconds (1 millisecond)
        //ring_buffer__poll(rb_open, 1000);
        ring_buffer__poll(rb_content, 1000);
    }


    return 0;
}
