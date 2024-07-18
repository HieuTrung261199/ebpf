#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <string.h>
#include <time.h> 
#include "msg.h"
#include "ringbuf.skel.h"  

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

static int system_process_modification(const char *pathname) {
    // Check if the file is in important system folders
    if (strncmp(pathname, "/etc/init.d/", 12) == 0 ||
        strncmp(pathname, "/etc/systemd/system/", 20) == 0 ||
        strncmp(pathname, "/usr/bin/", 9) == 0 ||
        strncmp(pathname, "/usr/sbin/", 10) == 0 ||
        strncmp(pathname, "./infec/",8 ) == 0) {
        return 1;
    }
    return 0;
}

static void log_current_time(FILE *log_file) {
    if (log_file == NULL) {
        fprintf(stderr, "Error: log_file is NULL\n");
        return;
    }

    time_t current_time;
    struct tm *time_info;
    char timeString[9];

    time(&current_time);
    time_info = localtime(&current_time);
    strftime(timeString, sizeof(timeString), "%H:%M:%S", time_info);

    fprintf(log_file, "\nTime: %s\n", timeString);
}

static int handle_open(void *ctx, void *data, size_t sz)
{   
    FILE *log_file = fopen(LOG_FILE_PATH, "a");
    const struct add_file *msg = data;

    if ( msg->command[0] != '\0' && strncmp(msg->command, "vmtoolsd", 7) != 0 && strncmp(msg->command, "cpuUsage.sh", 11) != 0 && system_process_modification(msg->pathname)){
        log_current_time(log_file);
        fprintf(log_file, "PID %d, command: %s, path: %s\n", msg->pid, msg->command, msg->pathname);
        fclose(log_file);
        }

    return 0;
}

static int handle_access(void *ctx, void *data, size_t sz)
{   
    FILE *log_file = fopen(LOG_FILE_PATH, "a");
    const struct access *msg = data;
    
    if ( msg->command[0] != '\0' && strncmp(msg->command, "vmtoolsd", 7) != 0 && strncmp(msg->command, "cpuUsage.sh", 11) != 0 && system_process_modification(msg->pathname) ){
        fprintf(log_file, "PID %d accessed file, comand %s , %s\n", msg->pid, msg->command, msg->pathname);
        log_current_time(log_file);
        fclose(log_file);
        }
    
    return 0;
}

static int handle_uid(void *ctx, void *data, size_t sz)
{   
    const struct getid *msg = data;

    // Check if it's root
    if(msg->uid == 0){
        FILE *log_file = fopen(LOG_FILE_PATH, "a");
        log_current_time(log_file);
        fprintf(log_file, "PID %d called setuid with UID %llu\n", msg->pid, msg->uid);
        fclose(log_file);
        return 1;   //Detect behavior
    }

    return 0;   //None
}

static int handle_content_evt(void *ctx, void *data, size_t sz)
{
    const struct content *msg = data;
    FILE *log_file = fopen(LOG_FILE_PATH, "a");
    log_current_time(log_file);
    fprintf(log_file, "sys_enter_pwrite64: fd=%d,  count=%zu, pos=%ld\n",msg -> fd, msg -> count, msg ->  pos);
    fclose(log_file);
    return 0;
}

int main(void)
{   
    bump_memlock_rlimit();

    struct ringbuf *skel = ringbuf__open();
    if (!skel){
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    if (ringbuf__load(skel)){
        fprintf(stderr, "Failed to load BPF skeleton\n");
    }

    if (ringbuf__attach(skel)){
        fprintf(stderr, "Failed to attach BPF skeleton\n");  
    }

    struct ring_buffer *rb_open = ring_buffer__new(bpf_map__fd(skel->maps.rb_open), handle_open, NULL, NULL);
    struct ring_buffer *rb_content = ring_buffer__new(bpf_map__fd(skel->maps.rb_content), handle_content_evt, NULL, NULL);
    struct ring_buffer *rb_access = ring_buffer__new(bpf_map__fd(skel->maps.rb_access), handle_access, NULL, NULL);
    struct ring_buffer *rb_id = ring_buffer__new(bpf_map__fd(skel->maps.rb_id), handle_uid, NULL, NULL);
    
    while (1) {
        ring_buffer__poll(rb_open, 1000);
        ring_buffer__poll(rb_access, 1000);
        ring_buffer__poll(rb_id, 1000);
        ring_buffer__poll(rb_content, 1000);
    }

    return 0;
}
