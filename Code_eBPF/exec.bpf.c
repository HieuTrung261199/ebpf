#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "msg.h"

#define O_CREAT 0x40
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct mkdir_params_t {
    u64 __unused;
    u64 __unused2;
    int dfd;
    char *pathname;
    int flags;
    mode_t mode;
};


SEC("tp/syscalls/sys_enter_openat")
int handle_syscall(struct mkdir_params_t *params)
{
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    struct my_msg *msg;

    // Kiểm tra nếu cờ O_CREAT được thiết lập, có nghĩa là file đang được tạo
    if (!(params->flags & O_CREAT))
        return 0;

    msg = bpf_ringbuf_reserve(&rb, sizeof(*msg), 0);
    if (!msg) {
        bpf_printk("ERROR: unable to reserve memory\n");
        return 0;
    }

    msg->pid = BPF_CORE_READ(task, pid);
    bpf_get_current_comm(&msg->command, sizeof(msg->command));
    bpf_probe_read_user_str(msg->pathname, sizeof(msg->pathname), params->pathname);
    bpf_ringbuf_submit(msg, 0);
    bpf_printk("File created!");

    return 0;
}

/*
struct change_params_t {
    uint64_t unused1;
    uint64_t unused2;
    unsigned int fd;
    const char * buf;
    size_t count;
    loff_t pos;
};

SEC("tp/syscalls/sys_enter_pwrite64")
int trace_sys_enter_pwrite64(struct change_params_t *params) {
    // Print or process the values as needed
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    struct my_msg *msg;
    msg = bpf_ringbuf_reserve(&rb, sizeof(*msg), 0);
    if (!msg) {
        bpf_printk("ERROR: unable to reserve memory\n");
        return 0;
    }
    
     msg -> fd = params -> fd ;
     msg -> count = params -> count ;
    msg -> pos  =  params -> pos;
    msg->pid = BPF_CORE_READ(task, pid);
    bpf_get_current_comm(&msg->command, sizeof(msg->command));
    //bpf_printk("sys_enter_pwrite64: fd=%lld,  count=%lld, pos=%lld\\n",params -> fd, params -> count, params ->  pos);
    bpf_ringbuf_submit(msg, 0);
    
    return 0;
}*/
char LICENSE[] SEC("license") = "GPL";

