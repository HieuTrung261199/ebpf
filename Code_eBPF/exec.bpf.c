#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "msg.h"


#define O_CREAT 0x02

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} rb_content SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} rb_access SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} rb_open SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} rb_id SEC(".maps");

//Event for create file in /etc/init.d
struct addfile_params_t {
    u64 __unused;
    u64 __unused2;
    int dfd;
    char *pathname;
    int flags;
    mode_t mode;
};



//Event for acess
struct acess_params_t {
    u64 __unused;
    u64 __unused2;
    char *pathname;
};

//Event for getid
struct id_params_t {
    u64 __unused;
    u64 __unused2;
    unsigned long long uid;
};


//Event for execve
struct exec_params_t {
    u64 __unused;
    u64 __unused2;
    char *file;
};

//Event for Content
struct change_params_t {
    u64 __unused;
    u64 __unused2;
    unsigned int fd;
    const char * buf;
    size_t count;
    loff_t pos;
};

SEC("tp/syscalls/sys_enter_openat")
int handle_open(struct addfile_params_t *params)
{
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    struct add_file * msg2;
    // Kiểm tra nếu cờ O_CREAT được thiết lập, có nghĩa là file đang được tạo
    if (!(params->flags & O_CREAT))
        return 0;
    msg2 = bpf_ringbuf_reserve(&rb_open , sizeof(*msg2), 0);

    if (!msg2) {
        bpf_printk("ERROR: unable to reserve memory of Open\n");
        return 0;
    }

    msg2->pid = BPF_CORE_READ(task, pid);
    bpf_get_current_comm(&msg2->command, sizeof(msg2->command));
    bpf_probe_read_user_str(msg2->pathname, sizeof(msg2->pathname), params->pathname);
    bpf_ringbuf_submit(msg2, 0);
    bpf_printk("111\n");
    return 0;
}


SEC("tp/syscalls/sys_enter_access")
int handle_access(struct acess_params_t *params)
{
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    struct access * msg2;

    msg2 = bpf_ringbuf_reserve(&rb_open , sizeof(*msg2), 0);

    if (!msg2) {
        bpf_printk("ERROR: unable to reserve memory\n");
        return 0;
    }

    msg2->pid = BPF_CORE_READ(task, pid);
    bpf_get_current_comm(&msg2->command, sizeof(msg2->command));
    bpf_probe_read_user_str(msg2->pathname, sizeof(msg2->pathname), params->pathname);
    bpf_ringbuf_submit(msg2, 0);
    bpf_printk("333\n");
    return 0;
}

SEC("tp/syscalls/sys_enter_setuid")
int handle_getupid(struct id_params_t *params)
{
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    struct getid * msg2;

    msg2 = bpf_ringbuf_reserve(&rb_open , sizeof(*msg2), 0);

    if (!msg2) {
        bpf_printk("ERROR: unable to reserve memory\n");
        return 0;
    }

    msg2 -> uid = params -> uid ;
    msg2->pid = BPF_CORE_READ(task, pid);
    
    bpf_printk("PID %d called setuid with UID %d\n", msg2->pid, msg2->uid);
    bpf_ringbuf_submit(msg2, 0);
    return 0;
}















/*
SEC("tp/syscalls/sys_enter_pwrite64")
int trace_sys_enter_pwrite64(struct change_params_t *params) {
    // Print or process the values as needed
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    struct content *msg1;
    msg1 = bpf_ringbuf_reserve(&rb_content, sizeof(*msg1), 0);
    if (!msg1) {
        bpf_printk("ERROR: unable to reserve memory\n");
        return 0;
    }
    
    msg1 -> fd = params -> fd ;
    msg1 -> count = params -> count ;
    msg1 -> pos  =  params -> pos;
    msg1->pid = BPF_CORE_READ(task, pid);
    
    //bpf_printk("sys_enter_pwrite64: fd=%lld,  count=%lld, pos=%lld\\n",params -> fd, params -> count, params ->  pos);
    bpf_ringbuf_submit(msg1, 0);
    bpf_printk("222\n");
    return 0;
}*/


char LICENSE[] SEC("license") = "GPL";

