#ifndef __MSG_H__
#define __MSG_H__

struct execve {
    pid_t pid;
    char command[128];
    char pathname[128];
    char filename[32];
};

struct add_file {
    pid_t pid;
    char command[128];
    char pathname[128];
};

struct content {
    pid_t pid;
    unsigned int fd;
    const char * buf;
    size_t count;
    loff_t pos;
};
#endif // __MSG_H__
