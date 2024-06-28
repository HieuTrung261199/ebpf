#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main() {
    int fd = open("/etc/init.d/test2.txt", O_WRONLY | O_CREAT, 0644);
    if (fd == -1) {
        return 1;
    }

    const char *buf = "Hello";
    pwrite(fd, buf, strlen(buf), 20); 

    close(fd);
    return 0;
}
