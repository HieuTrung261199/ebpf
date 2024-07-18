#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main() {
    int fd = open("text.txt", O_WRONLY | O_CREAT, 0644);
    if (fd == -1) {
        return 1;
    }

    const char *buf = "Hello, bpftrace!";
    pwrite(fd, buf, strlen(buf), 15); //write in position 0

    close(fd);
    return 0;
}
