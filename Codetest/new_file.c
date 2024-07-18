#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    
    const char *directory = "/etc/init.d/";

    
    const char *filename = "test_file.txt";

    //File path
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s%s", directory, filename);

    //Open file
    int fd = open(filepath, O_WRONLY | O_CREAT, 0644);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    
    const char *content = "Hello, this is a test file.\n";
    ssize_t bytes_written = write(fd, content, strlen(content));
    if (bytes_written == -1) {
        perror("write");
        close(fd);
        exit(EXIT_FAILURE);
    }

    
    if (close(fd) == -1) {
        perror("close");
        exit(EXIT_FAILURE);
    }

    printf("File '%s' created successfully.\n", filepath);

    return 0;
}
