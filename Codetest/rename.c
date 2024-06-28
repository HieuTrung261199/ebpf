#include <stdio.h>
#include <stdlib.h>

int main() {
    const char *old_filename = "/etc/init.d/test1.txt";
    const char *new_filename = "/etc/init.d/test2.txt";

    // Đổi tên file
    if (rename(old_filename, new_filename) == 0) {
        printf("File renamed successfully.\n");
    } else {
        perror("Error renaming file");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
