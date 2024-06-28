#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

int main() {
    const char *dir_name = "/etc/init.d/new_folder1.txt";

    // Tạo thư mục với quyền 0755 (rwxr-xr-x)
    if (mkdir(dir_name, 0755) == 0) {
        printf("Directory created successfully.\n");
    } else {
        perror("Error creating directory");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
