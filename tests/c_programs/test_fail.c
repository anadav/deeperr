#include <fcntl.h>
#include <stdio.h>

int main() {
    int fd = open("/nonexistent", O_RDONLY);
    if (fd < 0) {
        perror("open failed");
        return 1;
    }
    return 0;
}
