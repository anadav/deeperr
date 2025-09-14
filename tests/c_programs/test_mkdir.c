#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>

int main() {
    // Try to create directory in read-only location
    if (mkdir("/proc/test_dir", 0755) == -1) {
        perror("mkdir failed");
        return 1;
    }
    return 0;
}