#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    int failures = 0;
    
    // Multiple failing syscalls
    if (open("/nonexistent1", O_RDONLY) < 0) failures++;
    if (open("/nonexistent2", O_RDONLY) < 0) failures++;
    if (open("/nonexistent3", O_RDONLY) < 0) failures++;
    
    printf("Total failures: %d\n", failures);
    return failures > 0 ? 1 : 0;
}