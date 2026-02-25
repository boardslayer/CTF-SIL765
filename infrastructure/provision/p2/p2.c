#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void win(void) {
    setuid(0);
    setgid(0);
    system("/bin/sh");
}

static void vuln(void) {
    char buf[64];
    puts("Enter input:");
    gets(buf);
}

int main(void) {
    vuln();
    return 0;
}
