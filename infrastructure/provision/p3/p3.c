#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void mark_solved(void) {
    FILE *f = fopen("/opt/p3/solved", "w");
    if (f) {
        fputs("ok\n", f);
        fclose(f);
    }
}

static void win(void) {
    FILE *f = fopen("/opt/p3/flag_p3.txt", "r");
    if (!f) {
        puts("No flag");
        exit(1);
    }

    char flag[128];
    if (fgets(flag, sizeof(flag), f) != NULL) {
        printf("FLAG: %s\n", flag);
    } else {
        puts("No flag");
    }
    fclose(f);
    mark_solved();
    exit(0);
}

static void vuln(void) {
    char buf[64];
    puts("Say something:");
    gets(buf);
}

int main(void) {
    vuln();
    return 0;
}
