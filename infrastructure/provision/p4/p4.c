#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void win(void) {
    FILE *f = fopen("/opt/p4/flag_p4.txt", "r");
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
    FILE *s = fopen("/opt/p4/solved", "w");
    if (s) {
        fputs("ok\n", s);
        fclose(s);
    }
    exit(0);
}

static void safe(void) {
    puts("Nope.");
}

static void (*fp)(void) = safe;

static void vuln(void) {
    char buf[128];
    int auth = 0;
    int dummy = 0;
    puts("Input:");
    if (!fgets(buf, sizeof(buf), stdin)) {
        return;
    }
    printf(buf, &auth, dummy);
    if (auth == 0x1337) {
        fp = win;
    }
    fp();
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    setgid(getegid());
    setuid(geteuid());
    vuln();
    return 0;
}
