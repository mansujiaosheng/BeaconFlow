#include <stdio.h>
#include <string.h>

static int alpha(int value) {
    return value * 3 + 1;
}

static int beta(int value) {
    return value ^ 0x55;
}

int main(int argc, char **argv) {
    int value = argc > 1 ? (int)strlen(argv[1]) : 0;

    if (argc > 1 && strcmp(argv[1], "beta") == 0) {
        value = beta(value);
    } else {
        value = alpha(value);
    }

    printf("%d\n", value);
    return value == 0x42 ? 1 : 0;
}

