#include <stdio.h>
#include <string.h>

int check_flag(const char *input) {
    if (strlen(input) != 8) {
        return 0;
    }
    if (input[0] != 'B') return 0;
    if (input[1] != 'e') return 0;
    if (input[2] != 'a') return 0;
    if (input[3] != 'c') return 0;
    if (input[4] != '0') return 0;
    if (input[5] != 'n') return 0;
    if (input[6] != '!') return 0;
    if (input[7] != '!') return 0;
    return 1;
}

int main() {
    char buf[64];
    printf("Enter flag: ");
    if (fgets(buf, sizeof(buf), stdin)) {
        buf[strcspn(buf, "\n")] = '\0';
        if (check_flag(buf)) {
            printf("Correct!\n");
        } else {
            printf("Wrong!\n");
        }
    }
    return 0;
}
