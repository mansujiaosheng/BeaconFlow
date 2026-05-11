#include <stdio.h>
#include <string.h>

int check_flag(const char *input) {
    const char *flag = "FLAG{beaconflow_test}";
    if (strlen(input) != strlen(flag)) {
        return 0;
    }
    for (int i = 0; i < strlen(flag); i++) {
        if (input[i] != flag[i]) {
            return 0;
        }
    }
    return 1;
}

int main() {
    char buf[256];
    printf("Enter the flag: ");
    if (fgets(buf, sizeof(buf), stdin)) {
        buf[strcspn(buf, "\n")] = 0;
        if (check_flag(buf)) {
            printf("Correct!\n");
        } else {
            printf("Wrong!\n");
        }
    }
    return 0;
}
