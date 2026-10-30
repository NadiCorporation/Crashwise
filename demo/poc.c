#include <stdio.h>
#include <string.h>

#include "vuln.h"

/*
 * Standalone reproducer for the M1 demo bug.
 *
 * It feeds parse() exactly the input class the fuzzer finds: 'C'
 * followed by more than 16 bytes. Under AddressSanitizer this must
 * crash with a stack-buffer-overflow. After the patch is applied,
 * the same input must run cleanly.
 */
int main(void) {
    unsigned char input[64];
    memset(input, 'A', sizeof(input));
    input[0] = 'C';
    parse(input, sizeof(input));
    printf("clean execution (no crash)\n");
    return 0;
}
