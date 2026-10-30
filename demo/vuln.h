#ifndef CRASHWISE_DEMO_VULN_H
#define CRASHWISE_DEMO_VULN_H

#include <stddef.h>

/*
 * Deliberately vulnerable demo target.
 *
 * parse() copies the caller's input into a 16-byte stack buffer with no
 * length check when the first byte is 'C'. Any input longer than 16 bytes
 * starting with 'C' therefore overflows the buffer and AddressSanitizer
 * reports a stack-buffer-overflow. This is the bug the M1 demo is meant
 * to find, reproduce, and fix. Do not use this code in a real program.
 */
void parse(const unsigned char *data, size_t len);

#endif
