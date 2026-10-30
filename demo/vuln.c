#include "vuln.h"

#include <string.h>

void parse(const unsigned char *data, size_t len) {
    char buf[16];
    if (len > 0 && data[0] == 'C') {
        /* VULNERABLE: no bounds check on len. */
        memcpy(buf, data, len);
    }
    /* Touch the buffer so the copy is not optimised away. */
    volatile char sink = buf[0];
    (void)sink;
}
