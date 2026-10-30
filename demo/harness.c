#include <stddef.h>
#include <stdint.h>

#include "vuln.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse(data, size);
    return 0;
}
