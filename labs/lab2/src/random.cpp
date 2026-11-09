#include "random.hpp"
#include <sys/random.h>
#include <cerrno>
#include <cstdlib>

void random_bytes(uint8_t* buf, size_t len) {
    while (len > 0) {
        ssize_t r = getrandom(buf, len, 0);
        if (r < 0) { if (errno == EINTR) continue; std::abort(); }
        buf += r; len -= static_cast<size_t>(r);
    }
}
