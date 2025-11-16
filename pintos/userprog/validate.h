#include <stdbool.h>
#include <stddef.h>

bool validate_ptr(const void* uaddr, bool write);
bool validate_buffer(const void* uaddr, size_t size, bool write);
bool validate_string(const char* uaddr, bool write);