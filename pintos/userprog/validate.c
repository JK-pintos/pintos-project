#include "userprog/validate.h"

#include "threads/mmu.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

bool validate_ptr(const void* uaddr, bool write) {
    if (!is_user_vaddr(uaddr)) return false;
    uint64_t* pte = pml4e_walk(thread_current()->pml4, uaddr, 0);
    if (pte == NULL || !is_user_pte(pte) || (write && !is_writable(pte))) return false;
    return true;
}

bool validate_buffer(const void* uaddr, size_t size, bool write) {
    void* addr = uaddr;
    for (; addr < uaddr + size; addr = pg_round_down(addr + PGSIZE)) {
        if (!validate_ptr(addr, write)) return false;
    }
    return true;
}

bool validate_string(const char* uaddr, bool write) {
    char* ptr = uaddr;
    while (true) {
        if (!validate_ptr(ptr, write)) return false;
        for (; ptr < pg_round_down(ptr + PGSIZE); ptr++)
            if (*ptr == '\0') return true;
    }
}
