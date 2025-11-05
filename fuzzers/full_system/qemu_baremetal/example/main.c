#include <stdio.h>

#ifdef TARGET_CUSTOM_INSN
#include "lqemu.h"
#endif

#ifndef TARGET_CUSTOM_INSN
int __attribute__((noinline)) BREAKPOINT() {
    for (;;) {}
}
#endif

int LLVMFuzzerTestOneInput(unsigned int *Data, unsigned int Size) {
#ifdef TARGET_CUSTOM_INSN
    libafl_qemu_start_phys((void *)Data, Size);
#endif

    /* 超时条件测试 */
    if (Size >= 4 && Data[3] == 0) {
        while (1) {}  // cause a timeout
    }

    /* 执行 Hello World */
    printf("Hello World! %s\n");

#ifdef TARGET_CUSTOM_INSN
    libafl_qemu_end(LIBAFL_QEMU_END_OK);
#else
    return BREAKPOINT();
#endif
}

unsigned int FUZZ_INPUT[] = {
    101, 201, 700, 230, 860, 234, 980, 200, 340, 678, 230, 134, 900,
    236, 900, 123, 800, 123, 658, 607, 246, 804, 567, 568, 207, 407,
    246, 678, 457, 892, 834, 456, 878, 246, 699, 854, 234, 844, 290,
    125, 324, 560, 852, 928, 910, 790, 853, 345, 234, 586,
};

int main(void) {
    LLVMFuzzerTestOneInput(FUZZ_INPUT, 50);
    return 0;
}