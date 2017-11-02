#include "lowlevel.h"

static int pin_count (void *context, unsigned int slot_num, int sopin)
{
    return 2;
}

lowlevel_module* lowlevel_module_init(lowlevel_module *module) {
    module->pin_count = pin_count;
    return module;
}
