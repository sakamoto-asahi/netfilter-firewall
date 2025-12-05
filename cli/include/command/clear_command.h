#ifndef CLEAR_COMMAND_H
#define CLEAR_COMMAND_H

#include <stdbool.h>
#include "firewall_config.h"

bool clear_command(const char *filepath, ChainType target_chain);

#endif