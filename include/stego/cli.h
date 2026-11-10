/**
 * @file cli.h
 * @brief Command-line interface definitions and command dispatch.
 */

#ifndef STEGO_CLI_H
#define STEGO_CLI_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int stego_cli_run(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_CLI_H */

