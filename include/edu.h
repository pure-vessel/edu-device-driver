#ifndef _EDU_H
#define _EDU_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define EDU_MAJOR 0xD0

struct edu_xor_cmd {
    uint32_t val_in;
    uint32_t val_out;
};
#define EDU_IOCTL_XOR _IOWR(EDU_MAJOR, 0, struct edu_xor_cmd *)

struct edu_factorial_cmd {
    uint32_t val_in;
    uint32_t val_out;
};
#define EDU_IOCTL_FACTORIAL _IOWR(EDU_MAJOR, 1, struct edu_factorial_cmd *)

struct edu_intr_cmd {
    uint32_t val_in;
};
#define EDU_IOCTL_INTR _IOW(EDU_MAJOR, 2, struct edu_intr_cmd *)

#endif // _EDU_H
