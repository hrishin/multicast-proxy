#ifndef ASM_TYPES_WORKAROUND_H
#define ASM_TYPES_WORKAROUND_H

// Workaround for missing asm/types.h
// This provides the basic types that the kernel headers expect

#include <stdint.h>

// Define the types that are typically in asm/types.h
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

typedef int8_t __s8;
typedef int16_t __s16;
typedef int32_t __s32;
typedef int64_t __s64;

// Network byte order types
typedef uint32_t __be32;
typedef uint16_t __be16;
typedef uint32_t __le32;
typedef uint16_t __le16;

// Additional types that might be needed
typedef uint64_t __be64;
typedef uint64_t __le64;

#endif // ASM_TYPES_WORKAROUND_H
