#ifndef ASM_TYPES_WORKAROUND_H
#define ASM_TYPES_WORKAROUND_H

// Workaround for missing asm/types.h
// This provides the basic types that the kernel headers expect
// Using direct type definitions instead of stdint.h for BPF compatibility

// Define the types that are typically in asm/types.h
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

// Network byte order types
typedef __u32 __be32;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u16 __le16;

// Additional types that might be needed
typedef __u64 __be64;
typedef __u64 __le64;

#endif // ASM_TYPES_WORKAROUND_H
