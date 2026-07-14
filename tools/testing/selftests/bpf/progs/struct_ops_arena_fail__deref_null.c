// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Tejun Heo <tj@kernel.org> */

#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf_arena_common.h>
#include "../test_kmods/bpf_testmod.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
} arena SEC(".maps");

/* associates the program with the arena */
u64 __arena arena_touch;

/*
 * An __arena_nullable ctx argument is PTR_TO_ARENA | PTR_MAYBE_NULL, so
 * dereferencing it without a NULL check must be rejected.
 */
SEC("struct_ops/test_arena_nullable")
__arch_x86_64
__arch_arm64
__failure __msg("invalid mem access 'arena_or_null'")
int arena_fail__deref_null(unsigned long long *ctx)
{
	u64 __arena *ptr = (u64 __arena *)ctx[0];

	arena_touch++;
	*ptr += 1;
	return 0;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops3 testmod_arena_deref_null = {
	.test_arena_nullable = (void *)arena_fail__deref_null,
};
