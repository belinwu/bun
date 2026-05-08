// Verifies src/test_runner/harness/recover.zig does not reference
// setcontext() when compiled for Android. bionic never implemented the
// ucontext family (getcontext/setcontext/makecontext/swapcontext —
// obsoleted in POSIX.1-2008), so the zig unit-test binary would fail to
// link against it. The fix routes Android through the setjmp/longjmp
// path already used for musl.
//
// This test cross-compiles recover.zig to an object file targeting
// aarch64-linux-android and inspects the undefined symbols it emits.

import { test, expect, describe } from "bun:test";
import { isLinux, tempDir } from "harness";
import { existsSync } from "node:fs";
import { join } from "node:path";

const repoRoot = join(import.meta.dir, "..", "..");
const zig = join(repoRoot, "vendor", "zig", "zig");
const recoverZig = join(repoRoot, "src", "test_runner", "harness", "recover.zig");

// Resolve the Android NDK sysroot. CI puts it at /opt/android-ndk; locally
// honour the usual env vars. Skip the test when none is found — the check
// is only meaningful with bionic headers present.
function findNdkSysroot(): string | null {
  const bases = [
    process.env.ANDROID_NDK_SYSROOT,
    ...[process.env.ANDROID_NDK_HOME, process.env.ANDROID_NDK_ROOT, process.env.ANDROID_NDK, "/opt/android-ndk"]
      .filter(Boolean)
      .map(base => join(base!, "toolchains", "llvm", "prebuilt", "linux-x86_64", "sysroot")),
  ];
  for (const p of bases) {
    if (p && existsSync(join(p, "usr", "include", "setjmp.h"))) return p;
  }
  return null;
}

const sysroot = findNdkSysroot();
// linux-x86_64 host only (that's the only prebuilt toolchain we look for),
// needs vendored zig + NDK sysroot.
const skip =
  !isLinux || process.arch !== "x64" || !existsSync(zig) || !existsSync(recoverZig) || sysroot == null;

describe.skipIf(skip)("recover.zig on Android", () => {
  test("does not reference setcontext (bionic lacks it)", async () => {
    // Find a crt_dir — any API level with crtbegin works for build-obj.
    const libdir = join(sysroot!, "usr", "lib", "aarch64-linux-android");
    let crtDir = libdir;
    for (const api of ["30", "29", "28", "24", "21"]) {
      const d = join(libdir, api);
      if (existsSync(join(d, "crtbegin_dynamic.o"))) {
        crtDir = d;
        break;
      }
    }

    using dir = tempDir("recover-android", {
      // Reference both callForTest (getContext) and panicked (setContext)
      // so the object carries whatever extern each path needs.
      "driver.zig": `
        const recover = @import("recover");
        fn dummy() anyerror!void {}
        export fn entry() void {
            _ = recover.callForTest(&dummy) catch {};
            recover.panicked();
        }
      `,
      "libc.txt":
        `include_dir=${join(sysroot!, "usr", "include")}\n` +
        `sys_include_dir=${join(sysroot!, "usr", "include", "aarch64-linux-android")}\n` +
        `crt_dir=${crtDir}\n` +
        `msvc_lib_dir=\n` +
        `kernel32_lib_dir=\n` +
        `gcc_dir=\n`,
    });

    const obj = join(String(dir), "recover.o");
    await using build = Bun.spawn({
      cmd: [
        zig,
        "build-obj",
        "-target",
        "aarch64-linux-android",
        "--libc",
        join(String(dir), "libc.txt"),
        "-lc",
        "--dep",
        "recover",
        `-Mroot=${join(String(dir), "driver.zig")}`,
        `-Mrecover=${recoverZig}`,
        `-femit-bin=${obj}`,
        "--cache-dir",
        join(String(dir), "zig-cache"),
        "--global-cache-dir",
        join(String(dir), "zig-global-cache"),
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    const [buildOut, buildErr, buildExit] = await Promise.all([
      build.stdout.text(),
      build.stderr.text(),
      build.exited,
    ]);
    expect(buildErr).toBe("");
    expect(buildOut).toBe("");
    expect(buildExit).toBe(0);

    await using nm = Bun.spawn({
      cmd: ["nm", "-u", obj],
      stdout: "pipe",
      stderr: "pipe",
    });
    const [nmOut, nmErr, nmExit] = await Promise.all([nm.stdout.text(), nm.stderr.text(), nm.exited]);
    expect(nmErr).toBe("");
    expect(nmExit).toBe(0);

    const undef = nmOut
      .split("\n")
      .map(l => l.trim().replace(/^U\s+/, "").split(/\s+/).pop())
      .filter(Boolean);

    // bionic does not provide setcontext/getcontext; referencing them
    // makes the zig unit-test binary unlinkable on Android.
    expect(undef).not.toContain("setcontext");
    expect(undef).not.toContain("getcontext");

    // It should instead go through setjmp/longjmp, which bionic has.
    expect(undef).toContain("setjmp");
    expect(undef).toContain("longjmp");
  });
});
