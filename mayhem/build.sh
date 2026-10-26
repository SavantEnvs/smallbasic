#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# SmallBASIC: one file-input fuzz target (the console interpreter `sbasic`, fed a BASIC program) plus
# the unmodified console build used by mayhem/test.sh to replay upstream's golden-output suite.
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# SmallBASIC builds in-tree with autotools (autogen.sh -> configure -> make); every file that generates
# is gitignored upstream, so each pass starts and ends with `make distclean` (re-runnable, offline).
# build_console <out> <main.cpp defines> <CFLAGS> <CXXFLAGS> <LDFLAGS>
# Upstream compiles with -Werror, which stock clang trips on (-Wmissing-braces); the -Wno-error in the
# flags below comes later on the command line and wins.
build_console() {
  local out="$1" main_defs="$2" cflags="$3" cxxflags="$4" ldflags="$5"
  make distclean >/dev/null 2>&1 || true
  sh autogen.sh
  ./configure CC="$CC" CXX="$CXX" CFLAGS="$cflags" CXXFLAGS="$cxxflags" LDFLAGS="$ldflags"
  make -C src/common -j"$MAYHEM_JOBS"
  # console/main.cpp ends with a malloc() that forwards to __libc_malloc (a kdbg aid); under ASan that
  # bypasses the sanitizer allocator and aborts at startup. Its guard excludes __FreeBSD__, so define it
  # for that one file only (command-line override; no upstream file is edited).
  make -C src/platform/console -j"$MAYHEM_JOBS" main.o CXXFLAGS="$cxxflags $main_defs"
  make -j"$MAYHEM_JOBS"
  cp src/platform/console/sbasic "$out"
  make distclean >/dev/null 2>&1 || true
}

# 2) The oracle binary first: NORMAL flags, no sanitizers (test.sh replays upstream's golden outputs on it).
build_console "$SRC/sbasic-test" "" \
  "-O2 -Wno-error $COVERAGE_FLAGS" "-O2 -Wno-error $COVERAGE_FLAGS" "$COVERAGE_FLAGS"

# 3) The fuzz target: the whole interpreter (scanner, compiler, evaluator, runtime) built with the
#    sanitizers and DWARF 3. LeakSanitizer is switched off at build time by linking lsan_off.o.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$SRC/lsan_off.o"
#    Two UBSan checks are relaxed because they fire on idioms that are benign on the targets we run and
#    would halt nearly every valid program before it reaches the interpreter: `alignment` (bytecode is
#    read as unaligned uint32_t, blib.c:1755) and `shift-base` (1 << 31 on int, 0xFFFF.. << 4 on
#    var_int_t: blib_func.c:978, str.c:611). ASan and every other UBSan check stay on and halting.
UBSAN_RELAX="-fno-sanitize=alignment,shift-base"
build_console "$SRC/sbasic" "-D__FreeBSD__" \
  "-O2 -Wno-error $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS" "-O2 -Wno-error $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS" \
  "$SANITIZER_FLAGS $SRC/lsan_off.o"
