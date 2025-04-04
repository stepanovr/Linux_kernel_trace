# Linux_kernel_trace

Version 1.0.0 -- March 22 2025
Added Funcgraph tool allowing displaying the function calls within the requested function.
Select the tool from the File menu

The application is written on Python. It has two parts: client and server that communicate over UDP.
The server usws two files target.py and trace_base.py.
The server is a python script that runs on a limited resourses Linux machine that is 
the system under debugging. To run the server copy target.py and trace_base.py to
the same directory on the target machine and start the server execution with the command
sudo ./target.py

Check if debugfs and tracefs are mounted
$ mount  | grep -e tracefs -e debugfs
debugfs on /sys/kernel/debug type debugfs (rw,nosuid,nodev,noexec,relatime)
tracefs on /sys/kernel/tracing type tracefs (rw,nosuid,nodev,noexec,relatime)
tracefs on /sys/kernel/debug/tracing type tracefs (rw,nosuid,nodev,noexec,relatime)

The tool assumes that the tracefs is mounted to /sys/kernel/debug/tracing .

The client runs on a remote machine that has tkinter packet installed.

To install tkinter use Ubuntu sudo apt-get install python3-tk

Fedora sudo dnf install python3-tkinter

MacOS brew install python-tk

Windows gets it with the Python installation

The target kernel must have enabled the following kernel features.
Some system have enabled the features. It works on Ubuntu and Raspbian without any changes.

### Kernel configuration required for the tool operation
```
CONFIG_TASKS_RCU_GENERIC=y
CONFIG_TASKS_RUDE_RCU=y
CONFIG_KALLSYMS_ALL=y
CONFIG_TRACEPOINTS=y
CONFIG_KPROBES=y
CONFIG_UPROBES=y
CONFIG_KRETPROBES=y
CONFIG_BINARY_PRINTF=y
CONFIG_TRACE_IRQFLAGS=y
CONFIG_TRACE_IRQFLAGS_NMI=y
CONFIG_STACKTRACE=y
CONFIG_NOP_TRACER=y
CONFIG_TRACER_MAX_TRACE=y
CONFIG_RING_BUFFER=y
CONFIG_EVENT_TRACING=y
CONFIG_CONTEXT_SWITCH_TRACER=y
CONFIG_RING_BUFFER_ALLOW_SWAP=y
CONFIG_PREEMPTIRQ_TRACEPOINTS=y
CONFIG_TRACING=y
CONFIG_GENERIC_TRACER=y
CONFIG_FTRACE=y
CONFIG_FUNCTION_TRACER=y
CONFIG_FUNCTION_GRAPH_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_DYNAMIC_FTRACE_WITH_REGS=y
CONFIG_FUNCTION_PROFILER=y
CONFIG_IRQSOFF_TRACER=y
CONFIG_SCHED_TRACER=y
CONFIG_FTRACE_SYSCALLS=y
CONFIG_TRACER_SNAPSHOT=y
CONFIG_TRACER_SNAPSHOT_PER_CPU_SWAP=y
CONFIG_BRANCH_PROFILE_NONE=y
CONFIG_KPROBE_EVENTS=y
CONFIG_UPROBE_EVENTS=y
CONFIG_DYNAMIC_EVENTS=y
CONFIG_PROBE_EVENTS=y
CONFIG_FTRACE_MCOUNT_RECORD=y
CONFIG_FTRACE_MCOUNT_USE_PATCHABLE_FUNCTION_ENTRY=y
```

Another important moment is mounting debugfs.
Check if it is mounted on /sys/kernel/debug:
```
$ mount | grep debugfs
debugfs on /sys/kernel/debug type debugfs (rw,nosuid,nodev,noexec,relatime)
```

The application is a Python  implementation of Brendan Gregg's tracing scripts.
It doesn't access kernel. The debugfs has the tracing tools that are used by the application.

The client is a platform independent application.
Linux, Windows or MacOS are appropriate to execute the client application.

Two tracing modes implemented at the moment.
Function hit counter selected with "Func" selection in the File menu
Kprobe is selected with "Kprobe" selection in the File menu

Each mode selection sets appropriate "Trace:" window items as an example.
Replace them in the desired functions.

The Kprobe command format:
Following example shows the way to watch calls for do_sys_open() that will print
the registers values. 

p:myprobe do_sys_open dfd=%ax filename=%dx flags=%cx mode=+4($stack)

That example works for x86 CPU.
### The CPU register names for the system calls are following
``` 
       Arch/ABI    Instruction           System  Ret  Ret  Error    Notes
                                         call #  val  val2
       alpha       callsys               v0      v0   a4   a3       1, 6
       arc         trap0                 r8      r0   -    -
       arm/OABI    swi NR                -       a1   -    -        2
       arm/EABI    swi 0x0               r7      r0   r1   -
       arm64       svc #0                x8      x0   x1   -
       blackfin    excpt 0x0             P0      R0   -    -
       i386        int $0x80             eax     eax  edx  -
       ia64        break 0x100000        r15     r8   r9   r10      1, 6
       m68k        trap #0               d0      d0   -    -
       microblaze  brki r14,8            r12     r3   -    -
       mips        syscall               v0      v0   v1   a3       1, 6
       nios2       trap                  r2      r2   -    r7
       parisc      ble 0x100(%sr2, %r0)  r20     r28  -    -
       powerpc     sc                    r0      r3   -    r0       1
       powerpc64   sc                    r0      r3   -    cr0.SO   1
       riscv       ecall                 a7      a0   a1   -
       s390        svc 0                 r1      r2   r3   -        3
       s390x       svc 0                 r1      r2   r3   -        3
       superh      trap #0x17            r3      r0   r1   -        4, 6
       sparc/32    t 0x10                g1      o0   o1   psr/csr  1, 6
       sparc/64    t 0x6d                g1      o0   o1   psr/csr  1, 6
       tile        swint1                R10     R00  -    R01      1
       x86-64      syscall               rax     rax  rdx  -        5
       x32         syscall               rax     rax  rdx  -        5
       xtensa      syscall               a2      a2   -    -

```
The details are available on command "man syscall"
The trace instruction starts either with "p:" for the function entry
or with "r:" for the function return.

Kprobe details are here:
https://docs.kernel.org/trace/kprobetrace.html

git remote add origin git@github.com:stepanovr/Linux_kernel_trace.git


### kprobe request details
According to https://events.static.linuxfound.org/slides/lfcs2010_hiramatsu.pdf
```
p[:[GRP/]EVENT] SYMBOL[+offs]|MEMADDR [FETCHARGS]: Set a probe
r[:[GRP/]EVENT] SYMBOL[+0] [FETCHARGS] : Set a return probe


 %REG : Fetch register REG
 @ADDR : Fetch memory at ADDR (ADDR should be in kernel)
 @SYM[+|-offs] : Fetch memory at SYM +|- offs (SYM should be a data symbol)
 $stackN : Fetch Nth entry of stack (N >= 0)
 $stack : Fetch stack address.
 $retval : Fetch return value.(*)
 +|-offs(FETCHARG) : Fetch memory at FETCHARG +|- offs address.(**)
 NAME=FETCHARG : Set NAME as the argument name of FETCHARG.
 FETCHARG:TYPE : Set TYPE as the type of FETCHARG. Currently, basic types
 (u8/u16/u32/u64/s8/s16/s32/s64) are supported.

e.g.

 'foo=+10(%bp):u32'
 fetch u32 value from the address which bp register value plus 10.

 'bar=@tick_usec'
 fetch unsigned long value of tick_usec symbol.
```

According to https://www.kernel.org/doc/html//v4.18/trace/kprobetrace.html

### Synopsis of kprobe_events
```
 p[:[GRP/]EVENT] [MOD:]SYM[+offs]|MEMADDR [FETCHARGS]  : Set a probe
 r[MAXACTIVE][:[GRP/]EVENT] [MOD:]SYM[+0] [FETCHARGS]  : Set a return probe
 -:[GRP/]EVENT                                         : Clear a probe

GRP            : Group name. If omitted, use "kprobes" for it.
EVENT          : Event name. If omitted, the event name is generated
                 based on SYM+offs or MEMADDR.
MOD            : Module name which has given SYM.
SYM[+offs]     : Symbol+offset where the probe is inserted.
MEMADDR        : Address where the probe is inserted.
MAXACTIVE      : Maximum number of instances of the specified function that
                 can be probed simultaneously, or 0 for the default value
                 as defined in Documentation/kprobes.txt section 1.3.1.

FETCHARGS      : Arguments. Each probe can have up to 128 args.
 %REG          : Fetch register REG
 @ADDR         : Fetch memory at ADDR (ADDR should be in kernel)
 @SYM[+|-offs] : Fetch memory at SYM +|- offs (SYM should be a data symbol)
 $stackN       : Fetch Nth entry of stack (N >= 0)
 $stack        : Fetch stack address.
 $retval       : Fetch return value.(*)
 $comm         : Fetch current task comm.
 +|-offs(FETCHARG) : Fetch memory at FETCHARG +|- offs address.(**)
 NAME=FETCHARG : Set NAME as the argument name of FETCHARG.
 FETCHARG:TYPE : Set TYPE as the type of FETCHARG. Currently, basic types
                 (u8/u16/u32/u64/s8/s16/s32/s64), hexadecimal types
                 (x8/x16/x32/x64), "string" and bitfield are supported.

 (*) only for return probe.
 (**) this is useful for fetching a field of data structures.
```


