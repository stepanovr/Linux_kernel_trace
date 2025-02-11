# Linux_kernel_trace

The application is written on Python. It has two parts: client and server that communicate over UDP.
The server target.py is a simple python script that runs on a limited resourses Linux machine that is under debugging target system.
The client runs on a remote machine that has tkinter packet installed.

To install tkinter use Ubuntu sudo apt-get install python3-tk

Fedora sudo dnf install python3-tkinter

MacOS brew install python-tk

Windows gets it with the Python installation

The target kernel must have enabled the following kernel features.
Some system have enabled the features. It works on Ubuntu and Raspbian without any changes.

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

The application is a Python  implementation of Brendan Gregg's tracing scripts.
It doesn't access kernel. The debugfs has the tracing tools that are used by the application.

The client is a platform independent application.
Linux, Windows or MacOS are appropriate to execute the client application.


git remote add origin git@github.com:stepanovr/Linux_kernel_trace.git

