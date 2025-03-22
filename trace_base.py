#!/usr/bin/python3

import os
import time
import json
import threading
import select
import signal
import sys

Version = "1.0.0"


class trace_base:
    force = "force"
    duration : "duration"
    pid = "pid"
    tid = "tid"
    filt = "filter"
    header = "header"
    stack = "stack"

    cmd_str = "p:icmp_out_p icmp_out_count\nr:icmp_out_r icmp_out_count"
    op_name = "Option Name"
    op_but = " option button"

    options_select = {
         "force" : False,
         "duration" : True,
         "pid" : True,
         "tid" : True,
         "filt" : False,
         "header" : True,
         "stack" : True,
         "duration_val" : 1,
         "pid_val" : 1,
         "tid_val" : 1,
         "filter_val" : 1,
#         "trace_func" : "icmp_out_count",
#         "operation" : "funcgraph",
         "time" : False,
         "proc" : False,
         "tail" : False,
         "nodur" : False,
         "cpu" : False,
         "max" : False,
         "max" : False,
         "max_val" : 3,
    }


    skin = {
        "op_name" : 0,
        "op_but" : 0,
        "commands" : 0,
        "options" : 0,

    }


    def __init__(self):

        self.skin["op_name"] = self.op_name
        self.skin["op_but"] = self.op_but
        self.skin["commands"] = self.cmd_str
        self.skin["options"] = self.options_select
        self.trace_dir = "/sys/kernel/debug/tracing/"
  

    def pre_init(self):
        return

    def open(self):
        for cmd in self.program:
            self.write_file(cmd[0], cmd[1])

    def configure(self):
        return

    def get_result(self):
        return

    def close(self):
        self.clear_probe()

    def get_message(self):
        return

    def put_message(self):
        return

    def conf_once(self):
        return

    def rel_once(self):
        return

    def config(self):
        return

    def parse(self):
        return

    def operation():
        return

    def write_file(self, name, data):
        print(f'w_f echo {data} > {name}')
        with open(name, "w") as f:
            f.write(data)

    def append_file(self, name, data):
        print(f'a_f echo {data} >> {name}')
        with open(name, "a") as f:
            f.write(data)

    def read_file1(self, name):
        print(f'r_f1 {name}')
        f = open(name, "r")
        self.dump = f.readlines()
        result = ''.join(str(line) for line in self.dump)
        return result

    def read_file(self, name):
        print(f'r_f {name}')
        f = open(name, "r")
        self.dump = f.readlines()
        result = ''.join(str(line) for line in self.dump)
        return result

    def read_file_result(self, name):
        print(f'r_f_r {name}')
        f = open(name, "r")
        if self.header:
            self.dump = f.readlines()
        else:
            self.dump = [l for l in f.readlines() if not '#' in l]
        result = ''.join(str(line) for line in self.dump)
        return result


    def clear_probe(self):
        return

    def pre_init(self):
        self.filter_val = ''
        self.force = self.skin["options"]["force"]
        self.duration = self.skin["options"]["duration"]
        self.pid = self.skin["options"]["pid"]
        self.tid = self.skin["options"]["tid"]
        self.filter = self.skin["options"]["filt"]
        self.header = self.skin["options"]["header"]
        self.stack = self.skin["options"]["stack"]
        self.time = self.skin["options"]["time"]
        self.proc = self.skin["options"]["proc"]
        self.tail = self.skin["options"]["tail"]
        self.nodur = self.skin["options"]["nodur"]
        self.cpu = self.skin["options"]["cpu"]
        self.max = self.skin["options"]["max"]
        self.max_val = str(self.skin["options"]["max_val"])
        print(f'self.max_val {self.max_val}')
        if self.duration:
            self.duration_val = self.skin["options"]["duration_val"]
        else:
            self.duration_val = 1
        if self.filter:
            self.filter_val = self.skin["options"]["filter_val"]
        if self.pid:
            self.filter_val = self.pid_filter(self.skin["options"]["pid_val"])
        if self.tid:
            self.filter_val = self.tid_filter(self.skin["options"]["tid_val"])

        # Clear trace system.
        self.clear_probe()

    def run_test(self, options):
       match options["operation"]:
           case "kprobe":
               print("kprobe selected")
               tr = kprobe()
           case "func":
               print("func selected")
               tr = func()
           case "funcgraph":
               print("funcgraph selected")
               tr = funcgraph()
           
       tr.skin["options"] = options
       tr.pre_init()
       tr.config(options["trace_func"])
       tr.open()
       tr.operation()
       tr.close()
       return tr.dump

    def pid_tids_str(self, pid):
        path = "/proc/" + str(pid) + "/task"
        threads = os.listdir(path)
        result = ''
        for tid in threads:
            result += tid + '\n'
        return result

    def pid_tids_list(self, pid):
        path = "/proc/" + str(pid) + "/task"
        threads = os.listdir(path)
        result = []
        for tid in threads:
            result.append(tid)
        return result



class kprobe(trace_base):
    def __init__(self):
        super().__init__()
        self.this = "kprobe"


    def pid_filter(self, pid):
        path = "/proc/" + str(pid) + "/task"
        threads = os.listdir(path)
        result = ''
        for tid in threads:
            result += 'common_pid == ' + tid + ' || '
        result = result[:-4]
        return result

    def tid_filter(self, tid):
        return 'common_pid == ' + str(tid)

    def clear_probe(self):
        test_dir = self.trace_dir + "/events/kprobes/"
        if os.path.isdir(test_dir):
            print ("kprobes found")
            files = os.listdir(test_dir)
            for file in files:
                if file == "enable" or file == "filter":
                    continue
                self.write_file(test_dir + file + "/enable", '0')
            self.write_file(self.trace_dir + "/kprobe_events", '')
        self.write_file(self.trace_dir + "/options/stacktrace", '0')
  

    def config(self, trace_str):
        self.parse_probe(trace_str)
        self.tr_on = self.trace_dir + "/tracing_on"
        self.program = [
          [self.trace_dir + "/tracing_on", "0"],
          [self.trace_dir + "/current_tracer", "nop"],
          [self.trace_dir + "/kprobe_events", trace_str],
        ]
        for probe_name in self.probe_names:
            self.program.append([self.trace_dir + "/events/kprobes/" + probe_name + "/filter", self.filter_val])
            self.program.append([self.trace_dir + "/events/kprobes/" + probe_name + "/enable", "1"])
        if self.stack:
            self.program.append([self.trace_dir + "/options/stacktrace", '1'])
        self.program.append([self.trace_dir + "/tracing_on", "1"])

    def parse_probe(self, request):
        get_func = False
        kprobe_words = request.split()
        self.probe_names = []
        probe_funcs = []
        for kp in kprobe_words:
            if kp[1] == ':':
                 self.probe_names.append(kp[2:])
                 get_func = True
            else:
                if get_func:
                    probe_funcs.append(kp)
                    get_func = False
        self.probe_funcs = list(set(probe_funcs))
        for func in self.probe_funcs:
            # replace the following line with grep request
            print("just placeholder")
        # grep here if presented. Return the name that is missing. If OK return an empty string.

    def operation(self):
        time.sleep(self.duration_val)
        self.write_file(self.trace_dir + "/tracing_on", '0')
        self.dump = self.read_file_result(self.trace_dir + "/trace")
        print(self.dump)




class func(trace_base):
    def __init__(self):
        super().__init__()
        self.this = "func"

    def pid_filter(self, pid):
        return

    def tid_filter(self, tid):
        return

    def clear_probe(self):
        self.write_file(self.trace_dir + "/function_profile_enabled", '0')
        self.write_file(self.trace_dir + "/set_ftrace_filter", '')
  


    def config(self, trace_str):    
        self.parse_probe(trace_str)

        self.program = [
          [self.trace_dir + "/set_ftrace_filter", trace_str],
          [self.trace_dir + "/function_profile_enabled", '1'],
        ]

    def parse_probe(self, request):
        return
        
    def operation(self):
        time.sleep(self.duration_val)
        self.write_file(self.trace_dir + "/function_profile_enabled", '0')

        path = self.trace_dir + "/trace_stat/"
        cores = os.listdir(path)
        cores.sort()
        result = ''
        for core in cores:
            result += "\ncore " + core[8:] + '\n'
            file = path + core           
            result += self.read_file(file)
        print(result)
        self.dump = result


class funcgraph(trace_base):
    def __init__(self):
        super().__init__()
        self.this = "funcgraph"

    def pid_filter(self, pid):
        return

    def tid_filter(self, tid):
        return

    def clear_probe(self):
        if self.time :
            self.write_file(self.trace_dir + "/trace_options", "nofuncgraph-abstime")
        if self.proc :
            self.write_file(self.trace_dir + "/trace_options", "nofuncgraph-proc")
        if self.tail :
            self.write_file(self.trace_dir + "/trace_options", "nofuncgraph-tail")
        if self.nodur :
            self.write_file(self.trace_dir + "/trace_options", "funcgraph-duration")
        if self.cpu :
            self.write_file(self.trace_dir + "/trace_options", "sleep-time")

        self.write_file(self.trace_dir + "/current_tracer", "nop")
        if self.pid or self.tid:
            self.write_file(self.trace_dir + "/set_ftrace_pid", "")
#        if self.max :
#            self.write_file(self.trace_dir + "/max_graph_depth", str(self.max_val))
        self.write_file(self.trace_dir + "/set_graph_function", "")
        self.write_file(self.trace_dir + "/trace", "")



    def config(self, trace_str):
        os.system("sysctl -q kernel.ftrace_enabled=1")
#        self.parse_probe(trace_str)
        self.funcs = trace_str
        print(trace_str)
        mode = self.read_file(self.trace_dir + "/current_tracer")
        self.program = []
        if mode.rstrip() != "nop":
            print(f'current_tracer is {mode} Expected nop')
            return False
        if self.max:
            self.write_file(self.trace_dir + "/max_graph_depth", self.max_val)

        if self.pid:
            tid_str = pid_tids_str(self.pid_val)
            self.write_file(self.trace_dir + "/set_ftrace_pid", "")

        else:
            if self.tid:
                self.write_file(self.trace_dir + "/set_ftrace_pid", self.tid_val)
            else:
                self.write_file(self.trace_dir + "/set_ftrace_pid", '')

        self.program = [
          [self.trace_dir + "/set_ftrace_filter", ''],
          [self.trace_dir + "/set_graph_function", self.funcs],
          [self.trace_dir + "/current_tracer", "function_graph"],
        ]
        if self.cpu:
            self.program.append([self.trace_dir + "/trace_options", "nosleep-time"])
        if self.time:
            self.program.append([self.trace_dir + "/trace_options", "funcgraph-absime"])

        if self.proc:
            self.program.append([self.trace_dir + "/trace_options", "funcgraph-proc"])
        if self.tail:
            self.program.append([self.trace_dir + "/trace_options", "funcgraph-tail"])
        if self.nodur:
            self.program.append([self.trace_dir + "/trace_options", "nofuncgraph-duration"])
        if self.max:
            self.program.append([self.trace_dir + "/max_graph_depth", str(self.max_val)])
        else:
            self.program.append([self.trace_dir + "/max_graph_depth", "100"])

        self.program.append([self.trace_dir + "/tracing_on", "1"])
        self.program.append([self.trace_dir + "/trace", ""])

        return True

    def parse_probe(self, request):
        return

    def operation(self):
        global get_flow_global
        global stop
        self.get_flow = threading.Thread(target=self.get_data_thread, args=(self.trace_dir + "/trace_pipe",))
        signal.signal(signal.SIGINT, signal_handler)
        get_flow_global = self.get_flow
        stop = False
        self.get_flow.start()

        time.sleep(self.duration_val)
        stop = True


        self.get_flow.join()
        print("done")

           

    def get_data_thread(self, file_path):
        print(file_path)
        fp = open(file_path)
        files = [fp]
        self.dump = ""
        while not stop:
            ready = select.select(files, [], [], 1)[0]

            if fp in ready:
                line = fp.readline()
                if not line:
                    break
                print(line.rstrip())
                self.dump += line
#                if stop:
#                    break




def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
#    print(trs.this)
#    stop = True
#    get_flow_global.join()
    print("done")
    sys.exit(0)

#signal.signal(signal.SIGINT, signal_handler)
#print('Press Ctrl+C')
#signal.pause()




#################################

if __name__ == "__main__":

    options_select = { "1" : "2" }
    options_sel = {
         "force" : False,
         "duration" : True,
         "pid" : False,
         "tid" : False,
         "filt" : False,
         "header" : True,
         "stack" : False,
         "duration_val" : 8,
         "pid_val" : 924,
         "tid_val" : 924,
         "filter_val" : 1,
#         "trace_func" : "*icmp*",
#         "operation" : "func"
#         "trace_func" : "p:icmp_out_p icmp_out_count\nr:icmp_out_r icmp_out_count",
#         "operation" : "kprobe",
         "trace_func" : "icmp_out_count",
         "operation" : "funcgraph",
         "time" : False,
         "proc" : False,
         "tail" : False,
         "nodur" : False,
         "cpu" : False,
         "max" : False,
         "max" : False,
         "max_val" : 3,
    }
    
    stop = False
    get_flow_global = None
    
    serialized = json.dumps(options_sel)
    # Send serialized over UDP
    options_select = json.loads(serialized)

    trs = trace_base()
    trs.run_test(options_select)


