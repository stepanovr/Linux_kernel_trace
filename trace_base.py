#!/usr/bin/python3

#import glob
import os
import time
import json

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
         "filter_val" : 1
    }


    skin = {
        "op_name" : 0,
        "op_but" : 0,
        "commands" : 0,
        "options" : 0,
#        "opts" : 0
    }


    def __init__(self):
#        self.act["config_once"] = self.conf_once
#        self.act["release_once"] = self.rel_once
#        self.act["config"] = self.config
#        self.act["parse"] = self.parse

        self.skin["op_name"] = self.op_name
        self.skin["op_but"] = self.op_but
        self.skin["commands"] = self.cmd_str
        self.skin["options"] = self.options_select
        self.trace_dir = "/sys/kernel/debug/tracing/"
        

    def pre_init(self):
        return

    def open(self):
        return

    def configure(self):
        return

    def get_result(self):
        return

    def close(self):
        return

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
        with open(name, "w") as f:
            f.write(data)

    def read_file1(self, name):
        f = open(name, "r")
        self.dump = f.readlines()
        result = ''.join(str(line) for line in self.dump)
        return result

    def read_file(self, name):
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
       tr.skin["options"] = options
       tr.pre_init()
       tr.config(options["trace_func"])
       tr.open()
       tr.operation()
       tr.close()
#       print(f'RS1111 12 {tr.this}')
#       print(tr.dump)
       return tr.dump


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

    def open(self):
        for cmd in self.program:
            self.write_file(cmd[0], cmd[1])

    def operation(self):
        time.sleep(self.duration_val)
        self.write_file(self.trace_dir + "/tracing_on", '0')
        self.dump = self.read_file(self.trace_dir + "/trace")
        print(self.dump)

    def close(self):
        self.clear_probe()



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
        
    def open(self):
        for cmd in self.program:
            self.write_file(cmd[0], cmd[1])

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
        

    def close(self):
        self.clear_probe()
       

#################################

if __name__ == "__main__":

    options_select = { "1" : "2" }
    options_sel = {
         "force" : False,
         "duration" : True,
         "pid" : False,
         "tid" : False,
         "filt" : False,
         "header" : False,
         "stack" : False,
         "duration_val" : 4,
         "pid_val" : 924,
         "tid_val" : 924,
         "filter_val" : 1,
         "trace_func" : "p:icmp_out_p icmp_out_count\nr:icmp_out_r icmp_out_count",
         "operation" : "kprobe"
#         "trace_func" : "*icmp*",
#         "operation" : "func"
    }
    
    serialized = json.dumps(options_sel)
    # Send serialized over UDP
    options_select = json.loads(serialized)

    trs = trace_base()
    trs.run_test(options_select)


