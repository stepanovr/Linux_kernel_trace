#!/usr/bin/python3

#cat /sys/kernel/debug/tracing/trace_pipe

import xml.etree.ElementTree as ET

import socket
import os
import sys
import time
from tkinter import *
import tkinter as tk
import re

from tkinter import ttk

from tkinter import filedialog


force = "force       "
duration = "duration"
pid = "pid           "
tid = "tid            "
filter = "filter       "
header = "header  "
stack = "stack       "
none = "NONE    "

trace_default = "p:icmp_out_p icmp_out_count\nr:icmp_out_r icmp_out_count"

modes = ["ktrace", "func"]

op_name_ktrace = "Operation Ktrace"
op_butt_ktrace = "Read Ktrace"

op_name_func = "Operation Func"
op_butt_func = "Read Func"


# cmd value action target

class control():
  def __init__(self):
    self.batch = []
    return

  def new_cmd(self, cmd, value, action, target, display):
    command = [cmd, value, action, target]
    cmd = [command, display]
    self.batch.append(cmd)

  def extract(self):

    res1 = []
    res2 = []
    for i in range(len(self.batch)):
      string = self.batch[i][0][0] + ' ' + self.batch[i][0][1] + ' '  + self.batch[i][0][2] + ' ' + self.batch[i][0][3]
      res1.append(string)
      res2.append(self.batch[i][1])
    self.result = [res1, res2]
    return self.result

  def ctrl_process(self, prog):
    for cmd in range(len(self.batch)):
      self.handle(prog[0][cmd], prog[1][cmd])
      self.app.udp_exchange(prog[0][cmd], prog[1][cmd])

  def handle(self, cmd, cond):
#    print(f'cmd: {cmd}                            cond: {cond}')
    print(cmd)

  def clear(self):
    self.batch = []

class Application(Frame):
  """ GUI application that provides GUI interface to debugfs kernel tracing  """

  tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  address_step = 4
  connected = False
  num_per_line = 4
  log_enable = False
  logname = "logfile.txt"

  def __init__(self):
    """ To provide usage of API """
    super(Application, self).__init__()

  def __init__(self, master):
    """ Initialize Frame. """
    super(Application, self).__init__(master)
    self.grid()
    self.create_widgets()
    self.skin = skin(self, kprobe_skin)
    self.switch_mode(self.skin)
    print("Application started")

  def switch_mode(self, skin):
    self.skin = skin
    for option in self.skin.options:
      if self.skin.options[option] :
        self.opt_names[option].config(state = tk.NORMAL)
      else:
        self.opt_names[option].config(state = tk.DISABLED)

    self.act_name_str.set(skin.op_name)
    self.act_button_str.set(skin.op_butt)
    self.display_trace(skin.commands)

  def create_widgets(self):
    """ Create widgets to get story information and to display story. """

    Label(self,
      text = "Specify server information "
      ).grid(row = 0, column = 0, columnspan = 2, sticky = W)

    Label(self,
      text = "Address: "
      ).grid(row = 1, column = 0, sticky = W)

    self.serv_addr_ent = Entry(self)
    self.serv_addr_ent.grid(row = 1, column = 1, sticky = W)
    self.serv_addr_ent.delete(0,END)
    self.serv_addr_ent.insert(0, "192.168.1.125" )
    Label(self,
      text = "Port:"
      ).grid(row = 2, column = 0, sticky = W)
    self.serv_port_ent = Entry(self)
    self.serv_port_ent.grid(row = 2, column = 1, sticky = W)
    self.serv_port_ent.delete(0,END)
    self.serv_port_ent.insert(0, "34023" )

    Button(self,
      text = "Test connection",
      command = self.open_connection_UDP
      ).grid(row = 3, column = 0, sticky = W)

    Label(self,
      text = "Trace:"
      ).grid(row = 4, column = 0, sticky = W)

    self.trace_txt = Text(self, width = 60, height = 6, wrap = WORD)
    self.trace_txt.grid(row = 5, column = 0, columnspan = 4,sticky = W)
    self.display_trace(trace_default)


    self.story_txt = Text(self, width = 150, height = 20, wrap = WORD)
    self.story_txt.grid(row = 10, column = 0, columnspan = 4)

    self.act_name_str = StringVar()
    self.act_name_str.set(op_name_ktrace)
    self.action_name = Label(self,
      textvariable = self.act_name_str
      ).grid(row = 7, column = 0, sticky = W)

    self.act_button_str = StringVar()
    self.act_button_str.set(op_butt_ktrace)

    self.action_button = Button(self,
      textvariable = self.act_button_str,
      command = self.read_trace
      ).grid(row = 9, column = 0, sticky = W)

    self.force = BooleanVar(value=False)
    self.duration = BooleanVar(value=True)
    self.pid = BooleanVar(value=False)
    self.tid = BooleanVar(value=False)
    self.header = BooleanVar(value=False)
    self.stack = BooleanVar(value=False)
    self.filter = BooleanVar(value=False)

    opt_list= [self.force, self.duration, self.pid, self.tid, self.filter, self.header, self.stack]
    opts = [force, duration, pid, tid, filter, header, stack]
    column = 2
    row = 2
    pos = 0
    self.opt_names = {}
    for name in opts:

        cb = Checkbutton(self, width = 8, text = name, variable = opt_list[pos], justify = LEFT)
        cb.config(width=20, height=2)

        cb.grid(row = row, column = column, sticky = 'W')
        self.opt_names.update({name.rstrip(): cb})

        row += 1
        pos += 1

    self.duration_ent = Entry(self)
    self.duration_ent.grid(row = 3, column = 3, sticky = W)
    self.duration_ent.delete(0,END)
    self.duration_ent.insert(0, "1" )

    self.pid_ent = Entry(self)
    self.pid_ent.grid(row = 4, column = 3, sticky = W)
    self.pid_ent.delete(0,END)
    self.pid_ent.insert(0, "1" )

    self.tid_ent = Entry(self)
    self.tid_ent.grid(row = 5, column = 3, sticky = W)
    self.tid_ent.delete(0,END)
    self.tid_ent.insert(0, "1" )

    self.filter_ent = Entry(self)
    self.filter_ent.grid(row = 6, column = 3, sticky = W)
    self.filter_ent.delete(0,END)
    self.filter_ent.insert(0, "1" )


  def udp_exchange(self, request, disp = True):
    data = ''
    self.serv_addr = self.serv_addr_ent.get()
    self.serv_port = self.serv_port_ent.get()
    self.serverAddressPort = (self.serv_addr, int(self.serv_port))
    self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    bytesToSend = str.encode(request)
    self.udp_socket.sendto(bytesToSend, self.serverAddressPort)
    self.udp_socket.settimeout(2.0)
    self.log_message(request)

    output = ""
    while True:
      try:
        val, address = self.udp_socket.recvfrom(1024)
        data = str(val, "utf-8")
        if disp:
          print(data)

        output += data
        output += "\n"

      except socket.timeout:
        self.log_message(output)
        if disp:
          self.display_message(output)
        break;

    self.udp_socket.close()
    return output

  def write_reg(self):
    """ Write button handler """
    # get values from the GUI
    addr = self.wr_addr_ent.get()
    val = self.wr_val_ent.get()
    if self.connected == True:

      request = "w "
      request += addr
      request += " "
      request += val

      print(request)

      self.tcp_sock.sendall(str.encode(request))
      data = str(self.tcp_sock.recv(1024), "utf-8")
      print(data)


  def open_connection(self):

    if self.connected != True:
      self.serv_addr = self.serv_addr_ent.get()
      self.serv_port = self.serv_port_ent.get()

      sockaddr = socket.getaddrinfo(self.serv_addr, self.serv_port)

      print("Connection " + self.serv_addr)
      print(self.serv_port)
      bits = self.bits.get()
      print(bits)

      self.tcp_sock.connect((self.serv_addr, int(self.serv_port)))

      self.connected = True
    else:
      quit()

  def open_connection_UDP(self):
    self.serv_addr = self.serv_addr_ent.get()
    self.serv_port = self.serv_port_ent.get()
    self.serverAddressPort = (self.serv_addr, int(self.serv_port))

    msgFromClient       = "echo"

    self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    bytesToSend = str.encode(msgFromClient)
    self.udp_socket.sendto(bytesToSend, self.serverAddressPort)
    self.udp_socket.settimeout(2.0)

    try:
      data, addr = self.udp_socket.recvfrom(1024)
      self.display_message("Connected")
    except socket.timeout:
      self.display_message("No target connection")

    self.udp_socket.close()

    msg = str(data, "utf-8")
    print(msg)

  def parse_trace(self):
    self.skin.actions["parse"](self)
  
  def parse_func(self):
    return

  def parse_kprobe(self):
    kprobe_words = self.kp.kprobe.split()
    self.kp.func = kprobe_words[1]
    kprobe_name = kprobe_words[0].partition(':')
    self.kp.access = kprobe_name[0]
    self.kp.ktype = self.kp.access
    self.kp.kname = kprobe_name[2]

## Must assign self.action before call
  def for_each_trace(self):
    for self.kp.kprobe in self.gettrace():
      self.parse_trace()
      self.action(self)

  def set_skin(self, new_skin):
    self.skin = skin(self, new_skin)
    self.switch_mode(self.skin)

  def select_func(self):
    self.set_skin(func_skin)

  def select_ktrace(self):
    self.set_skin(kprobe_skin)

  def read_trace(self):
    print("read_trace")

    self.act_name_str.set(self.skin.op_name)
    self.act_button_str.set(self.skin.op_butt)
    
    self.kp.configure()
    self.kp.complete()
    return

  def display_message(self, out_string):
    self.story_txt.delete(0.0, END)
    self.story_txt.insert(0.0, out_string)

  def display_message_cont(self, out_string):
    self.story_txt.insert(0.0, out_string)

  def display_trace(self, out_string):
    self.trace_txt.delete(0.0, END)
    self.trace_txt.insert(0.0, out_string)

  def display_trace_add(self, out_string):
    self.trace_txt.insert(END, '\n' + out_string)

  def gettrace(self):
    return self.trace_txt.get('0.0', END).splitlines()


  def log_message(self, message):
    if self.log_enable:
      message = message + "\n"
      fi = open(self.logname, "a")  # append mode
      fi.write(message)
      fi.close()

  def log_on(self):
    self.log_enable = True

  def log_off(self):
    self.log_enable = False

  def set_kprobe(self, kprobe):
    self.kp = kprobe

class kprobe():

  def __init__(self, app, ctrl):
    self.app = app
    self.ctrl = ctrl
    self.tracing = "/sys/kernel/debug/tracing"
    self.flock = "/var/tmp/.ftrace-lock"
    self.app.set_kprobe(self)

  def fs_addr(self, local):
    return self.tracing + local

  def ktrace_config(self):
    self.opt_pid = self.app.pid.get()
    self.opt_tid = self.app.tid.get()
    self.opt_filter = self.app.filter.get()
    self.opt_force = self.app.force.get()
    self.opt_duration = self.app.duration.get()
    self.opt_view = False
    self.opt_header = self.app.header.get()
    self.opt_stack = self.app.stack.get()

    self.duration = int(self.app.duration_ent.get())
    self.pid = int(self.app.pid_ent.get())
    self.tid = int(self.app.tid_ent.get())
    self.filter = self.app.filter_ent.get()

    if (self.opt_pid and self.opt_tid) or (self.opt_pid and self.opt_filter) or (self.opt_filter and self.opt_tid):
      print("pid, tid and filter are mutually exclusive")
      self.app.display_message("pid, tid and filter are mutually exclusive")
      return False
    if self.opt_duration and self.opt_view:
      print("duration and view  are mutually exclusive")
      self.display_message("duration and view  are mutually exclusive")
      return False

    self.ctrl.clear()
    self.global_trace_enable('0')
    self.reset_tracer()
    self.stacktrace_enable('0')
    self.pre_action = self.ctrl.extract()
    self.process(self.ctrl.result)
    self.app.action = self.app.skin.actions["config_once"]
    self.app.for_each_trace()
    if not self.opt_duration or self.duration < 1:
      self.duration = 1

    self.ctrl.clear()

    self.global_trace_enable('1')
    self.pre_action = self.ctrl.extract()
    self.process(self.ctrl.result)
    self.ctrl.clear()

    time.sleep(self.duration)

    self.trace_show()
    self.global_trace_enable('0')

    self.action = self.ctrl.extract()
    self.process(self.ctrl.result)






  def configure(self):
    self.app.skin.actions["config"](self.app)

  def config_func_once(self):
    self.ctrl.clear()
    self.function_profile_enabled("0")
    self.add_ftrace_filter(self.kprobe)

  def config_kprobe_once(self):
    self.ctrl.clear()
    self.filter_disable()

    if self.opt_pid:
      self.opt_filter = True
      directory = "/proc/" + self.app.pid_ent.get() + "/task/"
      self.filter_str = ''

      dir = self.read_dir_immediately(directory)

      for f in dir.split():
        self.filter_str += "common_pid == " + f + " || "

      self.filter_str = self.filter_str[:-4]

    if self.opt_tid:
      self.opt_filter = True
      self.filter_str = "common_pid == " + self.app.tid_ent.get()

    cond = (self.kprobe[1] == ':') and ((self.kprobe[0] == 'p') or (self.kprobe[0] == 'r'))
    if not cond:
      print ("kprobe must start with 'p: or r:")
      return False

    if not self.opt_force:
      cmd = "grep -w " + self.func + " " + self.tracing + "/available_filter_functions"
      res = self.app.udp_exchange(cmd, disp = False).rstrip()


      if res != self.func:
        if not self.opt_force:
          print(f'ERROR: func {self.func} not in {self.tracing + "/available_filter_functions"}')
          print("Either it doesn't exist, or, it might be unsafe to kprobe.")
          print('Exiting. Use force selection to override.\n\n')
          return

#take lock

    self.kprobe_event_append()

    if self.opt_filter:
      self.filter_enable()

    if self.opt_stack:
      self.stacktrace_enable('1')


    self.kprobe_enable('1')
    self.pre_action = self.ctrl.extract()

    self.process(self.ctrl.result)

    return True

  def func_config(self):
    self.opt_pid = self.app.pid.get()
    self.opt_tid = self.app.tid.get()
    self.opt_filter = self.app.filter.get()
    self.opt_force = self.app.force.get()
    self.opt_duration = self.app.duration.get()
    self.opt_view = False
    self.opt_header = self.app.header.get()
    self.opt_stack = self.app.stack.get()

    self.duration = int(self.app.duration_ent.get())
    self.pid = int(self.app.pid_ent.get())
    self.tid = int(self.app.tid_ent.get())
    self.filter = self.app.filter_ent.get()


    self.opt_pid = self.app.pid.get()
    self.opt_tid = self.app.tid.get()
    self.opt_filter = self.app.filter.get()
    self.opt_force = self.app.force.get()
    self.opt_duration = self.app.duration.get()
    self.opt_view = False

    self.opt_header = self.app.header.get()
    self.opt_stack = self.app.stack.get()

    self.duration = int(self.app.duration_ent.get())
    self.pid = int(self.app.pid_ent.get())
    self.tid = int(self.app.tid_ent.get())
    self.filter = self.app.filter_ent.get()

    self.ctrl.clear()
    self.set_ftrace_filter("")
    self.pre_action = self.ctrl.extract()
    self.process(self.ctrl.result)

    self.app.action = self.app.skin.actions["config_once"]

    self.ctrl.clear()
    self.app.for_each_trace()
    self.pre_action = self.ctrl.extract()
    self.process(self.ctrl.result)
    if not self.opt_duration or self.duration < 1:
      self.duration = 1


    self.ctrl.clear()
    self.reset_tracer()
    self.function_profile_enabled("1")

    self.pre_action = self.ctrl.extract()
    self.process(self.ctrl.result)
    self.ctrl.clear()

    time.sleep(self.duration)
    self.trace_show()
    self.ctrl.clear()
    self.function_profile_enabled("0")
    self.set_ftrace_filter("")
    self.func_show()  #kprobe

    self.action = self.ctrl.extract()
    self.process(self.ctrl.result)

  def kprobe_event_append(self):
    self.ctrl.new_cmd('echo', self.kprobe, '>>', self.fs_addr("/kprobe_events"), False)

  def kprobe_event_remove(self):
    enable = '-:' + self.kname + ' 2> /dev/null'
    self.ctrl.new_cmd('echo', enable, '>>', self.fs_addr("/kprobe_events"), False)

  def filter_disable(self):
    name = self.app.kp.tracing + '/events/kprobes/' + self.app.kp.kname + '/filter'
    self.ctrl.new_cmd('echo', '0', '>', name, False)


  def filter_enable(self):
    name = self.app.kp.tracing + '/events/kprobes/' + self.app.kp.kname + '/filter'
    print(self.filter)
    self.ctrl.new_cmd('echo', '"' + self.filter_str + '"', '>', name, False)

  def stacktrace_enable(self, enable):
    name = self.app.kp.tracing + '/options/stacktrace'
    self.ctrl.new_cmd('echo', enable, '>', name, False)

  def kprobe_enable(self, enable):
    self.ctrl.new_cmd('echo', enable, '>', self.fs_addr("/events/kprobes/" + self.kname + "/enable"), False)

  def global_trace_enable(self, enable):
    name = self.tracing + '/tracing_on'
    self.ctrl.new_cmd('echo', enable, '>',  name, False)

  def read_dir_immediately(self, directory):
      cmd = "ls " + directory + ' 2> /dev/null'
      dir = self.app.udp_exchange(cmd, disp = False)
      return dir

  def trace_show(self):
    if self.opt_header:
      name = self.tracing + '/trace'
    else:
      name = self.tracing + '/trace | grep -v \#'

    self.ctrl.new_cmd('cat', '', '',  name, True)


  def reset_tracer(self):
    name = self.tracing + '/current_tracer'
    self.ctrl.new_cmd('echo', 'nop', '>',  name, False)


  def set_ftrace_filter(self, msg):
    name = self.tracing + '/set_ftrace_filter'
    self.ctrl.new_cmd('echo', "'" + msg + "'", '>',  name, False)

  def add_ftrace_filter(self, msg):
    name = self.tracing + '/set_ftrace_filter'
    self.ctrl.new_cmd('echo', "'" + msg + "'", '>>',  name, False)


  def function_profile_enabled(self, enable):
    name = self.tracing + '/function_profile_enabled'
    self.ctrl.new_cmd('echo', "'" + enable + "'", '>',  name, False)

  def func_show(self):
    name = self.tracing + '/trace_stat/'
    self.ctrl.new_cmd('ls', '', '',  name, False)
    self.pre_action = self.ctrl.extract()
    files = self.process(self.ctrl.result)
    fi_names = files.split('\n')
    cores = {}
    print()
    print()
    for file in fi_names:
      res = re.findall(r'\d+', file)
      if len(res) == 0:
        break
      cpu = "core" + res[0]
      cores[file] = cpu
    retval = ''
    for key, value in cores.items():
      self.ctrl.clear()
      name = self.tracing + '/trace_stat/' + key
      self.ctrl.new_cmd('cat', '', '',  name, False)
      self.pre_action = self.ctrl.extract()
      res = self.process(self.ctrl.result)
      retval += value + '\n' + res
      self.ctrl.clear()
      
    print(retval)
    self.app.display_message(retval)


  def complete(self):
    self.app.action = self.app.skin.actions["release_once"]

    self.app.for_each_trace()


  def complete_kprobe_once(self):
    self.ctrl.clear()
    self.kprobe_enable('0')
    print(self.opt_filter)
    if self.opt_filter:
        self.filter_disable()

    enable = '-:' + self.kname + ' 2> /dev/null'
    self.kprobe_event_remove()

    if self.opt_stack != 0:
        self.stacktrace_enable('0')

# That is the last code in the function:
    self.post_action = self.ctrl.extract()
    self.process(self.ctrl.result)

    return


  def complete_func_once(self):
    return
    self.ctrl.clear()
    self.function_profile_enabled("0")
    self.set_ftrace_filter("")

    self.action = self.ctrl.extract()
    self.process(self.ctrl.result)


  def process(self, prog):
    res = ''
    for cmd in range(len(self.ctrl.batch)):
      self.ctrl.handle(prog[0][cmd], prog[1][cmd])
      res += self.app.udp_exchange(prog[0][cmd], prog[1][cmd])
    return res

class skin():

  def __init__(self, app, skin_setup):
    self.op_name = skin_setup["op_name"]
    self.op_butt = skin_setup["op_butt"]
    self.commands = skin_setup["commands"]
    self.actions = skin_setup["act"]
    self.opts = skin_setup["opts"]
    self.options = skin_setup["options"]
#


opt_select = [
force.rstrip(),
duration.rstrip(),
pid.rstrip(),
tid.rstrip(),
filter.rstrip(),
header.rstrip(),
stack.rstrip()
]

######################
def kprobe_conf_once(app):
  app.kp.config_kprobe_once()


  return

def kprobe_rel_once(app):
  app.kp.complete_kprobe_once()

def kprobe_config(app):
#  print("kprobe_config")
  app.kp.ktrace_config()

def parse_kprobe(app):
    app.parse_kprobe()


kprobe_act = {
  "config_once" : kprobe_conf_once,
  "release_once" : kprobe_rel_once,
  "config" : kprobe_config,
  "parse" : parse_kprobe
}

kprobe_opts = {
  "force" : "force",
  "duration" : "duration",
  "pid" : "pid",
  "tid" : "tid",
  "filter" : "filter",
  "header" : "header",
  "stack" : "stack"
}

options_select_ktrace = {
               force.rstrip() : False,
               duration.rstrip() : True,
               pid.rstrip() : True,
               tid.rstrip() : True,
               filter.rstrip() : False,
               header.rstrip() : True,
               stack.rstrip() : True
               }


kprobe_skin = {
  "op_name" : op_name_ktrace,
  "op_butt" : op_butt_ktrace,
  "commands" : "p:icmp_out_p icmp_out_count\nr:icmp_out_r icmp_out_count",
  "options" : options_select_ktrace,
  "act"  : kprobe_act,
  "opts" : kprobe_opts
}

######################
def func_conf_once(app):
  app.kp.config_func_once()

def func_rel_once(app):
  app.kp.complete_func_once()

def func_config(app):
  app.kp.func_config()

def parse_func(app):
    app.parse_func()
    return



func_act = {
  "config_once" : func_conf_once,
  "release_once" : func_rel_once,
  "config" : func_config,
  "parse" : parse_func
}

func_opts = {
  "force" : "force",
  "duration" : "duration",
  "pid" : "pid",
  "tid" : "tid",
  "filter" : "filter",
  "header" : "header",
  "stack" : "stack"
}

options_select_func = {
               force.rstrip() : False,
               duration.rstrip() : True,
               pid.rstrip() : False,
               tid.rstrip() : False,
               filter.rstrip() : False,
               header.rstrip() : False,
               stack.rstrip() : False
               }

func_skin = {
  "op_name" : op_name_func,
  "op_butt" : op_butt_func,
  "commands" : "*icmp*",
  "options" : options_select_func,
  "act"  : func_act,
  "opts" : func_opts
}


ctr = control()


####################################

root = Tk()
root.title("Kernel tracing")
# create a menubar
menubar = Menu(root)
root.config(menu=menubar)
ap = Application(root)

kpr = kprobe(ap, ctr)

file_menu = Menu(menubar)

# add a menu items to the menu
file_menu.add_command(
    label='Kprobe',
    command=ap.select_ktrace
)

# add a menu items to the menu
file_menu.add_command(
    label='Func',
    command=ap.select_func
)


# add a menu items to the menu
file_menu.add_command(
    label='Log ON',
    command=ap.log_on
)

# add a menu items to the menu
file_menu.add_command(
    label='Log OFF',
    command=ap.log_off
)

file_menu.add_command(
    label='Exit',
    command=root.destroy
)

# add the File menu to the menubar
menubar.add_cascade(
    label="File",
    menu=file_menu
)


root.mainloop()



