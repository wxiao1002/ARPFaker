#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : Monit.py
# @Author: wang xiao
# @Date  : 2022/11/5
# @Desc  : trace
# @Use  python Monit.py pid

import sys
import time
import psutil

# get pid from args
if len(sys.argv) < 2:
    print("missing pid arg")
    sys.exit()

# get process
pid = int(sys.argv[1])
p = psutil.Process(pid)


interval = 3  # polling seconds
with open("process_monitor_" + p.name() + '_' + str(pid) + ".csv", "a+") as f:
    f.write("time,cpu%,mem%\n")  # titles
    while True:
        current_time = time.strftime('%Y%m%d-%H%M%S', time.localtime(time.time()))
        cpu_percent = p.cpu_percent()  # better set interval second to calculate like:  p.cpu_percent(interval=0.5)
        mem_percent = p.memory_percent()
        line = current_time + ',' + str(cpu_percent) + ',' + str(mem_percent)
        print(line)
        f.write(line + "\n")
        time.sleep(interval)
