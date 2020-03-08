#!/usr/bin/python

import subprocess
import os

bashCommand = "onos-buck run onos-local -- clean"
my_env = os.environ.copy()
process = subprocess.Popen(bashCommand.split(), cwd="/home/sdn/onos", env=my_env, stdout=subprocess.PIPE)
output, error = process.communicate()
