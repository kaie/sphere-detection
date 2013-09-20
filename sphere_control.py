import os
import signal
import sys
import ConfigParser

import stem.control
import stem.process
import stem.util.system

DEFAULT_BASE_PORT = 9160

def start_tor(tor_path, socks_port, control_port, data_dir, countries):
    log_setting = "notice file " + data_dir + os.sep + "tor.log"
    tor_config = {
	'SocksPort': str(socks_port),
	'ControlPort': str(control_port),
	'ExitPolicy': 'reject *:*',
	'ExitNodes': countries,
	'StrictExitNodes': str(1),
	'AvoidDiskWrites': str(1),
	'DataDirectory': data_dir,
	'Log': log_setting,
    }
    stem.process.launch_tor_with_config(config = tor_config, tor_cmd = tor_path, completion_percent=80)

def stop_tor(control_port):
    tor_pid = stem.util.system.get_pid_by_port(control_port)
    if tor_pid:
	os.kill(tor_pid, signal.SIGTERM)

def is_tor_running(control_port):
    return bool(stem.util.system.get_pid_by_port(control_port))

def ensure_dir(dir_name):
    if os.path.exists(dir_name):
	if os.path.isdir(dir_name) != True:
	    print "existing file %s conflicts with configuration directory" % dir_name
	    exit()
	return
    os.mkdir(dir_name)

#10 ports will be used, +0 to +9
def start(base_port = DEFAULT_BASE_PORT):
    config = ConfigParser.ConfigParser()
    config.readfp(open('sphere_control.config'))
    #config.read(['detector.config', os.path.expanduser('~/.myapp.cfg')])
    tor_path = config.get('global', 'tor_path')
    ensure_dir("tor_data_dir")
    countries_list = []
    controller = []
    for i in range(0,5):
	countries_list.append([])
	sphere = str(i+1)
	sphere_name = "sphere"+sphere
	socks_port = base_port + (i * 2)
	control_port = socks_port + 1
	print "%s: socks %s, control %s" % (sphere_name, str(socks_port), str(control_port))
	data_dir = "tor_data_dir"+os.sep+sphere_name
	ensure_dir(data_dir)
	countries = config.get(sphere_name, 'countries').splitlines()
	countries_string = ""
	for ci in countries:
	    c = ci.strip()
	    if c == "":
		continue
	    if len(c) != 2:
		print "invalid country %s in %s" % (c, sphere_name)
		exit()
	    for check_i in range(0, i):
		if c in countries_list[check_i]:
		    print "country %s is listed in multiple spheres" % c
		    exit()
	    countries_list[i].append(c)
	    if countries_string != "":
		countries_string += ","
	    countries_string += "{" + c + "}"
	if countries_string == "":
	    print "invalid empty countries list in " + sphere_name
	    exit()
	print "%s has countries %s" % (sphere_name, countries_string)
	start_tor(tor_path, socks_port, control_port, data_dir, countries_string)
	controller.append(stem.control.Controller.from_port(port = control_port))
	controller[i].authenticate()
    print "Tor spheres have been started... To stop the spheres, use:"
    print "  sphere_control.stop()"
    return controller
    #caller can use e.g.: controller[4].signal(stem.Signal.NEWNYM)

def stop(base_port = DEFAULT_BASE_PORT):
    for i in range(0,5):
	socks_port = base_port + (i * 2)
	control_port = socks_port + 1
	stop_tor(control_port)
