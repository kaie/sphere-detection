sphere-detection
================
Various modules to implement the DetecTor design from http://detector.io

Use these instructions to get and run the initial sphere-detection code
on a Linux system, which implements parts of the DetecTor design.
You must use a terminal to build and run.

Get the code and build
===================
```bash
$ git clone https://github.com/kaie/sphere-detection
$ cd sphere-detection
$ git clone https://git.torproject.org/stem.git
$ git clone https://github.com/ndevilla/iniparser
$ hg clone https://hg.mozilla.org/projects/nspr
$ hg clone https://hg.mozilla.org/projects/nss
$ ./build-libs.sh
$ ./build.sh
```
Ensure you have the python and the tor system packages installed.
Check if your tor binary is in /usr/bin/tor or /usr/sbin/tor
If necessary, edit file sphere_control.config to adjust the tor_path setting.

Run interactively once
======================
```bash
$ source env.sh
$ python -c "import sphere_control; controller, proc = sphere_control.start()"
```
Be patient. The previous command will take a while when you first execute it,
while we bootstrap 5 separate Tor connections. You may use the following
command to watch the progress. You should wait until all spheres have reported
100% done. (Hit CTRL-C to exit following the log files.)
```bash
$ tail -f tor_data_dir/sphere*/tor.log
$ sphere-probe -p 443 -h en.wikipedia.org
```
Be patient for about 30 seconds. The certificate obtained from the server using
the direct connection will be printed, and the number of matches using Tor
network connections. If at least 4 matches were found, it will print SUCCESS,
or it will print FAILURE if less than 4 matches were found.
Repeat sphere-probe using other hosts or ports, e.g.:
```bash
$ sphere-probe -p 465 -h smtp.gmail.com
```
You may use the -D parameter to request that the certificates seen are
dumped to a file (PEM format).
If you wish to stop the detection spheres, run:
```bash
$ python -c "import sphere_control; sphere_control.stop()"
```

Run in monitoring mode
======================
You may use a configuration file that lists multiple servers to probe
and the certificate(s) you expect. They will be probed periodically.
You may use your own alert script, which will be called when unexpected
certificates are encountered. Your script will be called with one paramter,
a filename that contains a report, which includes the certificates that
were seen.
An example configuration file name sphere_probe.ini is provided which will
probe the hosts mentioned in the previous sectoin.
An example alert script is provided, but it doesn't do anything besides
printing a statement. You must adjust the script according to your needs.

To test using the provided example configuration, execute:
```bash
$ sphere-probe -C ./sphere-probe.ini -A ./alert.sh
```

Of course, the included certificates are examples, only.
The servers might change their certificates.

The purpose of this software is to monitor your own server!
You should change the configuration to monitor servers that you control,
and update your configuration whenever you change the certificate on your
server.

At this time, no system integration is available, but you could start
using it by running it in a "screen" terminal session on your server.

It's probably a good idea to run sphere-probe on a separate server,
preferably at separate location, but not on the server you're monitoring.

Installation
============
At this time, no automatic installation is supported.
You should build this software locally, make sure the terminal's current working 
directory is the main directory where you unpacked and built this software,
and execute the commands from within that directory.
If used in this way, the software shouldn't modify any files in 
unrelated directories.
