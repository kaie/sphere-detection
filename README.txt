sphere-detection
================
Various modules to implement the DetecTor design from http://detector.io

Use these instructions to get and run the initial sphere-detection code
on a Linux system, which implements parts of the DetecTor design.
You must use a terminal to build and run.

Get the code and build
===================
$ git clone https://github.com/kaie/sphere-detection
$ cd sphere-detection
$ git clone https://git.torproject.org/stem.git
$ hg clone https://hg.mozilla.org/projects/nspr
$ hg clone https://hg.mozilla.org/projects/nss
$ ./build-nss.sh
$ ./build.sh
Ensure you have the python and the tor system packages installed.
Check if your tor binary is in /usr/bin/tor or /usr/sbin/tor
If necessary, edit file sphere_control.config to adjust the tor_path setting.

Run
===
$ source env.sh
$ python -c "import sphere_control; controller, proc = sphere_control.start()"
Be patient. The previous command will take a while when you first execute it,
while we bootstrap 5 separate Tor connections. You may use the following
command to watch the progress. You should wait until all spheres have reported
100% done. (Hit CTRL-C to exit following the log files.)
$ tail -f tor_data_dir/sphere*/tor.log
$ sphere-probe -p 443 -h en.wikipedia.org
Be patient for about 30 seconds. The certificate obtained from the server using
the direct connection will be printed, and the number of matches using Tor
network connections. If at least 4 matches were found, it will print SUCCESS,
or it will print FAILURE if less than 4 matches were found.
Repeat sphere-probe using other hosts or ports, e.g.:
$ sphere-probe -p 465 -h smtp.gmail.com
If you wish to stop the detection spheres, run:
$ python -c "import sphere_control; sphere_control.stop()"
