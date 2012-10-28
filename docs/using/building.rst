
.. _building:

**************
Building
**************

This proejct still is under development, to use it you have to download source code from github.com manually.

To build it, you need to prepare follow steps first:
   * Install git, for sources download.
   * Install libpcap and its development package for user space utility build. They are RPM package libpcap-devel on Redhat series distributions, or DEB package libpcap-dev on Debian based distributions.

Build patched kernel
===========================

Current source is based on upstream v3.6 kernel.

Steps:

* Download kernel sources by run "git clone git://github.com/Rover-Yu/skbtrace-kernel.git skbtrace-kernel.git"
* cd skbtrace-kernel.git
* Build kernel, please make sure below below configuration items are enabled:
     * CONFIG_SKBTRACE
     * CONFIG_SKBTRACE_IPV4
     * CONFIG_SKBTRACE_IPV6
     * (Optional, recommended) CONFIG_JUMP_LABEL
* Install built binary as upstream kernel, reboot your system, good luck.

Build user space utilities
==========================

Steps:

* Download userland utilies sources by "git clone git://github.com/Rover-Yu/skbtrace-userland.git skbtrace-userland.git"
* cd skbtrace-userland.git
* make

After above steps are done，you should get skbtrace [#]_ and skbparse [#]_

.. rubric:: Notes

.. [#] skbtrace, this utility is used to record traced binary data from kernel into some files
.. [#] skbparse, this utility is used to parse binary traced data into human readable text form.
