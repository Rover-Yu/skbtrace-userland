
.. _building:

**************
Building
**************

So far, the skbtrace still is under development, it has not an official release. You have to download source code from github.com manually.

To build it, you need:
* git. To download sources.
* libpcap and its development package. To build user space utility, that is the RPM package libpcap-devel on Redhat series distributions, or DEB package libpcap-dev on Debian based distributions.

Build patched kernel
===========================

Current source is based on upstream v3.6 kernel.

Steps:

* git clone git://github.com/Rover-Yu/skbtrace-kernel.git skbtrace-kernel.git
* cd skbtrace-kernel.git
* Make sure to turn on below kernel configuration:
     * CONFIG_SKBTRACE
     * CONFIG_SKBTRACE_IPV4
     * CONFIG_SKBTRACE_IPV6
     * (Optional, recommended) CONFIG_JUMP_LABEL
* Build and install kernel, reboot your system, good luck.

Build user space utilities
==========================

Steps:

* git clone git://github.com/Rover-Yu/skbtrace-userland.git skbtrace-userland.git
* cd skbtrace-userland.git
* make

After above steps are done，you should get skbtrace [#]_ and skbparse [#]_

.. rubric:: Notes

.. [#] skbtrace, this utility records traced binary data from kernel into some files
.. [#] skbparse, this utility parsed binary traced data into human readable text form.
