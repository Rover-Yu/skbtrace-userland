
.. _options:

***********************
Command line options
***********************

Skbtrace provides below two user space utilties:

* skbtrace, this utility is used to record traced binary data from kernel into some files
* skbparse, this utility is used to parse binary traced data into human readable text form.


skbtrace
==========

``-r PATH``
   The mount point of debugfs file system. skbtrace use debugfs to read traced binary data from kernel. skbtrace tries to mount it if it was not mounted at PATH.

   Default is /sys/kernel/debug.

``-D DIR``
   The directory which record traced binary data into. skbtrace tries to create it first if it did not exist.
   
   Default is ./skbtrace.results

``-w SECONDS``
   Sets run time to the number of seconds specified.

   Default: Run until receiving SIGINT signal (Press Ctrl-C and by kill command). Of course, you also can use SIGKILL to terminate skbtrace, but it is not recommended, because of skbtrace may drop some trace data at this time, and then you probably can not unload these skbtrace kernel modules since non-zero reference counts (Tips: normal terminating skbtrace again can reset reference count of kernel modules).

``-b BYTES`` ``-n COUNT``
   Specfify size and count of sub buffers in relay file system. You may try to increase these if skbtrace reported some traced data are dropped.

``-c PATH_LIST``
   The comma separated path list to locate configuration file skbtrace.conf. All configurations in found skbtrace.conf files will be merged together.
   
   Default is to enable all events.

``-C CONTEXT_LIST``
   Specify to which are interested contexts events are triggered under. Events may be triggered under hard interrupt context, softirq context or syscall context. Sometimes, we only focus on events are triggered under specific contexts, this option provides such capability to filter out these uninterested contexts.

   * CONTEXT_LIST The comma separated CONTEXT list, CONTEXT may be:
        * syscall
        * softirq
        * hardirq

   Default are all contexts.

``-p PROCESSOR_MASK``
   You can use this option if the events are triggered on only some specific processors are interested.
   
     * PROCESSOR_MASK 1 = CPU0, CPU1, 4 = CPU2, 8 = cpu3, and so on.

   Default is all processors.

``-e EVENT[,OPTIONS_LIST]``
   Specify which are events you interested to, this option can be used repeatly, each one give a different trace event.

       * EVENT	 The name of trace event.
       * OPTIONS_LIST	The colon separated OPTION list of trace event, 

   For completed events reference manual, please refer to :ref:`events` .

   Default are to enable all events.

``-F FILTER``
   Specify the BPF based packet events filter. Please refer to manual of libpcap for syntax details

   Default is empty filter.

``-S FILTER``
   Specify the BPF based connection events filter. It only support TCP/IPv4 connections at present, and only can use IP addresses or/and ports. Please refer to manual of libpcap for syntax details.

   Default is empty filter.

``-s``
   This option is designed to work together with skbparse, it control skbparse to show parsed results at console lively. But this feature still is incompleted.

``-f``
   Overwrite possible old traced data without any warning.

``-l``
   Show all available trace events list.

``-V``
   Show more internal runtime information.

``-v``
   Show version number, then quit.

skbparse
==========

``-v``
  Show version number, then quit.

``-s``
  Show parsed results on standard output lively, it is a TODO.

``-S``
  Show parsed results on standard output.

``-o PATH``
  The output directory to save parsed human readable results.
 
  Default is current directory.

``-i PATH``
  The output directory to read trace binary data are recorded by skbtrace.

  Default is ./skbtrace.results

``-h``
  Show helps, then quit.
