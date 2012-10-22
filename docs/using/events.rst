
.. _events:

*******************
Trace events list
*******************

Options
===========

The event options are used to tune conditions that events occur, e.g, we can skip CWR events by give mask=CWR option of tcp_congestion event.

Below are all common options.

mask
-----------

Not all events support this option.

This option can be used to skip some uninterested event conditions, e.g, the tcp_congestion event occurs on TCP feels networks is overloaded, the possible conditions are CWR, FRTO, Fast Retransmitation, Loss, FRTO-Loss. If we only care that segments loss conditions, then we can use follow command line option: ::

        -e tcp_congestion,mask=CWR:FRTO:FastRtx

So CWR, FRTO and Fast Retransmitation events do not be recorded at disk.

primary
-----------

By default, all trace events are treated independently. that is, if you enabled it and they are successfully passed a variety of filter operations, then all they will be recorded to disk. In many cases, this simple model works well, but these filtered events still result in a lot of results mixed much valueless and some valuable data in some cases.

We hope record the event more targeted by create dependency among events, we only care about the event A if and only if any of event B are occured later, that is, it is only valuable to record occured events A before event B occured. In this scenario, we called event B as the "primary event" of event A. The primary option is used to establish this kind of association among events.

For example, if we wanted to verify whether significant jitter of RTT can be used to predict possible TCP segments loss, then we may use below command line option: ::

       -e tcp_rttm,primary=tcp_congestion -e tcp_congestion,mask=CWR:FRTO:FastRtx

In above example, tcp_rttm is a slave event, tcp_congestion is its primary event. Only tcp_rttm events occus before tcp_congestion will be recorded on disks.

The limitation of current implementaton: a primary event can correspond to multiple slave events, but a event can not be as slave event of mulitple primary events at same time. 

You can record up to 32 slave events.

Common events
===============

Common parsed fields
---------------------

We will introduce many events, we use skb_rps_info as example to describe common parsed fields: ::

     144574 1347852135.451990372 action=rps_info skb=0xffff880037c7f4c0 rx-queue=0 rx-hash=0x0 cpu=0xffffffff ifindex=1 src=100007f dst=100007f sport=12865 dport=41223 proto=0x6

Fields：

    * 144574                    - sequence, each event has a unique sequence number, the events that have small value of sequence number ocurr before events that have big one.
    * 1347852135.451990372      - time stamp, the unit is second. 
    * action=rps_info           - event name, name is rps_info here.
    * skb=0xffff880037c7f4c0 (or sk=0x.....)    - the memory address of data structure triggers this event. e.g, we may use this magic number to find out further information of corresponding TCP connection.

skb_rps_info
------------

   Type: packet based event (Need -F option to filter it)
   Common options: primary

   To show hash details of RPS. As we know, RPS dispatch received packets onto different processors by hashing packets header.
   
   An example of parsed example: ::

     144574 1347852135.451990372 action=rps_info skb=0xffff880037c7f4c0 rx-queue=0 rx-hash=0x0 cpu=0xffffffff ifindex=1 src=100007f dst=100007f sport=12865 dport=41223 proto=0x6

   Fields:

    * rx-queue=0        - the rx queue of NIC.
    * rx-hash=0x0       - computed key of RPS hash.
    * cpu=0xffffffff    - target CPU.
    * ifindex=1         - the index of NIC.
    * src=100007f       - source address, in network byte order.
    * dst=100007f       - destination address, in network byte order.
    * sport=12865       - source port, in host byte order.
    * dport=41223       - destination port, in host byte order.
    * proto=0x6         - protocol number.

TCP
============

   All of the following events are based on the events of the connection, therefore need to use -S option filtration.

tcp_congestion
---------------

   Common options: mask,primary

TCP congestion event.

A parsed example ::

      1378215231 1347620030.225669489 action=tcp_cong state=FRTO-Loss sk=0xffff88062f8bc700 cwnd=32768 rto=201 sndnxt=1076842762 snduna=1076842762

Fields:
      * state=FRTO-Loss         - The type of congestion, Possible values of::
             * CWR              - Congestion Window Reduced, e.g. received ECE bit with ECN, or local congestion.
             * Loss             - Packets loss
             * FRTO-Loss        - Packets loss with enabled F-RTO.
             * FRTO             - F-RTO is detecting if RTO is spurious.
             * FastRtx          - Enter fast retransmitation
      * cwnd=32768              - Congestion window on congestion occurs, unit: segment
      * rto=201                 - RTO, unit：ms
      * sndnxt=1076842762       - TCP SND_NXT
      * snduna=1076842762       - TCP SND_UNA

tcp_connection
---------------
   Common options: primary   

   Basic state of TCP connection migration, except LISTEN.

   A parsed example ::

      88 1347851487.186018014 action=tcp_conn sk=0xffff880072144780  state=ESTABLISHED local=127.0.0.1:47857 peer=127.0.0.1:55469

Fields:
    * state=ESTABLISHED         - The new state of a TCP connection
    * local=127.0.0.1:47857     - The local address/port of a TCP connection
    * peer=127.0.0.1:55469      - The peer address/port of a TCP connection

icsk_connection
-----------------
   Common options: primary   

   Basic state of TCP connection migration, only contains LISTEN.

   A parsed example ::
     
      144561 1347851976.556067571 action=icsk_conn sk=0xffff880070ec4e40
      
Fields:
        See tcp_connection.

tcp_sendlimit
---------------
   Common options: primary,mask

   The reason of TCP stop sending data in tx queue.

   A parsed example ::

      144606 1347852135.453115265 action=tcp_sendlim sk=0xffff880037f96080 reason=ok cnt=1 mtuprobe=1 ssthresh=37 cwnd=10/0 swnd=33920

Fields:
      * reason=ok       - The reason of stop sending, they are also can used in mask option:
            * cwnd      - limited by cwnd
            * swnd      - limited by receiver advertised window
            * nagle     - limited by Nagle algorithm
            * tso       - limited by TSO
            * frag      - limited by failed to fragment
            * pushone   - limited by PSH
            * other     - limited by any other reason
            * ok        - sucessfully sent some data
      * cnt=1           - how many segments are sucessfully sent
      * mtuprobe=1      - executing PMTU probe
      * ssthresh=37     - current slow start threshold
      * cwnd=10/0       - snd_cwnd/snd_cwnd_cnt
      * swnd=33920      - current sending window

tcp_ca_state
--------------
   Common options: primary,mask

   TCP congestion avoidance state machine event.

   这个事件也支持mask选项，可以用于过滤不关心的状态，例如，tcp_ca_state,mask=disorder, 就不会记录切换到乱序状态的事件了。

   A parsed example ::

      1378026600 1347620023.792681609 action=tcp_ca_state sk=0xffff88062f8bc700
      
Fields:
      * state=Disorder CA states, they are also can used in mask option: ::
              * Open
              * Disorder
              * CWR
              * Recovery
              * Loss
      * Below are copied from tcp_sock data structure in kernel: ::
          * cwnd=2
          * rto=3216
          * snduna=1076842506
          * sndnxt=1076842762
          * snd_ssthresh=7 
          * snd_wnd=32768 
          * rcv_wnd=32768 
          * high_seq=1076842762 
          * packets_out=1 
          * lost_out=0 
          * retrans_out=0 
          * sacked_out=0 
          * fackets_out=0 
          * prior_ssthresh=67 
          * undo_marker=0
          * undo_retrans=0
          * total_retrans=4 
          * reordering=28 
          * prior_cwnd=4294967295 
          * mss_cache=16384

tcp_rttm
--------------
   Common options: primary

   TCP RTT measurement.

   A parsed example ::

      144577 1347852135.451990372 action=tcp_rttm sk=0xffff880037f96080 snd_una=256095406 rtt_seq=256095406 rtt=0 rttvar=200 srtt=8 mdev=2 mdev_max=200

Fields:
    * snd_una=256095406         - current SNA_UNA
    * rtt_seq=256095406         - current SND_NXT
    * rtt=0                     - current RTT sample
    * rttvar=200                - RTTVar
    * srtt=8                    - Smooth RTT
    * mdev=2                    - mdev
    * mdev_max=200              - mdev_max

sk_timer
-------------
   Common options: primary, mask

   TCP timers event

   A parsed example ::

      144604 1347852135.453115265  action=tcp_timer sk=0xffff880072422100

Fields:
     * op=reset         - operations, they are also can used in mask option, possbile values of: ::
        * setup
        * reset
        * stop
     * timers=delay-ack         - timer, they are also can used in mask option, possbile values of: ::
        * rexmit        - RTO timer
        * probe         - Zero window probe timer
        * keepalive     - Keepalive timer
        * delack        - Delayed ACK timer.
     * timeout=150ms    - Timeout, unit: microseconds

tcp_active_conn
-----------------
 　Record address information of current active TCP connections, each active TCP connection only can be record one time.

   A parsed example ::

      144572 1347852135.451990372 action=tcp_active_conn sk=0xffff880037f96080

Fields:
    * state=ESTABLISHED         - Current state of a TCP connection.
    * local=127.0.0.1:41223     - local address:port
    * peer=127.0.0.1:12865      - peer address:port
