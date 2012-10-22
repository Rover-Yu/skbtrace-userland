
.. _introduction:

************
Introduction
************

Motivations
================

As we known, the blktrace indeed helps Linux file system and block subsystem developers a lot, even it also help them to locate some problems in mm subsystem. However, the networking stack hackers don't have such like good luck, although tcpdump is very very useful, but they still often need to start investigation from limited exported statistics counters, then may directly dig into source code to guess possible solutions, then test their ideas, if good luck doesn't arrive, then start another investigation-guess-test loop. Even, for some performance problems, there have no appropriate counters at all. Now, you see, it is time-costly diffcult process, and it is almost hard to share experiences and report problem, many users have not enough understanding for protocol stack internals, I saw some "detailed reports" actually does not carry useful information to solve problem.

The networking subsystem is rather performance sensitive than block subsystem in kernel, so I do not want to add too detailed counters directly here. In fact, Some folks already tried to add more statistics counters for detailed performance measuration, e.g. RFC4898 and its implementation Web10g project. Web10g is a great project for researchers and engineers on TCP stack, which exports many valuable per-connection details to userland by procfs or netlink interface. However, it tightly depends on TCP and its implementation, other protocols implementation have to need some duplicated works to archive same goal, and it also has some measurable overhead (5% - 10% in my simple netperf TCP_STREAM benchmark), I think it'd better that such powerful tracing or instrumentation feature should be able to be zero overhead when it is off.

Goals
==============

The skbtrace project is designed to achieve below goals:

* Provide an extendable tracing infrastructure to support various protocols instead of specific one.
* Zero overhead when this feature is turned off.
* Directly report tracing details on per-connection/per-skb level instead of exporting information by some summary counters.
* Provide both BPF based filter capability for sk_buff (packets) and connections.

