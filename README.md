## Introduction

sfreport.pl is an diagnostics tool for Linux systems running AMD Solarflare branded hardware and software.

This Perl script generates an HTML file.
You may specify an alternate file name on the command line.  If the file name does not end in ".htm" or ".html" the information will be written in plain text format

The genertated file containing information about the configuration of the AMD Solarflare NIC and the system it is installed in.
For example: 
 * Interface statistics such as packet drops
 * AMD-Solarflare specific driver logging/error messages
 * Firmware and driver settings + version information
 * AMD-Solarflare product information such as NIC model
 * System information such as CPU architechture, kernel and OS

This information is intended for use by AMD Solarflare engineers but is recorded in a text format that may be useful to others.

## Usage

For the collection of full diagnostics information, the sfreport script should be run with root permissions. For example:
 $ sudo perl sfreport.pl
The output of sfreport will be in html format. The filename will be in the format sfreport-'date'-'time'.html.

## Notes

Information is collected using standard Linux utilites such as 'ethtool' or 'cat'.
For example, 'Interface Statistics' are gathered using 'ethtool -S'.

sfreport is designed for minimum impact on a system. However, for production systems, we recommend running outside of particularly busy periods.

## Copyright

This file: (c) Copyright 2020-2023 Advanced Micro Devices, Inc.
