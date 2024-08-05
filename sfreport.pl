#!/usr/bin/perl -w
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2022-2023, Advanced Micro Devices, Inc.
# Copyright (C) 2019-2022, Xilinx, Inc.
# Copyright (C) 2007-2019, Solarflare Communications.

# Reporting tool for AMD Solarflare under linux

# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation, incorporated herein by reference.

use strict;

use File::Basename;
use FileHandle;
use POSIX;
use Socket;
use Getopt::Long;


# AMD Solarflare device/driver identifiers.
use constant driver_name_re => 'sfc\w*|onload|xilinx_efct';
use constant rpm_name_prefixes =>
    'kernel-module-sfc-', 'kmod-solarflare-sfc-', 'sfc-dkms', 'sfutils', 'openonload', 'solar_capture', 'sfptp', 'kernel-module-xilinx-efct';
use constant deb_name_prefixes => 'sfc-modules-', 'xilinx-efct';
use constant EFX_VENDID_SFC => 0x1924;
use constant EFX_VENDID_XILINX => 0x10ee;

# General formatting.
use constant format_text => 0;
use constant format_html => 1;
use constant format_minimal => 2;

# Table formatting.
use constant gutter_width => 2;
use constant orient_horiz => 0;
use constant orient_vert => 1;
use constant values_format_default => 0;
use constant values_format_pre => 1;

# Interest types.
use constant interest_error => 0;  # probable serious error
use constant interest_warn => 1;   # general warning
use constant interest_perf => 2;   # performance problem
use constant interest_badpkt => 3; # bad packet received

# CSS classes and text labels for interesting values.
my @interest_css_classes = ("error", "warn", "perf", "badpkt");
my @interest_labels = ("Error", "Warning", "Performance Warning",
		       "Bad Packet Warning");

my $VERSION = "4.16.1";
my $USER = "ROOT USER";
my $DATE = localtime();
my $UPTIME = '';

# Rules for what's interesting.
# Keys are pseudo-type names.  Values are arrays of pseudo-tuples of
# conditions and interest types.  Conditions are strings of the form
# attribute-name comparison-operator attribute-name or
# attribute-name comparison-operator integer.
my %interest_rules =
    (net_stats_sfc => [['rx_lt64 != 0', interest_badpkt],
		       ['rx_gtjumbo != 0', interest_badpkt],
		       ['rx_bad_gtjumbo != 0', interest_badpkt],
		       ['rx_bad_lt64 != 0', interest_badpkt],
		       ['rx_bad != 0', interest_badpkt],
		       ['rx_align_error != 0', interest_badpkt],
		       ['rx_symbol_error != 0', interest_badpkt],
		       ['rx_internal_error != 0', interest_error],
		       ['rx_length_error != 0', interest_badpkt],
		       ['tx_lt64 != 0', interest_error],
		       ['tx_gtjumbo != 0', interest_error],
		       ['tx_non_tcpudp != 0', interest_error],
		       ['tx_mac_src_error != 0', interest_error],
		       ['tx_ip_src_error != 0', interest_error],
		       # The following may be reported via ethtool
		       # or only through debugfs/procfs, depending
		       # on the driver version.
		       ['rx_nodesc_drop_cnt != 0', interest_perf],
 		       ['rx_nodesc_drops != 0', interest_perf],
		       ['rx_reset != 0', interest_warn],
		       ['rx_frm_trunc != 0', interest_perf],
		       ['rx_ip_hdr_chksum_err != 0', interest_badpkt],
		       ['rx_tcp_udp_chksum_err != 0', interest_badpkt],
		       ['rx_char_error_lane0 != 0', interest_error],
		       ['rx_char_error_lane1 != 0', interest_error],
		       ['rx_char_error_lane2 != 0', interest_error],
		       ['rx_char_error_lane3 != 0', interest_error],
		       ['rx_disp_error_lane0 != 0', interest_error],
		       ['rx_disp_error_lane1 != 0', interest_error],
		       ['rx_disp_error_lane2 != 0', interest_error],
		       ['rx_disp_error_lane3 != 0', interest_error],
		       ['rx_pm_trunc_bb_overflow != 0', interest_error],
		       ['rx_pm_discard_bb_overflow != 0', interest_error],
		       ['rx_pm_trunc_vfifo_full != 0', interest_perf],
		       ['rx_pm_discard_vfifo_full != 0', interest_perf],
		       ['rx_pm_trunc_qbb != 0', interest_error],
		       ['rx_pm_discard_qbb != 0', interest_error],
		       ['rx_pm_discard_mapping != 0', interest_warn],
		       ['rx_dp_q_disabled_packets != 0', interest_warn]],
     sfc_nic => [['n_rx_nodesc_drop_cnt != 0', interest_perf]],
     sfc_errors => [['rx_reset != 0', interest_warn]],
     sfc_eventqueue => [['n_rx_frm_trunc != 0', interest_perf],
			['n_rx_ip_hdr_chksum_err != 0', interest_badpkt],
			['n_rx_tcp_udp_chksum_err != 0', interest_badpkt],
			['n_rx_overlength != 0', interest_badpkt]]);

# Extend $interest_rules{'net_stats_sfc'} to have port_ variants
my @orig_net_stats_sfc = @{$interest_rules{'net_stats_sfc'}};
foreach(@orig_net_stats_sfc) {
    my $port_rule = [ "port_" . $_->[0], $_->[1] ];
    push @{$interest_rules{'net_stats_sfc'}}, $port_rule;
}

my ($os_type, $hostname, $os_release, $os_version, $arch) = POSIX::uname();
my $arch_is_x86 = ($arch =~ /^(?:i[x3456]86|(?:x86[-_]|amd)64)$/);
my $arch_is_powerpc = ($arch =~ /^p(?:ower)?pc(?:64)?$/);

# Structure is a base class for wrapping C structures.

package Structure;

use overload '""' => \&_pack;

sub new {
    my $class = shift;
    my $data = ($#_ == 0) ? shift : '';
    my $self = bless({_data => pack('a' . $class->_structure_len, $data)},
		     $class);
    while ($#_ > 0) {
	my $name = shift;
	my $value = shift;
	_set($self, $name, $value);
    }
    return $self;
}

sub _pack {
    my $self = shift;
    return $self->{_data};
}

sub _get {
    my ($self, $name) = @_;
    my $class = ref($self);
    my $field_def = $self->_structure_fields->{$name};
    if (defined($field_def)) {
	my ($offset, $format) = @$field_def;
	return unpack($format, substr($self->{_data}, $offset));
    }
}

sub _set {
    my ($self, $name, $value) = @_;
    my $class = ref($self);
    my $field_def = $self->_structure_fields->{$name};
    if (defined($field_def)) {
	my ($offset, $format) = @$field_def;
	my $packed_value = pack($format, ($format =~ /^P/) ? $$value : $value);
	substr($self->{_data}, $offset, length($packed_value)) = $packed_value;
    }
}

sub AUTOLOAD {
    my $self = shift;
    my $class = ref($self);
    my $name = $Structure::AUTOLOAD;
    $name =~ s/^\w+:://;
    if ($#_ < 0) {
	return _get($self, $name);
    } else {
	return _set($self, $name, @_);
    }
}

package Ifreq;

use base qw(Structure);
use constant _structure_fields => {ifr_name => [0, 'Z16'],
				   ifr_hwaddr => [16, 'SC14'],
				   ifr_addr => [16, 'SC14'],
				   ifr_dstaddr => [16, 'SC14'],
				   ifr_broadaddr => [16, 'SC14'],
				   ifr_netmask => [16, 'SC14'],
				   ifr_flags => [16, 's'],
				   ifr_mtu => [16, 'i!'],
				   ifr_map => [16, 'L!L!SCCC'],
				   ifr_slave => [16, 'Z16'],
				   ifr_data => [16, 'P44'],
				   ifr_ifindex => [16, 'i!'],
				   ifr_bandwidth => [16, 'i!'],
				   ifr_qlen => [16, 'i!'],
				   ifr_newname => [16, 'Z16']};
use constant _structure_len => 32;

my $socket;
sub get_socket {
    use Socket;
    if (!defined($socket)) {
	$socket = new FileHandle;
	socket($socket, PF_INET, SOCK_STREAM, 0) or die "socket: $!";
    }
    return $socket;
}

package EthtoolDrvinfo;
use base qw(Structure);
use constant _structure_fields => {cmd => [0, 'L'],
				   driver => [4, 'Z32'],
				   version => [36, 'Z32'],
				   fw_version => [68, 'Z32'],
				   bus_info => [100, 'Z32'],
				   n_priv_flags => [176, 'L'],
				   n_stats => [180, 'L'],
				   testinfo_len => [184, 'L'],
				   eedump_len => [188, 'L'],
				   regdump_len => [192, 'L']};
use constant _structure_len => 196;

package Ethtool;

use constant SIOCETHTOOL => 0x8946;
use constant ETHTOOL_GDRVINFO => 0x00000003;
# ... to be continued

sub do_cmd {
    my ($if_name, $ecmd) = @_;
    my $ecmd_blob = "$ecmd";
    my $ifreq = new Ifreq(ifr_name => $if_name, ifr_data => \$ecmd_blob);
    return undef unless ioctl(Ifreq::get_socket(), SIOCETHTOOL, $ifreq);
    # Construct a new wrapper of the same type
    return ref($ecmd)->new($ecmd_blob);
}

package EfxSockIoctl;
use base qw(Structure);
use constant _structure_fields => {cmd => [0, 'S'],
				   u => [4, 'a1000']};
use constant _structure_len => 1004; # this is quite arbitrary

use constant SIOCEFX => 0x89f3;
use constant EFX_GET_TS_CONFIG => 0xef25;
# ... to be continued

package HwtstampConfig;
use base qw(Structure);
use constant _structure_fields => {flags => [0, 'i'],
				   tx_type => [4, 'i'],
				   rx_filter => [8, 'i']};
use constant _structure_len => 12;

use constant SIOCGHWTSTAMP => 0x89b1;

package main;

# Some utility functions we need.

# Tell whether the given string starts with the given prefix string.
sub startswith {
    my ($s, $prefix) = @_;
    return substr($s, 0, length($prefix)) eq $prefix;
}

sub max {
    my $result;
    for (@_) {
	if (!defined($result) || $_ > $result) {
	    $result = $_;
	}
    }
    $result;
}

# Return sum of a sequence of numbers.
sub sum {
    my $result = 0;
    for (@_) {
	$result += $_;
    }
    $result;
}

sub first_defined {
    for (@_) {
	return $_ if defined($_);
    }
}

sub pairs {
    use integer;
    my @result;
    for my $i (0 .. $#_ / 2) {
	push @result, [$_[2 * $i], $_[2 * $i + 1]];
    }
    return @result;
}

sub html_encode {
    my $result = shift;
    $result =~ s/([\&<\'\"])/'&#'.ord($1).';'/eg;
    return $result;
}

my $out_file;
my $out_format = format_text;
my @interesting_stuff = ();

# Print a table of values and apply interest rules to them.
# title       title string to show above the table
# type_name   (pseudo-)type name of values (may be undef)
# attributes  ref to array of names for the attributes to show in columns
# values      ref to array of values to show in rows;
#             each value is a ref to an array with values in the same
#             order as the given names
# orientation if orient_horiz, values are in rows;
#             if orient_vert, values are in columns
# values_fmt  if values_format_pre, values are preformatted text
#             if values_format_default, use default formatting
sub tabulate {
    my ($title, $type_name, $attributes, $values, $orientation, $values_fmt, $id) = @_;
    my @col_widths;
    my @cell_texts;
    my @cell_interest;

    $orientation = orient_horiz unless defined($orientation);
    $orientation == orient_horiz or $orientation == orient_vert or die;
    $values_fmt = values_format_default unless defined($values_fmt);
    $values_fmt == values_format_default
      or $values_fmt == values_format_pre
      or die;

    for my $j (0..$#$attributes) {
	my $cell_text = $attributes->[$j];
	my ($x, $y);
	if ($orientation == orient_horiz) {
	    ($x, $y) = ($j, 0);
	} else {
	    ($x, $y) = (0, $j);
	}
	$cell_texts[$y]->[$x] = $cell_text;
	$col_widths[$x] = max($col_widths[$x] || 0, length($cell_text));
    }
    for my $i (0..$#$values) {
	my $value = $values->[$i];
	my $value_interest = apply_interest_rules($type_name, $value);
	for my $j (0..$#$attributes) {
	    my $attr_value;
	    if (ref($value) eq 'HASH') {
		$attr_value = $value->{$attributes->[$j]};
	    } elsif (ref($value) eq 'ARRAY') {
		$attr_value = $value->[$j];
	    }
	    my $cell_text = defined($attr_value) ? $attr_value : "<N/A>";
	    my ($x, $y);
	    if ($orientation == orient_horiz) {
		($x, $y) = ($j, 1 + $i);
	    } else {
		($x, $y) = (1 + $i, $j);
	    }
	    $cell_texts[$y]->[$x] = $cell_text;
	    if (exists($value_interest->{$attributes->[$j]})) {
		$cell_interest[$y]->[$x] =
		    $value_interest->{$attributes->[$j]};
	    }
	    $col_widths[$x] = max($col_widths[$x] || 0, length($cell_text));
	}
    }

    print_heading($title, $id);

    if ($out_format == format_html) {
	$out_file->print("    <table class="
			 .($orientation == orient_horiz ? 'horiz' : 'vert')
			 .">\n");
	for my $y (0..$#cell_texts) {
	    $out_file->print("      <tr>\n");
	    for my $x (0..$#{$cell_texts[$y]}) {
		my $head_cell = ($orientation == orient_horiz ? $y : $x) == 0;
		my $elem_name = $head_cell ? 'th' : 'td';
		my $cell_text = $cell_texts[$y]->[$x];
		$out_file->print("        <$elem_name");
		# If this cell is interesting, style it accordingly
		# and define an identifier so the summary can link to
		# it.
		if (defined($cell_interest[$y]->[$x])) {
		    $out_file->print(" class="
				     . ($interest_css_classes
					[$cell_interest[$y]->[$x]->[0]])
				     . " id=match" .
				     $cell_interest[$y]->[$x]->[1]);
		}
		$out_file->print(">");
		if (!$head_cell && $values_fmt == values_format_pre) {
			print_preformatted($cell_text);
		} else {
			$out_file->print(html_encode($cell_text));
		}
		$out_file->print("</$elem_name>\n");
	    }
	    if ($orientation == orient_vert && $#$values == -1 && $y == 0) {
		$out_file->print("        <td rowspan=".($#$attributes + 1).">"
				 ."<em>none found</em></td>\n");
	    }
	    $out_file->print("      </tr>\n");
	}
	if ($orientation == orient_horiz && $#$values == -1
	    && $#$attributes >= 0) {
	    $out_file->print("      <tr>\n"
			     ."       <td colspan=".($#$attributes + 1).">"
			     ."<em>none found</em></td>\n"
			     ."     </tr>\n");
	} elsif ($#$values == -1 && $#$attributes == -1) {
	    $out_file->print("      <tr><td><em>none found</em></td></tr>\n");
	}
	$out_file->print("    </table>\n");
    } else {
	for my $y (0..$#cell_texts) {
	    my $row = '';
	    for my $x (0..$#{$cell_texts[$y]}) {
		my $cell_text = $cell_texts[$y]->[$x];
		my $pad = $col_widths[$x] - length($cell_text);
		$row .= $cell_text . (' ' x ($pad + gutter_width));
		if ($orientation == orient_vert && $x == 0) {
		    $row = substr($row, 0, -1) . '| ';
		}
	    }
	    if ($orientation == orient_vert && $#$values == -1 && $y == 0) {
		$row .= ' ' x gutter_width . 'none found';
	    }
	    $out_file->print("$row\n");
	    if ($orientation == orient_horiz && $y == 0
		&& $#$attributes >= 0) {
		my $table_width = (sum(@col_widths)
				   + gutter_width * $#$attributes);
		$out_file->print('=' x $table_width . "\n");
	    }
	}
	if (($orientation == orient_horiz || $#$attributes == -1)
	    && $#$values == -1) {
	    $out_file->print("none found\n");
	}
	$out_file->print("\n");
    }
    
  if ( $id ) {
    print_footer( $id );
  }
}

sub print_text {
    my $text = shift;
    $out_file->print($out_format == format_html ? html_encode($text) : $text);
}

sub print_heading {
    my $text = shift;
    my $id = shift;
    my $hide = shift;
    my $display = 'block';
    my $link = ' Hide...';
    if ( $hide ) {
      $display = 'none';
      $link = ' ...Show';
    }
    if ($out_format == format_html) {
      if ( $id ) {
        $out_file->print("<table rows=1 cols=2 style='border:none;'><tr style='border:none;'><td style='border:none;'>");
        $out_file->print("<a name='$id'><h2>".html_encode($text)."</h2></name></td>");
        $out_file->print("<td style='border:none;'><a id='$id\_l' href='\#$id' onclick='toggle(\"$id\"); return false;'>$link</a></td></tr></table>\n");
        $out_file->print("<div style='display:$display' id='$id\_c'>\n");
      } else {
        $out_file->print("    <h2>".html_encode($text)."</h2>\n");
      }
    } else {
      $out_file->print("$text\n\n");
    }
}

sub print_footer {
  my $id = shift;
  if ($out_format == format_html) {
    if ( $id ) {
      $out_file->print("<a href='\#$id' onclick='toggle(\"$id\");'>Hide $id</a><br>\n");
    }
    $out_file->print("</div>\n");
  }
}

sub print_bold {
    my $text = shift;
        if ($out_format == format_html) {
            $out_file->print("    <h4>".html_encode($text)."</h4>\n");
    } else {
        $out_file->print("$text\n\n");
    }

}

sub print_warning {
    my $text = shift;
    if ($out_format == format_html) {
	$out_file->print("    <p><em>".html_encode($text)."</em></p>\n");
    } else {
	$out_file->print("$text\n\n");
    }
}

sub begin_preformatted {
    my $use_delimiters = shift;
    if ($out_format == format_html) {
	$out_file->print("    <pre>");
    } elsif ($use_delimiters) {
	$out_file->print("--- BEGIN ---\n");
    }
}

sub end_preformatted {
    my $use_delimiters = shift;
    if ($out_format == format_html) {
	$out_file->print("</pre>\n");
    } elsif ($use_delimiters) {
	$out_file->print("--- END ---\n\n");
    } else {
	$out_file->print("\n");
    }
}

sub print_preformatted {
    my ($text, $use_delimiters) = @_;
    begin_preformatted($use_delimiters);
    print_text($text);
    end_preformatted($use_delimiters);
}

# Return the entire contents of a binary file as a string.
# Return undef on failure.
sub read_file {
    my ($path, $offset) = @_;
    my $result;
    my $fd = POSIX::open($path, &POSIX::O_RDONLY);
    if (defined($fd)) {
	if (defined($offset)) {
	    POSIX::lseek($fd, $offset, 0);
	}
	$result = '';
	my ($buf, $length);
	$! = 0;
	while (($length = POSIX::read($fd, $buf, 65536))
	       && $length != 0) {
	    $result .= substr($buf, 0, $length);
	}
	my $saved_errno = $!;
	POSIX::close($fd);
	if ($! = $saved_errno) {
	    $result = undef;
	}
    }
    return $result;
}

# Return a reference to an array of the names in a directory.
# Return undef on failure.
sub list_dir {
    my ($path) = @_;
    my $result;
    if (my $dir = POSIX::opendir($path)) {
	$! = 0;
	my @result = grep(!/^\.\.?$/, readdir($dir));
	@result = reverse(@result);
	my $saved_errno = $!;
	POSIX::closedir($dir);
	$! = $saved_errno;
	$result = $! ? undef : \@result;
    }
    return $result;
}

# Return a reference to an array of file names and contents found in
# a directory.  The optional name_filter parameter is used to check
# whether a file of the given name should be included.  The optional
# value_map is used to modify the value.
sub read_dir_files {
    my ($dir_path, $name_filter, $value_map) = @_;
    my $result;
    if (my $list = list_dir($dir_path)) {
	$result = [];
	for (@$list) {
	    my $file_path = "$dir_path/$_";
	    if (-f $file_path
		&& (!defined($name_filter) || &$name_filter())) {
		my $name = $_;
		local $_ = read_file($file_path);
		&$value_map() if defined($value_map) && defined($_);
		push @$result, [$name, $_];
	    }
	}
    }
    return $result;
}

sub find_sfc_debug_dir {
    my @sfc_paths = ();
    for my $path ('/proc/driver', '/debug', '/sys/kernel/debug') {
	for my $driver ('sfc', 'sfc_ef100') {
	    push @sfc_paths, "$path/$driver" if -d "$path/$driver";
	}
    }
    return @sfc_paths;
}

sub find_x3_debug_dir {
	my @xlnx_paths = ();
	for my $path ('/proc/driver', '/debug', '/sys/kernel/debug') {
	for my $driver ('xilinx_efct') {
		push @xlnx_paths, "$path/$driver" if -d "$path/$driver";
	}
	}
	return @xlnx_paths;
}

sub get_sfc_drvinfo {
    my %sfc_drvinfo;
    if (my $list = list_dir('/sys/class/net')) {
	for my $iface_name (@$list) {
	    my $drvinfo = Ethtool::do_cmd(
		$iface_name,
		new EthtoolDrvinfo(cmd => Ethtool::ETHTOOL_GDRVINFO));
		next unless defined($drvinfo);
		if ($drvinfo->driver eq 'sfc' || $drvinfo->driver eq 'sfc_ef100' || $drvinfo->driver eq 'xilinx_efct') {
		$sfc_drvinfo{$iface_name} = $drvinfo;
	    }
	}
    }
    return \%sfc_drvinfo;
}

sub get_hwtstamp_config {
    my $iface_name = shift;
    my $config = new HwtstampConfig;
    my $config_blob = "$config";
    my $ifreq = new Ifreq(ifr_name => $iface_name);

    # Standard ioctl
    $ifreq->ifr_data(\$config_blob);
    if (ioctl(Ifreq::get_socket(), HwtstampConfig::SIOCGHWTSTAMP, "$ifreq")) {
	return new HwtstampConfig($config_blob);
    }

    # Private ioctl
    my $efxsi = new EfxSockIoctl(cmd => EfxSockIoctl::EFX_GET_TS_CONFIG);
    my $efxsi_blob = "$efxsi";
    $ifreq->ifr_data(\$efxsi_blob);
    if (ioctl(Ifreq::get_socket(), EfxSockIoctl::SIOCEFX, "$ifreq")) {
	$efxsi = new EfxSockIoctl($efxsi_blob);
	return new HwtstampConfig($efxsi->u);
    }

    return undef;
}

sub get_iface_bus_addr {
    my $iface_name = shift;
    if (my $device_path = readlink("/sys/class/net/$iface_name/device")) {
	return File::Basename::basename($device_path);
    } else {
	return undef;
    }
}

sub get_iface_mac_addr {
    my $iface_name = shift;
    if (my $dev_addr = read_file("/sys/class/net/$iface_name/address")) {
        $dev_addr =~ s/\n//s;
        return $dev_addr;
    } else {
        return undef;
    }
}

sub get_onload_version {
    my $onload_ver;
    if (my $module_ver = read_file("/sys/module/onload/version")) {
        $module_ver =~ s/\n//s;
	$onload_ver = $module_ver;
    } else {
        $onload_ver = 'N/A';
    }
    return $onload_ver;
}

sub get_xilinx_efct_version {
    my $efct_ver;
    if (my $module_ver = read_file("/sys/module/xilinx_efct/version")) {
        $module_ver =~ s/\n//s;
	$efct_ver = $module_ver;
    } else {
        $efct_ver = 'N/A';
    }
    return $efct_ver;
}

sub get_linux_cpuinfo {
    my @log_procs;
    my $log_id;
    my $cpus_dir = '/sys/devices/system/cpu';
    my $nodes_dir = '/sys/devices/system/node';
    my %x86_cpuinfo_map = (
	'cpu family'	=> 'family',
	'model'		=> 'model',
	'cpu variation'	=> 'variation',
	'stepping'	=> 'stepping',
	'vendor_id'	=> 'vendor',
	'model name'	=> 'full_name',
	'cpu MHz'	=> 'clock_mhz',
	'core id'	=> 'core_id',
	'physical id'	=> 'physical_id'
	);
    my %powerpc_cpuinfo_map = (
	'cpu'		=> 'family',
	'clock'		=> 'clock_mhz'
	);
    my $cpuinfo_map;
    if ($arch_is_x86) {
	$cpuinfo_map = \%x86_cpuinfo_map;
    } elsif ($arch_is_powerpc) {
	$cpuinfo_map = \%powerpc_cpuinfo_map;
    }

    # Try to read generic cputopology
    if (my $cpu_list = list_dir($cpus_dir)) {
	my $have_phys_id;
	for my $name (@$cpu_list) {
	    next unless $name =~ /^cpu(\d+)$/;
	    $log_id = $1;
	    my $topo_dir = "$cpus_dir/$name/topology";
	    next unless -d $topo_dir;
	    my $proc = {};
	    $proc->{core_id} = read_file("$topo_dir/core_id");
	    my $phys_id = read_file("$topo_dir/physical_package_id");
	    if ($phys_id >= 0) {
		$have_phys_id = 1;
		$proc->{physical_id} = $phys_id;
	    }
	    $log_procs[$log_id] = $proc;
	}
	if (!$have_phys_id) {
	    # Assume NUMA nodes are physical packages
	    if (my $node_list = list_dir($nodes_dir)) {
		for my $name (@$node_list) {
		    next unless $name =~ /^node(\d+)$/;
		    my $node_id = $1;
		    my $cpu_list = list_dir("$nodes_dir/$name");
		    next unless $cpu_list;
		    for my $name (@$cpu_list) {
			next unless $name =~ /^cpu(\d+)$/;
			$log_procs[$1]->{physical_id} = $node_id;
		    }
		}
	    }
	}
    }

    # Parse /proc/cpuinfo into per-logical-processor hashes.
    if (defined($cpuinfo_map) &&
	(my $file = new FileHandle('/proc/cpuinfo', 'r'))) {
	while (<$file>) {
	    if (/^([^:]*?)[ \t]*:[ \t]*(.*)\n$/) {
		my ($key, $value) = ($1, $2);
		if ($key eq 'processor') {
		    $log_id = $value;
		    $log_procs[$log_id] ||= {};
		} elsif (defined($key = $cpuinfo_map->{$key})) {
		    if ($key eq 'clock_mhz') {
			$value =~ s/(?:\.0+)? *MHz$//;
		    }
		    $log_procs[$log_id]->{$key} = $value;
		}
	    }
	}
	$file->close();
    }

    return undef unless @log_procs;

    # Group processors into physical processors and count logical
    # processors.
    my @phys_procs = ();
    my @phys_proc_cores = ();
    for $log_id (0..$#log_procs) {
	my $proc = $log_procs[$log_id];
	next unless defined($proc); # there may be gaps in numbering
	my $phys_id = first_defined($proc->{'physical_id'}, $log_id);
	if (defined($phys_procs[$phys_id])) {
	    ++$phys_procs[$phys_id]->{n_log_procs};
	} else {
	    $phys_procs[$phys_id] = {%$proc};
	    $phys_procs[$phys_id]->{n_log_procs} = 1;
	    $phys_procs[$phys_id]->{n_cores} = 1;
	    $phys_proc_cores[$phys_id] = {};
	}
	my $core_id = $proc->{core_id};
	if (defined($core_id)) {
	    $phys_proc_cores[$phys_id]->{$core_id} = 1;
	    $phys_procs[$phys_id]->{n_cores} =
		scalar(keys(%{$phys_proc_cores[$phys_id]}));
	}
    }
    return \@phys_procs;
}

# Produce a system summary along the lines of msinfo32 output.
sub print_system_summary {
    my $smbios = shift;
    my @attributes = ('OS Name', 'Version', 'Architecture');
    my @value = ($os_type, "$os_release $os_version", $arch);
    if ($os_type eq 'Linux') {
	$_ = read_file('/proc/cmdline');
	chomp;
	push @attributes, 'Kernel Command Line';
	push @value, $_;
	# Newer distributions implement LSB release information so
	# look for that first.  If that fails look in /etc/*-release
	# (RPM-based distributions use these) and /etc/debian_version.
	my $distribution;
	$_ = `lsb_release -d 2>/dev/null`;
	if ($? == 0 && /^Description:[ \t]*(.*)\n$/) {
	    $distribution = $1;
	} else {
	    my @release_files = glob('/etc/*-release');
	    if ($#release_files >= 0) {
		$distribution = read_file($release_files[0]);
	    } elsif (-f '/etc/debian_version') {
		$distribution = 'Debian ' . read_file('/etc/debian_version');
	    }
	}
	$distribution =~ s/\n.*//s if defined($distribution);
	push @attributes, 'Distribution';
	push @value, $distribution;
    }
    push @attributes, 'System Name';
    push @value, $hostname;
    push @attributes, 'System Manufacturer';
    push @value, $smbios->get_single_string(1, 4);
    push @attributes, 'System Model';
    push @value, $smbios->get_single_string(1, 5);
    if ($os_type eq 'Linux') {
	if (my $phys_procs = get_linux_cpuinfo()) {
	    for my $proc (@$phys_procs) {
		next unless defined($proc); # there may be gaps in numbering
		my $proc_desc = '';
		for (['family',      '',   'Family ',     '',
		      'unknown'],
		     ['model',       ' ',  ' Model ',     ''],
		     ['variation',   ' ',  ' Variation ', ''],
		     ['stepping',    ' ',  ' Stepping ',  ''],
		     ['vendor',      ' ',  ' Vendor ',    ''],
		     ['full_name',   ', ', undef,         ''],
		     ['clock_mhz',   undef, ', ',         ' MHz'],
		     ['n_cores',     undef, ', ',         ' Core(s)'],
		     ['n_log_procs', undef, ', ',
		      ' Logical Processor(s)', '']) {
		    my ($key, $prefix, $num_prefix, $suffix, $default) = @$_;
		    my $value = $proc->{$key};
		    if (!defined($value)) {
			$proc_desc .= $default if defined($default);
		    } elsif ($value =~ /^[\d.]+$/) {
			$proc_desc .= "$num_prefix$value$suffix";
		    } else {
			$proc_desc .= "$prefix$value$suffix";
		    }
		}
		push @attributes, 'Processor';
		push @value, $proc_desc;
	    }
	}
    }
    if ($smbios->expected) {
	push @attributes, 'BIOS Version/Date';
	my $bios_id = $smbios->get_single_string(0, 4); # vendor
	if (defined($bios_id)) {
	    my $bios_version = $smbios->get_single_string(0, 5);
	    if (defined($bios_version)) {
		$bios_id .= ' ' . $bios_version;
		my $bios_date = $smbios->get_single_string(0, 8);
		if (defined($bios_date)) {
		    $bios_id .= ', ' . $bios_date;
		}
	    }
	}
	push @value, $bios_id;
    }
    if ($os_type eq 'Linux') {
	if (my $meminfo_file = new FileHandle('/proc/meminfo', 'r')) {
	    my %meminfo = ();
	    while (<$meminfo_file>) {
		if (/^([^ ]+):[ \t]*(\d+) kB\n$/) {
		    $meminfo{$1} = $2;
		}
	    }
      
	    $meminfo_file->close();
	    push @attributes, ('Total Physical Memory',
			       'Free Physical Memory',
			       'Available Physical Memory',
			       'Total Virtual Memory',
			       'Available Virtual Memory',
			       'Page File Space');
	    push @value, map(sprintf('%d MB', $_ / 1024),
			     $meminfo{MemTotal},
			     $meminfo{MemFree},
			     $meminfo{MemAvailable},
			     # Count all physical memory and swap
			     # minus kernel allocations as virtual
			     # memory.  Assume kernel code and static
			     # data is excluded from MemTotal.
			     $meminfo{MemTotal} + $meminfo{SwapTotal}
			     - $meminfo{Slab} - $meminfo{PageTables},
			     # Count all free physical memory and
			     # swap, plus all buffers and cache, as
			     # 'available' (even though the cache
			     # includes all user code!).
			     $meminfo{MemFree} + $meminfo{SwapFree}
			     + $meminfo{Buffers} + $meminfo{Cached}
			     + $meminfo{SwapCached},
			     $meminfo{SwapTotal});
	}
    }

    tabulate('System Summary', undef, \@attributes, [\@value], orient_vert);
} # print_system_summary

sub print_physical_memory {
    my $smbios = shift;
    my @mem_arrays = $smbios->get_by_type(16);
    my @mem_devices = $smbios->get_by_type(17);
    my @values = ();

    if (@mem_arrays && @mem_devices) {
	my %mem_arrays;
	for (@mem_arrays) {
	    my ($handle, $loc, $use, $slots) = unpack('x2vCCx7v', $_->[0]);
	    # Only count slots on the motherboard for system memory
	    $mem_arrays{$handle} = 1 if $loc == 3 && $use == 3;
	}
	my (%mem_sets, %mem_sets_pop);
	for (@mem_devices) {
	    my ($header, $strings) = @$_;
	    my ($array, $size_code, $slot_str_i, $bank_str_i) =
		unpack('x4vx6vx2CC', $header);
	    if ($mem_arrays{$array}) {
		my $size;
		if ($size_code != 0 && $size_code != 0xffff) {
		    $size = (($size_code & 0x7fff) *
			     (($size_code & 0x8000) ? 1 : 1024));
		}
		push @values, [SmbiosInfo::get_string($strings, $slot_str_i),
			       SmbiosInfo::get_string($strings, $bank_str_i),
			       ($size_code == 0) ? 0 : 1,
			       $size];
	    }
	}
    }

    print_heading('Hardware', 'hw');

    tabulate('Physical memory slots',
	     undef,
	     [qw(slot_id bank_id filled size_kbytes)],
	     \@values,
	     orient_vert);
} # print physical_memory

# SmbiosInfo is a reimplementation of some of dmidecode, which we can't
# rely on being installed.

package SmbiosInfo;

sub new {
    use PerlIO;

    my $self = bless({
	expected => ($arch_is_x86 || $arch eq 'ia64'),
	handle_index => {},
	type_index => {}
    });

    return $self unless $self->{expected};

    my $mem_file = new FileHandle('/dev/mem', 'r') or return $self;
    my $read_error;

    # Find SMBIOS entry point
    my $entry;
    if (my $systab_file = new FileHandle('/sys/firmware/efi/systab', 'r')) {
	# EFI should tell us exactly where it is
	while (<$systab_file>) {
	    if (/^SMBIOS=(.*)/) {
		my $addr = POSIX::strtoul($1, 0);
		$! = 0;
		if (seek($mem_file, $addr + 0x10, &POSIX::SEEK_SET) &&
		    read($mem_file, $entry, 0x10)) {
		    _check_entry($entry) or $entry = undef;
		} else {
		   $read_error = $!; 
		   $entry = undef;
		}
		last;
	    }
	}
	$systab_file->close();
    }

    # Otherwise scan through the BIOS (0xf0000-0x100000)
    if (!defined($entry) && $arch_is_x86) {
	# Reopen the file handler in case there was a failed read before
        $mem_file->close();
	$mem_file = new FileHandle('/dev/mem', 'r') or return $self;
	my $buf;
	$! = 0;
	if (seek($mem_file, 0xf0000, &POSIX::SEEK_SET) &&
	    read($mem_file, $buf, 0x10000)) {
	    for (my $off = 0; $off < length($buf); $off += 0x10) {
		if (_check_entry(substr($buf, $off))) {
		    $entry = substr($buf, $off, 0x10);
		    last;
		}
	    }
	} else {
	    $read_error = $!;
	    $entry = undef;
	}
    }

    # Decode the entry and read the table
    my ($table, $num);
    if (defined($entry)) {
	my ($len, $base);
	($len, $base, $num) = unpack('x6vVv', $entry);
	unless (seek($mem_file, $base, &POSIX::SEEK_SET) &&
		read($mem_file, $table, $len)) {
	    $read_error = $!;
	    $table = undef;
	}
    }

    $mem_file->close();

    if (defined($table)) {
	my ($i, $pos) = (0, 0);
	while ($i < $num && $pos + 4 <= length($table)) {
	    my ($type, $header_len, $handle) =
		unpack('CCv', substr($table, $pos));
	    last if $header_len < 4;  # invalid structure; table is broken
	    my $next = index($table, "\0\0", $pos + $header_len);
	    $next = ($next < 0) ? length($table) : $next + 2;
	    _add($self, $type, $handle,
		 substr($table, $pos, $header_len),
		 substr($table, $pos + $header_len,
			$next - $pos - $header_len));
	    ++$i;
	    $pos = $next;
	}
    }
    # We might get EFAULT when trying to read an SMBIOS table at a
    # high address on a 32-bit system.  For some reason Linux applies
    # a lower address limit to read() than to mmap() on /dev/mem.
    # Perl won't let us mmap() a character device, so fall back to
    # dmidecode if available because it does use mmap().
    elsif (defined($read_error)) {
	if (my $dmidecode_file =
	    new FileHandle('dmidecode --dump 2>/dev/null |')) {
	    my ($type, $handle, $header, $strings);
	    while (<$dmidecode_file>) {
		# Parse dmidecode dump back into binary form
		if (/^Handle 0x([\dA-F]{4}), DMI type (\d+)/) {
		    $type = $2;
		    ($handle, undef) = POSIX::strtoul($1, 16);
		    $header = '';
		} elsif (/^\tStrings:/) {
		    $strings = '';
		} elsif (/^\t\t(?!\")/) {
		    s/\s//g;
		    (defined($strings) ? $strings : $header) .= pack('H*', $_);
		} elsif (/^\n$/ && defined($type)) {
		    _add($self, $type, $handle,
			 $header,
			 defined($strings) ? ($strings . "\0") : "\0\0");
		    ($type, $handle, $header, $strings) = ();
		}
	    }
	}
    }

    return $self;
}

sub _check_entry {
    my $entry = shift;
    return 0 if substr($entry, 0, 5) ne '_DMI_';
    my $sum = 0;
    for (0..0xe) {
	$sum += ord(substr($entry, $_, 1));
    }
    return ($sum & 0xff) == 0;
}

sub _add {
    my ($self, $type, $handle, $header, $strings) = @_;
    my $structure = [$header, $strings];
    push @{$self->{type_index}{$type}}, $structure;
    $self->{handle_index}{$handle} = $structure;
}

sub get_by_handle {
    my ($self, $handle) = @_;
    my $structure = $self->{handle_index}{$handle};
    return $structure ? @$structure : ();
}

sub get_by_type {
    my ($self, $type) = @_;
    my $structures = $self->{type_index}{$type};
    return $structures ? @$structures : ();
}

sub get_single_string {
    my ($self, $type, $offset) = @_;

    # Take first structure of given type
    my @structures = get_by_type($self, $type);
    return undef unless @structures;
    my ($header, $strings) = @{$structures[0]};

    # Get string index
    return undef unless length($header) > $offset;
    my $target_i = ord(substr($header, $offset, 1));

    return get_string($strings, $target_i);
}

sub get_string {
    my ($strings, $target_i) = @_;

    # String indices are 1-based, with 0 indicating no string present
    return undef if $target_i == 0;

    my ($i, $pos) = (1, 0);
    while ($pos < length($strings)) {
	my $end = index($strings, "\0", $pos);
	return undef if $end == $pos; # end of strings
	if ($i == $target_i) {
	    return substr($strings, $pos, $end - $pos);
	}
	++$i;
	$pos = $end + 1;
    }

    return undef;
}

sub expected {
    my ($self) = @_;
    return $self->{expected};
}

# PciFunction class represents individual PCI functions and abstracts
# config register reading in a general way.

package PciFunction;

my %config_regs = (VENDOR_ID =>            [0x00, 2],
		   DEVICE_ID =>            [0x02, 2],
		   STATUS =>               [0x06, 2],
		   REVISION =>             [0x08, 1],
		   CLASS_DEVICE =>         [0x0a, 2],
		   SECONDARY_BUS =>        [0x19, 1],
		   SUBORDINATE_BUS =>      [0x1a, 1],
		   SUBSYSTEM_VENDOR_ID =>  [0x2c, 2],
		   SUBSYSTEM_ID =>         [0x2e, 2],
		   CAPABILITIES_POINTER => [0x34, 1]);
my %pcie_regs = (MAX_PAYLOAD_SIZE_SUPPORTED => [4,  4, 0,  2],
		 MAX_PAYLOAD_SIZE =>           [8,  2, 5,  7],
		 MAX_READ_REQUEST_SIZE =>      [8,  2, 12, 14],
		 MAXIMUM_LINK_WIDTH =>         [12, 4, 4,  9],
		 NEGOTIATED_LINK_WIDTH =>      [18, 2, 4,  9]);
my %config_regs_per_cap = (16 => \%pcie_regs);

sub new {
    my ($class, $address, $config) = @_;
    my %registers = %config_regs;
    my $self = bless({
	_address => $address,
	_config => $config,
	_registers => \%registers
    });
    # Add registers on the capabilities list.
    if ($self->STATUS & 0x10) { # test CAPABILITIES_LIST flag
	# Protect against loops.
	my %seen = ();
	my $cap_ptr = $self->CAPABILITIES_POINTER;
	while (($cap_ptr &= 0xFC) && $cap_ptr + 2 <= length($config)
	       && !$seen{$cap_ptr}) {
	    $seen{$cap_ptr} = 1;
	    my ($cap_id, $cap_next) =
		unpack('CC', substr($config, $cap_ptr, 2));
	    if (my $cap_regs = $config_regs_per_cap{$cap_id}) {
		for my $name (keys(%$cap_regs)) {
		    # Add the register definition with the capability
		    # offset applied.
		    my @reg = @{$cap_regs->{$name}};
		    $reg[0] += $cap_ptr;
		    $registers{$name} = \@reg;
		}
	    }
	    $cap_ptr = $cap_next;
	}
    }
    return $self;
}

sub address {
    my $self = shift;
    return $self->{_address};
}

sub read {
    my ($self, $offset, $length) = @_;
    return $offset < length($self->{_config})
	? substr($self->{_config}, $offset, $length)
	: undef;
}

sub _read_register {
    my ($self, $name) = @_;
    my ($offset, $length, $lsb, $msb) = @{$self->{_registers}->{$name}};
    my ($value) = unpack(substr('_Cv_V', $length, 1),
			 substr($self->{_config}, $offset, $length));
    if (defined($lsb)) {
	# Return a bitfield, not the whole register.
	# Shift before masking because construction of a mask with bit
	# 31 set may result in overflow.
	return ($value >> $lsb) & ((1 << 1 + $msb - $lsb) - 1);
    } else {
	return $value;
    }
}

sub AUTOLOAD {
    my $self = shift;
    my $name = $PciFunction::AUTOLOAD;
    if ($name =~ s/^PciFunction::// && exists($self->{_registers}->{$name})) {
	return _read_register($self, $name);
    } else {
	return undef;
    }
}
    
package main;

sub get_pci_devices {
    my %devices;
    if (my $device_list = list_dir('/sys/bus/pci/devices')) {
	for my $address (@$device_list) {
	    next unless $address =~ /^([0-9a-f]{4}:)/;
	    my $device_dir = "/sys/bus/pci/devices/$address";
	    $devices{$address} =
		new PciFunction($address, read_file("$device_dir/config"));
	}
    }
    return \%devices;
}

sub get_file_attributes {
    my $path = $_;
    if (my @status = stat($path)) {
	my $md5sum = `md5sum '$path' 2>/dev/null`;
	$md5sum =~ s/^([0-9a-f]{32})\s.*\n/$1/ or $md5sum = undef;
	my $version = `modinfo -F version '$path' 2>/dev/null`;
	chomp $version;
	return [$path,
		$version ne '' ? $version : undef,
		$status[7],
		strftime('%Y-%m-%d %H:%M:%S', gmtime($status[9])),
		$md5sum];
    } else {
	# TODO: Provide a more explicit indication that the file is
	# missing or otherwise inaccessible.
	return [$path,
		undef,
		undef,
		undef,
		undef];
    }
}

sub get_device_drivers {
    # Scan sysfs to find PCI devices' driver names.
    my %device_drivers = ();
    if (my $driver_list = list_dir('/sys/bus/pci/drivers')) {
        for my $driver_name (@$driver_list) {
            if (my $device_list =
                list_dir("/sys/bus/pci/drivers/$driver_name")) {
                for my $address (@$device_list) {
                    $device_drivers{$address} = $driver_name
                        if $address =~ /^[0-9a-f]{4}:/;
                }
            }
        }
    }
    return %device_drivers;
}

sub get_sfc_devices {
    my $devices = shift;
    my %sfc_devices = ();

    for my $address (keys(%$devices)) {
        my $device = $devices->{$address};
        if ($device->VENDOR_ID == EFX_VENDID_SFC) {
            $sfc_devices{$address} = $device;
        } elsif ($device->VENDOR_ID == EFX_VENDID_XILINX && $device->CLASS_DEVICE == 0x200) {
            $sfc_devices{$address} = $device;
        }
    }

    return %sfc_devices;
}

sub get_sfc_vpd {
    my $sfc_drvinfo = shift;
    my @attributes = shift;
    my %vpd = ();
    my %return_values = ();

    for my $name (keys(%$sfc_drvinfo)) {
        my $vpd = read_file("/sys/class/net/$name/device/vpd");
        $vpd{$name} = $vpd if defined($vpd);
    }

    for my $name (keys(%vpd)) {
        my $vpd = $vpd{$name};
        my %values = ();

        # Iterate over VPD resources.
        my $res_addr = 0;
        my $res_len;
        while ($res_addr + 1 <= length($vpd)) {
            my $tag = ord(substr($vpd, $res_addr, 1));
            if ($tag & 0x80) {
                # Large resource; length is in next 2 bytes.
                last unless $res_addr + 3 <= length($vpd);
                $res_len = unpack('v', substr($vpd, $res_addr + 1, 2));
                $res_addr += 3;
            } else {
                # Small resource; length is in lowest 3 bits.
                $res_len = $tag & 7;
                $res_addr += 1;
            }
            # Check for end marker; check length is valid.
            last if $res_len == 0;
            last unless $res_addr + $res_len <= length($vpd);

            if ($tag == 0x82) {
                $values{product_name} =
                    substr($vpd, $res_addr, $res_len);
            } elsif ($tag == 0x90) {
                # Iterate over key/value pairs.
                my $key_addr = 0;
                while ($key_addr + 3 <= $res_len) {
                    my $key = substr($vpd, $res_addr + $key_addr, 2);
                    my $value_len =
                        ord(substr($vpd, $res_addr + $key_addr + 2, 1));
                    last unless $key_addr + 3 + $value_len <= $res_len;
                    $values{"vpdr_$key"} =
                        substr($vpd, $res_addr + $key_addr + 3, $value_len);
                    $key_addr += 3 + $value_len;
                }
            }
            $res_addr += $res_len;
        }
	
        $values{$name} = $name;
        $return_values{$name} = \%values;
    }

    return %return_values;
}

sub get_turbo_status {
    my $address = shift;
    my $turbo_mode = '<N/A>';

    if (my $status = read_file("/sys/bus/pci/devices/$address/turbo_mode")) {
        $turbo_mode = $status;
        $turbo_mode =~  s/\n.*//s;
    }

    return $turbo_mode;
}

sub print_short_device_status {
    my ($devices, $sfc_drvinfo) = @_;

    my %device_drivers = get_device_drivers();
    my %sfc_devices = get_sfc_devices($devices);

    my @vpd_attributes = qw(address product_name vpdr_PN vpdr_EC vpdr_SN);
    my %vpd_values = get_sfc_vpd($sfc_drvinfo, @vpd_attributes);

    my @headings = ('name', 'device_id', 'revision', 'subsys_id', 'driver', 'pci_address',
                    'driver_version', 'controller_version',
                    'mac_address', 'product_name', 'vpdr_PN',
                    'vpdr_EC', 'vpdr_SN','onload_version');

    my @data = map({[$_, sprintf('%04x:%04x', $sfc_devices{$sfc_drvinfo->{$_}->bus_info}->VENDOR_ID,
                                              $sfc_devices{$sfc_drvinfo->{$_}->bus_info}->DEVICE_ID),
                         sprintf('%02x', $sfc_devices{$sfc_drvinfo->{$_}->bus_info}->REVISION),
                         sprintf('%04x:%04x', $sfc_devices{$sfc_drvinfo->{$_}->bus_info}->SUBSYSTEM_VENDOR_ID,
                                              $sfc_devices{$sfc_drvinfo->{$_}->bus_info}->SUBSYSTEM_ID),
                            $sfc_drvinfo->{$_}->driver,
                            $sfc_drvinfo->{$_}->bus_info,
                            $sfc_drvinfo->{$_}->version,
                            $sfc_drvinfo->{$_}->fw_version,
                            get_iface_mac_addr($_),
                            $vpd_values{$_}->{"product_name"},
                            $vpd_values{$_}->{"vpdr_PN"},
                            $vpd_values{$_}->{"vpdr_EC"},
                            $vpd_values{$_}->{"vpdr_SN"},
			    get_onload_version()]}
                            keys(%$sfc_drvinfo));


    $out_file->print("CSV:AMD Solarflare inventory report\n");
    # Print the attributes as a single list
    foreach (@headings) {
        $out_file->print($_);
        if ($_ ne $headings[-1]) {
            $out_file->print(",");
        } else {
            $out_file->print("\n");
        }
    }

    my $values = \@data;
    my $attributes = @headings;

    # Print out the actual data with one controller per line
    for my $i (0..$#$values) {
        my $value = $values->[$i];
        my $line = '';
        for my $j (0..$#headings) {
            my $attr_value;
            if (ref($value) eq 'HASH') {
                $attr_value = $value->{$attributes->[$j]};
            } elsif (ref($value) eq 'ARRAY') {
                $attr_value = $value->[$j];
            }
            if ( defined $attr_value ) {
                $line .= ($attr_value);
            }
            if ($j ne $#headings) {
                $line .= (",");
            }
        }
        $line .= "\n";
        $out_file->print($line);
    }

    $out_file->print("\n");

}

sub print_device_status {
    my ($devices, $sfc_drvinfo) = @_;

    # Scan sysfs to find PCI devices' driver names.
    my %device_drivers = ();
    if (my $driver_list = list_dir('/sys/bus/pci/drivers')) {
	for my $driver_name (@$driver_list) {
	    if (my $device_list =
		list_dir("/sys/bus/pci/drivers/$driver_name")) {
		for my $address (@$device_list) {
		    $device_drivers{$address} = $driver_name
			if $address =~ /^[0-9a-f]{4}:/;
		}
	    }
	}
    }

    # Identify and report the devices we're interested in.
    my %bridge_devices;
    my %sfc_devices;
    for my $address (keys(%$devices)) {
	my $device = $devices->{$address};
	if ($device->CLASS_DEVICE == 0x0604) {
	    $bridge_devices{$address} = $device;
	} elsif ($device->VENDOR_ID == EFX_VENDID_SFC) {
	    $sfc_devices{$address} = $device;
	} elsif ($device->VENDOR_ID == EFX_VENDID_XILINX && $device->CLASS_DEVICE == 0x200) {
	    $sfc_devices{$address} = $device;
	}
    }
    tabulate('PCI bridge devices',
	     undef,
	     ['address', 'device_id', 'revision', 'subsystem_id',
	      'secondary_bus', 'subordinate_bus',
	      'max_payload_size_supported', 'max_payload_size',
	      'max_read_request_size', 'maximum_link_width',
	      'negotiated_link_width'],
	     [map({[$_->address,
		    sprintf('%04x:%04x', $_->VENDOR_ID, $_->DEVICE_ID),
		    sprintf('%02x', $_->REVISION),
		    sprintf('%04x:%04x',
			    $_->SUBSYSTEM_VENDOR_ID, $_->SUBSYSTEM_ID),
		    $_->SECONDARY_BUS,
		    $_->SUBORDINATE_BUS,
		    $_->MAX_PAYLOAD_SIZE_SUPPORTED,
		    $_->MAX_PAYLOAD_SIZE,
		    $_->MAX_READ_REQUEST_SIZE,
		    $_->MAXIMUM_LINK_WIDTH,
		    $_->NEGOTIATED_LINK_WIDTH]}
		  values(%bridge_devices))]);
    tabulate('AMD Solarflare PCI devices',
	     'pci_device_sfc',
	     ['address', 'device_id', 'revision', 'subsystem_id',
	      'max_payload_size_supported', 'max_payload_size',
	      'max_read_request_size', 'maximum_link_width',
	      'negotiated_link_width', 'turbo'],
	     [map({{address => $_->address,
		    device_id => sprintf('%04x:%04x',
					 $_->VENDOR_ID, $_->DEVICE_ID),
		    revision => sprintf('%02x', $_->REVISION),
		    subsystem_id => sprintf('%04x:%04x',
					    $_->SUBSYSTEM_VENDOR_ID,
					    $_->SUBSYSTEM_ID),
		    max_payload_size_supported =>
			$_->MAX_PAYLOAD_SIZE_SUPPORTED,
		    max_payload_size => $_->MAX_PAYLOAD_SIZE,
		    max_read_request_size => $_->MAX_READ_REQUEST_SIZE,
		    maximum_link_width => $_->MAXIMUM_LINK_WIDTH,
		    negotiated_link_width => $_->NEGOTIATED_LINK_WIDTH,
                    turbo => get_turbo_status($_->address)}}
		  values(%sfc_devices))]);
  print_footer('hw');
	print_heading("PCI configuration", "pci_config", 'hide');
    for my $address (keys(%bridge_devices), keys(%sfc_devices)) {
	print_heading("PCI configuration space for $address");
	# Emulate lspci -x.
	begin_preformatted(0);
	for my $offset (0..0xff) {
	    my $data = $devices->{$address}->read($offset, 1);
	    last if !defined($data);
	    if ($offset % 0x10 == 0) {
		$out_file->printf("%02x:", $offset);
	    }
	    $out_file->printf(" %02x", ord($data));
	    if ($offset % 0x10 == 0x0F) {
		$out_file->print("\n");
	    }
	}
	end_preformatted(0);
    }
  print_footer('pci_config' );

    my $modules_base = "/lib/modules/$os_release";

    tabulate('Driver bindings',
	     undef,
	     ['address', 'driver_name'],
	     [map({[$_, $device_drivers{$_}]} keys(%sfc_devices))]);

    my %sfc_modules = ();
    if (my $pcimap_file =
	new FileHandle("$modules_base/modules.pcimap", 'r')) {
	my @pcimap = ();
	my $vendor_id_long = sprintf('0x%08x', EFX_VENDID_SFC);
	my $vendor_id2_long = sprintf('0x%08x', EFX_VENDID_XILINX);
	while (<$pcimap_file>) {
	    next if $. == 1;
	    my @fields = split(/\s+/);
	    if ($fields[1] eq $vendor_id_long || $fields[1] eq $vendor_id2_long) {
		push @pcimap, \@fields;
		$sfc_modules{$fields[0]} = undef;
	    }
	}
	tabulate('Known kernel modules for AMD Solarflare PCI IDs',
		 undef,
		 ['module_name', 'vendor', 'device', 'subvendor', 'subdevice',
		  'class', 'class_mask', 'driver_data'],
		 \@pcimap,
		 orient_horiz,
		 values_format_default,
		 'pci_id');
    }

    my @loaded_sfc_modules = ();
    if (my $modules_file = new FileHandle('/proc/modules')) {
	my $re = '^(' . driver_name_re . ') ';
	while (<$modules_file>) {
	    if (/$re/) {
		push @loaded_sfc_modules, [$1];
		$sfc_modules{$1} = undef;
	    }
	}
    }
    tabulate('Loaded AMD Solarflare kernel modules',
	     undef,
	     ['module_name'],
	     \@loaded_sfc_modules);

    for my $name (keys(%sfc_modules)) {
	my $path = `modinfo -F filename '$name' 2>/dev/null`;
	if ($path ne '') {
	    chomp $path;
	    $sfc_modules{$name} = $path;
	}
    }

    tabulate('Module file names',
	     undef,
	     ['module_name', 'file_name'],
	     [pairs(%sfc_modules)]);

    tabulate('File properties',
	     'file_properties',
	     ['file_name', 'version', 'size', 'date_last_modified', 'md5sum'],
	     [map(get_file_attributes, grep(defined, values(%sfc_modules)))],
	     orient_horiz,
	     values_format_default,
	     'file_props');

  print_heading('Module Parameters', 'mod_params');
    for my $module_name (keys(%sfc_modules)) {
	# Module parameters may be found under one of two directories
	# (or not at all) depending on the kernel version.
	if (my $params =
	    read_dir_files("/sys/module/$module_name/parameters",
			   undef,
			   sub {chomp})
	    || read_dir_files("/sys/module/$module_name",
			      sub {$_ ne 'refcnt'},
			      sub {chomp})) {
	    tabulate("Parameters for $module_name",
		     undef,
		     ['name', 'value'],
		     $params);
	}
    }

    my @module_config_lines;
    for my $config_path ('/etc/modules.conf', '/etc/modprobe.conf',
			 glob('/etc/modprobe.d/*')) {
	if (my $config_file = new FileHandle($config_path, 'r')) {
	    my $re = '^(?:' . driver_name_re . ')$';
	    while (<$config_file>) {
		if (grep({$_ =~ /$re/} split /\b/)) {
		    chomp;
		    push @module_config_lines, [$config_path, $., $_];
		}
	    }
	}
    }
    # Also check whether third-party modules are auto-loaded (SuSE only).
    for my $config_path ('/etc/sysconfig/hardware/config') {
	if (my $config_file = new FileHandle($config_path)) {
	    while (<$config_file>) {
		if (/^\s*LOAD_UNSUPPORTED_MODULES_AUTOMATICALLY\b/) {
		    chomp;
		    push @module_config_lines, [$config_path, $., $_];
		}
	    }
	}
    }
    tabulate('Configuration lines for AMD Solarflare modules',
	     undef,
	     ['file_name', 'line', 'text'],
	     \@module_config_lines);

  print_footer('mod_params');

    # Ask package managers about installed module packages.
    # rpm doesn't support package name wildcards, so we must query all
    # packages and filter by name prefix.
    # dpkg lists matching packages it knows about even if they're
    # not installed, so we must filter by status.
    my @packages;
    for (['RPM', [rpm_name_prefixes],
	  "rpm -qa --queryformat '%{Name} %{Version} - - installed\\n'"],
	 ['deb', [deb_name_prefixes],
	  join(' ',
	       "dpkg-query -W -f '\${Package} \${Version} \${Status}\\n'",
	       map({"'$_*'"} deb_name_prefixes))]) {
	my ($type, $prefixes, $command) = @$_;
	if (my $query_file = new FileHandle("$command 2>/dev/null |")) {
	    while (<$query_file>) {
		chomp;
		my ($name, $version, undef, undef, $status) = split(/ /);
		if (grep({startswith($name, $_)} @$prefixes) &&
		    $status eq 'installed') {
		    push @packages, [$type, $name, $version];
		}
	    }
	}
    }
    tabulate("AMD Solarflare software packages installed",
	     undef,
	     ['type', 'name', 'version'],
	     \@packages);

    # Onload kernel modules and shared libraries are not currently
    # installed as packages.
    my @onload_comps;
    for (glob('/lib/modules/*/extra/onload.ko')) {
	my $path = $_;
	my $name = 'kmod-' . (split(/\//, $path))[3];
	my $version = `modinfo -F version '$path'`;
	chomp $version;
	push @onload_comps, [$name, $version];
    }
    for (grep({-f} '/usr/lib64/libonload.so', '/usr/lib/libonload.so')) {
	my $path = $_;
	my $name = (split(/\//, $path))[2];
	my $version = `$path 2>/dev/null`;
	$version =~ s/\n.*//s;
	$version =~ s/^OpenOnload //;
	push @onload_comps, [$name, $version];
    }
    tabulate("Onload components installed",
	     undef,
	     ['name', 'version'],
	     \@onload_comps);

    if (my $tcpdirect_file = `zf_stackdump version 2>&1 |grep version`) {
        print_heading('TCPDirect version');
        print_preformatted($tcpdirect_file);
    }

    if (my $ptp_file = `cat /var/lib/sfptpd/version 2>/dev/null` ) {
        print_heading('sfptpd version installed');
        print_preformatted($ptp_file);
    }

    if (my $clock_file = `cat /sys/devices/system/clocksource/*/current_clocksource 2>/dev/null` ) {
        print_heading('Clock Source (/sys/devices/system/clocksource/*/current_clocksource) ');
        print_preformatted($clock_file);
    }

    print_heading('Network interfaces for AMD Solarflare adapters', 'controller');
    tabulate('',
	     undef,
	     ['name', 'address', 'driver_version', 'controller_version'],
	     [map({[$_, $sfc_drvinfo->{$_}->bus_info,
		    $sfc_drvinfo->{$_}->version,
		    $sfc_drvinfo->{$_}->fw_version]}
		  keys(%$sfc_drvinfo))]);

    if (my $interrupts_file = new FileHandle('/proc/interrupts')) {
	my @attributes = ('number', 'type', 'affinity', 'sources');
	my @values = ();
	my $n_cpus;
	while (<$interrupts_file>) {
	    s/^\s+//; s/\s+$//; # trim leading and trailing space
	    my @fields = split(/:?\s+/, $_);
	    if ($. == 1) {
		# Header line labels CPU columns.
		# The other columns are unlabelled.
		# We assume that channel name is in last column.
		push @attributes, map($_ . '_count', @fields);
		$n_cpus = @fields;
	    } elsif ($fields[1] =~ /^\d+$/) {
		# Check whether any of the interrupts sources matches
		# Interrupts can have suffix with one or more dash
		# (e.g. -1, -rx-1, -ptp) but interface name could also contain
		# a dash.  Test suffixes to see if anything matches an interface
		my @ifname_parts = split(/-/, $fields[-1]);
		my $ifname = shift(@ifname_parts);
		while (scalar @ifname_parts and not exists $sfc_drvinfo->{$ifname}
					    and $ifname ne "onld") {
			$ifname .= '-' . shift(@ifname_parts);
		}
		if (exists($sfc_drvinfo->{$ifname}) or $ifname eq "onld") {
		    my $irq = $fields[0];
		    my $affinity = read_file("/proc/irq/$irq/smp_affinity");
		    chomp($affinity) if defined($affinity);
		    my $type = ($arch_is_powerpc ?
				"${fields[-3]} ${fields[-2]}" : $fields[-2]);
		    push @values, [$irq, $type, $affinity, $fields[-1],
				   @fields[1..$n_cpus]];
		}
	    }
	}
	tabulate('IRQs for AMD Solarflare adapters',
		 undef,
		 \@attributes,
		 \@values,
		 orient_horiz,
		 values_format_default,
		 'irq');
    }
  print_footer();
  
    if (my $hwmon_devices = list_dir('/sys/class/hwmon')) {
	my @attributes = ();
	my @values = ();

	for (@$hwmon_devices) {
	    my $device_dir = "/sys/class/hwmon/$_/device";
	    my $device_dir1 = "/sys/class/hwmon/$_";
	    my $sensor_values;

	    # Check whether this is a grandchild of a device handled
	    # by sfc or xilinx_efct (the I2C adapter is a child of the PCI
            # device and the hardware monitor is a child of I2C adapter).
	    my $grandparent_driver = readlink("$device_dir/driver");
	    next unless defined($grandparent_driver)
		&& ($grandparent_driver =~ m|/sfc$| ||
                  $grandparent_driver =~ m|/xilinx_efct$|);

	    # Use last three components of the device path as its address.
	    # That should be the PCI device's address, the I2C adapter
	    # id and the I2C address of the hardware monitor.
	    my $address = readlink($device_dir);
	    $address =~ s|.*/([^/]*)$|$1|;
            if ( my $temp_file = `ls $device_dir |grep temp`){
                $sensor_values = read_dir_files($device_dir,
                                               sub {/^(in|temp)\d+_/},
                                               sub {chomp});
            }
            else {
                $sensor_values = read_dir_files($device_dir1,
                                               sub {/^(in|temp)\d+_/},
                                               sub {chomp});
            }

	    next unless defined($sensor_values);

	    my %value = (address => $address);
	    for (@$sensor_values) {
		my ($attr, $attr_value) = @$_;
		push @attributes, $attr
		    unless grep({$_ eq $attr} @attributes);
		# Convert from thousandths of implicit units to explicit
		# full units
		
		if (($attr !~ /_alarm$/) && ($attr !~ /_label$/)) {	
                    no warnings 'numeric';
                    if (defined($attr_value)) {
                        my ($whole, $milli) =
                           ($attr_value / 1000, $attr_value % 1000);
                        if ($attr =~ /^in/) {
                            $attr_value = sprintf('%d.%03d V', $whole, $milli);
                        } elsif ($attr =~ /^temp/) {
                            $attr_value = sprintf('%d degC', $whole);
                        }
                    }
                }
		$value{$attr} = $attr_value;
	    }
	    push @values, \%value;
	}

	@attributes = ('address', sort @attributes);

	tabulate('Hardware monitors (Sensors)',
		 undef,
		 \@attributes,
		 \@values,
		 orient_vert,
		 values_format_default,
		 'hwmon');
    }


    if (my $dmesg_file = new FileHandle('dmesg --ctime 2>/dev/null |')) {
        $_ = `dmesg --ctime 2>/dev/null`; 
        if ($?!=0) {
            $dmesg_file->close();
            $dmesg_file = new FileHandle('dmesg |');
        }
	print_heading("Recent kernel messages about AMD Solarflare adapters"
		      ." and drivers", "dmesg");
	begin_preformatted(1);
	my $word_alternation = join('|',
				    'solarflare',
				    map({s/\./\\./; $_} keys(%sfc_devices)),
				    keys(%$sfc_drvinfo));
	for (<$dmesg_file>) {
	    print_text($_) if /\b(sfc|onload|ef[x1]|($word_alternation)\b)/i;
	}
	end_preformatted(1);
    }
  print_footer("dmesg");
} # print_device_status

sub parse_ipv4 {
    my $addr = shift;
    return unpack('N', inet_aton($addr));
}

sub decode_ipv4_netmask {
    my $mask = shift;
    my $prefix_len = 0;
    while ($mask && $prefix_len < 32) {
	 $mask -= 0x80000000 >> $prefix_len;
	 ++$prefix_len;
    }
    return ($mask == 0) ? $prefix_len : undef;
}

sub print_net_status {
    my $sfc_drvinfo = shift;
    my %iface_names;

    for my $iface_name (keys(%$sfc_drvinfo)) {
	$iface_names{$iface_name} = 1;
    }

    # Add related VLAN and bonding interfaces
    my $link_info = `ip link show 2>/dev/null`;
    while ($link_info =~ /^\d+: (?:([^ ]+)@)?([^ @]+): \<.*\> (.*)/gm) {
	my ($vlan_name, $name, $attrs) = ($1, $2, $3);
	if ($iface_names{$name}) {
	    if (defined($vlan_name)) {
		$iface_names{$vlan_name} = 1;
	    }
	    if ($attrs =~ / master ([^ ]+)/) {
		$iface_names{$1} = 1;
	    }
	}
    }

    if (my $iface_list = list_dir('/sys/class/net')) {
        print_heading('Ifconfig', 'ifconfig');
        for my $iface_name (@$iface_list) {
            for my $command ('ifconfig') {
                if (my $report = `$command '$iface_name' 2>/dev/null`) {
                    print_heading("Network configuration for $iface_name"
                                  ." ($command)");
                    print_preformatted($report);
                    last;
                }
            }
        }
        print_footer('ifconfig');
    }

    print_heading('Network Configuration Scripts', 'netcfg');
    for my $config_path ('/etc/sysconfig/network',
			 map('/etc/sysconfig/network-scripts/ifcfg-' . $_,
			     keys %iface_names),
			 '/etc/network/interfaces') {
	print_heading("Configuration file $config_path");
	if (my $config = read_file($config_path)) {
	    print_preformatted($config, 1);
	} else {
	    print_warning("not readable: $!");
	}
    }
  print_footer('netcfg');

    print_heading("Sysctl -a", 'sysctl', 'hide');
    if (my $report =`sysctl -a 2>/dev/null`) {
            print_preformatted($report);
    }
  print_footer('sysctl');
	
    print_heading("NUMA information ");
    if (my $NUMA = `numactl --hardware 2>/dev/null`) {
        print_preformatted($NUMA); 
    }
    for my $iface_name(keys %iface_names) {
        if (my $report = `cat /sys/class/net/'$iface_name'/device/local_cpulist 2>/dev/null`) {
            print_preformatted($iface_name);
            print_preformatted($report);
        }
    }

    print_heading("HugePages information ");
    if (my $HugePages = `cat /proc/meminfo | grep Huge 2>/dev/null; cat /sys/devices/system/node/node*/meminfo | grep Huge 2>/dev/null`) {
        print_preformatted($HugePages);
    }

    print_heading("Packet buffer information ");
    if (my $PacketBufferUsage = `grep '' /proc/driver/sfc_resource/devices/*/pd* 2>/dev/null`) {
        print_preformatted($PacketBufferUsage);
    }

tabulate('TCP (IPv4) settings',
	     undef,
	     ['name', 'value'],
	     read_dir_files('/proc/sys/net/ipv4',
			    sub {$_ =~ /^tcp_/},
			    sub {chomp; s/\t/ /g;}),
	     orient_horiz,
	     values_format_default,
	     'tcp_cfg');

    if (my $netstat_file = new FileHandle('netstat -s 2>/dev/null |')) {
	my $netstat_output;
	while (<$netstat_file>) {
	    $netstat_output .= $_;
	}
	print_heading('Network statistics (netstat -s)', 'netstat');
	print_preformatted($netstat_output);
  print_footer('netstat');
    }

    if (my $arp_file = new FileHandle('arp -n 2>/dev/null |')) {
	my @values = ();
	while (<$arp_file>) {
	    next if $. == 1;
	    my ($ip_addr, $hw_type, $mac_addr, $flags, $iface) = split /\s+/;
	    push @values, [$ip_addr, $mac_addr, $flags, $iface]
		if $hw_type eq 'ether';
	}
	tabulate('ARP cache',
		 'arp_cache',
		 ['ip_address', 'mac_address', 'flags', 'iface_name'],
		 \@values,
		 orient_horiz);
    }

    if (my $route_file = new FileHandle('route -A inet -n 2>/dev/null |')) {
	my @values = ();
	while (<$route_file>) {
	    next if $. <= 2;
	    my ($dest, $gw, $mask, $flags, $metric, undef, undef, $iface) =
		split /\s+/;
	    my $prefix_len = decode_ipv4_netmask(parse_ipv4($mask));
	    push @values, ["$dest/$prefix_len", $gw, $flags, $metric, $iface];
	}
	tabulate('Routing table (IPv4)',
		 'route_ipv4',
		 ['dest_address', 'gateway_address', 'flags', 'metric',
		  'iface_name'],
		 \@values,
		 orient_horiz);
    }

    if (my $route_file = new FileHandle('route -A inet6 -n 2>/dev/null |')) {
	my @values = ();
	while (<$route_file>) {
	    next if $. <= 2;
	    my ($dest, $gw, $flags, $metric, undef, undef, $iface) =
		split /\s+/;
	    push @values, [$dest, $gw, $flags, $metric, $iface];
	}
	tabulate('Routing table (IPv6)',
		 'route_ipv6',
		 ['dest_address', 'gateway_address', 'flags', 'metric',
		  'iface_name'],
		 \@values,
		 orient_horiz);
    }

    if (my $route_file = new FileHandle("ip route show table all 2>&1 |")) {
        my $output = '';
        while (<$route_file>) {
            $output .= $_;
        }
        print_heading('Full Routing table (ip route show table all)');
        print_preformatted($output);
    }
   
    if (my $route_file = new FileHandle("ip rule show 2>&1 |")) {
        my $output = '';
        while (<$route_file>) {
            $output .= $_;
        }
        print_heading('ip rule show');
        print_preformatted($output);
    }

    if (my $route_file = new FileHandle("ip link show 2>&1 |")) {
        my $output = '';
        while (<$route_file>) {
            $output .= $_;
        }
        print_heading('ip link show');
        print_preformatted($output);
    }

    if (my $netns_file = new FileHandle("ip netns 2>&1 |")) {
        my $output = '';
        while (<$netns_file>) {
            $output .= $_;
        }
        print_heading('Namespace (ip netns)');
        print_preformatted($output);
        
        if (my $netns_file2 = new FileHandle("ip netns identify 2>&1 |")){
            my $output2 = '';
        while (<$netns_file2>) {
            $output2 .= $_;
        }
            print_preformatted("sfreport run in the namespace (ip netns identify): $output2");
        }
    }

    if (my $addr_file = new FileHandle("ip -s -d addr show 2>&1 |")) {
        my $output = '';
        while (<$addr_file>) {
            $output .= $_;
        }
        print_heading('ip addr show');
        print_preformatted($output);
    }

    for my $bond_dir ('/proc/net/bonding') {
        if (opendir(DIR, $bond_dir)){
                print_heading('/proc/net/bonding');
            while (my $bond_file = readdir(DIR)) {
                next if ($bond_file =~ m/^\./);
                print_bold($bond_file);
                if (my $bond_state = read_file("$bond_dir/$bond_file")){
                    print_preformatted($bond_state);
                }
            }
            closedir(DIR);
        }
    }

    if (my $cstate_file = `cat /sys/module/intel_idle/parameters/max_cstate 2>/dev/null` ) {
        print_heading('Max Cstates');
        print_bold('/sys/module/intel_idle/parameters/max_cstate');
        print_preformatted($cstate_file);
    }

    if (my $ovs_file = `ovs-vsctl -V 2>/dev/null; ovs-vsctl show 2>/dev/null` ) {
        print_heading('OVS Information');
        print_heading('ovs-vsctl -V; show');
        print_preformatted($ovs_file);
        if (my $ovs_file1 = `ovs-appctl dpctl/show 2>/dev/null`){
           print_heading('ovs-appctl dpctl/show');
           print_preformatted($ovs_file1);
        }
        if (my $ovs_file2 = `ovs-appctl dpctl/dump-flows -m  2>/dev/null`){
           print_heading('ovs-appctl dpctl/dump-flows -m');
           print_preformatted($ovs_file2);
        }
    }

    for my $onload_dir ('/proc/driver/onload','/proc/driver/onload_cplane') {
        if (opendir(DIR, $onload_dir)){
            if ($onload_dir eq "/proc/driver/onload"){
                print_heading('Onload Control Plane State');
            }
            if ($onload_dir){
                print_heading($onload_dir);
            }
            while (my $onload_file = readdir(DIR)) {
                next if ($onload_file =~ m/^\./);
                print_bold($onload_file);
                if (my $onload_control = read_file("$onload_dir/$onload_file")){
                    print_preformatted($onload_control);
                }
            }
            closedir(DIR);
        }
    }

    if (my $mib_file = `onload_mibdump all 2>&1` ) {
        print_heading('onload_mibdump','mibdump','hide');
        print_preformatted($mib_file);
    }
  print_footer('mibdump');
    if (my $cplane_file = `journalctl --since=yesterday 2>/dev/null | grep onload_cp` ){
        print_heading('Control Plane Logs (journalctl)','cplane','hide');
        print_preformatted($cplane_file);
    }
    elsif (my $cplane_file1 = `cat /var/log/messages 2>/dev/null | grep onload_cp` ) {
        print_heading('Control Plane Logs (/var/log/messages)','cplane','hide');
        print_preformatted($cplane_file1);
    }
  print_footer('cplane');

    if (my $aoed_file = `cat /var/log/solar_aoed.log 2>/dev/null` ) {
        print_heading('Solar_Aoed Logs (/var/log/solar_aoed.log) ');
        print_preformatted($aoed_file);
    }

    my @stat_names = ('name');
    my @stat_values = ();

    for my $iface_name (sort keys(%iface_names)) {
	# ethtool's default output is difficult to parse so
	# include it (almost) verbatim.
	my %ethtool_output;
	for my $option ('', '-a', '-c', '-k', '-g', '-m', '-T', '-n', '--show-fec') {
	    if (my $ethtool_file =
		new FileHandle("ethtool $option '$iface_name' 2>/dev/null |")) {
		while (<$ethtool_file>) {
		    if ($. == 1) {
			s/^\s+//;               # remove whitespaces at the beginning
			s/ for $iface_name://;  # remove redundancy in heading
		    } elsif (/^\n/) {
			next;                   # remove blank lines
		    } else {
			s/^\s*/        /gm;     # indent others consistently
		    }
		    $ethtool_output{$option} .= $_;
		}
	    }
	}
	if (defined(keys %ethtool_output)) {
	    print_heading("Ethernet settings for $iface_name (ethtool)", 'ethset_'.$iface_name);
            for(sort(keys %ethtool_output)) {
                print_heading("ethtool $_ $iface_name");
                print_preformatted($ethtool_output{$_});
            }
      print_footer('ethset_'.$iface_name);
	}
    }

    for my $iface_name (sort(keys(%$sfc_drvinfo))) {
        my $bus_info = $sfc_drvinfo->{$iface_name}->bus_info;

	if (my $versions_file = `cat /sys/class/net/$iface_name/device/versions 2>/dev/null`) {
	    print_heading("Version information for $iface_name (/sys/class/net/$iface_name/device/versions)");
	    print_preformatted($versions_file);
	} elsif (my $devlink_file =`devlink dev info pci/$bus_info  2>/dev/null`) {
	    print_heading("Version information for $iface_name (devlink dev info pci/$bus_info)");
	    print_preformatted($devlink_file);
	}

	if (my $devlink_params_file = `devlink dev param show pci/$bus_info name ct_thresh 2>/dev/null`) {
	    print_heading("Devlink ct_thresh Param");
	    print_preformatted($devlink_params_file);
	}

	if (my $devlink_params_file = `devlink dev param show pci/$bus_info name dist_layout 2>/dev/null`) {
	    print_heading("Devlink dist_layout Param");
	    print_preformatted($devlink_params_file);
	}
	if (my $devlink_params_file = `devlink dev param show pci/$bus_info name separated_cpu 2>/dev/null`) {
	    print_heading("Devlink separated_cpu Param");
	    print_preformatted($devlink_params_file);
	}
    }

    if (my $uefi_info_x3 = `lspci -d 10ee:5084 -vvv | egrep 'Ethernet|Expansion' 2>/dev/null`) {
        print_heading("UEFI image used for x3 NIC (lspci -d 10ee:5084 -vvv | egrep 'Ethernet|Expansion')");
        print_preformatted($uefi_info_x3);
    }

    if (my $auxdev_file = `ls -l /sys/bus/auxiliary/devices/ 2>/dev/null`) {
        print_heading("Auxiliary devices list (ls /sys/bus/auxiliary/devices/)");
        print_preformatted($auxdev_file);
    }

    if (my $auxdrv_file = `ls -l /sys/bus/auxiliary/drivers/ 2>/dev/null`) {
        print_heading("Auxiliary drivers list (ls /sys/bus/auxiliary/drivers/)");
        print_preformatted($auxdrv_file);
    }

    if (my $firmware_file = `ls -l /lib/firmware/xilinx/* 2>/dev/null`) {
        print_heading("Xilinx firmware files (ls -l /lib/firmware/xilinx/* )");
        print_preformatted($firmware_file);
    }

    for my $iface_name (sort (keys%$sfc_drvinfo)) {
	# The additional statistics are regular so parse and re-
	# tabulate them.
	my %stats = (name => $iface_name);
	if (my $ethtool_file =
	    new FileHandle("ethtool -S '$iface_name' 2>/dev/null |")) {
	    while (<$ethtool_file>) {
		if (/^\s*([^:]+):\s*(.+)\n$/) {
		    if (!( grep( /^$1$/, @stat_names ))) {
			push @stat_names, $1;
		    }
		    $stats{$1} = $2;
		}
	    }
	}
	push @stat_values, \%stats;
    }

    print_heading("Interface Statistics", "ethtool");
    tabulate("",
	     'net_stats_sfc',
	     \@stat_names,
	     \@stat_values,
	     orient_vert);
    print_footer();

    if (my $tc_file = new FileHandle("tc -s qdisc show 2>&1 |")) {
	my $output = '';
	while (<$tc_file>) {
	    $output .= $_;
	}
	print_heading('Network queue discipline status (tc)');
	print_preformatted($output);
    }

    if (my $rt_file = `ps -eLo pid,lwp,rtprio,policy,lastcpu,comm |egrep -i -v ' 99 | - '`) {
        print_heading('Real Time Priority (ps -eLo pid,lwp,rtprio,policy,lastcpu,comm)');
        print_preformatted($rt_file);
    }

    if (-e "/etc/udev/rules.d/70-persistent-net.rules")
    { 	
        if (my $license_file = new FileHandle("cat /etc/udev/rules.d/70-persistent-net.rules 2>/dev/null |")) {
            my $output = '';
            while (<$license_file>) {
                $output .= $_;
            }
            print_heading('70-persistent-net.rules');
            print_preformatted($output);
        }
    }

    if (my $license_file = new FileHandle("sfupdate 2>&1 |")) {
        my $output = '';
        while (<$license_file>) {
            $output .= $_;
        }
        print_heading('Update Utility Output (sfupdate)');
        print_preformatted($output);
    }

    if (my $license_file = new FileHandle("sfkey --report --all 2>&1 |")) {
        my $output = '';
        while (<$license_file>) {
            $output .= $_;
        }
        print_heading('License Information(sfkey --report --all)');
        print_preformatted($output);
    }
    
    if (my $license_file = new FileHandle("sfboot 2>&1 |")) {
        my $output = '';
        while (<$license_file>) {
            $output .= $_;
        }
        print_heading('Sfboot Configurations (sfboot)','sfboot');
        print_preformatted($output);
        print_footer('sfboot');
    }
	
    my @hwtstamp_config;
    for my $iface_name (keys %iface_names) {
	if (my $config = get_hwtstamp_config($iface_name)) {
	    push @hwtstamp_config, [$iface_name, $config->flags,
				    $config->tx_type, $config->rx_filter];
	} else {
	    push @hwtstamp_config, [$iface_name];
	}
    }
    tabulate("Hardware timestamp configuration",
	     'hwtstamp_config',
	     ['iface_name', 'flags', 'tx_type', 'rx_filter'],
	     \@hwtstamp_config,
	     orient_horiz);
} # print_net_status

#Recursively get list of files under $directory"
sub get_recursive_file_in_dir {
    my ($directory) = @_;

    my @all_files;
    opendir my $dh, $directory or die "Could not open directory $directory: $!";
    while (my $entry = readdir $dh) {
        next if $entry eq '.' || $entry eq '..';
	my $full_path = "$directory/$entry";

	if (-f $full_path) {
		push @all_files, $full_path;
	} elsif (-d $full_path) {
		push @all_files, get_recursive_file_in_dir($full_path);
	} } closedir $dh;

    return @all_files;
}

sub print_preformatted_file {
	my @filenames = @_;
	$out_file->print("<div style='display: flex;'>\n");
	for my $filename (@filenames) {
	if (my $content = `cat $filename 2>/dev/null` ) {
		my $heading = join("/", (split(/\//, $filename))[5..8]);
		$out_file->print("<div style='border: 1px solid #000; padding: 10px; margin: 10px;'>\n");
		$out_file->print("<h3>".html_encode($heading)."</h3>\n");
		print_preformatted($content);
		$out_file->print("</div>\n");
	}
}
	$out_file->print("</div>\n");
}

sub read_key_value_debug_files {
    my ($base_dir, @files) = @_;
    my @attributes = ('address');
    my @values = ();

	# Open the file for reading
    for my $file (@files) {
	my $relative_path = substr($file, length($base_dir) + 1);
	push @values, {address => $relative_path};
	open my $fh, '<', $file or die "Cannot open $file: $!";

	while (my $line = <$fh>) {
		chomp $line; # Remove newline characters
		my ($key, $value) = split(':', $line, 2); # Assuming key-value pairs are separated by ':'
		push @attributes, $key if defined $key && !grep { $_ eq $key } @attributes;
		$values[-1]->{$key} = $value;
	}
	close $fh;
    }

    return \@attributes, \@values;
}
sub read_debug_oneline_files {
    my ($base_dir, @files) = @_;
    my @attributes = ('address');
    my @values = ();

	# Open the file for reading
    push @values, {address => "Value"};
    for my $file (@files) {
	my $relative_path = substr($file, length($base_dir) + 1);
	open my $fh, '<', $file or die "Cannot open $file: $!";
	    my $line = <$fh>;
	    chomp $line; # Remove newline characters
            if ($line eq '') {
		next;
	}
	    push @attributes, $relative_path;
	    $values[-1]->{$relative_path} = $line;

	    close $fh;
        }

    return \@attributes, \@values;
}


sub read_debug_dir {
    my ($base_dir, @sub_dirs) = @_;
    my @attributes = ('address');
    my @values = ();
    my @sub_sub_dirs = ();
    for my $sub_dir (@sub_dirs) {
	if (my $list = list_dir("$base_dir/$sub_dir")) {
	    if ($#values < 0) {
		# Get the list of files from the first directory
		# (we assume all directories have the same set of
		# files).
		# Ignore '*_hist' files because they're binary.
		push @attributes, grep(!/_hist$/ && -f "$base_dir/$sub_dir/$_",
				       @$list);
	    }
	    push @values, {address => $sub_dir};
	    for my $attr_name (@attributes[1..$#attributes]) {
		my $attr_value = read_file("$base_dir/$sub_dir/$attr_name");
		chomp($attr_value) if defined($attr_value);
		$values[-1]->{$attr_name} = $attr_value;
	    }
	    # Record subdirectories for later inspection.
	    push @sub_sub_dirs, map("$sub_dir/$_",
				    grep(-d "$base_dir/$sub_dir/$_",
					 @$list));
	}
    }
    return \@attributes, \@values, \@sub_sub_dirs;
}

sub print_sfc_debug_info {
    # This relies on debugfs/procfs support which is likely to be
    # excluded from production drivers.  The most interesting
    # information available here should also be found in the kernel
    # log or the interface statistics.

    my @debug_dirs = find_sfc_debug_dir();

    print_heading('SFC Debug Info', 'sfcdebug');
    foreach my $debug_dir (@debug_dirs) {
        my $base_dir = "$debug_dir/cards";
	if (my $card_dirs = list_dir($base_dir)) {
	    my ($attributes, $values, $sub_dirs);

	    ($attributes, $values, $sub_dirs) =
		read_debug_dir($base_dir, @$card_dirs);
	    tabulate('SFC Adapters', 'sfc_nic',
		     $attributes, $values, orient_vert);

	    ($attributes, $values) =
		read_debug_dir($base_dir, grep(m|/errors$|, @$sub_dirs));
	    tabulate('Error counts', 'sfc_errors',
		     $attributes, $values, orient_vert);

	    ($attributes, $values) =
		read_debug_dir($base_dir, grep(m|/rxq|, @$sub_dirs));
	    tabulate('Receive queues', 'sfc_rxqueue',
		     $attributes, $values, orient_vert);

	    ($attributes, $values) =
		read_debug_dir($base_dir, grep(m|/txq|, @$sub_dirs));
	    tabulate('Transmit queues', 'sfc_txqueue',
		     $attributes, $values, orient_vert);

	    ($attributes, $values) =
		read_debug_dir($base_dir, grep(m|/chan|, @$sub_dirs));
	    tabulate('Event queues', 'sfc_eventqueue',
		     $attributes, $values, orient_vert);

	    ($attributes, $values) =
		read_debug_dir($base_dir, grep(m|/port|, @$sub_dirs));
	    tabulate('Ports', 'sfc_port',
		     $attributes, $values, orient_vert, values_format_pre);
	  }
    }
	print_footer('sfcdebug');
} # print_sfc_debug_info

sub print_x3_debug_info_compat {
    # This relies on debugfs/procfs support which is likely to be
    # excluded from production drivers.  The most interesting
    # information available here should also be found in the kernel
    # log or the interface statistics.
    my @debug_dirs = find_x3_debug_dir();

    print_heading('X3 Debug Info', 'x3debug', 'hide');
    foreach my $debug_dir (@debug_dirs) {
        my $base_dir = "$debug_dir";
        if (my $card_dirs = list_dir($debug_dir)) {
            my ($attributes, $values, $sub_dirs, $sub_dirs_aux, $sub_dirs_rxq, $sub_sub_dirs);

            my $i = 0;
            #print "card dir: $card_dirs\n"
            ($attributes, $values, $sub_dirs) =
            read_debug_dir($base_dir, @$card_dirs);
            tabulate('X3 NIC Params', 'x3_nic',
                 $attributes, $values, orient_vert);

            ($attributes, $values) =
            read_debug_dir($base_dir, grep(m|/design_params$|, @$sub_dirs));
            tabulate('X3 Design Params', 'x3_design_params',
                 $attributes, $values, orient_vert);

            ($attributes, $values, $sub_dirs) =
            read_debug_dir($base_dir, grep(m|/port|, @$sub_dirs));
            tabulate('X3 Ports', 'x3_port',
                 $attributes, $values, orient_vert);

            ($attributes, $values) =
            read_debug_dir($base_dir, grep(m|/errors$|, @$sub_dirs));
            tabulate('X3 Error counts', 'x3_errors',
                 $attributes, $values, orient_vert);

            ($attributes, $values) =
            read_debug_dir($base_dir, grep(m|/link_state$|, @$sub_dirs));
            tabulate('X3 Link State', 'x3_linkstate',
                 $attributes, $values, orient_vert);

            ($attributes, $values) =
            read_debug_dir($base_dir, grep(m|/txq|, @$sub_dirs));
            tabulate('X3 Transmit queues', 'x3_txqueue',
                 $attributes, $values, orient_vert);

            ($attributes, $values) =
            read_debug_dir($base_dir, grep(m|/evq|, @$sub_dirs));
            tabulate('X3 Event queues', 'x3_eventqueue',
                 $attributes, $values, orient_vert);

            ($attributes, $values, $sub_dirs_aux) =
            read_debug_dir($base_dir, grep(m|/efct|, @$sub_dirs));
            tabulate('X3 Aux Device', 'x3_linkstate',
                 $attributes, $values, orient_vert);

            ($attributes, $values, $sub_sub_dirs) =
            read_debug_dir($base_dir, grep(m|/client|, @$sub_dirs_aux));
            tabulate('X3 Aux Client', 'x3_client',
                 $attributes, $values, orient_vert);

            ($attributes, $values) =
            read_debug_dir($base_dir, grep(m|rxq_info|, @$sub_sub_dirs));
            tabulate('X3 RxqInfo', 'x3_client',
                $attributes, $values, orient_vert);

            ($attributes, $values, $sub_dirs_rxq) =
            read_debug_dir($base_dir, grep(m|/rxq|, @$sub_dirs));
            tabulate('X3 Receive queues', 'x3_rxqueue',
                 $attributes, $values, orient_vert);

            ($attributes, $values, $sub_sub_dirs) =
            read_debug_dir($base_dir, grep(m|/nbl$|, @$sub_dirs_rxq));
            tabulate('X3 NIC Buffer List', 'x3_rxqueue',
                 $attributes, $values, orient_vert);

            print_heading('X3 NB List');
            for ($i = 0; $i < 8; $i++) {
                ($attributes, $values) =
                read_debug_dir($base_dir, grep(m|rxq$i/nbl/nb|, @$sub_sub_dirs));
                tabulate("Rxq$i", 'x3_rxqueue',
                    $attributes, $values, orient_vert);
            }

            ($attributes, $values) =
            read_debug_dir($base_dir, grep(m|/hpl$|, @$sub_dirs_rxq));
            tabulate('X3 HP List', 'x3_rxqueue',
                 $attributes, $values, orient_vert);

            ($attributes, $values, $sub_sub_dirs) =
            read_debug_dir($base_dir, grep(m|/dbl$|, @$sub_dirs_rxq));

            print_heading('X3 DB List');
            for ($i = 0; $i < 8; $i++) {
                ($attributes, $values) =
                read_debug_dir($base_dir, grep(m|rxq$i/dbl/db|, @$sub_sub_dirs));
                tabulate("Rxq$i", 'x3_rxqueue',
                    $attributes, $values, orient_vert);
            }

            ($attributes, $values, $sub_sub_dirs) =
            read_debug_dir($base_dir, grep(m|/sbl$|, @$sub_dirs_rxq));

            print_heading('X3 SB List');
            for ($i = 0; $i < 8; $i++) {
                ($attributes, $values) =
                read_debug_dir($base_dir, grep(m|rxq$i/sbl/sb|, @$sub_sub_dirs));
                tabulate("Rxq$i", 'x3_rxqueue',
                    $attributes, $values, orient_vert);
            }
        }
    }
	print_footer('x3debug');
} # print_x3_debug_info_compat

sub print_x3_debug_info {
    # This relies on debugfs/procfs support which is likely to be
    # excluded from production drivers.  The most interesting
    # information available here should also be found in the kernel
    # log or the interface statistics.
    my @debug_dirs = find_x3_debug_dir();

    my $maxrx = 16;
    print_heading('X3 Debug Info', 'x3debug');
    foreach my $debug_dir (@debug_dirs) {
        my $base_dir = "$debug_dir";
        if (my @file_list = get_recursive_file_in_dir($base_dir)) {
            my ($attributes, $values);

            my $i = 0;

            ($attributes, $values) =
            read_key_value_debug_files($base_dir, grep(m|/card_params$|, reverse @file_list));
            tabulate('X3 Card Params', 'x3_card_params',
                 $attributes, $values, orient_vert);

            ($attributes, $values) =
            read_key_value_debug_files($base_dir, grep(m|/design_params$|, reverse @file_list));
            tabulate('X3 Design Params', 'x3_design_params',
                 $attributes, $values, orient_vert);

            ($attributes, $values) =
            read_key_value_debug_files($base_dir, grep(m|/port_params$|, reverse @file_list));
            tabulate('X3 Port params', 'x3_port',
                 $attributes, $values, orient_vert);
                             
            ($attributes, $values) =
            read_key_value_debug_files($base_dir, grep(m|/nic_errors$|, reverse @file_list));
            tabulate('X3 NIC errors', 'x3_errors',
                 $attributes, $values, orient_vert);

            ($attributes, $values) =
            read_key_value_debug_files($base_dir, grep(m|/link_state$|, reverse @file_list));
            tabulate('X3 Link State', 'x3_linkstate',
                 $attributes, $values, orient_vert);


            ($attributes, $values) =
            read_key_value_debug_files($base_dir, grep(m|/txq|, reverse @file_list));
            tabulate('X3 Transmit queues', 'x3_txqueue',
                 $attributes, $values, orient_vert);

            ($attributes, $values) =
            read_key_value_debug_files($base_dir, grep(m|/evq|, reverse @file_list));
            tabulate('X3 Event queues', 'x3_eventqueue',
                 $attributes, $values, orient_vert);

            ($attributes, $values) =
            read_key_value_debug_files($base_dir, grep(m|/aux_dev_params$|, reverse @file_list));
            tabulate('aux_dev_params', 'x3_aux_dev_params',
                 $attributes, $values, orient_vert);
            
            ($attributes, $values) =
            read_key_value_debug_files($base_dir, grep(m|/client_params|, reverse @file_list));
            tabulate('client_params', 'x3_client',
                 $attributes, $values, orient_vert);
            
	    print_heading("client_rxinfo\n");
	    print_preformatted_file(grep(m|client_rxinfo|, reverse @file_list));
             
            ($attributes, $values) =
            read_key_value_debug_files($base_dir, grep(m|/rx_queue_params|, reverse @file_list));
            tabulate('X3 Receive queues params', 'x3_rxqueue',
                 $attributes, $values, orient_vert);

            ($attributes, $values) =
            read_key_value_debug_files($base_dir, grep(m|/nbl_params$|, reverse @file_list));
            tabulate('X3 NBL Params', 'x3_nbl_params',
                 $attributes, $values, orient_vert);
            

            print_heading('X3 NB List');
	    my @buf_files = grep { $_ =~ m|rxq\d{1,$maxrx}/nbl_buf_list| } reverse @file_list;
	    my %bus_val;
	    map { my $bus = (split('/'))[-4]; $bus =~ s/\.\d$//; push @{$bus_val{$bus}}, $_ } @buf_files;
	    for my $bus (keys %bus_val) {
		    for ($i = 0; $i < 4; $i++) {
			    my @file = grep { $_ =~ m|port$i/rxq\d{1,$maxrx}/nbl_buf_list| } @{$bus_val{$bus}};
			    if (@file) {
				    print_heading("$bus/port$i\n");
				    print_preformatted_file(@file);
			    }
		    }
	    }

	    ($attributes, $values) =
            read_debug_oneline_files($base_dir, grep(m|/max_hp_id$|, reverse @file_list));
            tabulate('max_hp_id', 'x3_hbl',
                 $attributes, $values, orient_vert);

            print_heading('X3 DB List');
	    my @db_buf_files = grep { $_ =~ m|rxq\d{1,$maxrx}/dbl_buf_list| } reverse @file_list;
	    my %db_bus_val;
	    map { my $bus = (split('/'))[-4]; $bus =~ s/\.\d$//; push @{$db_bus_val{$bus}}, $_ } @db_buf_files;
	    for my $bus (keys %db_bus_val) {
		    for ($i = 0; $i < 4; $i++) {
			    my @file = grep { $_ =~ m|port$i/rxq\d{1,$maxrx}/dbl_buf_list| } @{$db_bus_val{$bus}};
			    if (@file) {
				    print_heading("$bus/port$i\n");
				    print_preformatted_file(@file);
			    }
		    }
	    }

            print_heading('X3 SB List');
	    my @sb_buf_files = grep { $_ =~ m|rxq\d{1,$maxrx}/sbl_buf_list| } reverse @file_list;
	    my %sb_bus_val;
	    map { my $bus = (split('/'))[-4]; $bus =~ s/\.\d$//; push @{$sb_bus_val{$bus}}, $_ } @sb_buf_files;
	    for my $bus (keys %sb_bus_val) {
		    for ($i = 0; $i < 4; $i++) {
			    my @file = grep { $_ =~ m|port$i/rxq\d{1,$maxrx}/sbl_buf_list| } @{$sb_bus_val{$bus}};
			    if (@file) {
				    print_heading("$bus/port$i\n");
				    print_preformatted_file(@file);
			    }
		    }
	    }
    }
}
	print_footer('x3debug');
} # print_x3_debug_info

sub print_nic_type {
    my ($devices, $sfc_drvinfo) = @_;
    my %device_drivers = get_device_drivers();
    my %sfc_devices = get_sfc_devices($devices);
    my @headings = ('subsys_id','vpdr_SN');
    my @vpd_attributes = qw(address product_name vpdr_PN vpdr_EC vpdr_SN);
    my %vpd_values = get_sfc_vpd($sfc_drvinfo, @vpd_attributes);
    my @data = map({[$_, sprintf('%04x', $sfc_devices{$sfc_drvinfo->{$_}->bus_info}->SUBSYSTEM_ID), $vpd_values{$_}->{"vpdr_SN"},]} keys(%$sfc_drvinfo));

    my $values = \@data;
    my $attributes = @headings;
    my @tmp=0;
    if(@data){
    foreach my $line (@data){
        if($line->[2]){
        if( grep(/^$line->[2]/, @tmp) ){
        if( ($line->[1] eq "082C") or ($line->[1] eq "082D")){
            $out_file->print("<p>Note: NIC with Serial number: $line->[2] is a Dell version NIC </p>");
        }
        elsif(($line->[1] eq "082F")){
            $out_file->print("<p>Note: NIC with Serial number: $line->[2] is a Lenovo version NIC </p>");
        }}
        push(@tmp,$line->[2]);
        }}}
    return 0;
} #print brand version of the NIC

sub print_sfc_vpd {
    my ($devices, $sfc_drvinfo) = @_;

    my @attributes = qw(address product_name vpdr_PN vpdr_EC vpdr_SN);
    my %values = get_sfc_vpd($sfc_drvinfo, @attributes);
    my @data = map({[$sfc_drvinfo->{$_}->bus_info,
                            $values{$_}->{"product_name"},
                            $values{$_}->{"vpdr_PN"},
                            $values{$_}->{"vpdr_EC"},
                            $values{$_}->{"vpdr_SN"}]}
                            keys(%$sfc_drvinfo));

    tabulate('Vital product data (VPD)', undef,
	     \@attributes, \@data, orient_vert,
	     values_format_default, 'vitalpd');
} # print_sfc_vpd

sub print_interesting {
    print_heading('Summary of interesting values');
    if ($out_format == format_html) {
	$out_file->print("    <ul>\n");
    }
    for my $i (0..$#interesting_stuff) {
	my ($condition, $int_type) = @{$interesting_stuff[$i]};
	my $message = $interest_labels[$int_type] . ': ' . $condition;
	if ($out_format == format_html) {
	    $out_file->print("      <li class="
			     . $interest_css_classes[$int_type]
			     . "><a href=\"#match$i\">"
			     . html_encode($message) . "</a></li>\n");
	} else {
	    $out_file->print("$message\n");
	}
    }
    if ($out_format == format_html) {
	$out_file->print("    </ul>\n");
    }
} # print_interesting

sub print_mtd {
    print_heading('MTD partitions (/proc/mtd)');
    if (my $mtd_parts = read_file('/proc/mtd')) {
	print_preformatted($mtd_parts, 0);
    } else {
	print_warning("not readable: $!");
    }
}

sub print_aoe_status {
    my $aoe_data = '/sys/devices/sfc_aoe';
    my $aoe_ls = list_dir($aoe_data);
    my @map_headers = ("index", "base_addr", "comp_info", "length", "name");
    my @version_headers = ("index", "board_rev", "fpga_version",
                           "fc_version", "mum_version", "cpld_version");
    my @build_headers = ("index", "fpga_services_version", "fpga_bsp_version",
                           "fpga_build_changeset", "fpga_services_changeset");
    my @dimm_headers = ("index", "size", "type", "voltage", "status", "partnum");
    my @info_headers = ("index", "byteblaster", "fc_running", "aoe_sm_state", "fpga_powered", "bad_sodimm", "boot");
    my @port_headers = ("index", "vod", "preemp_1stposttap", "preemp_pretap", "preemp_2ndposttap",
			"dc_gain", "rx_eq");
    my %maps = ();
    my @versions = ();
    my @build_params = ();
    my @infos = ();
    my %dimms = ();
    my %ports = ();
    for (@$aoe_ls) {
        if (index($_, 'fpga') != -1) {
            $maps{$_} = [];
        }
    }
    for (@$aoe_ls) {
        if (index($_, 'fpga') != -1) {
            $dimms{$_} = [];
        }
    }

    foreach my $fpga (keys %maps) {
        my $fpga_data = $aoe_data.'/'.$fpga;
        my $fpga_ls = list_dir($fpga_data);
        for (@$fpga_ls) {
            if(index($_, "map") == -1) {
                next;
            }
            my $base_addr = read_file($fpga_data.'/'.$_.'/base_addr');
            my $comp_info = read_file($fpga_data.'/'.$_.'/comp_info');
            my $length = read_file($fpga_data.'/'.$_.'/length');
            my $name = read_file($fpga_data.'/'.$_.'/name');
            chomp $base_addr;
            chomp $comp_info;
            chomp $length;
            chomp $name;
            push @{$maps{$fpga}}, [$_, $base_addr, $comp_info, $length, $name];
        }
        for (@$fpga_ls) {
            if(index($_, "dimm") == -1) {
                next;
            }
            my $size = read_file($fpga_data.'/'.$_.'/size');
            my $type = read_file($fpga_data.'/'.$_.'/type');
            my $voltage = read_file($fpga_data.'/'.$_.'/voltage');
            my $status = read_file($fpga_data.'/'.$_.'/status');
            my $partnum = read_file($fpga_data.'/'.$_.'/partnum');
            chomp $size;
            chomp $type;
            chomp $voltage;
            chomp $status;
            chomp $partnum;
            push @{$dimms{$fpga}}, [$_, $size, $type, $voltage, $status, $partnum];
        }
        my $aoe_state = '';
        for (@$fpga_ls) {
            if(index($_, "state") != -1) {
                $aoe_state = '/state';
                last;
            }
        }
        my $board_rev = read_file($fpga_data.$aoe_state.'/board_rev');
        my $fpga_version = read_file($fpga_data.$aoe_state.'/fpga_version');
        my $fc_version = read_file($fpga_data.$aoe_state.'/fc_version');
        my $mum_version = read_file($fpga_data.$aoe_state.'/mum_version');
        my $cpld_version = read_file($fpga_data.$aoe_state.'/cpld_version');
        my $fpga_services_version = read_file($fpga_data.$aoe_state.'/fpga_services_version');
        my $fpga_bsp_version = read_file($fpga_data.$aoe_state.'/fpga_bsp_version');
        my $fpga_build_changeset = read_file($fpga_data.$aoe_state.'/fpga_build_changeset');
        my $fpga_services_changeset = read_file($fpga_data.$aoe_state.'/fpga_services_changeset');
        if ($aoe_state ne '') {
            my $byteblaster = read_file($fpga_data.$aoe_state.'/has_byteblaster');
            my $fc_running = read_file($fpga_data.$aoe_state.'/fc_running');
            my $aoe_sm_state = read_file($fpga_data.$aoe_state.'/aoe_state');
            my $fpga_power = read_file($fpga_data.$aoe_state.'/fpga_power');
            my $bad_sodimm = read_file($fpga_data.$aoe_state.'/bad_sodimm');
            my $boot_result = read_file($fpga_data.$aoe_state.'/boot_result');
            if (defined($byteblaster)) {
                chomp $byteblaster;
            }
            chomp $fc_running;
            chomp $aoe_sm_state;
            chomp $fpga_power;
            chomp $bad_sodimm;
            chomp $boot_result;
            push @infos, [$fpga, $byteblaster, $fc_running, $aoe_sm_state, $fpga_power,
                         $bad_sodimm, $boot_result];
        }
        chomp $board_rev;
        chomp $fpga_version;
        chomp $fc_version;
        chomp $mum_version;
        if (defined($cpld_version)) {
            chomp $cpld_version;
        }
        chomp $fpga_services_version;
        chomp $fpga_bsp_version;
        chomp $fpga_build_changeset;
        chomp $fpga_services_changeset;
        push @versions, [$fpga, $board_rev, $fpga_version,
                         $fc_version, $mum_version, $cpld_version];
        push @build_params, [$fpga, $fpga_services_version,
                         $fpga_bsp_version, $fpga_build_changeset,
                         $fpga_services_changeset];
        for (@$fpga_ls) {
            if(index($_, "port") == -1) {
                next;
            }
            my $vod = read_file($fpga_data.'/'.$_.'/vod');
            my $preemp_1stposttap = read_file($fpga_data.'/'.$_.'/preemp_1stposttap');
            my $preemp_pretap = read_file($fpga_data.'/'.$_.'/preemp_pretap');
            my $preemp_2ndposttap = read_file($fpga_data.'/'.$_.'/preemp_2ndposttap');
            my $dc_gain = read_file($fpga_data.'/'.$_.'/dc_gain');
            my $rx_eq = read_file($fpga_data.'/'.$_.'/rx_eq');
            chomp $vod;
            chomp $preemp_1stposttap;
            chomp $preemp_pretap;
            chomp $preemp_2ndposttap;
            chomp $dc_gain;
            chomp $rx_eq;
            push @{$ports{$fpga}}, [$_, $vod, $preemp_1stposttap, $preemp_pretap,
				    $preemp_2ndposttap, $dc_gain, $rx_eq];
        }
    }

    tabulate("AOE FPGA Versions", undef, \@version_headers, \@versions,
             orient_horiz);

    tabulate("AOE FPGA Build Info", undef, \@build_headers, \@build_params,
             orient_horiz);

    tabulate("AOE FPGA state", undef, \@info_headers, \@infos,
             orient_horiz);

    foreach my $fpga (keys %ports) {
        tabulate("AOE Port Info ($fpga)", undef, \@port_headers, \@{$ports{$fpga}},
                 orient_horiz);
    }

    foreach my $fpga (keys %dimms) {
        tabulate("AOE DDR Info ($fpga)", undef, \@dimm_headers, \@{$dimms{$fpga}},
                 orient_horiz);
    }

    foreach my $fpga (keys %maps) {
        tabulate("AOE Memory Map ($fpga)", undef, \@map_headers, \@{$maps{$fpga}},
                 orient_horiz);
    }
}

sub apply_interest_rules {
    my $result = {};
    my ($type_name, $value) = @_;
    if (defined($type_name) && exists($interest_rules{$type_name})) {
	for my $rule (@{$interest_rules{$type_name}}) {
	    my ($condition, $int_type) = @$rule;
	    my @tokens = split / /, $condition;
	    my $left_value = $value->{$tokens[0]};
	    my $right_value =
		$tokens[2] =~ /^-?\d/ ? $tokens[2] : $value->{$tokens[2]};
	    next unless defined($left_value) && defined($right_value);
	    if (eval($left_value . ${tokens[1]} . $right_value)) {
 		push @interesting_stuff, ["$condition ($left_value)", $int_type];
		$result->{$tokens[0]} = [$int_type, $#interesting_stuff];
	    }
	}
    }
    return $result;
} # apply_interest_rules

# Return -1 if $version1 less than $version2
# Return 1 if $version1 greater than $version2
# Return 0 if $version1 and $version2 are equal
sub compare_versions {
    my ($version1, $version2) = @_;

    my @parts1 = split /\./, $version1;
    my @parts2 = split /\./, $version2;

    for my $i (0 .. $#parts1) {
        return -1 if ($parts1[$i] < $parts2[$i]);
        return 1 if ($parts1[$i] > $parts2[$i]);
    }
    return 0;
}
sub check_x3_debug_info {

    my @x3_debug_dirs = find_x3_debug_dir();

    my $x3_dir = $x3_debug_dirs[0];
    if (defined $x3_dir and -d $x3_dir) {
	    my $efct_version = get_xilinx_efct_version();
	    my $target_efct_version = "1.5.4.0";
	    my $check_version_info = compare_versions($efct_version, $target_efct_version);
	    if ($check_version_info < 0) {
		    print_x3_debug_info_compat;
	    } else {
		    print_x3_debug_info;
	    }
    }
}


# Establish output stream.
my $minimal = '';
my $version = '';
GetOptions("m" => \$minimal,
           "version|v" => \$version);

if ($version) {
    STDERR->print("AMD Solarflare system report (version $VERSION)\n");
    exit 0;
}

if ($minimal) {
    $out_format = format_minimal;
}

my $out_path;
if ($#ARGV >= 0) {
    $out_path = $ARGV[0];
} else {
    $out_path = 'sfreport-'.$hostname.POSIX::strftime('-%Y-%m-%d-%H-%M-%S.html',
				localtime);
}

if ($out_path ne '-') {
    STDERR->print("AMD Solarflare system report (version $VERSION)\n");
}

if ($out_format != format_minimal) {
    if ($out_path eq '-') {
        $out_file = *STDOUT{IO};
        $out_format = format_text;
    } else {
        $out_file = new FileHandle($out_path, 'w') or die "open: $!";
        if ($out_path =~ /\.html?$/) {
            $out_format = format_html;
        } else {
            $out_format = format_text;
        }
    }
} else {
    if ($out_path eq '-') {
        $out_file = *STDOUT{IO};
    } else {
        $out_path = 'sfreport-'.$hostname.POSIX::strftime('-%Y-%m-%d-%H-%M-%S.txt',
                                    localtime);
        $out_file = new FileHandle($out_path, 'w') or die "open: $!";
    }        
}

if ($< != 0) {
    STDERR->print
	("WARNING: This script will not provide a full report\n"
	 ."unless you run it as root.\n");
    $USER = "NON-ROOT USER"; 
}

if (my $uptime_file = new FileHandle("uptime 2>&1 |")) {
    $UPTIME = '';
    while (<$uptime_file>) {
         $UPTIME .= $_;
    }
}

if ($out_format == format_html) {
    $out_file->print("\
<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"\
 \"http://www.w3.org/TR/html4/strict.dtd\">
<html>
  <head>
    <title>AMD Solarflare system report</title>
    <meta name=\"generator\" value=\"sfreport.pl\">
    <style type=\"text/css\">
      table { border-collapse: collapse; }
      th, td { text-align: left; border: 1px solid black; }
      table.vert th { text-align: right; }
      .error { background-color: #ff5555 }
      .warn { background-color: #ccaa55 }
      .perf { background-color: #cc8080 }
      .badpkt { background-color: #cc55aa }
      td > pre { margin: 0; }
    </style>
    <script>
    function toggle(id) {
      var obj = document.getElementById(id+'_c');
      var lnk = document.getElementById(id+'_l');
      if ( obj ) {
        if ( obj.style.display == 'block' ) {
          obj.style.display = 'none';
          lnk.innerHTML = ' ...Show';
        } else {
          obj.style.display = 'block';
          lnk.innerHTML = ' Hide...';
        }
      }
    }
    </script>
    </head>
  <body>
    <h1>AMD Solarflare system report (version $VERSION)</h1>
    $DATE ($USER)
    
    <hr>
    
    <ul>
      <li><a href='#controller'>Driver / Firmware</a>
      <li><a href='#dmesg'>Kernel messages</a>
      <li><a href='#ethtool'>Interface stats</a>
      <li><a href='#irq'>Interrupts</a>
      <li><a href='#mod_params'>Module Parameters</a>
      <li><a href='#netstat'>Netstat</a>
      <li><a href='#sfboot'>Sfboot</a>
      <li><a href='#sfcdebug'>SFC Debug Info</a>
      <li><a href='#x3debug'>X3 Debug Info</a>
      <li><a href='#vitalpd'>Vital Product Data</a>
    </ul>
    <hr>
    <h2> System Uptime </h2> $UPTIME
");
} elsif ($out_format == format_text) {
    $out_file->print("AMD Solarflare system report (version $VERSION)\n\n");
}

my $devices = get_pci_devices();
my $sfc_drvinfo = get_sfc_drvinfo();

if ($out_format != format_minimal) {
    my $smbios = new SmbiosInfo;
    print_system_summary($smbios);
    print_physical_memory($smbios) if $smbios->expected;
    print_device_status($devices, $sfc_drvinfo);
    print_net_status($sfc_drvinfo);
    print_sfc_debug_info;
    check_x3_debug_info;
    print_sfc_vpd($devices, $sfc_drvinfo);
    print_mtd;
    print_aoe_status;

    print_interesting;
    print_nic_type($devices, $sfc_drvinfo);
} else {
    print_short_device_status($devices, $sfc_drvinfo);
}

if ($out_format == format_html) {
    $out_file->print("  </body>\n"
		     ."</html>\n");
}

# Let the user know what output path we picked if none was specified.
STDERR->print("Finished writing report to $out_path\n");
