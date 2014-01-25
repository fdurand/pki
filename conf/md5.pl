#!/usr/bin/perl
use strict;

use Digest::MD5 qw(md5_hex);
my $digest = md5_hex($ARGV[2]);

print $digest;
