#!/usr/bin/perl
use strict;
use warnings;

# ==============================
# Config
# ==============================
my $threshold = 3;  # soglia brute-force

# ==============================
# Argomento file
# ==============================
my $logfile = $ARGV[0] or die "Usage: perl log_audit.pl <logfile>\n";

open(my $fh, '<', $logfile) or die "Cannot open $logfile: $!\n";

my %failed;
my %accepted;
my $total_lines = 0;

while (my $line = <$fh>) {
    chomp $line;
    $total_lines++;

    # Failed password
    if ($line =~ /Failed password.*from (\d+\.\d+\.\d+\.\d+)/) {
        my $ip = $1;
        $failed{$ip}++;
    }

    # Accepted login
    if ($line =~ /Accepted .* from (\d+\.\d+\.\d+\.\d+)/) {
        my $ip = $1;
        $accepted{$ip}++;
    }
}

close($fh);

# ==============================
# Output
# ==============================

print "\n===== Log Audit Report =====\n";
print "File analyzed: $logfile\n";
print "Total lines: $total_lines\n\n";

print "---- Failed Login Attempts ----\n";
foreach my $ip (sort { $failed{$b} <=> $failed{$a} } keys %failed) {
    printf "%-15s -> %d failed attempts\n", $ip, $failed{$ip};
}

print "\n---- Successful Logins ----\n";
foreach my $ip (sort { $accepted{$b} <=> $accepted{$a} } keys %accepted) {
    printf "%-15s -> %d successful logins\n", $ip, $accepted{$ip};
}

print "\n---- Suspicious IPs (>$threshold attempts) ----\n";
foreach my $ip (keys %failed) {
    if ($failed{$ip} > $threshold) {
        printf "[!] %-15s -> %d failed attempts\n", $ip, $failed{$ip};
    }
}

print "\nAnalysis complete.\n";