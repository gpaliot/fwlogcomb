#!/usr/bin/perl

use strict;
use warnings;
use Net::CIDR ':all';
use Storable;
use Net::Whois::IP qw(whoisip_query);
use Getopt::Long;

use Data::Dumper;

my %net;
my $ip;
my $cidr;
my $cidr_is_new;
my $whois;
my $whois_timeout = 15;

#%net = %{retrieve 'my.db'};
foreach $cidr (keys (%net)) {
    undef $net{$cidr}{'sum'};
    undef $net{$cidr}{'addresses'};
}


while ($ip = <>) {
    chomp $ip;
    if (cidrvalidate($ip)) {
        $cidr_is_new = 1;
        foreach $cidr (keys (%net)) {
            if (cidrlookup($ip, $cidr)) {
                $net{$cidr}{'addresses'}{$ip}++;
                $net{$cidr}{'sum'}++;
                $cidr_is_new = 0;
            }
        }
        if ($cidr_is_new) {
            $whois = whoisip_query($ip) || die "WHOIS error";
            sleep $whois_timeout;
            foreach $cidr (range2cidr($whois->{'inetnum'})) {
                foreach (keys(%{$whois}) ) { $net{$cidr}{'whois'}{$_} = $whois->{$_} };
                    $net{$cidr}{'addresses'}{$ip}++;
                    $net{$cidr}{'sum'}++;
                    $net{$cidr}{'state'} = 'unknown';
            }
        }

    }
}

print Dumper(\%net);
store \%net, 'my.db';
