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

# Options
my $state_file;
my $whois_timeout = 15;

sub load_state {
    my %state;
    my $filename = shift;
    my $cdr;
    if (-e $filename) {
        %state = %{retrieve $filename};
        foreach $cdr (keys (%state)) {
            undef $state{$cdr}{'sum'};
            undef $state{$cdr}{'addresses'};
        }
    }
    return (%state);
}

sub save_state {
    my $state = shift;
    my $filename = shift;
    store $state, $filename;
}

GetOptions (
    'state|s:s' => \$state_file,
    'whois-timeout|t:i' => \$whois_timeout
);

%net = load_state($state_file) if ($state_file);

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

save_state(\%net, $state_file) if ($state_file);

print Dumper(\%net);

