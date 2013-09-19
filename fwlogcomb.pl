#!/usr/bin/perl

use strict;
use warnings;
use Net::CIDR ':all';
use Storable;
use Net::Whois::IP qw(whoisip_query);
use Getopt::Long;

# Globals
my %net;
my $ip;
my $cidr;
my $cidr_is_new;
my $whois;
my @range;

# Options
my $state_file;
my $whois_timeout = 15;


sub load_state {
    my %state;
    my $filename = shift;
    my $cdr;
    # Load the state if the file exists
    if (-e $filename) {
        %state = %{retrieve $filename};
        # Remove all counters and sums
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

sub output_net_by_count {
# Output all non-whitelisted nets sorted by connection count (descending)
    my $nets = shift;
    my $netname;
    my $orgname;
    my $sum;
    foreach (sort { $nets->{$b}{'sum'} <=> $nets->{$a}{'sum'} } keys %{$nets}) {
        $netname = '';
        $orgname = 'Unknown';
        $sum = 0;
        $sum = $nets->{$_}{'sum'} if (defined $nets->{$_}{'sum'});
	    $netname = $nets->{$_}{'whois'}{'netname'} if (defined $nets->{$_}{'whois'}{'netname'});
	    $netname = $nets->{$_}{'whois'}{'NetName'} if (defined $nets->{$_}{'whois'}{'NetName'});
	    $orgname = $nets->{$_}{'whois'}{'orgname'} if (defined $nets->{$_}{'whois'}{'orgname'});
	    $orgname = $nets->{$_}{'whois'}{'OrgName'} if (defined $nets->{$_}{'whois'}{'OrgName'});
        print "$nets->{$_}{'sum'} - $orgname / $netname ($_)\n" if (not $nets->{$_}{'state'} eq 'whitelist');
    }
};

# Read command line options
GetOptions (
    'state|s:s' => \$state_file,
    'whois-timeout|t:i' => \$whois_timeout
);

# Load the state (whois cache) if the statefile option was set
%net = load_state($state_file) if ($state_file);

# Read IPs from STDIN
while ($ip = <>) {
    # Remove newline
    chomp $ip;

    # Check if the IP is valid IPv4 or IPv6
    if (cidrvalidate($ip)) {
        # Assume a new net
        $cidr_is_new = 1;

        # Check if the IP matches one of the known nets
        foreach $cidr (keys (%net)) {
            # On match, add the IP occurence and mark the net as known
            if (cidrlookup($ip, $cidr)) {
                $net{$cidr}{'addresses'}{$ip}++;
                $net{$cidr}{'sum'}++;
                $cidr_is_new = 0;
            }
        }

        # For new nets
        if ($cidr_is_new) {
            # Lookup whois info online, could be replaced by offline DB
            $whois = whoisip_query($ip) || die "WHOIS error";
            save_state(\%net, $state_file) if ($state_file);
            sleep $whois_timeout;

            # Calculate the CIDR from the whois inetnum/NetRange and add whois info
            if (defined $whois->{'inetnum'}) { @range = range2cidr($whois->{'inetnum'}) };
            if (defined $whois->{'NetRange'}) { @range = range2cidr($whois->{'NetRange'}) };

            print "$ip - $range[0]\n";

            foreach $cidr (@range) {
                foreach (keys(%{$whois}) ) { $net{$cidr}{'whois'}{$_} = $whois->{$_} };
                    # Add the IP occurence
                    $net{$cidr}{'addresses'}{$ip}++;
                    $net{$cidr}{'sum'}++;

                    # Set the new CIDR state to unknown
                    $net{$cidr}{'state'} = 'unknown';
            }
        }
    }
}

# Save state if the statefile option was set
save_state(\%net, $state_file) if ($state_file);

output_net_by_count(\%net);

