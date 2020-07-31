#!/usr/bin/env perl

my $mondata;
open($mondata, "<:raw:bytes", $ARGV[0]);
my ($handle, $offset, $buffer);
my $edited = 0;
for my $line (<STDIN>) {
    my ($a, $b, $c, $d) = split(" ", $line);
    if ($a eq "file") {
        if ($edited) {
            print($handle $buffer);
            $edited = 0;
        }
        if ($handle) {
            close($handle);
        }
        open($handle, "+<:raw:bytes", $b);
        $offset = $d;
    } elsif ($a eq "monster") {
        if ($edited) {
            print($handle $buffer);
        }
        seek($handle, $offset + $b * 836 - 784, 0);
        seek($mondata, $d * 88 + 8, 0);
        read($mondata, $buffer, 80);
        $edited = 1;
    } else {
        substr($buffer, hex($a) - 8, 1, chr(hex($d)));
    }
}
if ($handle) {
    if ($edited) {
        print($handle $buffer);
    }
    close($handle);
}
close($mondata);
