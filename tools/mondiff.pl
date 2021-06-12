#!/usr/bin/env perl

my $mondata;
open($mondata, "<:raw:bytes", $ARGV[0]);
for my $line (<STDIN>) {
    my ($file, $offset) = split(" ", $line);
    my $handle;
    open($handle, "<:raw:bytes", $file);
    seek($handle, $offset, 0);
    my $buffer;
    read($handle, $buffer, 4);
    my $count = unpack("L", $buffer);
    print("file ", $file, " offset ", $offset + 4, "\n");
    for (my $idx = 1; $idx <= $count; $idx++) {
        seek($handle, 52, 1);
        my $mod;
        read($handle, $mod, 80);
        seek($handle, 704, 1);
        my $id = unpack("S", substr($mod, 44, 2));
        print("monster ", $idx, " id ", $id, "\n");
        seek($mondata, $id * 88 + 8, 0);
        my $orig;
        read($mondata, $orig, 80);
        $orig = reverse($orig);
        $mod = reverse($mod);
        for (my $pos = 8; $pos < 88; $pos++) {
            my $o = ord(chop($orig));
            my $m = ord(chop($mod));
            if ($o != $m) {
                printf("%02X : %02X %02X\n", $pos, $o, $m);
            }
        }
    }
    close($handle);
}
close($mondata);
