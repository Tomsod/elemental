#!/usr/bin/env perl

my @indoors = glob("*.blv");

for my $file (@indoors) {
    my $handle;
    open($handle, "<:raw:bytes", $file);
    seek($handle, 104, 0);
    my $buffer;
    read($handle, $buffer, 36);
    my ($facets1, $rooms1, $rooms2, $vertices) = unpack("L3x20L", $buffer);
    seek($handle, $vertices * 6, 1);
    read($handle, $buffer, 4);
    my $facets = unpack("L", $buffer);
    seek($handle, $facets * 106 + $facets1, 1);
    read($handle, $buffer, 4);
    my $facet_data = unpack("L", $buffer);
    seek($handle, $facet_data * 46, 1);
    read($handle, $buffer, 4);
    my $rooms = unpack("L", $buffer);
    seek($handle, $rooms * 116 + $rooms1 + $rooms2 + 4, 1);
    read($handle, $buffer, 4);
    my $sprites = unpack("L", $buffer);
    close($handle);
    $file =~ s/blv$/dlv/;
    print($file, " ", 915 + $facets * 4 + $sprites * 2, "\n");
}

my @outdoors = glob("*.odm");

for my $file (@outdoors) {
    my $handle;
    open($handle, "<:raw:bytes", $file);
    seek($handle, 49328, 0);
    my $buffer;
    read($handle, $buffer, 4);
    my $ternorms = unpack("L", $buffer);
    seek($handle, 196608 + $ternorms * 12, 1);
    read($handle, $buffer, 4);
    my $models = unpack("L", $buffer);
    my $model_data = 0;
    my $total_facets = 0;
    for (1 .. $models) {
        read($handle, $buffer, 188);
        my ($vertices, $facets, $bspnodes) = unpack("x68Lx4Lx12Lx92", $buffer);
        $model_data += $vertices * 12 + $facets * 320 + $bspnodes * 8;
        $total_facets += $facets;
    }
    seek($handle, $model_data, 1);
    read($handle, $buffer, 4);
    my $sprites = unpack("L", $buffer);
    close($handle);
    $file =~ s/odm$/ddm/;
    print($file, " ", 1976 + $total_facets * 4 + $sprites * 2, "\n");
}
