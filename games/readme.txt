Instead of modified *.dlv and *.ddm files, here are the tools I used
to patch them.

The only thing I changed is pre-placed monsters.  They are not affected
by monsters.txt changes, having their own embedded properties instead,
so those have to be edited manually.  These perl scripts automate the process.

The first, offsets.pl, scans all *.blv and *.odm files in the current directory
and outputs the offsets to monster data in the corresponding *.dlv and *.ddm.

The mondiff.pl script takes those offsets as input, reads monster structs
in the listed files (which should also be in the current directory)
and compares them with the binary data file provided as the first argument,
outputting the differing bytes.

The binary data represents the parsed monster.txt file and can be obtained
by dumping 23320 bytes at the address 0x5cccc0 from the memory of a running
MM7.exe (make sure it has finished loading).  For the purposes of mondiff.pl,
make sure monsters.txt is unmodified.

The third script, monpatch.pl, takes the output of mondiff.pl as the input,
and combines it with (another) binary file, patching the listed
*.dlv and *.ddm files.  Specifically, the relevant struct in the binary file
is copied, and then any bytes mentioned in the diff are overwritten in it.

So, if you made a change in monsters.txt and want to update
the pre-placed monsters, run:

perl offsets.pl | perl mondiff.pl original.bin | perl monpatch.pl modded.bin

where original.bin is obtained from an unmodded MM7 game, and modded.bin is
dumped from a process that had parsed your modded monsters.txt file.
The pre-placed monsters will be updated with your new monster properties,
but any quirks they had in the original game (such as changed resistances)
will remain the same.

Anyway, if you just want to re-create the modified *.dlv and *.ddm files
shipped with this mod, run:

perl monpatch.pl monsters.bin < diff.txt

after extracting the *.dlv and *.ddm files from games.lod.  Note that
the diff.txt file has been edited manually, so the piped command above
wouldn't work properly in this case.
