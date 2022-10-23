This is the repository of source files for the Elemental Mod for the Might and
Magic VII game.  The mod basically tries to correct the flaws of the original
game by adding or changing features where it's lacking.  There are basically
no new monsters or dungeons, as I'm not good at this, although I did add a
bunch of new artifacts and other items.  But most of the changes concern game
mechanics, i.e. the game code, as tweaking it is what I enjoy the most.

You can discuss the mod in this Celestial Heavens topic:
https://www.celestialheavens.com/forum/10/17167

This repository is mostly for source-diving and archival purposes, so there's
no Makefile or anything.  But if you so wish, you can probably re-compile
the mod yourself.  The only source file for the DLL is elemental.c
(elemental.rc is optional).  I used clang for compilation, but the code
is theoretically MSVC-compatible.  I think.

The subfolders contain the files from the respective *.lod archives.
If you intend to re-create them, be aware that MM7 does not seem to recognize
archives newly created by MMArchive (at least not by the version I used).
Instead, you can copy an existing archive, then delete all files from it.
That usually works.  It's also possible to choose the archive type when
creating a new archive, although some types appear not to be listed.

The tools folder contains tools I used for patching dungeon files
in games.lod.  See the readme there.  The misc folder has the text files
included in the release for MMExtension compatibility.
