Here are the source files for the Elemental Mod.

This repository is mostly for source-diving and archival purposes, so there's
no Makefile or anything.  But if you so wish, you can probably re-compile
the mod yourself.  The only source file for the DLL is elemental.c
(elemental.rc is optional).  I used clang for compilation, but the code
is theoretically MSVC-compatible.  I think.

The subfolders contain the files from the respective *.lod archives.
If you intend to re-create them, be aware that MM7 does not seem to recognize
archives newly created by MMArchive (at least not by the version I used).
Instead, you can copy an existing archive, then delete all files from it.
That usually works.

The games folder contains tools for patching dungeon files
instead of the files themselves.  See the readme there.
