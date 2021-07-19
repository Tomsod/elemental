-- This file ensures compatibility between the Elemental Mod and MMExtension.
-- It's not necessary if the latter is not installed.

-- elemental.dll changes the address of EVT lines buffer, and MMExtension
-- needs to be notified in order for the evt.* commands to work.
offsets.CurrentEvtLines = mem.u4[0x446904]

-- We also change the NPC greetings array to fit new greetings.
-- MMExtension is a bit more procative with it; without telling it
-- the new address, the greetings won't be displayed at all.
rawset(Game.NPCGreet, "?ptr", mem.u4[0x476e3a] - 8)
