-- This file ensures compatibility between the Elemental Mod and MMExtension.
-- It's not necessary if the latter is not installed.

-- The mod changes the NPC greetings array to fit new greetings.
-- MMExtension is somewhat procative with it; without telling it
-- the new address, the greetings won't be displayed at all.
rawset(Game.NPCGreet, "?ptr", mem.u4[0x476e3a] - 8)

-- Another relocated structure is the generated artifacts array.
-- Not a big deal, but still better to inform MMExtension about it.
rawset(Party.ArtifactsFound, "?ptr", mem.u4[0x4568f7])

-- The audible sprite IDs are relocated as well (vanilla array was too short).
rawset(Map.SoundSprites, "?ptr", mem.u4[0x4ab49d])

-- The mod overwrites some exe data that is exposed by MMExtension tables.
-- Since pre-existing tables would take higher precedence than elemental.dll,
-- and deleting them during install is impossible as the mod is distributed
-- via an archive, we instead place a checklist of files in Data that will be
-- read and deleted by the below code.  Sure, we could also distribute
-- actual tables with mod-appropriate data, but that would mean duplicating
-- the data, which is generally bad.
local name = "Data/elemental.delete.txt"
local list = io.open(name)
if list then
    for line in list:lines() do
        os.remove(line)
    end
    list:close()
    os.remove(name)
end
DataTables.LazyMode = true -- prevent the tables from being re-created in v2.3

-- Disable MMExt v2.3 map array extender (we handle it ourselves).
rawset(Game.MapStats, "count", 78)
-- Same for the hireling text array.
if Game.NPCProfNames then rawset(Game.NPCProfNames, "limit", 63) end
