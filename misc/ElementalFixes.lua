-- This file ensures compatibility between the Elemental Mod and MMExtension.
-- It's not necessary if the latter is not installed.

-- The mod changes the NPC greetings array to fit new greetings.
-- MMExtension is somewhat procative with it; without telling it
-- the new address, the greetings won't be displayed at all.
rawset(Game.NPCGreet, "?ptr", mem.u4[0x476e3a] - 8)

-- Another relocated structure is the generated artifacts array.
-- Not a big deal, but still better to inform MMExtension about it.
rawset(Party.ArtifactsFound, "?ptr", mem.u4[0x4568f7])

-- The mod overwrites some exe data that is exposed by MMExtension tables.
-- Since pre-existing tables would take higher precedence than elemental.dll,
-- and outright deleting them is impossible as the mod is distributed
-- via an archive, this simple hack allows overwriting them with dummies
-- that will be deleted by the below code.  Sure, we could also distribute
-- actual tables with mod-appropriate data, but that would mean duplicating
-- the data, which is generally bad.
for table in path.find("Data/Tables/*.txt") do
    file = io.open(table)
    if file then
        line = file:read()
        file:close()
        if line == "deleteme" then
            path.DeleteFile(table)
        end
    end
end

