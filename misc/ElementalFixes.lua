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
-- Same for v2.3 hireling professions array (I added several new ones).
if Game.NPCProfTxt then rawset(Game.NPCProfTxt, "?ptr", mem.u4[0x420cab]) end
-- Also v2.3 spcitems.txt struct, which is relocated by me.
if Game.SpcItemsTxt then rawset(Game.SpcItemsTxt, "?ptr", mem.u4[0x456616] + structs.SpcItemsTxtItem["?size"]) end

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

-- Disable MMExt map array extender (we handle it ourselves).
if mem.ExtendGameStructure then -- v2.3
    rawset(Game.MapStats, "count", 78)
else -- v2.2, tricky
    local old_ComputeRowCountInPChar = DataTables.ComputeRowCountInPChar
    function DataTables.ComputeRowCountInPChar(p, MinCols, NeedCol)
        local genie = string.find(mem.string(p), "genie.blv")
        local restore
        if genie then
            restore = mem.u1[p+genie]
            mem.u1[p+genie] = 0 -- disable the last line
        end
        local result = old_ComputeRowCountInPChar(p, MinCols, NeedCol)
        if restore then
            mem.u1[p+genie] = restore
        end
        return result
    end
end
-- Same for the hireling text array.
if Game.NPCProfNames then rawset(Game.NPCProfNames, "limit", 63) end
-- Also the award text/category array (which is relocated by us).
rawset(Party.PlayersArray[0].Awards, "count", 500) -- there are 512 pc bits
rawset(Game.AwardsTxt, "?ptr", mem.u4[0x41910b]) -- must provide new address
-- And the autonote text/category array (also relocated).
if mem.ExtendGameStructure then -- v2.3
    rawset(Game.AutonoteTxt, "limit", 256)
    -- reverse what we can't knock out
    mem.IgnoreProtection(true)
    mem.i4[0x412648] = mem.i4[0x412648] + 196 - 256
    mem.i4[0x413827] = mem.i4[0x413827] + 196 - 256
    mem.i4[0x47689D] = mem.i4[0x47689D] + (196 - 256) * 8
    mem.IgnoreProtection(false)
end

-- Fix travel table generation (it breaks now that mapstats start from 0).
function events.ScriptsLoaded()
    local old_UpdateDataTables = UpdateDataTables
    function UpdateDataTables()
        rawset(Game.MapStats, "?ptr", Game.MapStats["?ptr"] - Game.MapStats[0]["?size"])
        old_UpdateDataTables()
        rawset(Game.MapStats, "?ptr", Game.MapStats["?ptr"] + Game.MapStats[0]["?size"])
    end
end
if DataTables.LazyMode == nil then -- v2.2, can't turn tables off
    local name = "Data/Tables/Transport Locations.txt" -- assume all tables are created at once
    if not os.rename(name, name) then -- only need to shift when they're not created yet
        function events.GameInitialized2()
            rawset(Game.MapStats, "?ptr", Game.MapStats["?ptr"] - Game.MapStats[0]["?size"])
        end
        function events.ScriptsLoaded() -- after the data table hook is added
            function events.GameInitialized2()
                rawset(Game.MapStats, "?ptr", Game.MapStats["?ptr"] + Game.MapStats[0]["?size"])
            end
        end
    end
else
    DataTables.LazyMode = true -- prevent the tables from being re-created in v2.3
end
