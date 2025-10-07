#include <windows.h>
#include <winuser.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#ifdef CHECK_OVERWRITE
#include <stdio.h>
#endif

#define byte(address) (*(uint8_t *) (address))
#define word(address) (*(uint16_t *) (address))
#define dword(address) (*(uint32_t *) (address))
#define pointer(address) (*(void **) (address))

#ifdef CHECK_OVERWRITE
static FILE *owlog, *binary;
static uint8_t owbuffer[100];

static void check_overwrite(uintptr_t address, size_t size)
{
    if (address < 0x400000 || address >= 0x4f6000)
        return;
    fseek(binary, address - 0x400000, SEEK_SET);
    fread(owbuffer, 1, size, binary);
    for (int i = 0; i < size; i++)
        if (owbuffer[i] != byte(address + i))
            fprintf(owlog, "Overwriting patched byte %.2x (was %.2x) "
                           "at address %.6x!\n",
                    byte(address + i), owbuffer[i], address + i);
}
#else
static inline void check_overwrite(uintptr_t address, size_t size)
{
}
#endif

static void patch_byte(uintptr_t address, uint8_t value)
{
    check_overwrite(address, 1);
    DWORD OldProtect;
    VirtualProtect((LPVOID) address, 1, PAGE_EXECUTE_READWRITE, &OldProtect);
    byte(address) = value;
    VirtualProtect((LPVOID) address, 1, OldProtect, &OldProtect);
}

static void patch_word(uintptr_t address, uint16_t value)
{
    check_overwrite(address, 2);
    DWORD OldProtect;
    VirtualProtect((LPVOID) address, 2, PAGE_EXECUTE_READWRITE, &OldProtect);
    word(address) = value;
    VirtualProtect((LPVOID) address, 2, OldProtect, &OldProtect);
}

static void patch_dword(uintptr_t address, uint32_t value)
{
    check_overwrite(address, 4);
    DWORD OldProtect;
    VirtualProtect((LPVOID) address, 4, PAGE_EXECUTE_READWRITE, &OldProtect);
    dword(address) = value;
    VirtualProtect((LPVOID) address, 4, OldProtect, &OldProtect);
}

static inline void patch_pointer(uintptr_t address, const void *value)
{
    patch_dword(address, (uint32_t) value);
}

static void patch_bytes(uintptr_t address, const void *src, size_t size)
{
    check_overwrite(address, size);
    DWORD OldProtect;
    VirtualProtect((LPVOID) address, size, PAGE_EXECUTE_READWRITE,
                   &OldProtect);
    memcpy((void *) address, src, size);
    VirtualProtect((LPVOID) address, size, OldProtect, &OldProtect);
}

typedef void *funcptr_t;

static void hook_jump(uintptr_t address, funcptr_t func)
{
    check_overwrite(address, 5);
    DWORD OldProtect;
    VirtualProtect((LPVOID) address, 5, PAGE_EXECUTE_READWRITE, &OldProtect);
    byte(address) = 0xe9;
    pointer(address + 1) = (char *) func - address - 5;
    VirtualProtect((LPVOID) address, 5, OldProtect, &OldProtect);
}

static void hook_call(uintptr_t address, funcptr_t func, int length)
{
    check_overwrite(address, length);
    DWORD OldProtect;
    VirtualProtect((LPVOID) address, length, PAGE_EXECUTE_READWRITE,
                   &OldProtect);
    byte(address) = 0xe8;
    pointer(address + 1) = (char *) func - address - 5;
    if (length > 5)
        memset((void *) (address + 5), 0x90, length - 5);
    VirtualProtect((LPVOID) address, length, OldProtect, &OldProtect);
}

static void erase_code(uintptr_t address, int length)
{
    check_overwrite(address, length);
    DWORD OldProtect;
    VirtualProtect((LPVOID) address, length, PAGE_EXECUTE_READWRITE,
                   &OldProtect);
    memset((void *) address, 0x90, length);
    if (length > 10)
      {
        byte(address) = 0xeb;
        byte(address + 1) = length - 2;
      }
    VirtualProtect((LPVOID) address, length, OldProtect, &OldProtect);
}

//---------------------------------------------------------------------------//

enum elements
{
    FIRE = 0,
    SHOCK = 1,
    COLD = 2,
    POISON = 3,
    PHYSICAL = 4,
    NO_ELEMENT = 5,
    HOLY = 6,
    MIND = 7,
    MAGIC = 8,
    PHYS_SPELL = 9, // like physical, but medusae resist a lot
    DRAGONFIRE = 10, // fire AND physical
    ENERGY = 12, // conforming to mmpatch
};

#define IMMUNE 200

#define GLOBAL_TXT_ADDR 0x5e4000
#define GLOBAL_TXT ((char **) GLOBAL_TXT_ADDR)

enum spcitems_txt
{
    SPC_CARNAGE = 3,
    SPC_ICE = 6,
    SPC_LIGHTNING = 8,
    SPC_FIRE = 10,
    SPC_FLAME = 11,
    SPC_INFERNOS = 12,
    SPC_VENOM = 14,
    SPC_VAMPIRIC = 16,
    SPC_IMMUNITY = 18,
    SPC_SANITY = 19,
    SPC_FREEDOM = 20,
    SPC_ANTIDOTES = 21,
    SPC_ALARMS = 22,
    SPC_MEDUSA = 23,
    SPC_SHIELDING = 36,
    SPC_DEMON_SLAYING = 39,
    SPC_DRAGON_SLAYING = 40,
    SPC_DARKNESS = 41,
    SPC_DRAGON = 46,
    SPC_SWIFT = 59,
    SPC_ELF_SLAYING = 63,
    SPC_UNDEAD_SLAYING = 64,
    SPC_DAVID = 65,
    SPC_ASSASSINS = 67,
    SPC_BARBARIANS = 68,
    SPC_STORM = 69,
    // 73+ are my addition
    SPC_SPECTRAL = 73,
    SPC_CURSED = 74,
    SPC_WRAITH = 75,
    SPC_SOUL_STEALING = 76,
    SPC_BACKSTABBING = 77,
    SPC_LIGHTWEIGHT = 78,
    SPC_LEAPING = 79,
    SPC_PERMANENCE = 80,
    SPC_FIRE_AFFINITY = 81,
    SPC_EARTH_AFFINITY = 84,
    SPC_BODY_AFFINITY = 87,
    SPC_TAUNTING = 88,
    SPC_JESTER = 89,
    SPC_INFERNOS_2 = 90,
    SPC_ELEMENTAL_SLAYING = 91,
    SPC_BLESSED = 92,
    SPC_TERRIFYING = 93,
    SPC_MASTERFUL = 94,
    SPC_KICKING = 95,
    SPC_ABSORPTION = 96,
    SPC_KEEN = 97,
    SPC_VORPAL = 98,
    SPC_COUNT = 98
};

enum player_stats
{
    STAT_MIGHT = 0,
    STAT_INTELLECT = 1,
    STAT_PERSONALITY = 2,
    STAT_ENDURANCE = 3,
    STAT_ACCURACY = 4,
    STAT_SPEED = 5,
    STAT_LUCK = 6,
    STAT_HP = 7,
    STAT_SP = 8,
    STAT_AC = 9,
    STAT_FIRE_RES = 10,
    STAT_SHOCK_RES = 11,
    STAT_COLD_RES = 12,
    STAT_POISON_RES = 13,
    STAT_MIND_RES = 14,
    STAT_MAGIC_RES = 15,
    STAT_ALCHEMY = 16,
    STAT_THIEVERY = 17,
    STAT_DISARM = 18,
    STAT_ARMSMASTER = 21,
    STAT_DODGING = 22,
    STAT_UNARMED = 23,
    STAT_MELEE_ATTACK = 25,
    STAT_MELEE_DAMAGE_BASE = 26,
    STAT_RANGED_ATTACK = 29,
    STAT_HOLY_RES = 33,
    STAT_FIRE_MAGIC = 34,
    STAT_LIGHT_MAGIC = 41,
    STAT_DARK_MAGIC = 42,
    STAT_BOW = 44,
};

enum class
{
    CLASS_KNIGHT = 0,
    CLASS_CHAMPION = 2,
    CLASS_BLACK_KNIGHT = 3,
    CLASS_THIEF = 4,
    CLASS_ASSASSIN = 7,
    CLASS_MONK = 8,
    CLASS_INITIATE = 9,
    CLASS_MASTER = 10,
    CLASS_PALADIN = 12,
    CLASS_MASTER_ARCHER = 18,
    CLASS_SNIPER = 19,
    CLASS_RANGER = 20,
    CLASS_HUNTER = 21,
    CLASS_BOUNTY_HUNTER = 23,
    CLASS_DRUID = 28,
    CLASS_WARLOCK = 31,
    CLASS_LICH = 35,
    CLASS_COUNT = 36,
};

enum new_strings
{
    STR_HOLY,
    STR_TEMPORARY,
    STR_ALCH_SKILL,
    STR_ALCH_REAGENTS,
    STR_ALCH_RECIPE,
    STR_ALCH_BOTTLES,
    STR_BLESS_WATER,
    STR_ALWAYS,
    STR_CANNOT_RECHARGE,
    STR_RECHARGE,
    STR_RATING,
    STR_BASE_VALUE,
    STR_HALVE_ARMOR,
    STR_DAMAGE_MANY,
    STR_KILL_MANY,
    STR_HUNTER,
    STR_VERSION,
    STR_BLACK_POTION,
    STR_AVERAGE_DAMAGE,
    STR_ACCOUNT_RACE,
    STR_HUMANS,
    STR_ELVES,
    STR_GOBLINS,
    STR_DWARVES,
    STR_ID_BEFORE_READ,
    STR_ABSORB_SPELL,
    STR_GM_FOR_ITEM,
    STR_PRACTICE_0,
    STR_PRACTICE_1,
    STR_PRACTICE_2,
    STR_PRACTICE_3,
    STR_OPEN_RIGHT_BAG,
    STR_KNIVES,
    STR_CANNOT_KNIVES,
    STR_REPAIR_KNIVES,
    STR_CANNOT_RECALL,
    STR_BOTCHED,
    STR_TAXES,
    STR_CAN_LEARN,
    STR_CANNOT_LEARN,
    STR_ALREADY_LEARNED,
    STR_BUY_HORSE,
    STR_HITS,
    STR_CRITICALLY_HITS,
    STR_BACKSTABS,
    STR_SHOOTS,
    STR_CRITICALLY_SHOOTS,
    STR_CRIT_HIT_CHANCE,
    STR_CRIT_MISS_CHANCE,
    STR_AVERAGE_DPR,
    STR_SPELL_POWER,
    STR_ID_ITEM,
    STR_ID_MONSTER,
    STR_CONFIRM_DISMISS,
    STR_PARRY,
    STR_DEPOSIT_BOX,
    STR_BUY_DEPOSIT_BOX,
    STR_BUY_SCROLLS,
    STR_RESTORE_SP,
    STR_PLACE_ORDER,
    STR_PROMPT1,
    STR_PROMPT2,
    STR_CONFIRM_ORDER,
    STR_NOT_ENOUGH_REAGENTS,
    STR_ORDER_READY,
    STR_ORDER_NOT_READY,
    STR_EI_NO_ORDER,
    STR_CONFIRM_ORDER_HINT,
    STR_GENIE_ARTIFACT,
    STR_GENIE_STAT,
    STR_GENIE_CURSE,
    STR_GENIE_TITHE,
    STR_GENIE_NOTHING,
    STR_GENIE_HOSTILE,
    STR_GENIE_NEUTRAL,
    STR_GENIE_ALLY,
    STR_GENIE_ITEM_INIT,
    STR_GENIE_ITEM_ASK,
    STR_GENIE_ITEM_OK,
    STR_GENIE_ITEM_DEFAULT,
    STR_SUN_INITIATE,
    STR_MONK,
    STR_MOON_ACOLYTE,
    STR_MOON_INITIATE,
    STR_MOON_PRELATE,
    STR_NINJA,
    STR_MERCHANT,
    STR_FIRE_IMM,
    STR_SHOCK_IMM,
    STR_COLD_IMM,
    STR_POISON_IMM,
    STR_MIND_IMM,
    STR_MAGIC_IMM,
    STR_AURA_OF_CONFLICT,
    STR_DIVINE_MASTERY,
    STR_ANCHORED_MANA,
    STR_CURSE,
    STR_WEAKNESS,
    STR_SLEEP,
    STR_INEBRIATION,
    STR_INSANITY,
    STR_DISEASE,
    STR_PARALYSIS,
    STR_STUN,
    STR_DEATH,
    STR_PETRIFACTION,
    STR_ERADICATION,
    STR_BREAK_ITEM,
    STR_BREAK_ARMOR,
    STR_BREAK_WEAPON,
    STR_STEAL_ITEM,
    STR_AGING,
    STR_DRAIN_MAGIC,
    STR_FEAR,
    STR_NO_HEALING_POTIONS,
    STR_NO_INITIATE_TOKEN,
    STR_MANA_ANCHOR_TRIGGERED,
    STR_QUICK_REPAIR,
    STR_ARENA_CHAMPION,
    STR_HOURGLASS_USED,
    STR_MAP_REFILL,
    STR_MAP_REFILL_SOON_1,
    STR_MAP_REFILL_SOON_2,
    STR_MAP_REFILL_SOON_3,
    STR_MAP_REFILL_SOON_4,
    STR_ARENA_HOURGLASS,
    STR_INVISIBILITY_EASY,
    STR_INVISIBILITY_MEDIUM,
    STR_INVISIBILITY_HARD,
    STR_BUY_WEAPONS,
    STR_BUY_ARMOR,
    STR_BUY_MAGIC,
    STR_NO_REFILL,
    STR_REFILLED_MAP,
    STR_TELEPATHY_ITEM,
    STR_TELEPATHY_GOLD,
    STR_TELEPATHY_NOTHING,
    STR_NOT_WOUNDED,
    NEW_STRING_COUNT
};

#define SKIP(bytes) char JOIN(unknown_, __COUNTER__)[bytes]
#define JOIN(a, b) JOIN2(a, b)
#define JOIN2(a, b) a ## b

struct __attribute__((packed)) item
{
    uint32_t id;
    uint32_t bonus;
    uint32_t bonus_strength;
    uint32_t bonus2;
    uint32_t charges;
    uint32_t flags;
    uint8_t body_slot;
    uint8_t max_charges;
    uint8_t owner;
    SKIP(1);
    uint64_t temp_ench_time;
};
typedef struct item s_item;

#define IFLAGS_ID 1
#define IFLAGS_BROKEN 2
#define IFLAGS_STOLEN 0x100

struct __attribute__((packed)) spell_buff
{
    uint64_t expire_time;
    uint16_t power;
    uint16_t skill;
    uint16_t overlay_id;
    uint8_t caster;
    uint8_t bits;
};
typedef struct spell_buff s_spell_buff;

enum skill
{
    SKILL_MASK = 63,
    SKILL_EXPERT = 64,
    SKILL_MASTER = 128,
    SKILL_GM = 256,
};

enum skills
{
    SKILL_STAFF = 0,
    SKILL_SWORD = 1,
    SKILL_DAGGER = 2,
    SKILL_AXE = 3,
    SKILL_SPEAR = 4,
    SKILL_BOW = 5,
    SKILL_MACE = 6,
    SKILL_BLASTER = 7,
    SKILL_SHIELD = 8,
    SKILL_LEATHER = 9,
    SKILL_CHAIN = 10,
    SKILL_PLATE = 11,
    SKILL_FIRE = 12,
    SKILL_AIR = 13,
    SKILL_WATER = 14,
    SKILL_EARTH = 15,
    SKILL_SPIRIT = 16,
    SKILL_MIND = 17,
    SKILL_BODY = 18,
    SKILL_LIGHT = 19,
    SKILL_DARK = 20,
    SKILL_IDENTIFY_ITEM = 21,
    SKILL_MERCHANT = 22,
    SKILL_REPAIR = 23,
    SKILL_BODYBUILDING = 24,
    SKILL_MEDITATION = 25,
    SKILL_PERCEPTION = 26,
    SKILL_DISARM_TRAPS = 29,
    SKILL_DODGING = 30,
    SKILL_UNARMED = 31,
    SKILL_IDENTIFY_MONSTER = 32,
    SKILL_ARMSMASTER = 33,
    SKILL_THIEVERY = 34,
    SKILL_ALCHEMY = 35,
    SKILL_LEARNING = 36,
    SKILL_NONE = 37, // used by clubs
    SKILL_COUNT = 37,
    SKILL_MISC = 38, // used widely in items.txt
};

#define PLAYER_MAX_ITEMS 138

struct __attribute__((packed)) player
{
    uint64_t conditions[20];
    SKIP(8);
    char name[16];
    uint8_t gender;
    uint8_t class;
    uint8_t face;
    SKIP(1);
    union {
        struct {
            uint16_t might_base;
            uint16_t might_bonus;
            uint16_t intellect_base;
            uint16_t intellect_bonus;
            uint16_t personality_base;
            uint16_t personality_bonus;
            uint16_t endurance_base;
            uint16_t endurance_bonus;
            uint16_t speed_base;
            uint16_t speed_bonus;
            uint16_t accuracy_base;
            uint16_t accuracy_bonus;
            uint16_t luck_base;
            uint16_t luck_bonus;
        };
        uint16_t stats[7][2];
    };
    uint16_t ac_bonus;
    uint16_t level_base;
    uint16_t level_bonus;
    uint16_t age_bonus;
    SKIP(40);
    uint16_t skills[SKILL_COUNT];
    uint32_t awards[16];
    uint8_t spells_known[100];
    SKIP(2);
    uint32_t black_potions[7];
    struct item items[PLAYER_MAX_ITEMS];
    uint32_t inventory[14*9];
    union {
        struct {
            uint16_t fire_res_base;
            uint16_t shock_res_base;
            uint16_t cold_res_base;
            uint16_t poison_res_base;
            SKIP(6);
            uint16_t mind_res_base;
            uint16_t magic_res_base;
        };
        uint16_t res_base[9];
    };
    SKIP(4);
    int16_t fire_res_bonus;
    int16_t shock_res_bonus;
    int16_t cold_res_bonus;
    int16_t poison_res_bonus;
    SKIP(6);
    int16_t mind_res_bonus;
    int16_t magic_res_bonus;
    SKIP(4);
    struct spell_buff spell_buffs[24];
    uint32_t voice;
    uint32_t old_voice;
    uint32_t old_face;
    SKIP(8);
    uint16_t recovery;
    SKIP(2);
    uint32_t skill_points;
    int32_t hp;
    int32_t sp;
    int32_t birth_year;
    uint32_t equipment[16];
    SKIP(198);
    uint8_t spellbook_page;
    uint8_t quick_spell;
    uint8_t bits[512/8];
    SKIP(8);
    int8_t hp_bonus;
    SKIP(1);
    int8_t sp_bonus;
    SKIP(160);
    uint8_t beacon_casts; // my addition
};
typedef struct player s_player;

enum player_buffs
{
    PBUFF_SHOCK_RES = 0,
    PBUFF_BLESS = 1,
    PBUFF_POISON_RES = 2,
    PBUFF_MAGIC_RES = 3,
    PBUFF_FIRE_RES = 5,
    PBUFF_HAMMERHANDS = 6,
    PBUFF_HEROISM = 8,
    PBUFF_MIND_RES = 9,
    PBUFF_PAIN_REFLECTION = 10,
    PBUFF_PRESERVATION = 11,
    PBUFF_REGENERATION = 12,
    PBUFF_SHIELD = 13,
    PBUFF_COLD_RES = 22,
};

// The array is in elemdata below.  The order is important.
enum new_player_buffs
{
    NBUFF_FIRE_IMM,
    NBUFF_SHOCK_IMM,
    NBUFF_COLD_IMM,
    NBUFF_POISON_IMM,
    NBUFF_MIND_IMM,
    NBUFF_MAGIC_IMM,
    NBUFF_AURA_OF_CONFLICT,
    NBUFF_DIVINE_MASTERY,
    NBUFF_ANCHORED_MANA,
    NBUFF_COUNT
};

enum skill_mastery
{
    NORMAL = 1,
    EXPERT = 2,
    MASTER = 3,
    GM = 4,
};

#define MOUSE_ITEM 0xad458c

#define CURRENT_TIME_ADDR 0xacce64
#define CURRENT_TIME (*(uint64_t *) CURRENT_TIME_ADDR)
#define MINUTE (60 * 128 / 30)
#define ONE_HOUR (60 * MINUTE)
#define ONE_DAY (24 * ONE_HOUR)
#define ANIM_TIMER 0x50ba5c

enum items
{
    SHARKTOOTH_DAGGER = 17,
    BLASTER = 64,
    BLASTER_RIFLE = 65,
    FIRST_SHIELD = 79,
    LAST_SHIELD = 88, // not counting relics etc.
    HORNED_HELM = 89,
    LEATHER_CLOAK = 105,
    LAST_OLD_PREFIX = 134, // before robes and knives were added
    FIRST_WAND = 135,
    LAST_WAND = 159,
    FIRST_ROBE = 160,
    PILGRIMS_ROBE = 160,
    MARTIAL_ROBE = 161,
    WIZARDS_ROBE = 162,
    THROWING_KNIVES = 163,
    LIVING_WOOD_KNIVES = 164,
    BOOMERANG_KNIFE = 165,
    BRASS_KNUCKLES = 166,
    LAST_PREFIX = 168, // last enchantable item
    CLANKERS_JOURNAL = 184,
    LARGE_GOLD_PILE = 199,
    FIRST_REAGENT = 200,
    SULFUR = 212,
    LAST_REAGENT = 214, // not counting gray
    FIRST_GRAY_REAGENT = 215,
    PHILOSOPHERS_STONE = 219,
    LAST_GRAY_REAGENT = 219,
    POTION_BOTTLE = 220,
    CATALYST = 221,
    FIRST_POTION = 222,
    POTION_CURE_WOUNDS = 222,
    FIRST_COMPLEX_POTION = 225,
    MAGIC_POTION = 227,
    FIRST_LAYERED_POTION = 228,
    FIRST_WHITE_POTION = 240,
    FLAMING_POTION = 246,
    FREEZING_POTION = 247,
    NOXIOUS_POTION = 248,
    SHOCKING_POTION = 249,
    SWIFT_POTION = 250,
    POTION_DIVINE_CURE = 253,
    POTION_DIVINE_MAGIC = 254,
    FIRST_BLACK_POTION = 262,
    SLAYING_POTION = 263,
    PURE_LUCK = 264,
    REJUVENATION = 271,
    LAST_OLD_POTION = 271,
    POTION_FIRE_IMMUNITY = 272,
    POTION_MAGIC_IMMUNITY = 277,
    POTION_PAIN_REFLECTION = 278,
    POTION_DIVINE_MASTERY = 279,
    POTION_ULTIMATE_CURE = 280,
    LAST_POTION = 280,
    HOLY_WATER = 281, // not a potion
    FIRST_SCROLL = 300,
    SCROLL_FATE = 399,
    FIRST_BOOK = 400,
    FIRST_LOST_ITEM = 487, // divine intervention book
    SCROLL_TELEPATHY = 499,
    FIRST_ARTIFACT = 500,
    PUCK = 500,
    IRON_FEATHER = 501,
    CORSAIR = 503,
    GOVERNORS_ARMOR = 504,
    SPLITTER = 506,
    GHOULSBANE = 507,
    GIBBET = 508,
    CHARELE = 509,
    ETHRICS_STAFF = 515,
    OLD_NICK = 517,
    AMUCK = 518,
    KELEBRIM = 520,
    TALEDONS_HELM = 521,
    PHYNAXIAN_CROWN = 523,
    TITANS_BELT = 524,
    TWILIGHT = 525,
    ANIA_SELVING = 526,
    JUSTICE = 527,
    MEKORIGS_HAMMER = 528,
    LAST_OLD_ARTIFACT = 528,
    HERMES_SANDALS = 529,
    ELFBANE = 531,
    MINDS_EYE = 532,
    ELVEN_CHAINMAIL = 533,
    FORGE_GAUNTLETS = 534,
    HEROS_BELT = 535,
    LADYS_ESCORT = 536,
    CLANKERS_AMULET = 537,
    THE_PERFECT_BOW = 543,
    SHADOWS_MASK = 544,
    SACRIFICIAL_DAGGER = 553,
    RED_DRAGON_SCALE_MAIL = 554,
    RED_DRAGON_SCALE_SHIELD = 555,
    FIRST_NEW_ARTIFACT = 557,
    DRAGONS_WRATH = 557,
    HEADACHE = 558,
    STORM_TRIDENT = 559,
    ELLINGERS_ROBE = 560,
    VIPER = 561,
    FENCERS_FRIEND = 562,
    SWORD_OF_LIGHT = 563,
    OGHMA_INFINIUM = 564,
    GRIM_REAPER = 565,
    WITCHBANE = 566,
    BAG_OF_HOLDING = 567,
    CLOVER = 568,
    FLATTENER = 569,
    ELOQUENCE_TALISMAN = 570,
    GADGETEERS_BELT = 571,
    GARDENERS_GLOVES = 572,
    LAST_ARTIFACT = 572,
    SNIPERS_QUIVER = 594,
    ROBE_OF_THE_ARCHMAGISTER = 598,
    RED_APPLE = 630,
    FIRST_ORE = 686,
    LAST_LOST_ITEM = 733, // scroll of waves alt 3
    FIRST_RECIPE = 740,
    LAST_RECIPE = 780,
    MAGIC_EMBER = 785,
    INITIATE_TOKEN = 787,
    GOLDEN_APPLE = 788,
    WINE_BOTTLE = 789,
    MAGIC_WINE = 790,
    HOURGLASS_OF_IMPATIENCE = 791,
};

enum item_slot
{
    SLOT_OFFHAND = 0,
    SLOT_MAIN_HAND = 1,
    SLOT_MISSILE = 2,
    SLOT_BODY_ARMOR = 3,
    SLOT_HELM = 4,
    SLOT_BELT = 5,
    SLOT_CLOAK = 6,
    SLOT_GAUNTLETS = 7,
    SLOT_BOOTS = 8,
    SLOT_AMULET = 9,
    SLOT_COUNT = 16,
    SLOT_ANY = 16, // used by has_item_in_slot()
};

#define TEMP_ENCH_MARKER 0xff

// Maximum number of alternative recipe chains for a potion that is itself
// present in some recipe (i.e. white or simpler).  Currently that's
// Divine Restoration with 3 recipes.
#define MAX_WHITE_BREWS 3
// Maximum number of alternative recipe chains for any potion (including
// black).  Currently that's Rejuvenation, which can be brewn in 3*3 ways
// (3 ways to brew the first potion and 3 alternatives for the second one).
#define MAX_BLACK_BREWS 9

struct __attribute__((packed)) items_txt_item
{
    char *bitmap;
    char *name;
    char *generic_name;
    SKIP(4);
    uint32_t value;
    SKIP(8);
    uint8_t equip_stat;
    uint8_t skill;
    uint8_t mod1_dice_count;
    uint8_t mod1_dice_sides;
    uint8_t mod2;
    uint8_t type;
    SKIP(6);
    uint8_t chance[6];
    int8_t id_difficulty;
    SKIP(1);
};
typedef struct items_txt_item s_items_txt_item;

#define ITEMS_TXT_ADDR 0x5d2864
#define ITEMS_TXT ((struct items_txt_item *) ITEMS_TXT_ADDR)

enum face_animations
{
    ANIM_DODGE = 6,
    ANIM_ID_FAIL = 9,
    ANIM_REPAIR = 10,
    ANIM_REPAIR_FAIL = 11,
    ANIM_QUICK_SPELL = 12,
    ANIM_WONT_FIT = 15,
    ANIM_MIX_POTION = 16,
    ANIM_LEARN = 21,
    ANIM_SMILE = 36,
    ANIM_DISMAY = 40,
    ANIM_SHAKE_HEAD = 67,
    ANIM_AWARD = 96,
};

#define SOUND_BUZZ 27
#define SOUND_WOOD_METAL 105
#define SOUND_GOLD 200
#define SOUND_FIZZLE 203
#define SOUND_TURN_PAGE_UP 204
#define SOUND_SPELL_FAIL 209
#define SOUND_DRINK 210
#define SOUND_HARM 16031
#define SOUND_DIE 18100
#define SOUND_QUEST 20001

#define EVT_AWARDS 12
#define EVT_QBITS 16
#define EVT_ITEMS 17
#define EVT_AUTONOTES 223
// my additions
#define EVT_REP_GROUP 400
#define EVT_DISABLED_SPELL 401
#define EVT_MOUSE_ITEM_CONDITION 402
#define EVT_VARIABLE 403
#define EVT_LOST_ITEM 404

#define MAP_EVT_DATA 0x5b33a0
#define MAP_EVT_LINES 0x5b6458
#define MAP_EVT_LINE_COUNT 0x5b0f90
#define PROC_EVENT_LABEL_ID 0x597d98
#define GLOBAL_EVENT_FLAG 0x5c32a0

enum gender
{
    GENDER_MASCULINE = 0,
    GENDER_FEMININE,
    GENDER_NEUTER,
    GENDER_PLURAL,
};

#define EVENTS_LOD ((void *) 0x6be8d8)
#define SAVEGAME_LOD ((void *) 0x6a06a0)
#define GAMES_LOD ((void *) 0x6a08e0)

#define MAP_VARS ((uint8_t *) 0x5e4b10)
#define MAP_COUNT 77

#define CURRENT_SCREEN 0x4e28d8

struct __attribute__((packed)) file_header
{
    char name[20]; // could be shorter, I'm guessing here
    uint32_t size;
    SKIP(4);
};

#define CHEST_MAX_ITEMS 140
struct __attribute__((packed)) map_chest
{
    uint16_t picture;
    uint16_t bits;
    struct item items[CHEST_MAX_ITEMS];
    int16_t slots[CHEST_MAX_ITEMS];
};
typedef struct map_chest s_map_chest;

#define MAP_CHESTS_ADDR 0x5e4fd0
#define MAP_CHESTS ((struct map_chest *) MAP_CHESTS_ADDR)
#define EXTRA_CHEST_COUNT 8
#define BOH_CHEST_ID 7 // must be last, for looping through all items

// For the temple in a bottle and beacon master hirelings.
struct beacon
{
    int x, y, z, direction, look_angle, map_index;
};

// All the stuff I need to preserve across save/loads (except WoM barrels).
static struct elemdata
{
    // Mod version in case I'll need to ensure backward compatibility again.
    int version;
    // Stored reputation for the game's different regions.  [0] is always zero.
    int reputation[12];
    // Expanded "artifacts found" bool array to fit the new additions.
    char artifacts_found[LAST_ARTIFACT-FIRST_ARTIFACT+1];
    // Skill training for all 4 PCs.  Not all values are used.
    int training[4][SKILL_COUNT];
    // Location where the temple in a bottle was last used.
    struct beacon bottle;
    // For the bag of holding and porter-like NPCs.
    struct map_chest extra_chests[EXTRA_CHEST_COUNT];
    // Difficulty level!  Yes, it's stored in the savegame.
    int difficulty;
    // Last region visited for Master Town Portal purposes.
    int last_region;
    // For Harmondale taxes.
    int last_tax_month, last_tax_fame;
    // Preserve the active PC on reload.
    int current_player;
    // Items for the newly added scroll shelves at the magic guilds.
    struct item guild_scrolls[32][12];
    // Items that were ordered at shops.
    struct item current_orders[42];
    // And the time of their competion.
    uint64_t order_timers[42];
    // Random seed for genie lamps.
    uint32_t genie;
    // For the Armageddon nerf (healing monsters after 24 hours).
    int current_map;
    // Same.
    uint64_t map_enter_time;
    // Stores new player buffs (mostly potion effects).
    struct spell_buff new_pc_buffs[4][NBUFF_COUNT];
    // The amount of bank money that had persisted for a full week.
    int last_bank_gold;
    // Additional quick spells, bound to the mod's new hotkeys.
    int quick_spells[4][4];
    // Total amount of arena wins multiplied by difficulty (determines prizes).
    int arena_points;
    // For Beacon Master NPCs.
    struct beacon beacon_masters[2];
    // Per-map random seeds for street NPCs and their expire time.
    int street_npc_seed[MAP_COUNT], street_npc_time[MAP_COUNT];
    // Counters for Bard NPC bonus reputation ([0] is unused).
    int bard_xp[12], bard_bonus[12];
    // Per-map random seeds for corpse loot (does not apply on Easy).
    int monster_loot_seed[MAP_COUNT];
    // For fountain_timers(), to reset them only after rest.
    uint64_t last_rest_time;
    // To track area refill when the maps are unloaded.
    int next_refill_day[MAP_COUNT];
    // A better tracking system for misplaced quest items.
    char lost_items[LAST_LOST_ITEM-FIRST_LOST_ITEM+1];
#define LOST_NOTRACK 0
#define LOST_INV -1
#define LOST_GONE -2
#define MAX_STOLEN_ITEMS 16
    // Party items stolen by enemy thieves etc.
    struct item stolen_items[MAX_STOLEN_ITEMS];
    // Prevent the player from stealing too many items at once.
    int shop_wariness[53];
} elemdata;

// Number of barrels in the Wall of Mist.
#define WOM_BARREL_CNT 15

enum qbits
{
    QBIT_EVENMORN_MAP = 64,
    QBIT_LIGHT_PATH = 99,
    QBIT_DARK_PATH = 100,
    QBIT_KILL_TOLBERTI = 109,
    QBIT_KILL_ROBERT = 127,
    QBIT_LEFT_EMERALD_ISLAND = 136,
    QBIT_FIRST_OBELISK = 164,
    QBIT_LAST_OBELISK = 177,
    QBIT_DIVINE_INTERVENTION = 239,
    QBIT_DUMMY = 245,
    // my additions
    QBIT_REFILL_WOM_BARRELS = 350,
    QBIT_ELVES_WON = 360,
    QBIT_HARMONDALE_INDEPENDENT = 362,
    QBIT_BOW_GM_QUEST_ACTIVE = 367,
    QBIT_BOW_GM_QUEST = 368,
    QBIT_BLASTER_GM_QUEST_ACTIVE_LIGHT = 369,
    QBIT_BLASTER_GM_QUEST_ACTIVE_DARK = 370,
    QBIT_BLASTER_GM_QUEST = 371,
    QBIT_BODYBUIDING_GM_QUEST_ACTIVE = 372,
    QBIT_BODYBUIDING_GM_QUEST = 373,
    QBIT_MEDITATION_GM_QUEST_ACTIVE = 374,
    QBIT_MEDITATION_GM_QUEST = 375,
    QBIT_ALCHEMY_GM_QUEST_ACTIVE = 376,
    QBIT_ALCHEMY_GM_QUEST = 377,
    QBIT_CAVALIER_HORSE = 383,
    QBIT_USED_PEGASUS = 384,
    QBIT_TEMPLE_UNDERWATER = 386,
    QBIT_PIRATE_SHIP = 410,
    QBIT_DEPOSIT_BOX = 414,
    QBIT_GENIE_ARTIFACT = 415,
    QBIT_ARENA_CHAMPION = 416,
    QBIT_BM_ARTIFACT = 417,
};

// The table of qbits and item ids for the vanilla judge "I lost it" thing.
#define LOST_QBITS 0x4f0700
#define LOST_QBIT_COUNT 27

enum item_types
{
    ITEM_TYPE_WEAPON = 1,
    ITEM_TYPE_WEAPON2 = 2,
    ITEM_TYPE_MISSILE = 3,
    ITEM_TYPE_ARMOR = 4,
    ITEM_TYPE_SHIELD = 5,
    ITEM_TYPE_HELM = 6,
    ITEM_TYPE_BELT = 7,
    ITEM_TYPE_CLOAK = 8,
    ITEM_TYPE_GAUNTLETS = 9,
    ITEM_TYPE_BOOTS = 10,
    ITEM_TYPE_RING = 11,
    ITEM_TYPE_AMULET = 12,
    ITEM_TYPE_WAND = 13,
    ITEM_TYPE_REAGENT = 14,
    ITEM_TYPE_POTION = 15,
    ITEM_TYPE_SCROLL = 16,
    ITEM_TYPE_BOOK = 17,
    ITEM_TYPE_GEM = 20, // sometimes it's "1h weapon" instead
    ITEM_TYPE_MISC = 22,
    ITEM_TYPE_SWORD = 23,
    ITEM_TYPE_DAGGER = 24,
    ITEM_TYPE_AXE = 25,
    ITEM_TYPE_SPEAR = 26,
    ITEM_TYPE_BOW = 27,
    ITEM_TYPE_MACE = 28,
    ITEM_TYPE_STAFF = 30,
    ITEM_TYPE_GEMS = 46, // use instead of GEM in randomize_item()
    // my additions
    ITEM_TYPE_ROBE = 47,
    ITEM_TYPE_SPECIAL = 48,
};

enum objlist
{
    OBJ_ARROW = 545,
    OBJ_FIREARROW = 550,
    OBJ_LASER = 555,
    OBJ_FIRE_SPIKE = 1060,
    OBJ_IMPLOSION = 2080,
    OBJ_ACID_BURST = 3060,
    OBJ_BERSERK = 6060,
    OBJ_FLAMING_POTION = 12000,
    OBJ_FLAMING_EXPLOSION = 12001,
    OBJ_SHOCKING_POTION = 12010,
    OBJ_SHOCKING_EXPLOSION = 12011,
    OBJ_FREEZING_POTION = 12020,
    OBJ_FREEZING_EXPLOSION = 12021,
    OBJ_NOXIOUS_POTION = 12030,
    OBJ_NOXIOUS_EXPLOSION = 12031,
    OBJ_THROWN_HOLY_WATER = 12040,
    OBJ_HOLY_EXPLOSION = 12041,
    OBJ_KNIFE = 12050,
    OBJ_BLASTER_ERADICATION = 12060,
};
#define SPELL_OBJ_IDS 0x4e3ab0

#define ELEMENT_ADDR 0x5cbecc
#define ELEMENT(spell) byte(ELEMENT_ADDR + (spell) * 0x24)

#define PARTY_BUFF_ADDR 0xacd6c4
#define PARTY_BUFFS ((struct spell_buff *) PARTY_BUFF_ADDR)

enum party_buffs
{
    BUFF_FEATHER_FALL = 5,
    BUFF_FLY = 7,
    BUFF_IMMOLATION = 10,
    BUFF_INVISIBILITY = 11,
    BUFF_IMMUTABILITY = 13,
    BUFF_SHIELD = 14,
    BUFF_TORCH_LIGHT = 16,
    BUFF_WATER_WALK = 18,
    BUFF_WIZARD_EYE = 19,
};

struct __attribute((packed)) spell_info
{
    uint16_t bits;
    union
      {
        struct
          {
            uint16_t cost_normal;
            uint16_t cost_expert;
            uint16_t cost_master;
            uint16_t cost_gm;
          };
        uint16_t cost[4];
      };
    uint16_t delay_normal;
    uint16_t delay_expert;
    uint16_t delay_master;
    uint16_t delay_gm;
    uint8_t damage_fixed;
    uint8_t damage_dice;
};
typedef struct spell_info s_spell_info;

#define SPELL_INFO_ADDR 0x4e3c46
#define SPELL_INFO ((struct spell_info *) SPELL_INFO_ADDR)

enum spells
{
    SPL_TORCH_LIGHT = 1,
    SPL_FIRE_BOLT = 2,
    SPL_FIRE_AURA = 4,
    SPL_HASTE = 5,
    SPL_FIREBALL = 6,
    SPL_IMMOLATION = 8,
    SPL_METEOR_SHOWER = 9,
    SPL_INFERNO = 10,
    SPL_INCINERATE = 11,
    SPL_WIZARD_EYE = 12,
    SPL_FEATHER_FALL = 13,
    SPL_SPARKS = 15,
    SPL_JUMP = 16,
    SPL_SHIELD = 17,
    SPL_LIGHTNING_BOLT = 18,
    SPL_INVISIBILITY = 19,
    SPL_IMPLOSION = 20,
    SPL_STARBURST = 22,
    SPL_POISON_SPRAY = 24,
    SPL_RECHARGE_ITEM = 28,
    SPL_ENCHANT_ITEM = 30,
    SPL_ICE_BLAST = 32,
    SPL_LLOYDS_BEACON = 33,
    SPL_STUN = 34,
    SPL_SLOW = 35,
    SPL_DEADLY_SWARM = 37,
    SPL_STONE_SKIN = 38,
    SPL_ROCK_BLAST = 41,
    SPL_TELEKINESIS = 42,
    SPL_DEATH_BLOSSOM = 43,
    SPL_MASS_DISTORTION = 44,
    SPL_BLESS = 46,
    SPL_SPECTRAL_WEAPON = 47,
    SPL_TURN_UNDEAD = 48,
    SPL_PRESERVATION = 50,
    SPL_HEROISM = 51,
    SPL_SPIRIT_LASH = 52,
    SPL_RAISE_DEAD = 53,
    SPL_RESURRECTION = 55,
    SPL_REMOVE_FEAR = 56,
    SPL_MIND_BLAST = 57,
    SPL_AURA_OF_CONFLICT = 59,
    SPL_CHARM = 60,
    SPL_BERSERK = 62,
    SPL_MASS_FEAR = 63,
    SPL_CURE_INSANITY = 64,
    SPL_PSYCHIC_SHOCK = 65,
    SPL_ENSLAVE = 66,
    SPL_CURE_WEAKNESS = 67,
    SPL_REGENERATION = 71,
    SPL_HAMMERHANDS = 73,
    SPL_ELIXIR_OF_LIFE = 74,
    SPL_FLYING_FIST = 76,
    SPL_POWER_CURE = 77,
    SPL_LIGHT_BOLT = 78,
    SPL_DESTROY_UNDEAD = 79,
    SPL_DISPEL_MAGIC = 80,
    SPL_PARALYZE = 81,
    SPL_PRISMATIC_LIGHT = 84,
    SPL_DAY_OF_PROTECTION = 85,
    SPL_HOUR_OF_POWER = 86,
    SPL_SUNRAY = 87,
    SPL_DIVINE_INTERVENTION = 88,
    SPL_VAMPIRIC_WEAPON = 91,
    SPL_SHRINKING_RAY = 92,
    SPL_SHRAPMETAL = 93,
    SPL_CONTROL_UNDEAD = 94,
    SPL_PAIN_REFLECTION = 95,
    SPL_ARMAGEDDON = 98,
    LAST_REAL_SPELL = 99,
    SPL_ARROW = 100, // pseudo-spell for bows
    SPL_KNIFE = 101, // for throwing knives (my addition)
    SPL_BLASTER = 102, // ditto for blasters
    SPL_FATE = 103, // was 47
    // new pseudo-spells
    SPL_FLAMING_POTION = 104,
    SPL_SHOCKING_POTION = 105,
    SPL_FREEZING_POTION = 106,
    SPL_NOXIOUS_POTION = 107,
    SPL_HOLY_WATER = 108,
    SPL_TELEPATHY = 109, // was 59
    SPL_QUICK_HEAL = 110,
};
#define SPAN_EVT_SET 150
#define SPAN_DEBUFF 153

#define SPELL_SOUNDS 0x4edf30

struct __attribute__((packed)) map_monster
{
    SKIP(36);
    uint32_t bits;
    uint16_t hp;
    SKIP(2);
    char *name;
    SKIP(4);
    uint8_t level;
    uint8_t item_chance;
    SKIP(2);
    uint8_t item_level;
    uint8_t item_type;
    uint8_t flight;
    SKIP(1);
    uint8_t ai_type;
    SKIP(2);
    uint8_t attack_special;
    uint8_t attack_special_chance;
    SKIP(1);
    uint8_t attack1_damage_dice_count;
    uint8_t attack1_damage_dice_sides;
    uint8_t attack1_damage_add;
    SKIP(1);
    uint8_t attack2_chance;
    uint8_t attack2_element;
    SKIP(5);
    uint8_t spell1;
    SKIP(1);
    uint8_t spell2;
    uint8_t fire_resistance;
    SKIP(2);
    uint8_t poison_resistance;
    uint8_t mind_resistance;
    uint8_t holy_resistance;
    uint8_t magic_resistance;
    uint8_t phys_spell_resistance;
    SKIP(1);
    uint8_t physical_resistance;
    SKIP(6);
    uint16_t id;
    SKIP(2);
    uint16_t spell1_skill;
    uint16_t spell2_skill;
    SKIP(2);
    uint8_t alter_spell1; // was padding
    uint8_t alter_spell2; // ditto
    uint32_t max_hp;
    SKIP(4);
    uint32_t experience;
    SKIP(4);
    uint32_t recovery;
    uint16_t preference; // was 32 bit, but top 16 unused
    uint8_t alter_flag1; // so I repurposed them
    uint8_t alter_flag2; // and this one
    SKIP(4);
    uint16_t radius;
    uint16_t height;
    uint16_t velocity;
    int16_t x;
    int16_t y;
    int16_t z;
    SKIP(4);
    int16_t speed_z;
    int16_t direction;
    int16_t look_angle;
    uint16_t room;
    uint16_t action_length;
    SKIP(14);
    uint16_t ai_state;
#define AI_DYING 4
#define AI_DEAD 5
#define AI_PURSUE 6
#define AI_REMOVED 11
#define AI_INVISIBLE 19
    uint16_t gfx_state;
    uint16_t item;
    uint8_t id_level; // was padding
    uint8_t mod_flags; // same
#define MMF_ERADICATED 1
#define MMF_REANIMATE 2
#define MMF_ZOMBIE 4
#define MMF_EXTRA_REAGENT 8
#define MMF_REAGENT_MORE_LIKELY 16
#define MMF_JUMPING 32
    uint32_t action_time;
    SKIP(24);
    struct spell_buff spell_buffs[22];
    struct item items[4];
    uint32_t group;
    uint32_t ally;
    SKIP(104);
    uint32_t name_id;
    SKIP(12);
};
typedef struct map_monster s_map_monster;
#define MONSTERS_TXT 0x5cccc0
// I *think* this is the line-of-sight bit,
// although it's inconsistent on peaceful monsters.
#define MBIT_LOS 0x200000

#define MAP_MONSTERS_ADDR 0x5fefd8
#define MAP_MONSTERS ((struct map_monster *) MAP_MONSTERS_ADDR)
#define MONSTER_COUNT 0x6650a8

#define MON_TARGETS ((uint32_t *) 0x4f6c88)

enum target
{
    TGT_MONSTER = 3,
    TGT_PARTY = 4,
};

#define PARTY_ADDR 0xacd804
#define PARTY ((struct player *) PARTY_ADDR)

enum condition
{
    COND_CURSED = 0,
    COND_WEAK = 1,
    COND_AFRAID = 3,
    COND_DRUNK = 4,
    COND_INSANE = 5,
    COND_POISONED_GREEN = 6,
    COND_DISEASED_GREEN = 7,
    COND_POISONED_RED = 10,
    COND_DISEASED_RED = 11,
    COND_PARALYZED = 12,
    COND_UNCONSCIOUS = 13,
    COND_DEAD = 14,
    COND_STONED = 15,
    COND_ERADICATED = 16,
    COND_ZOMBIE = 17,
    COND_INCINERATED = 18, // my addition
};

struct __attribute__((packed)) spell_queue_item
{
    uint16_t spell;
    uint16_t caster;
    uint16_t target_pc;
    SKIP(2);
    uint16_t flags;
    uint16_t skill;
    uint32_t target_object;
    SKIP(4);
};
typedef struct spell_queue_item s_spell_queue_item;

#define STATE_BITS 0xad45b0

#define SPELL_QUEUE ((struct spell_queue_item *) 0x50bf48)

struct __attribute__((packed)) mapstats_item
{
    char *name;
    char *file_name;
    SKIP(4);
    char *monster2;
    char *monster3;
    SKIP(8);
    int refill_days;
    SKIP(12);
    uint8_t reputation_group; // my addition
    SKIP(23);
};
typedef struct mapstats_item s_mapstats_item;

#define MAPSTATS_ADDR 0x5caa38
#define MAPSTATS ((struct mapstats_item *) MAPSTATS_ADDR)

#define CUR_MAP_FILENAME_ADDR 0x6be1c4
#define CUR_MAP_FILENAME ((char *) CUR_MAP_FILENAME_ADDR)
// TODO: instead of comparing map names we could fetch indices on game start
#define MAP_ARENA_ADDR 0x4e44b0 // d05.blv
#define MAP_BREEDING_ZONE_ADDR 0x4e99e4 // d10.blv
#define MAP_WALLS_OF_MIST_ADDR 0x4e99ec // d11.blv
#define MAP_WALLS_OF_MIST ((const char *) MAP_WALLS_OF_MIST_ADDR)
#define MAP_MOUNT_NIGHON "out10.odm"
#define MAP_SHOALS ((const char *) 0x4e4648) // out15.odm
static const char map_altar_of_wishes[] = "genie.blv";
#define UNDERWATER 0x6be244
#define CURRENT_MAP_ID 0x6bdfbc
static int castle_id, bottle_id, genie_id;

#define OUTDOOR_LAST_VISIT_TIME 0x6a1160
#define INDOOR_LAST_VISIT_TIME 0x6be534
#define OUTDOOR_LAST_REFILL_DAY 0x6a113c
#define INDOOR_LAST_REFILL_DAY 0x6be510
// Indoor or outdoor reputation for the loaded map.
#define OUTDOORS 0x6be1e0
#define CURRENT_REP (*(int32_t *) (dword(OUTDOORS) == 2 ? 0x6a1140 : 0x6be514))

enum profession
{
    NPC_SMITH = 1,
    NPC_ARMORER = 2,
    NPC_ALCHEMIST = 3,
    NPC_SCHOLAR = 4,
    NPC_GUIDE = 5,
    NPC_TRACKER = 6,
    NPC_PATHFINDER = 7,
    NPC_SAILOR = 8,
    NPC_NAVIGATOR = 9,
    NPC_MERCHANT = 21,
    NPC_PORTER = 29,
    NPC_QUARTER_MASTER = 30,
    NPC_COOK = 33,
    NPC_CHEF = 34,
    NPC_HORSEMAN = 35,
    NPC_BARD = 36,
    NPC_WIND_MASTER = 39,
    NPC_EXPLORER = 44,
    NPC_PIRATE = 45,
    NPC_GYPSY = 48,
    NPC_BEACON_MASTER = 49,
    NPC_DUPER = 50,
    NPC_BURGLAR = 51,
    NPC_FALLEN_WIZARD = 52,
    NPC_MONK = 56,
    LAST_OLD_NPC = 58,
    NPC_MOON_ACOLYTE,
    NPC_MOON_INITIATE,
    NPC_MOON_PRELATE,
    NPC_NINJA,
    NPC_COUNT
};

// New max number of global.evt commands (was 4400 before).
#define GLOBAL_EVT_LINES 6000
// New max size of global.evt itself (was 46080 bytes before).
#define GLOBAL_EVT_SIZE 60000

#define CURRENT_PLAYER 0x507a6c

enum race
{
    RACE_HUMAN = 0,
    RACE_ELF = 1,
    RACE_GOBLIN = 2,
    RACE_DWARF = 3,
};

// I could've used a malloc, but this is simpler.
#define MAX_STATRATE_COUNT 50
struct statrate
{
    int value;
    int bonus;
    char *rating;
};

// Data from parsing spcitems.txt.
struct __attribute__((packed)) spcitem
{
    char *name;
    char *description;
    uint8_t probability[12]; // for item types 1-12
    uint32_t value;
    uint8_t level; // A-D == 0-3
    uint8_t robe_prob; // my addition
    uint8_t crown_prob; // ditto
    uint8_t caestus_prob; // and this
};
typedef struct spcitem s_spcitem;

enum monster_buffs
{
    MBUFF_CURSED = 0, // my addition
    MBUFF_CHARM = 1,
    MBUFF_FEAR = 4,
    MBUFF_PARALYSIS = 6,
    MBUFF_SLOW = 7,
    MBUFF_HALVED_ARMOR = 8,
    MBUFF_BERSERK = 9,
    MBUFF_MASS_DISTORTION = 10, // also used for eradication in the mod
    MBUFF_FATE = 11,
    MBUFF_ENSLAVE = 12,
    MBUFF_DAY_OF_PROTECTION = 13,
};

#define NPC_COMMAND 0x590f0c
// Flag controlling which hireling reply is displayed.
#define HIRELING_REPLY 0xf8b06c

// new NPC greeting count (starting from 1)
#define GREET_COUNT 235
// new NPC topic count
#define TOPIC_COUNT 641
// count of added NPC text entries
#define NEW_TEXT_COUNT (922-789)
// new award count
#define AWARD_COUNT 114

// exposed by MMExtension in "Class Starting Stats.txt"
#define RACE_STATS_ADDR 0x4ed658
#define RACE_STATS ((uint8_t (*)[7][4]) RACE_STATS_ADDR)

#define CLASS_HP_FACTORS ((uint8_t *) 0x4ed610)
#define CLASS_STARTING_HP ((uint8_t *) 0x4ed5f8)
#define CLASS_SP_FACTORS ((uint8_t *) 0x4ed634)
#define CLASS_STARTING_SP ((uint8_t *) 0x4ed604)
// this is actually a switchtable, and the first 5 entries are garbage
#define CLASS_SP_STATS ((const uint8_t *) 0x48e62a)

// exposed as "Class Starting Skills.txt"
#define STARTING_SKILLS_ADDR 0x4ed6c8
#define STARTING_SKILLS ((uint8_t (*)[SKILL_COUNT]) STARTING_SKILLS_ADDR)
// exposed as "Class Skills.txt"
#define CLASS_SKILLS_ADDR 0x4ed818
#define CLASS_SKILLS ((uint8_t (*)[SKILL_COUNT]) CLASS_SKILLS_ADDR)

// Projectiles, items on the ground, etc.
struct __attribute__((packed)) map_object
{
    uint16_t type;
    uint16_t index;
    uint32_t x;
    uint32_t y;
    uint32_t z;
    int16_t speed_x;
    int16_t speed_y;
    int16_t speed_z;
    SKIP(4);
    uint16_t bits;
#define MO_DROPPED 8
#define MO_MISSILE 0x100
    SKIP(2);
    uint16_t age;
    SKIP(4);
    struct item item;
    uint32_t spell_type;
    uint32_t spell_power;
    uint32_t spell_mastery;
    SKIP(4);
    uint32_t owner;
    SKIP(20);
};
typedef struct map_object s_map_object;
#define MAP_OBJECTS ((struct map_object *) 0x6650b0)

#define COLOR_FORMAT_ADDR 0x4e2d60
#define COLOR_FORMAT ((char *) COLOR_FORMAT_ADDR)
enum colors
{
    CLR_WHITE,
    CLR_ITEM,
    CLR_RED,
    CLR_YELLOW,
    CLR_PALE_YELLOW,
    CLR_GREEN,
    CLR_BLUE,
    CLR_PURPLE,
    CLR_COUNT
};
static int colors[CLR_COUNT];

#define SKILL_NAMES_ADDR 0xae3150
#define SKILL_NAMES ((char **) SKILL_NAMES_ADDR)

struct __attribute__((packed)) npc_topic_text
{
    char *topic;
    char *text;
};
#define NPC_TOPIC_TEXT_ADDR 0x7214e8
#define NPC_TOPIC_TEXT ((struct npc_topic_text *) NPC_TOPIC_TEXT_ADDR - 1)

// TOptions from MM7Patch v2.5.
static struct __attribute__((packed)) patch_options
{
    SKIP(36);
    int inventory_key;
    int char_screen_key;
    int double_speed_key;
    int quick_load_key;
    int autorun_key;
    SKIP(140);
    int fix_unimplemented_spells;
    SKIP(44);
    int axe_gm_perk_chance;
    double mouse_dx;
    double mouse_dy;
    SKIP(56);
    int fix_unmarked_artifacts;
    SKIP(8);
    int fix_light_bolt;
    int armageddon_element;
    SKIP(16);
    int keep_empty_wands;
    SKIP(16);
} *patch_options;
typedef struct patch_options s_patch_options;

// my additions
#define ACTION_EXTRA_CHEST 40
#define ACTION_PLACE_ORDER 41
#define ACTION_VARIABLE_EVENT 42
#define ACTION_THIRD_KEY_CONFIG_PAGE 43
#define ACTION_QUICK_SPELL_HINT 44
#define ACTION_QUICK_SPELL_PRESS 45
//vanilla
#define ACTION_EXIT 113
#define ACTION_SCROLL 146
#define ACTION_CHANGE_CONVERSATION 405

// Cavalier horse NPCs.
enum horses
{
    HORSE_HARMONDALE = 19,
    HORSE_ERATHIA,
    HORSE_TULAREAN,
    HORSE_DEYJA,
    HORSE_BRACADA,
    HORSE_TATALIA,
    HORSE_AVLEE,
};

struct __attribute__((packed)) npc
{
    char *name;
    SKIP(4);
    int bits;
    SKIP(8);
    int house;
    int profession;
    SKIP(40);
    int used_ability;
    SKIP(4);
};
typedef struct npc s_npc;

#define NPC_ADDR 0x72d50c
#define NPCS ((struct npc *) NPC_ADDR)
#define NPCDATA_ADDR 0x724050
#define NPCDATA ((struct npc *) NPCDATA_ADDR)
#define NPCS_LENGTH 0x73c014
#define NPC_HIRED 0x80
#define HIRED_NPC_1 0xad44f4
#define HIRED_NPC_2 0xad4540
#define DIALOG_NPC 0x590f10
#define CURRENT_HIRELING (!dword(HIRED_NPC_1) || ~dword(DIALOG_NPC))

// Data from parsing stditems.txt.
struct __attribute__((packed)) stditem
{
    char *name;
    char *description;
    uint8_t probability[11]; // was 9 in vanilla
    SKIP(1);
};
#define STDITEMS ((struct stditem *) 0x5dbe64)

// From parsing 2devents.txt.
struct __attribute__((packed)) event2d
{
    uint16_t type;
    SKIP(2);
    char *name;
    SKIP(20);
    uint16_t restock;
    SKIP(2);
    float multiplier;
    SKIP(16);
};
typedef struct event2d s_event2d;
#define EVENTS2D_ADDR 0x5912b8
#define EVENTS2D ((struct event2d *) EVENTS2D_ADDR)

// there are two black market buildings with different price multipliers
#define BLACK_MARKET_1 39
#define BLACK_MARKET_2 40
#define FIRST_GUILD 139
#define MASTER_THIEF 185

// Shop subactions.  The third one has remnant code but was unused.
#define CONV_BUY_STD 2
#define CONV_BUY_SPC 95
#define CONV_BUY_ARMOR 6
#define CONV_INVENTORY 94
#define CONV_LEARN 96
// My additions.
#define CONV_QUERY_ORDER 97
#define CONV_CONFIRM_ORDER 98
// Magic guild subactions -- the second one is my addition.
#define CONV_BUY_SPELLS 18
#define CONV_BUY_SCROLLS 19

// From npcprof.txt, now extended and relocated.
static struct npcprof
{
    uint32_t cost;
    char *description, *action, *join, *dismiss;
} npcprof[NPC_COUNT];
typedef struct npcprof s_npcprof;

struct __attribute__((packed)) map_room
{
    SKIP(98);
    uint16_t darkness;
    SKIP(16);
};
#define MAP_ROOMS ((struct map_room *) pointer(0x6be4d4))

struct __attribute__((packed)) travel_route
{
    uint8_t map_index;
    uint8_t weekdays[7];
    uint8_t time;
    SKIP(3);
    int32_t x, y, z;
    int32_t direction;
    uint32_t qbit;
};
#define TRAVEL_ROUTES ((struct travel_route *) 0x4f0830)
#define TRANSPORT ((int8_t (*)[4]) 0x4f0c90)

struct __attribute__((packed)) house_movie
{
    char *name;
    SKIP(4);
    uint32_t portrait;
    uint8_t type;
    uint8_t voice;
    SKIP(2);
};
#define HOUSE_MOVIES ((struct house_movie *) 0x4e5f40)

enum sizes
{
    SIZE_ITEM = sizeof(struct item),
    SIZE_BUFF = sizeof(struct spell_buff),
    SIZE_CHEST = sizeof(struct map_chest),
    SIZE_PLAYER = sizeof(struct player),
    SIZE_ITEM_TXT = sizeof(struct items_txt_item),
    SIZE_SPL_INFO = sizeof(struct spell_info),
    SIZE_MAPSTAT = sizeof(struct mapstats_item),
    SIZE_SPCITEM = sizeof(struct spcitem),
    SIZE_EVENT2D = sizeof(struct event2d),
    SIZE_NPC = sizeof(struct npc),
    SIZE_MONSTER = sizeof(struct map_monster),
};

// Some inline assembly limitations prevent directly addressing these.
enum struct_offsets
{
    S_PL_ITEMS = offsetof(struct player, items),
    S_PL_ITEM0 = S_PL_ITEMS - SIZE_ITEM,
    S_PL_STATS = offsetof(struct player, stats),
    S_PL_RES = offsetof(struct player, res_base),
    S_SB_POWER = offsetof(struct spell_buff, power),
    S_MM_HP = offsetof(struct map_monster, hp),
    S_SPC_PROB = offsetof(struct spcitem, probability),
    S_SPC_LEVEL = offsetof(struct spcitem, level),
    S_SI_COST = offsetof(struct spell_info, cost),
};

#define CURRENT_CONVERSATION 0xf8b01c
#define ICONS_LOD_ADDR 0x6d0490
#define ICONS_LOD ((void *) ICONS_LOD_ADDR)
#define DIALOG1 0x507a3c
#define DIALOG2 0x507a40
#define DIALOG5 0x507a4c
#define DIALOG7 0x507a54
#define PARTY_X 0xacd4ec
#define PARTY_Y 0xacd4f0
#define PARTY_Z 0xacd4f4
#define PARTY_DIR 0xacd4f8
#define PARTY_LOOK_ANGLE 0xacd4fc
#define FLYING 0xacd53c
#define PARTY_GOLD 0xacd56c
// Pointers for images in the shop window: [0] = background, [1+] = wares.
#define SHOP_IMAGES 0xf8afe4
#define MOUSEOVER_BUFFER 0xe31a9c
#define SCANLINE_OFFSET 0x505828
#define SHOP_STANDARD_ITEMS 0xad45b4
#define SHOP_SPECIAL_ITEMS 0xad9f24
#define CURRENT_TEXT_ADDR 0xf8b068
#define CURRENT_TEXT (*(char **) CURRENT_TEXT_ADDR)
#define STATUS_MESSAGE 0x5c32a8
#define ARRUS_FNT 0x5c3468
#define MESSAGE_DIALOG 0x507a64
#define SHOPKEEPER_MOOD 0xf8b064
#define SHOP_VOICE_NO_GOLD 2
#define NEW_SKILL_COST 0xf8b034
// can learn skill, can join guild, returned judge item
#define TOPIC_ACTION 0xf8b028
#define ARENA_TOPIC 0xacd5ed

#define WEAPON_SHOP_STD ((uint16_t (*)[5]) 0x4f0288)
#define WEAPON_SHOP_SPC ((uint16_t (*)[5]) 0x4f04c8)
#define ARMOR_SHOP_STD ((uint16_t (*)[2][5]) 0x4f0318)
#define ARMOR_SHOP_SPC ((uint16_t (*)[2][5]) 0x4f0558)
#define MAGIC_SHOP_STD ((uint16_t *) 0x4f0430)
#define MAGIC_SHOP_SPC ((uint16_t *) 0x4f0670)
#define POTION_SHOP_STD ((uint16_t *) 0x4f044c)
#define POTION_SHOP_SPC ((uint16_t *) 0x4f068c)
#define TRAIN_MAX_LEVELS ((int16_t *) 0x4f0798)

#define TURN_BASED 0xacd6b4
#define BANK_GOLD 0xacd570
#define PC_POINTERS 0xa74f48
#define SELECTED_SPELL 0x5063cc
#define SPELLS_TXT 0x5cbeb0
#define MOVEMAP_STYLE 0x576cbc
#define HOUR_OF_DAY 0xacd554
#define REFRESH_SCREEN 0x576eac
#define CURRENT_HITBOX 0x7213b0
#define BLINK_AUTONOTES 0x5077c9
#define AUTONOTES_PAGE 0x5063e8

#ifdef CHECK_OVERWRITE
#define sprintf sprintf_mm7
#define fread fread_mm7
#endif

static int __cdecl (*uncased_strcmp)(const char *left, const char *right)
    = (funcptr_t) 0x4caaf0;
static int __thiscall (*player_resists)(void *player, int element, int damage)
    = (funcptr_t) 0x48d499;
static int __thiscall (*get_resistance)(const void *player, int stat)
    = (funcptr_t) 0x48e7c8;
static int __thiscall (*has_item_in_slot)(void *player, int item, int slot)
    = (funcptr_t) 0x48d6ef;
static int __fastcall (*rgb_color)(int red, int green, int blue)
    = (funcptr_t) 0x40df03;
static int __cdecl (*sprintf)(char *str, const char *format, ...)
    = (funcptr_t) 0x4cad70;
static funcptr_t ftol = (funcptr_t) 0x4ca74c;
static int __thiscall (*add_buff)(struct spell_buff *buff, long long time,
                                  int skill, int power, int overlay,
                                  int caster) = (funcptr_t) 0x458519;
static int __thiscall (*expire_buff)(void *buff, long long current_time)
    = (funcptr_t) 0x458603;
static void __thiscall (*reset_stat_boni)(void *player) = (funcptr_t) 0x490707;
static int __fastcall (*elem_damage)(void *weapon, int *ret_element,
                                     int *ret_vampiric) = (funcptr_t) 0x439e16;
static int __stdcall (*monster_resists)(void *monster, int element, int damage)
    = (funcptr_t) 0x427522;
static void __thiscall (*expire_temp_bonus)(struct item *item, long long time)
    = (funcptr_t) 0x458299;
static funcptr_t is_artifact = (funcptr_t) 0x456d98;
static int __thiscall (*get_skill)(void *player, int skill)
    = (funcptr_t) 0x48f87a;
static void __fastcall (*show_status_text)(char *string, int seconds)
    = (funcptr_t) 0x44c1a1;
static void __thiscall (*show_face_animation)(void *player, int animation,
                                              int unused)
    = (funcptr_t) 0x4948a9;
static void __thiscall (*delete_backpack_item)(void *player, int cell)
    = (funcptr_t) 0x492a2e;
static void __thiscall (*add_mouse_item)(void *this, struct item *item)
    = (funcptr_t) 0x4936d9;
#define PARTY_BIN_ADDR 0xacce38
#define PARTY_BIN ((void *) PARTY_BIN_ADDR)
static int __thiscall (*put_in_backpack)(void *player, int slot, int item_id)
    = (funcptr_t) 0x4927a0;
static int __thiscall (*put_item_in_backpack)(struct player *player, int slot,
                                              struct item *item)
    = (funcptr_t) 0x49281e;
static void __thiscall (*make_sound)(void *this, int sound, int object,
                                     int loops, int x, int y, int angle,
                                     int volume, int playback_rate)
    = (funcptr_t) 0x4aa29b;
#define SOUND_THIS_ADDR 0xf78f58
#define SOUND_THIS ((void *) SOUND_THIS_ADDR)
static void __thiscall (*evt_set)(void *player, int what, int amount)
    = (funcptr_t) 0x44a5ee;
static int __thiscall (*exists_in_lod)(void *lod, char *filename)
    = (funcptr_t) 0x461659;
static char *__thiscall (*load_from_lod)(void *lod, char *filename,
                                         int use_malloc)
    = (funcptr_t) 0x410897;
static void (*mm7_free)(void *ptr) = (funcptr_t) 0x4caefc;
#define QBITS_ADDR 0xacd59d
#define QBITS ((void *) QBITS_ADDR)
#define AUTONOTES_ADDR 0xacd636
#define AUTONOTES ((void *) AUTONOTES_ADDR)
static int __fastcall (*check_bit)(void *bits, int bit)
    = (funcptr_t) 0x449b7a;
static int __fastcall (*get_darkness)(int base, int room, float x, float y,
                                      float z) = (funcptr_t) 0x43f5eb;
static char __thiscall (*add_light_source)(int this, int x, int y, int z,
                                           int unknown_1, int power,
                                           int unknown_2, int unknown_3,
                                           int unknown_4, int unknown_5)
    = (funcptr_t) 0x467d8c;
#define LIGHT_SOURCE_THIS 0x519938
static void __fastcall (*add_reply)(int number, int action)
    = (funcptr_t) 0x4b362f;
static void __fastcall (*spend_gold)(int amount) = (funcptr_t) 0x492bae;
static void __thiscall (*init_item)(void *item) = (funcptr_t) 0x402f07;
static void __fastcall (*print_text)(int *bounds, void *font, int x, int y,
                                     int color, char *text, int unknown)
    = (funcptr_t) 0x44d432;
static int __thiscall (*spend_sp)(void *player, int sp) = (funcptr_t) 0x4276e7;
static int (*get_game_speed)(void) = (funcptr_t) 0x46bdac;
static void __fastcall (*projectile_hit)(int projectile, int target)
    = (funcptr_t) 0x43a9a1;
static int __thiscall (*get_race)(void *player) = (funcptr_t) 0x490101;
static int __thiscall (*get_gender)(void *player) = (funcptr_t) 0x490139;
static int __thiscall (*get_might)(void *player) = (funcptr_t) 0x48c922;
static int __thiscall (*get_intellect)(void *player) = (funcptr_t) 0x48c9a8;
static int __thiscall (*get_personality)(void *player) = (funcptr_t) 0x48ca25;
static int __thiscall (*get_endurance)(void *player) = (funcptr_t) 0x48caa2;
static int __thiscall (*get_accuracy)(void *player) = (funcptr_t) 0x48cb1f;
static int __thiscall (*get_speed)(void *player) = (funcptr_t) 0x48cb9c;
static int __thiscall (*get_luck)(void *player) = (funcptr_t) 0x48cc19;
static int __thiscall (*get_base_intellect)(void *player)
    = (funcptr_t) 0x48c852;
static int __thiscall (*get_base_personality)(void *player)
    = (funcptr_t) 0x48c869;
static int __thiscall (*get_base_endurance)(void *player)
    = (funcptr_t) 0x48c880;
static int __thiscall (*do_monster_bonus)(void *player, int bonus,
                                          void *monster)
    = (funcptr_t) 0x48dcdc;
static int __fastcall (*check_monster_in_hitbox)(int monster_id, int radius)
    = (funcptr_t) 0x46df1e;
static funcptr_t save_game = (funcptr_t) 0x45f4a2;
static void (*change_weather)(void) = (funcptr_t) 0x48946d;
static int __fastcall (*is_hostile_to)(void *monster, void *target)
    = (funcptr_t) 0x40104c;
static int __fastcall (*color_stat)(int modified, int base)
    = (funcptr_t) 0x4178a7;
static void __thiscall (*set_specitem_bonus)(int this, void *item)
    = (funcptr_t) 0x456d51;
// Possibly it's not just for buttons.
static int __thiscall (*remove_button)(void *this, void *button)
    = (funcptr_t) 0x42641d;
#define REMOVE_BUTTON_THIS 0x7029a8
static void __fastcall (*shop_voice)(int house, int topic)
    = (funcptr_t) 0x4b1df5;
static char __thiscall (*timed_cure_condition)(void *player, int condition,
                                               int time1, int time2)
    = (funcptr_t) 0x4908a0;
static void __thiscall (*heal_hp)(void *player, int hp) = (funcptr_t) 0x48db9f;
static void __fastcall (*update_face)(int player_id, int face)
    = (funcptr_t) 0x491ddf;
static int __thiscall (*get_full_hp)(void *player) = (funcptr_t) 0x48e4f0;
static int __fastcall (*get_monsters_around_party)(int *buffer,
                                                   int buffer_size, int radius)
    = (funcptr_t) 0x46a8a2;
static void __fastcall (*damage_monster_from_party)(int source, int monster,
                                                    void *force_vector)
    = (funcptr_t) 0x439463;
static void __fastcall (*print_string)(void *dialog, void *font, int x, int y,
                                       int color, const char *string,
                                       int unknown_1, int unknown_2,
                                       int unknown_3) = (funcptr_t) 0x44ce34;
static void __thiscall (*remove_buff)(void *buff) = (funcptr_t) 0x4585be;
// Not dead, stoned, paralyzed, etc.
static int __thiscall (*player_active)(void *player) = (funcptr_t) 0x492c03;
// Seems like this is a method of player, but ecx isn't actually used.
static int __stdcall (*get_effective_stat)(int stat) = (funcptr_t) 0x48ea13;
static int __fastcall (*roll_dice)(int count, int sides)
    = (funcptr_t) 0x452b5a;
static int __fastcall (*spell_damage)(int spell, int skill, int mastery,
                                      int monster_hp) = (funcptr_t) 0x43b006;
static int __thiscall (*damage_player)(void *player, int damage, int element)
    = (funcptr_t) 0x48dc04;
static void __fastcall (*attack_monster)(int attacker, int defender,
                                         void *force, int attack_type)
    = (funcptr_t) 0x43b1d3;
static int __fastcall (*skill_mastery)(int skill) = (funcptr_t) 0x45827d;
static int (*random)(void) = (funcptr_t) 0x4caac2;
static void __cdecl (*srandom)(unsigned int seed) = (funcptr_t) 0x4caab5;
static int (*get_thread_context)(void) = (funcptr_t) 0x4cecd2;
static int __thiscall (*save_file_to_lod)(void *lod, const void *header,
                                          void *file, int unknown)
    = (funcptr_t) 0x461b85;
static int __thiscall (*generate_artifact)(struct item *buffer)
    = (funcptr_t) 0x4505f8;
static void __fastcall (*summon_monster)(int id, int x, int y, int z)
    = (funcptr_t) 0x4bbec4;
static int __thiscall (*dir_cosine)(void *this, int dir)
    = (funcptr_t) 0x402cae;
#define TRIG_THIS ((void *) 0x56c680)
static int __thiscall (*find_active_player)(void *this) = (funcptr_t) 0x493707;
static int __thiscall (*get_map_index)(struct mapstats_item *mapstats,
                                       const char *filename)
    = (funcptr_t) 0x4547cf;
static void *__thiscall (*find_in_lod)(void *lod, const char *filename,
                                       int unknown) = (funcptr_t) 0x4615bd;
static int __cdecl (*fread)(void *buffer, int size, int count, void *stream)
    = (funcptr_t) 0x4cb8a5;
static int (*get_eff_reputation)(void) = (funcptr_t) 0x47752f;
static int __thiscall (*get_full_sp)(void *player) = (funcptr_t) 0x48e55d;
static void __thiscall (*kill_civilian)(int id) = (funcptr_t) 0x438ce2;
static int __thiscall (*monster_active)(void *monster) = (funcptr_t) 0x40894b;
static int __fastcall (*parse_spell)(char **words, int *extra_words)
    = (funcptr_t) 0x45490e;
static int __thiscall (*monster_considers_spell)(void *this, void *monster,
                                                 int spell)
    = (funcptr_t) 0x4270b9;
static void __fastcall (*monster_casts_spell)(int monster_id, void *vector,
                                              int spell, int action, int skill)
    = (funcptr_t) 0x404ac7;
static int __thiscall (*equipped_item_type)(void *player, int slot)
    = (funcptr_t) 0x48d612;
static int __thiscall (*equipped_item_skill)(void *player, int slot)
    = (funcptr_t) 0x48d637;
static int __thiscall (*has_anything_in_slot)(void *player, int slot)
    = (funcptr_t) 0x48d690;
static int __thiscall (*get_min_melee_damage)(void *player)
    = (funcptr_t) 0x48cd2b;
static int __thiscall (*get_max_melee_damage)(void *player)
    = (funcptr_t) 0x48cd76;
static int __thiscall (*get_min_ranged_damage)(void *player)
    = (funcptr_t) 0x48d10a;
static int __thiscall (*get_max_ranged_damage)(void *player)
    = (funcptr_t) 0x48d177;
static int __thiscall (*get_attack_delay)(void *player, int ranged)
    = (funcptr_t) 0x48e19b;
static int __thiscall (*hireling_action)(int id) = (funcptr_t) 0x4bb6b9;
static int __cdecl (*add_button)(void *dialog, int left, int top, int width,
                                 int height, int unknown_1, int hover_action,
                                 int action, int action_param, int key,
                                 char *text, ...) // varpart is sprite(s)
    = (funcptr_t) 0x41d0d8;
static void (*on_map_leave)(void) = (funcptr_t) 0x443fb8;
static void __fastcall (*change_map)(char *map, int unknown)
    = (funcptr_t) 0x44989e;
static void __thiscall (*click_on_portrait)(int player_id)
    = (funcptr_t) 0x421ca9;
static int __fastcall (*add_chest_item)(int unused, void *item, int chest_id)
    = (funcptr_t) 0x41ff4b;
static void __thiscall (*remove_mouse_item)(void *this) = (funcptr_t) 0x4698aa;
#define MOUSE_THIS_PTR 0x720808
#define MOUSE_THIS (*(int **) MOUSE_THIS_PTR)
#define MOUSE_X (MOUSE_THIS[66])
#define MOUSE_Y (MOUSE_THIS[67])
static void __stdcall (*start_new_music)(int track) = (funcptr_t) 0x4aa0cf;
// Technically thiscall, but ecx isn't used.
static int __stdcall (*monster_resists_condition)(void *monster, int element)
    = (funcptr_t) 0x427619;
// Same.
static void __stdcall (*magic_sparkles)(void *monster, int color)
    = (funcptr_t) 0x4a7e19;
static int __thiscall (*has_enchanted_item)(void *player, int enchantment)
    = (funcptr_t) 0x48d6b6;
static int __thiscall (*load_bitmap)(void *lod, char *name, int lod_type)
    = (funcptr_t) 0x40fb2c;
#define LOADED_BITMAPS_ADDR 0x6d06cc
#define LOADED_BITMAPS ((uint32_t (*)[18]) 0x6d06cc)
static void __fastcall (*aim_spell)(int spell, int pc, int skill, int flags,
                                    int unknown) = (funcptr_t) 0x427734;
#define CGAME 0x71fe94
#define SPELL_ANIM_THIS ((void *) dword(dword(CGAME) + 0xe50))
static void __thiscall (*spell_face_anim)(void *this, short spell, short pc)
    = (funcptr_t) 0x4a894d;
#define ACTION_THIS_ADDR 0x50ca50
#define ACTION_THIS ((void *) ACTION_THIS_ADDR)
static void __thiscall (*add_action)(void *this, int action, int param1,
                                     int param2) = (funcptr_t) 0x42eb69;
static void __thiscall (*rest_party)(void *this) = (funcptr_t) 0x490cfa;
static int __thiscall (*get_fame)(void *this) = (funcptr_t) 0x491356;
static int __thiscall (*open_chest)(int chest) = (funcptr_t) 0x4203c7;
static void __thiscall (*resurrect_monster)(int mon_id) = (funcptr_t) 0x402f27;
static int __thiscall (*identify_price)(void *player, float shop_multiplier)
    = (funcptr_t) 0x4b80dc;
static char *__thiscall (*item_name)(struct item *item) = (funcptr_t) 0x4564c5;
static int (*new_game_get_bonus)(void) = (funcptr_t) 0x49090b;
static int __thiscall (*get_level)(void *player) = (funcptr_t) 0x48c8f3;
static int __thiscall (*get_bodybuilding_bonus)(void *player)
    = (funcptr_t) 0x491075;
static int __thiscall (*get_meditation_bonus)(void *player)
    = (funcptr_t) 0x4910a0;
static int __thiscall (*get_stat_bonus_from_items)(void *player, int stat,
                                                   int ignore_offhand)
    = (funcptr_t) 0x48eaa6;
static funcptr_t get_text_width = (funcptr_t) 0x44c52e;
static int __thiscall (*is_bare_fisted)(void *player) = (funcptr_t) 0x48d65c;
static funcptr_t reset_interface = (funcptr_t) 0x422698;
static int __thiscall (*get_perception_bonus)(void *player)
    = (funcptr_t) 0x491252;
static int __thiscall (*get_merchant_bonus)(void *player)
    = (funcptr_t) 0x4911eb;
static int __thiscall (*get_learning_bonus)(void *player)
    = (funcptr_t) 0x49130f;
static int __thiscall (*get_disarm_bonus)(void *player) = (funcptr_t) 0x4912a8;
static int __thiscall (*find_objlist_item)(void *this, int id)
    = (funcptr_t) 0x42eb1e;
#define OBJLIST_THIS_ADDR 0x680630
#define OBJLIST_THIS ((void *) OBJLIST_THIS_ADDR)
static int __fastcall (*launch_object)(struct map_object *object,
                                       int direction, int look_angle,
                                       int speed, int player)
    = (funcptr_t) 0x42f5c9;
static int __thiscall (*item_value)(struct item *item) = (funcptr_t) 0x45646e;
static int __thiscall (*get_ac)(void *player) = (funcptr_t) 0x48e687;
static int __stdcall (*monster_hits_player)(void *monster, void *player)
    = (funcptr_t) 0x427464;
static int __fastcall (*monster_attack_damage)(void *monster, int attack)
    = (funcptr_t) 0x43b403;
static int __thiscall (*get_base_resistance)(const void *player, int stat)
    = (funcptr_t) 0x48e737;
static int __thiscall (*get_base_ac)(void *player) = (funcptr_t) 0x48e64e;
static void __fastcall (*process_event)(int event, int target, int verbose)
    = (funcptr_t) 0x44686d;
static void __thiscall (*evt_sub)(void *player, int what, int amount)
    = (funcptr_t) 0x44b9f0;
static int __thiscall (*have_npc_hired)(int npc) = (funcptr_t) 0x476399;
static int __thiscall (*repair_price)(void *player, int item_value,
                                      float shop_multiplier)
    = (funcptr_t) 0x4b8126;
static void __thiscall (*set_gold)(int value) = (funcptr_t) 0x492b68;
static int *__fastcall (*aim_at_target)(int attacker, int target, int *buffer,
                                        int eye_level) = (funcptr_t) 0x4040e9;
static void __fastcall (*monster_shoots)(int monster_id, void *vector,
                                         int missile, int attack)
    = (funcptr_t) 0x404874;
static int __fastcall (*get_text_height)(void *font, char *string,
                                         const int *bounds, int unknown,
                                         int unknown2) = (funcptr_t) 0x44c5c9;
static void __fastcall (*change_bit)(void *bits, int bit, int set)
    = (funcptr_t) 0x449ba1;
static void (*restock_books)(void) = (funcptr_t) 0x4bc838;
static void __fastcall (*message_dialog)(int event, int label, int type)
    = (funcptr_t) 0x4451cb;
// These are really script command IDs, but message_dialog() also uses them.
#define MESSAGE_QUESTION 26
#define MESSAGE_SIMPLE 33
// To distinguish our prompts/etc. from genuine script commands.
#define MESSAGE_MARKER 0xd00d
static void __thiscall (*draw_background)(void *this, int x, int y,
                                          void *image) = (funcptr_t) 0x4a5e42;
#define DRAW_IMAGE_THIS_ADDR 0xdf1a68
#define DRAW_IMAGE_THIS ((void *) DRAW_IMAGE_THIS_ADDR)
static void __thiscall (*draw_over_other)(void *this, int x, int y,
                                          void *image) = (funcptr_t) 0x4a6204;
static void __fastcall (*set_mouse_mask)(int *buffer, void *image, int id)
    = (funcptr_t) 0x40f936;
static int *__thiscall (*get_mouse_coords)(void *this, int *buffer)
    = (funcptr_t) 0x469c3d;
static void __thiscall (*randomize_item)(int this, int level, int type,
                                         void *item) = (funcptr_t) 0x45664c;
static void __fastcall (*set_image_mouseover)(void *buffer, void *image,
                                              int id) = (funcptr_t) 0x40f8a8;
#define GET_ASYNC_KEY_STATE 0x4d8260
static int __thiscall (*append_to_lod)(void *lod,
                                       const struct file_header *header,
                                       void *buffer) = (funcptr_t) 0x461fae;
static int __thiscall (*get_config_key_color)(int id) = (funcptr_t) 0x414d2f;
static char *__stdcall (*get_key_name)(int key) = (funcptr_t) 0x45ae65;
static int __thiscall (*parse_key_name)(int this, const char *name)
    = (funcptr_t) 0x45ac03;
#define KEY_THIS 0x69ac80
static void __fastcall (*read_registry)(const char *key, char *buffer,
                                        int length, const char *default_value)
    = (funcptr_t) 0x464c2c;
static void __fastcall (*write_registry)(const char *key, const char *value)
    = (funcptr_t) 0x464b3f;
static void __thiscall (*unload_bitmap)(void *bitmap) = (funcptr_t) 0x40f788;
// Actually it's not the entire function, but we don't need the first half.
static char __stdcall (*check_key_pressed)(int key) = (funcptr_t) 0x45b118;
static void __thiscall (*set_recovery_delay)(void *player, int delay)
    = (funcptr_t) 0x48e962;
#define TURN_BASED_THIS 0x4f86d8
static void __thiscall (*turn_based_pass)(int this) = (funcptr_t) 0x40471c;
#define CAN_REPAIR_ADDR 0x491149
static int __thiscall (*can_repair)(struct player *player, struct item *item)
    = (funcptr_t) CAN_REPAIR_ADDR;
static void __thiscall (*set_hint)(char *hint) = (funcptr_t) 0x41c061;
static void __thiscall (*fetch_spell_sound)(void *this, int spell, int id)
    = (funcptr_t) 0x49482e;

//---------------------------------------------------------------------------//

static const char *const elements[] = {"fire", "elec", "cold", "pois", "phys",
                                       0, "holy", "mind", "magic", 0,
                                       "dragfire", 0, "ener"};

// Translated attack element names.  Filled in new_element_names() below.
static char *element_names[ENERGY+1];

// Print the spell's attack element instead of its school.
static void __declspec(naked) print_spell_element_common(void)
{
    asm
      {
        lea eax, [eax+eax*8]
        mov eax, dword ptr [ELEMENT_ADDR+eax*4]
        cmp eax, NO_ELEMENT
        je skip
        mov eax, dword ptr [element_names+eax*4]
        mov dword ptr [esp+16], eax
        jmp dword ptr ds:print_text ; replaced call
        skip:
        ret 20 ; print nothing
      }
}

// Call the above hook for a spell in PC spellbook.
static void __declspec(naked) print_spell_element_spellbook(void)
{
    asm
      {
        imul eax, eax, 11 ; spellbook page
        add eax, dword ptr [ebp-20] ; spell idx on page
        inc eax
        jmp print_spell_element_common
      }
}

// And also for spell preview in magic guilds.
static void __declspec(naked) print_spell_element_guild(void)
{
    asm
      {
        mov eax, esi ; spell id
        jmp print_spell_element_common
      }
}

// Patch spells.txt parsing, specifically possible spell elements.
// Also here: show attack element in spell description.
static inline void spells_txt(void)
{
    patch_pointer(0x45395c, elements[SHOCK]);
    patch_pointer(0x453975, elements[COLD]);
    patch_pointer(0x45398e, elements[POISON]);
    patch_pointer(0x4539a7, elements[HOLY]);
    patch_pointer(0x4539d9, elements[PHYSICAL]);
    patch_byte(0x4539ea, PHYS_SPELL); // separate from weapon to handle medusae
    patch_pointer(0x4539f2, elements[ENERGY]);
    patch_byte(0x453a03, ENERGY);
    patch_pointer(0x453a0b, elements[DRAGONFIRE]);
    patch_byte(0x453a39, MAGIC); // was unused (5)
    patch_byte(0x453947, NO_ELEMENT); // the new default
    hook_call(0x410d34, print_spell_element_spellbook, 5);
    hook_call(0x4b169c, print_spell_element_guild, 5);
}

// The original function compared the first letter only.
// This is why some monsters attacked with earth instead of energy.
static int __fastcall attack_type(const char *attack)
{
    if (!attack)
        return PHYSICAL;
    for (int idx = FIRE; idx <= ENERGY; idx++)
        if (elements[idx] && !uncased_strcmp(attack, elements[idx]))
            return idx;
    return PHYSICAL;
}

// For the parse code just below.
static const char special_type[] = "SPECIAL";
static const char reagent_type[] = "REAGENT";
static const char potion_type[] = "POTION";

// Parse new item drop types in monsters.txt.
static void __declspec(naked) new_item_drop_types(void)
{
    asm
      {
        mov byte ptr [esi+12], cl ; replaced code
        cmp byte ptr [edi], 0 ; ditto
        jz quit
        push edi
#ifdef __clang__
        mov eax, offset special_type
        push eax
#else
        push offset special_type
#endif
        call dword ptr ds:uncased_strcmp
        test eax, eax
        jnz not_special
        mov byte ptr [esi+13], ITEM_TYPE_SPECIAL
        jmp restore
        not_special:
        mov dword ptr [esp], offset reagent_type
        call dword ptr ds:uncased_strcmp
        test eax, eax
        jnz not_reagent
        mov byte ptr [esi+13], ITEM_TYPE_REAGENT
        jmp restore
        not_reagent:
        mov dword ptr [esp], offset potion_type
        call dword ptr ds:uncased_strcmp
        test eax, eax
        jnz restore
        mov byte ptr [esi+13], ITEM_TYPE_POTION
        restore:
        pop eax
        pop eax
        quit:
        ret
      }
}

// Patch monsters.txt parsing: remove two resistance fields and change
// the possible attack elements.  Also here: add some specific monster drops.
static inline void monsters_txt(void)
{
    patch_byte(0x455108, byte(0x455108) - 1); // one less field now
    patch_dword(0x456402, dword(0x456406)); // tweaking the jumptable
    patch_dword(0x456406, dword(0x45640a)); // ditto
    hook_jump(0x454ce0, attack_type); // replace the old function entirely
    hook_call(0x4553a5, new_item_drop_types, 6);
    // special item type converted to the items in rnd_robe_type() below
}

// Note: for this purpose, "undead" is any monster not immune to Holy.
// The original game just checked monster ID.  I haven't yet replaced
// all such checks.
static void __declspec(naked) skip_known_monster_res(void)
{
    asm
      {
        mov ecx, dword ptr [ebp-8]
        cmp ecx, 0x10
        jne not_holy
        cmp dword ptr [ebp-0xb0], IMMUNE
        jne not_holy
        add ecx, 4
        not_holy:
        cmp ecx, 0x18
        jne not_light
        add ecx, 8
        not_light:
        add ecx, 4
        mov dword ptr [ebp-8], ecx
        mov ecx, dword ptr [ebp-4]
        ret
      }
}

// The original code just displayed "?" here, but I still need to remove it.
static void __declspec(naked) skip_unknown_monster_res(void)
{
    asm
      {
        mov ecx, dword ptr [ebp-0x24]
        cmp ecx, 4
        jne not_holy
        cmp dword ptr [ebp-0xb0], IMMUNE
        jne not_holy
        inc ecx
        not_holy:
        cmp ecx, 6
        jne not_light
        add ecx, 2
        not_light:
        inc ecx
        mov dword ptr [ebp-0x24], ecx
        mov ecx, dword ptr [ebp-4]
        ret
      }
}

// Don't show light and dark (and holy for non-undead) resistances
// when looking at a monster.
static inline void skip_monster_res(void)
{
    hook_call(0x41f34e, skip_known_monster_res, 7);
    hook_call(0x41f3a3, skip_unknown_monster_res, 6);
}

// The original code used the same constant of 8 both for damage and element
// of the "of venom" modifier, so I couldn't easily patch it in-place.
// Instead, I rewrote the poison code entirely.  As a bonus, Old Nick's
// damage is now in the separate chunk of code.
static void __declspec(naked) poisoned_weapons(void)
{
    asm
      {
        dec ebx
        jz poison
        dec ebx
        jz venom
        dec ebx
        jz acid
        ret
        poison:
        mov esi, 5
        ret
        venom:
        mov esi, 8
        ret
        acid:
        mov esi, 12
        ret
      }
}

static void __declspec(naked) poison_chunk(void)
{
    asm
      {
        push esi
        nop
      }
}

// Change poisoned weapons' damage from Body to Poison.
static inline void elemental_weapons(void)
{
    hook_call(0x439f47, poisoned_weapons, 7);
    patch_bytes(0x439f70, poison_chunk, 2);
    patch_dword(0x439f6c, POISON); // was 2 (water) for some reason
    patch_dword(0x439f7d, POISON); // was 8 (body)
    patch_dword(0x439e67, dword(0x439e67) + 7); // Old Nick
    patch_byte(0x439f82, 13); // this is now Old Nick's posion damage
}

// Fire-physical resistance is the minimum of the two.
static void __declspec(naked) dragonfire_monster(void)
{
    asm
      {
        movzx edx, byte ptr [eax].s_map_monster.fire_resistance
        movzx eax, byte ptr [eax].s_map_monster.phys_spell_resistance
        cmp eax, IMMUNE
        jae fire
        lea esi, [edx+ecx] ; with day of protection
        cmp eax, esi
        jae fire
        xor edx, edx
        jmp quit
        fire:
        mov eax, edx
        mov edx, ecx
        quit:
        mov ecx, 0x427595 ; after res code
        jmp ecx
      }
}

// Equal element 9 (physical spells) with physical damage.
static void __declspec(naked) physical_spells(void)
{
    asm
      {
        jnz not_magic
        mov eax, 0x48d4c1
        jmp eax
        not_magic:
        dec eax
        jnz skip
        phys_spell:
        mov dword ptr [ebp+8], PHYSICAL
        skip:
        xor edi, edi
        mov eax, 0x48d4e4
        jmp eax
      }
}

// Defined below.
static int __thiscall resist_phys_damage(struct player *player, int damage);
static int __thiscall is_immune(struct player *player, unsigned int element);

// Can't just compare resistance values in-function, as player resistances
// are quite complex, and furthermore physical damage uses fixed reduction
// instead of random rolls.  So let's replace the call to player_resists()
// and figure out the element which will be resisted less on average.
static int __thiscall dragonfire_player(void *player, int element, int damage)
{
    if (element == DRAGONFIRE)
      {
        int fire_res = get_resistance(player, STAT_FIRE_RES);
        if (fire_res)
            fire_res += get_effective_stat(get_luck(player)) * 4;
        int physical = resist_phys_damage(player, 12); // it's in 1/12s
        // convert fixed damage reduction to equivalent resistance
        static const int effective_res[13] = { 99999, 2292, 420, 211, 131,
                                               89, 62, 44, 31, 21, 13, 6, 0};
        if (is_immune(player, FIRE) || fire_res >= effective_res[physical])
            element = PHYSICAL;
        else element = FIRE;
      }
    return player_resists(player, element, damage);
}

// Handle exotic spell elements (Dragon Breath and physical vs. medusae).
static inline void special_spell_elements(void)
{
    patch_pointer(0x427615, dragonfire_monster); // patch jumptable
    hook_jump(0x48d4bb, physical_spells);
    hook_call(0x48dc1a, dragonfire_player, 5);
}

// Increase primary stat effect on resisting conditions 4x.
static void __declspec(naked) quadruple_stat_effect(void)
{
    asm
      {
        pop ebx
        call dword ptr ds:get_effective_stat
        shl eax, 2
        jmp ebx
      }
}

// Only skip SP drain if the PC has none left.
static void __declspec(naked) check_sp_to_drain(void)
{
    asm
      {
        cmp edi, dword ptr [esi].s_player.sp ; edi == 0
        mov eax, 0x48df06 ; past resistance checks
        jmp eax ; will skip drain if >=
      }
}

// Instead of vampires etc. occasionally draining all SP, which usually
// warranted a reload, let them sip smaller amounts with every attack.
static void __thiscall partial_sp_drain(struct player *player,
                                        struct map_monster *monster)
{
    // since chance is now 100%, use the old chance as sp fraction to drain
    double fraction = monster->level * monster->attack_special_chance / 100.0;
    int resistance = get_effective_stat(get_intellect(player))
                   + get_effective_stat(get_luck(player));
    resistance *= 4; // stat-based!
    // the usual (damage) resistance rolls
    if (resistance > 0) for (int i = 0; i < 4; i++)
      {
        if (random() % (resistance + 30) < 30)
            break;
        fraction /= 2;
      }
    int heal = player->sp;
    if (fraction >= 1)
        player->sp = 0;
    else
        player->sp *= 1 - fraction;
    // since mostly vampires do this, let them heal
    if (elemdata.difficulty && (heal -= player->sp))
      {
        monster->hp += heal * elemdata.difficulty;
        if (monster->hp > monster->max_hp)
            monster->hp = monster->max_hp;
      }
}

// Hook for the above.
static void __declspec(naked) partial_sp_drain_hook(void)
{
    asm
      {
        mov ecx, esi ; player
        push dword ptr [ebp+12] ; monster
        call partial_sp_drain
        ret
      }
}

// Skip the usual level*multiplier check for the sp drain ability.
static void __declspec(naked) unconditional_sp_drain(void)
{
    asm
      {
        imul eax, ecx ; replaced code
        cmp byte ptr [esi].s_map_monster.attack_special, 22 ; drain sp
        cmove eax, esi ; set less
        cmp edx, eax ; also replaced
        ret
      }
}

// Tweak which stats protect against which conditions.  Most importantly,
// for conditions that are governed by a base stat's effective value,
// this value is now multiplied x4.  Also here: drain SP redesign.
static inline void condition_resistances(void)
{
    hook_call(0x48dedd, quadruple_stat_effect, 5);
    // Reorder the jumptable:
    uint32_t poison_res = dword(0x48e109);
    patch_dword(0x48e0e5, poison_res); // poisoned 1
    patch_dword(0x48e0e9, poison_res); // poisoned 2
    patch_dword(0x48e0ed, poison_res); // poisoned 3
    uint32_t magic_res = dword(0x48e105);
    patch_dword(0x48e109, magic_res); // stoned
    patch_dword(0x48e121, magic_res); // aged
    // Let's make SP drain a bit more deterministic.
    patch_pointer(0x48e125, check_sp_to_drain); // jumptable
    hook_call(0x48e081, partial_sp_drain_hook, 6);
    hook_call(0x43a33f, unconditional_sp_drain, 5);
    hook_call(0x43a861, unconditional_sp_drain, 5); // two entry points
}

// Undead players are either liches (returns 1) or zombies (returns 2).
static int __thiscall __declspec(naked) is_undead(void *player)
{
    asm
      {
        xor eax, eax
        cmp dword ptr [ecx+COND_ZOMBIE*8], 0
        jnz zombie
        cmp dword ptr [ecx+COND_ZOMBIE*8+4], 0
        jnz zombie
        cmp byte ptr [ecx].s_player.class, CLASS_LICH
        je lich
        ret
        zombie:
        inc eax
        lich:
        inc eax
        ret
      }
}

// Returns 2 for temporary immunity (zombie or potion), 1 for permanent
// (lich or artifact), 3 for both, or 0 if no immunity.
static int __thiscall is_immune(struct player *player, unsigned int element)
{
    int result = 0;
    if (element <= POISON || element == MIND || element == MAGIC)
      {
        int buff = element < MIND ? element - FIRE + NBUFF_FIRE_IMM
                                  : element - MIND + NBUFF_MIND_IMM;
        if (elemdata.new_pc_buffs[player-PARTY][buff].expire_time)
            result |= 2;
      }

    int undead = is_undead(player);
    if (undead)
      {
        if (element == POISON || element == MIND)
            result |= undead; // we assume here liches cannot be zombies
      }
    else
      {
        if (element == HOLY)
            result |= 1;
      }

    switch (element)
      {
    case FIRE:
        if (has_item_in_slot(player, SPLITTER, SLOT_MAIN_HAND)
            || has_item_in_slot(player, FORGE_GAUNTLETS, SLOT_GAUNTLETS)
            || has_item_in_slot(player, RED_DRAGON_SCALE_MAIL, SLOT_BODY_ARMOR)
            || has_item_in_slot(player, RED_DRAGON_SCALE_SHIELD, SLOT_OFFHAND))
            result |= 1;
        break;
    case SHOCK:
        if (has_item_in_slot(player, STORM_TRIDENT, SLOT_MAIN_HAND))
            result |= 1;
        break;
    case COLD:
        if (has_item_in_slot(player, PHYNAXIAN_CROWN, SLOT_HELM))
            result |= 1;
        break;
    case POISON:
        if (has_item_in_slot(player, TWILIGHT, SLOT_CLOAK))
            result |= 1;
        break;
    case MIND:
        if (has_item_in_slot(player, MINDS_EYE, SLOT_HELM))
            result |= 1;
        break;
    case MAGIC:
        if (has_item_in_slot(player, WITCHBANE, SLOT_AMULET)
            || (player->class & -4) == CLASS_KNIGHT
                && NPCS[HORSE_AVLEE].bits & NPC_HIRED)
            result |= 1;
        break;
      }
    return result;
}

// Calls the old, replaced function.
static int __thiscall __declspec(naked) old_inflict_condition(void *player,
                                                              int condition,
                                                              int can_resist)
{
    asm
      {
        push ebp
        mov ebp, esp
        push ecx
        push ecx
        push 0x492d62
        ret
      }
}

// Some of the status conditions can be prevented by high
// Poison, Mind or Magic resistance, so naturally
// a corresponding immunity will apply to them as well.
// Update: also put Preservation's new effect here.
// Also check for Blaster GM quest and Ellinger's Robe's effects.
// Finally, Blessed weapons' curse immunity is also handled here.
static int __thiscall inflict_condition(struct player *player, int condition,
                                        int can_resist)
{
    int robe = has_item_in_slot(player, ELLINGERS_ROBE, SLOT_BODY_ARMOR);
    if (condition == COND_WEAK && robe) // even if can_resist == 0!
        return FALSE; // because most sources of weak are coded as such
    uint64_t immutability = 0;
    if (can_resist)
      {
        int bit = 1 << condition;
        int element = -1;
        if (condition == COND_INCINERATED) // like instadeath but not "magical"
            element = FIRE;
        else if (bit & 0x540) // poisoned 1, 2, 3
            element = POISON;
        else if (bit & 0x1028) // afraid, insane, paralyzed
            element = MIND;
        else if (bit & 0x1c000) // dead, stoned, eradicated
            element = MAGIC;
        if (element != -1 && is_immune(player, element))
            return FALSE;
        // Preservation now gives a 50% chance to avoid instant death.
        if ((bit & 0x54000) // dead (incl. incinerated) or eradicated
            && (player->spell_buffs[PBUFF_PRESERVATION].expire_time || robe)
            && random() & 1)
            return FALSE;
        if (condition == COND_CURSED
            && has_enchanted_item(player, SPC_BLESSED))
            return FALSE;
        if (random() % 4 < elemdata.difficulty)
          {
            immutability = PARTY_BUFFS[BUFF_IMMUTABILITY].expire_time;
            PARTY_BUFFS[BUFF_IMMUTABILITY].expire_time = 0; // disable
          }
      }
    if (condition == COND_INCINERATED) // fake condition
        condition = COND_DEAD; // is actually death
    int result = old_inflict_condition(player, condition, can_resist);
    if (immutability)
        PARTY_BUFFS[BUFF_IMMUTABILITY].expire_time = immutability; // restore
    if (condition == COND_ERADICATED && result
        && (check_bit(QBITS, QBIT_BLASTER_GM_QUEST_ACTIVE_LIGHT)
            || check_bit(QBITS, QBIT_BLASTER_GM_QUEST_ACTIVE_DARK))
        && !check_bit(QBITS, QBIT_BLASTER_GM_QUEST)
        && player->skills[SKILL_BLASTER] >= SKILL_MASTER)
      {
        evt_set(player, EVT_QBITS, QBIT_BLASTER_GM_QUEST);
        // make the quest book blink
        evt_set(player, EVT_QBITS, QBIT_DUMMY);
        evt_sub(player, EVT_QBITS, QBIT_DUMMY);
      }
    return result;
}

// Add another immunity check in the code that handles
// special monster attacks.  All relevant attacks, except aging,
// inflict conditions that are already handled above, but
// disabling them here also prevents relevant face animations.
static void __declspec(naked) monster_bonus_immunity(void)
{
    asm
      {
        mov eax, dword ptr [esp+4]
        cmp eax, STAT_POISON_RES
        jne not_poison
        sub eax, 3
        not_poison:
        sub eax, 7
        push eax
        call is_immune
        test eax, eax
        jnz immune
        mov ecx, esi
        push 0x48e7c8
        ret
        immune:
        push 0x48e0c8
        ret 8
      }
}

// The original code equaled body (now magic) and spirit (now holy) resistance
// for players.  Now that holy is relevant, I need to separate it.
static void __declspec(naked) holy_is_not_magic(void)
{
    asm
      {
        mov edi, MAGIC
        cmp ebp, STAT_HOLY_RES
        jne not_holy
        mov edi, HOLY
        not_holy:
        test ebx, ebx
        ret
      }
}

// Ditto, but for the base resistance.
static void __declspec(naked) holy_is_not_magic_base(void)
{
    asm
      {
        mov edi, MAGIC
        cmp dword ptr [esp+20], STAT_HOLY_RES
        jne not_holy
        mov edi, HOLY
        not_holy:
        test eax, eax
        ret
      }
}

// The original lich immunities were weird!  The character got 200 body and
// mind resistance on lichification, and then any resistance that was 200
// or above was treated as an immunity.  That meant a lich could become
// immune to other elements by stacking enough buffs; conversely, if body
// or mind resistance was lowered (e.g. by equipping Hareck's Leather),
// the existing immunity was lost.
// In this mod, liches and zombies are always immune to poison and mind,
// and their resistances aren't even checked for this purpose.  The magic
// number 200 is only respected for monsters.

// Replace the old code described above with the new immunity check.
static void __declspec(naked) immune_to_damage(void)
{
    asm
      {
        push eax
        mov ecx, esi
        push dword ptr [ebp+8]
        call is_immune
        test eax, eax
        pop eax
        jnz immune
        test eax, eax
        ret
        immune:
        xor eax, eax
        ret
      }
}

// New code for displaying elemental immunity in the stats screen.
// White if permanent, green if temporary.
static void __declspec(naked) display_immunity(int string, int element)
{
    asm
      {
        mov ecx, edi
        push dword ptr [esp+8]
        call is_immune
        test eax, eax
        jz not_immune
        dec eax
        cmovnz eax, dword ptr [colors+CLR_GREEN*4]
        mov ecx, dword ptr [esp+4]
        push dword ptr [GLOBAL_TXT_ADDR+625*4]
        push eax
        push dword ptr [GLOBAL_TXT_ADDR+ecx*4]
        push 0x4e2de0
        push esi
        call dword ptr ds:sprintf
        add esp, 20
        not_immune:
        ret 8
      }
}

// The unmodded game did not have the immunity code for the first four
// resistances, so I'm adding the instructions I owerwrote at the end here.

static void __declspec(naked) display_fire_immunity(void)
{
    asm
      {
        push FIRE
        push 87
        call display_immunity
        mov edx, dword ptr [ARRUS_FNT]
        ret
      }
}

static void __declspec(naked) display_elec_immunity(void)
{
    asm
      {
        push SHOCK
        push 6
        call display_immunity
        mov edx, dword ptr [ARRUS_FNT]
        ret
      }
}

static void __declspec(naked) display_cold_immunity(void)
{
    asm
      {
        push COLD
        push 240
        call display_immunity
        mov edx, dword ptr [ARRUS_FNT]
        ret
      }
}

static void __declspec(naked) display_poison_immunity(void)
{
    asm
      {
        push POISON
        push 70
        call display_immunity
        mov edx, dword ptr [ARRUS_FNT]
        ret
      }
}

static void __declspec(naked) display_mind_immunity(void)
{
    asm
      {
        push MIND
        push 142
        call display_immunity
        ret
      }
}

static void __declspec(naked) display_magic_immunity(void)
{
    asm
      {
        push MAGIC
        push 29
        call display_immunity
        ret
      }
}

// Do not inflict Zombie on liches who fail to Reanimate.
// This is very important as mixing zombies and liches leads to bugs.
static void __declspec(naked) fix_lich_reanimate(void)
{
    asm
      {
        test eax, eax ; result of zombification attempt
        jz skip
        jmp dword ptr ds:get_gender ; replaced call
        skip:
        add dword ptr [esp], 42 ; skip the zombie condition code
        ret
      }
}

// Cure Zombie status on lichification and make sure that zombie face
// is not stored as the original face.  Again, very important.
static void __declspec(naked) unzombie_liches(void)
{
    asm
      {
        call dword ptr ds:get_gender ; replaced call
        mov ecx, dword ptr [esi+COND_ZOMBIE*8]
        or ecx, dword ptr [esi+COND_ZOMBIE*8+4]
        jnz zombie
        ret
        zombie:
        mov dword ptr [esi+COND_ZOMBIE*8], edi ; == 0
        mov dword ptr [esi+COND_ZOMBIE*8+4], edi
        add dword ptr [esp], 27 ; skip the face/voice code
        cmp eax, edi ; but keep the comparison
        ret
      }
}

// Rewrite and expand the old lich immunity system.  Now one can also
// get an immunity from zombification, potions, or artifacts.
static inline void undead_immunities(void)
{
    hook_jump(0x492d5d, inflict_condition);
    hook_call(0x48dd27, monster_bonus_immunity, 5);
    hook_call(0x48e85f, holy_is_not_magic, 5);
    hook_call(0x48e764, holy_is_not_magic_base, 5);
    hook_call(0x48d4e7, immune_to_damage, 7);
    erase_code(0x48d4f3, 10); // overwrites an mm7patch hook

    // Remove the code that capped lich resistances at 200.
    erase_code(0x48e7af, 7);
    erase_code(0x48e7b8, 11);
    erase_code(0x48e8d1, 7);
    erase_code(0x48e8db, 13);

    // Tweak bonus resistances on lichification: remove 200 body and mind,
    // but add 20 holy and 20 magic.
    patch_dword(0x44a758, dword(0x44a758) + 10); // earth -> magic
    patch_dword(0x44a769, dword(0x44a769) - 2); // mind -> holy
    patch_word(0x44a76d, 20); // 200 res -> 20 res
    // body res at 0x44a76f is overwritten in racial_traits() below

    hook_call(0x418d8e, display_fire_immunity, 6);
    hook_call(0x418e0f, display_elec_immunity, 6);
    hook_call(0x418e90, display_cold_immunity, 6);
    hook_call(0x418f0c, display_poison_immunity, 6);
    hook_call(0x418f91, display_mind_immunity, 5);
    erase_code(0x418f96, 51); // old mind immunity code
    hook_call(0x41904e, display_magic_immunity, 5);
    erase_code(0x419053, 51); // old body immunity code

    // Make liches consistently immune to Zombie.
    hook_call(0x42dd5c, fix_lich_reanimate, 5);
    hook_call(0x44a778, unzombie_liches, 5);
}

static char *new_strings[NEW_STRING_COUNT];

// We need a few localizable strings, which we'll add to global.txt.
static void __declspec(naked) read_global_txt(void)
{
    asm
      {
        cmp dword ptr [esp+24], 0x5e4a94
        jne not_at_end
        mov dword ptr [esp+24], offset new_strings
        not_at_new_end:
        cmp ebx, 1
        ret
        not_at_end:
        cmp dword ptr [esp+24], offset new_strings + NEW_STRING_COUNT * 4
        jne not_at_new_end
        ret
      }
}

// Rewrite an MM7Patch fix that was keyed to the old global.txt end.
// Is this... metahacking?
static void __declspec(naked) new_global_txt_parse_check(void)
{
    asm
      {
        cmp dword ptr [esp+28], offset new_strings + NEW_STRING_COUNT * 4
        je quit
        push 0x4cc17b
        quit:
        ret
      }
}

// Fetch the MM7Patch string for "energy".
static char *__thiscall __declspec(naked) patch_energy(int address)
{
    asm
      {
        mov eax, ENERGY
        push eax
        call ecx
        pop eax
        ret
      }
}

// Instead of replacing every instance of e.g. "water" with "cold",
// overwrite string pointers themselves.  Note that spell school names
// are stored separately by now and are thus not affected.
// Also here: populate the element names array and localize Telepathy.
static void new_element_names(void)
{
    // fire is unchanged
    GLOBAL_TXT[6] = GLOBAL_TXT[71]; // electricity
    GLOBAL_TXT[240] = GLOBAL_TXT[43]; // cold
    GLOBAL_TXT[70] = GLOBAL_TXT[166]; // poison
    GLOBAL_TXT[214] = new_strings[STR_HOLY];
    // mind is unchanged
    GLOBAL_TXT[29] = GLOBAL_TXT[138]; // magic
    // light and dark are not displayed anymore
    element_names[FIRE] = GLOBAL_TXT[87];
    element_names[SHOCK] = GLOBAL_TXT[71];
    element_names[COLD] = GLOBAL_TXT[43];
    element_names[POISON] = GLOBAL_TXT[166];
    element_names[PHYSICAL] = element_names[PHYS_SPELL] = GLOBAL_TXT[624];
    element_names[HOLY] = new_strings[STR_HOLY];
    element_names[MIND] = GLOBAL_TXT[142];
    element_names[MAGIC] = GLOBAL_TXT[138];
    static char fire_physical[20];
    sprintf(fire_physical, "%s/\n%s",
            element_names[FIRE], element_names[PHYSICAL]);
    element_names[DRAGONFIRE] = fire_physical;
    element_names[ENERGY] = patch_energy(dword(0x41ef90) + 0x41ef94 + 12);
    // Localize Telepathy output strings.
    patch_pointer(0x42c3cd, new_strings[STR_TELEPATHY_ITEM]);
    patch_pointer(0x42c3e1, new_strings[STR_TELEPATHY_GOLD]);
    patch_pointer(0x42c410, new_strings[STR_TELEPATHY_NOTHING]);
}

// We need to do a few things after global.txt is parsed.
static void __declspec(naked) global_txt_tail(void)
{
    asm
      {
        mov dword ptr [0x5067f4], eax
        call new_element_names
        ret
      }
}

// Messing with global.txt.
static inline void global_txt(void)
{
    hook_call(0x452d41, read_global_txt, 8);
    hook_call(0x452d3a, new_global_txt_parse_check, 5);
    hook_call(0x45386a, global_txt_tail, 5);
}

static void throw_potions_jump(void); // defined below
static uintptr_t check_inactive_player;

// Add elemental immunity potions and the pain reflection potion.
// Magic immunity lasts 3 min/level, the rest are 10 min/level.
// The potion of Divine Mastery is also here.
// Also here: forbid using potions by recovering PCs (depends on MM7Patch).
static void __declspec(naked) new_potion_effects(void)
{
    asm
      {
        mov ebx, edx
        mov ecx, dword ptr [ebp-4]
        call dword ptr ds:check_inactive_player
        test eax, eax
        jnz ok
        mov eax, 0x4685f6 ; inactive pc code
        jmp eax
        ok:
        mov edx, ebx
        lea eax, [edx-POTION_BOTTLE]
        mov ecx, 3 ; just in case
        xor ebx, ebx
        cmp edx, LAST_OLD_POTION
        ja new
        jmp dword ptr [0x468ebe+eax*4]
        new:
        cmp edx, HOLY_WATER
        je throw_potions_jump
        cmp edx, POTION_ULTIMATE_CURE
        je ultimate_cure
        cmp edx, POTION_PAIN_REFLECTION
        je pain_reflection
        mov ecx, dword ptr [ebp+8] ; pc id
        dec ecx
        imul ecx, ecx, NBUFF_COUNT * SIZE_BUFF
        lea eax, [edx*4+NBUFF_FIRE_IMM*4-POTION_FIRE_IMMUNITY*4]
        lea ecx, [elemdata.new_pc_buffs+ecx+eax*4]
        jmp got_buff
        pain_reflection:
        lea ecx, [esi+PBUFF_PAIN_REFLECTION*SIZE_BUFF].s_player.spell_buffs
        got_buff:
        push ebx
        push ebx
        cmp edx, POTION_DIVINE_MASTERY
        je divine_mastery
        push ebx
        push GM ; black = gm, not that it matters much
        cmp edx, POTION_MAGIC_IMMUNITY
        je magic
        mov edx, 10 * MINUTE
        jmp multiply
        magic:
        mov edx, 3 * MINUTE
        jmp multiply
        divine_mastery:
        mov eax, dword ptr [MOUSE_ITEM].s_item.bonus ; potion power
        xor edx, edx
        mov edi, 5 ; unused at this point
        div edi
        inc eax
        push eax
        push GM
        mov edx, 30 * MINUTE
        multiply:
        mov eax, dword ptr [MOUSE_ITEM].s_item.bonus
        mul edx
        add eax, dword ptr [CURRENT_TIME_ADDR]
        adc edx, dword ptr [CURRENT_TIME_ADDR+4]
        push edx
        push eax
        call dword ptr ds:add_buff
        quit:
        push 0x4687a8
        ret
        ultimate_cure:
        mov ecx, esi
        call dword ptr ds:get_full_hp
        sub eax, dword ptr [esi].s_player.hp
        jle quit
        add eax, dword ptr [MOUSE_ITEM].s_item.bonus
        push eax
        mov ecx, esi
        push 0x4687a8 ; this return address enables overheal
        jmp dword ptr ds:heal_hp
      }
}

// Pretend the new potions are Rejuvenation (271) for purposes of mixing.
// Black potions always explode anyway, so the separate logic is unneeded.
static void __declspec(naked) mix_new_potions_1(void)
{
    asm
      {
        cmp ecx, LAST_POTION
        jg quit
        cmp ecx, LAST_OLD_POTION
        jng quit
        mov ecx, LAST_OLD_POTION
        cmp ecx, ecx
        quit:
        ret
      }
}

// Ditto, but substitute Pure Might instead if mixing two different
// new potions.  Otherwise they wouldn't explode (nor mix at all).
static void __declspec(naked) mix_new_potions_2(void)
{
    asm
      {
        cmp edx, LAST_POTION
        jg quit
        cmp edx, LAST_OLD_POTION
        jng quit
        cmp edx, dword ptr [MOUSE_ITEM]
        je okay
        cmp ecx, LAST_OLD_POTION
        jne okay
        mov edx, LAST_OLD_POTION - 1
        ret ; zf is set
        okay:
        mov edx, LAST_OLD_POTION
        cmp edx, edx
        quit:
        ret
      }
}

// Pre-identify sold recipes.  Non-consequental in vanilla, but I want the type
// of all recipes to be just "Recipe" and this allows still showing their name.
static void __declspec(naked) identify_recipes(void)
{
    asm
      {
        mov dword ptr [SHOP_SPECIAL_ITEMS+eax*4], edx ; replaced code
        or byte ptr [SHOP_SPECIAL_ITEMS+eax*4].s_item.flags, IFLAGS_ID
        ret
      }
}

// Add a Raise Dead black potion (replaces Stone to Flesh).
static void __declspec(naked) raise_dead_potion(void)
{
    asm
      {
        mov eax, dword ptr [esi+COND_DEAD*8]
        or eax, dword ptr [esi+COND_DEAD*8+4]
        jz quit
        mov dword ptr [esi+COND_DEAD*8], ebx ; == 0
        mov dword ptr [esi+COND_DEAD*8+4], ebx
        mov dword ptr [esi+COND_UNCONSCIOUS*8], ebx
        mov dword ptr [esi+COND_UNCONSCIOUS*8+4], ebx
        mov ecx, esi
        call dword ptr ds:get_full_hp
        cmp eax, dword ptr [MOUSE_ITEM].s_item.bonus ; potion power
        cmova eax, dword ptr [MOUSE_ITEM].s_item.bonus
        mov dword ptr [esi].s_player.hp, eax
        push ebx ; cannot resist
        push COND_WEAK
        mov ecx, esi
        call inflict_condition
        quit:
        push 0x468da0 ; post-drink code
        ret
      }
}

// Text color for the new player buffs.  Used just below.
static const uint8_t new_buff_colors[NBUFF_COUNT][3] = {
      { 0xff, 0x55, 0x00 }, // fire
      { 0x96, 0xd4, 0xff }, // air
      { 0x00, 0x80, 0xff }, // water
      { 0xff, 0x80, 0x00 }, // body
      { 0xeb, 0x0f, 0xff }, // mind
      { 0x80, 0x80, 0x80 }, // earth
      { 0xeb, 0x0f, 0xff }, // mind
      { 0xff, 0xff, 0x9b }, // light
      { 0x00, 0x80, 0xff }, // water
};

// Inject the new player buffs into the loop for buff duration window.
static void __declspec(naked) display_new_buffs(void)
{
    asm
      {
        cmp dword ptr [ebp-4], 0x506798 + 24 * 4 ; replaced code
        jl skip
        jg new
        mov dword ptr [ebp-4], offset new_strings + STR_FIRE_IMM * 4
        sub edx, PARTY_ADDR ; this only works because it`s offset
        shr edx, 13 ; now we have pc number
        imul edx, edx, NBUFF_COUNT * SIZE_BUFF
        add edx, offset elemdata.new_pc_buffs
        mov edi, offset new_buff_colors + 1
        new:
        cmp dword ptr [ebp-4], offset new_strings + STR_ANCHORED_MANA * 4 + 4
        skip:
        ret
      }
}

// We also need to account for new buffs when precalculating window height.
static void __declspec(naked) count_new_buffs(void)
{
    asm
      {
        mov eax, dword ptr [edi+28] ; pc id
        mov ebx, NBUFF_COUNT
        mul ebx
        shl eax, 4
        add eax, offset elemdata.new_pc_buffs
        loop:
        cmp dword ptr [eax], edx
        jnz yes
        cmp dword ptr [eax+4], edx
        jz no
        yes:
        inc ecx
        no:
        add eax, SIZE_BUFF
        dec ebx
        jnz loop
        mov eax, dword ptr [ARRUS_FNT] ; replaced code
        ret
      }
}

// Check new buff expiration time each tick, same as with vanilla ones.
static void __declspec(naked) expire_new_buffs(void)
{
    asm
      {
        mov eax, dword ptr [esp+28] ; pc pointer
        sub eax, PC_POINTERS ; now we got pc number x4
        mov ebp, NBUFF_COUNT
        mul ebp
        lea edi, [elemdata.new_pc_buffs+eax*4]
        loop:
        push dword ptr [CURRENT_TIME_ADDR+4]
        push dword ptr [CURRENT_TIME_ADDR]
        mov ecx, edi
        call dword ptr ds:expire_buff
        add edi, SIZE_BUFF
        dec ebp
        jnz loop
        lea edi, [esi].s_player.spell_buffs ; replaced code
        ret
      }
}

// Shared code for the two hooks below.
static void __declspec(naked) remove_new_buffs(void)
{
    asm
      {
        shl eax, 1
        mov ebx, NBUFF_COUNT
        mul ebx
        lea edi, [elemdata.new_pc_buffs+eax*8]
        loop:
        mov ecx, edi
        call dword ptr ds:remove_buff
        add edi, SIZE_BUFF
        dec ebx
        jnz loop
        ret
      }
}

// Also remove the new buffs when resting, training, travelling etc.
static void __declspec(naked) reset_new_buffs(void)
{
    asm
      {
        call dword ptr ds:reset_stat_boni ; replaced call
        mov eax, dword ptr [ebp-4] ; pc id
        jmp remove_new_buffs
      }
}

// Finally, make them subject to monster Dispel Magic.
static void __declspec(naked) dispel_new_buffs(void)
{
    asm
      {
        mov eax, dword ptr [ebp+16] ; pc id (1-4)
        dec eax
        jmp remove_new_buffs
      }
}

// Add Divine Mastery buff power to temporary level.
static void __declspec(naked) divine_mastery_effect(void)
{
    asm
      {
        movsx eax, word ptr [esi].s_player.level_base ; replaced code
        add edi, eax ; add to total
        sub esi, PARTY_ADDR - 0x1000
        shr esi, 13 ; got pc id
        imul esi, esi, NBUFF_COUNT * SIZE_BUFF
        mov ax, word ptr [elemdata.new_pc_buffs+esi \
                          +NBUFF_DIVINE_MASTERY*SIZE_BUFF].s_spell_buff.power
        movsx eax, ax
        ret
      }
}

// Add new (black) potions and rearrange others.  Also some holy water code.
// We extend character buffs here, which is later used by Aura of Conflict.
static inline void new_potions(void)
{
    // holy water is handled below but the jump is here
    patch_byte(0x46878a, HOLY_WATER - POTION_BOTTLE);
    check_inactive_player = dword(0x4685ee) + 0x4685f2; // get mmpatch hook
    hook_jump(0x468791, new_potion_effects);
    hook_call(0x4163b1, mix_new_potions_1, 6);
    hook_call(0x4163d7, mix_new_potions_2, 6);
    patch_byte(0x4b8fd4, LAST_RECIPE - FIRST_RECIPE + 1); // sell new recipes
    patch_dword(0x490f1f, LAST_RECIPE); // allow selling new recipes
    patch_dword(0x4bda2b, LAST_RECIPE); // ditto
    hook_call(0x4b8ff1, identify_recipes, 7);
    // Rearrange some potion effects.
    int awaken = dword(0x468eda);
    patch_dword(0x468eda, dword(0x468eca)); // swap with magic potion
    patch_dword(0x468eca, awaken); // ditto
    patch_byte(0x4687be, 5); // nerf magic potions (5 less SP per potion)
    patch_dword(0x468ef2, dword(0x468f3a)); // recharge now cures paralysis
    patch_dword(0x468f3a, dword(0x468f66)); // cure paralysis -> stone to flesh
    patch_pointer(0x468f66, raise_dead_potion); // stone to flesh -> raise dead
    hook_call(0x41d69b, display_new_buffs, 7);
    hook_call(0x41d3a7, count_new_buffs, 5);
    hook_call(0x494636, expire_new_buffs, 6);
    hook_call(0x490d48, reset_new_buffs, 5);
    hook_call(0x4054bc, dispel_new_buffs, 5);
    hook_call(0x48c916, divine_mastery_effect, 7);
}

// We now store a temporary enchantment in the bonus strength field,
// with the bonus ID set to 0xff.  The following patches
// make the game ignore this ID where appropriate.
// The first one deals with the displayed name.
static void __declspec(naked) ignore_temp_ench_name(void)
{
    asm
      {
        cmp dword ptr [esi].s_item.bonus, eax ; replaced code (eax == 0)
        jz ignore
        cmp dword ptr [esi].s_item.bonus, TEMP_ENCH_MARKER
        jnz quit
        ignore:
        push 0x4565b2
        ret 4
        quit:
        ret
      }
}

// This one deals with description.  (See also display_temp_enchant below.)
static void __declspec(naked) ignore_temp_ench_desc(void)
{
    asm
      {
        mov eax, dword ptr [ecx].s_item.bonus ; replaced code
        cmp eax, TEMP_ENCH_MARKER
        jz quit
        cmp eax, ebx ; also replaced
        quit:
        ret
      }
}

// Next, we handle the price.
static void __declspec(naked) ignore_temp_ench_price(void)
{
    asm
      {
        cmp dword ptr [esi].s_item.bonus, eax ; replaced code (eax == 0)
        jz ignore
        cmp dword ptr [esi].s_item.bonus, TEMP_ENCH_MARKER
        jnz quit
        ignore:
        push 0x4564a2
        ret 4
        quit:
        ret
      }
}

// Finally, let's allow the Enchant Item spell to enchant such weapons.
static void __declspec(naked) ignore_temp_ench_enchant_item(void)
{
    asm
      {
        jz quit
        cmp dword ptr [edi].s_item.bonus, TEMP_ENCH_MARKER
        quit:
        ret
      }
}

// Used just below, to store the two-handed check result.
static int extra_temp_damage;

// Replace the calls to the weapon elemental damage function with
// our code that calls it twice, for both permanent and temporary bonus.
// Also here: increase elemental damage done by two-handed weapons.
static void __declspec(naked) temp_elem_damage(void)
{
    asm
      {
        push ecx
        push eax
        call dword ptr ds:elem_damage
        pop ecx
        mov edx, dword ptr [ecx]
        lea edx, [edx+edx*2]
        shl edx, 4
        and dword ptr [extra_temp_damage], 0
        cmp byte ptr [ITEMS_TXT_ADDR+edx].s_items_txt_item.equip_stat, \
            ITEM_TYPE_WEAPON2 - 1
        jne one_handed
        cmp byte ptr [ITEMS_TXT_ADDR+edx].s_items_txt_item.skill, SKILL_SWORD
        je two_handed
        cmp byte ptr [ITEMS_TXT_ADDR+edx].s_items_txt_item.skill, SKILL_AXE
        jne one_handed
        two_handed:
        cmp dword ptr [ebp-8], POISON
        je poison
        push eax
        push ecx
        call dword ptr ds:random
        test eax, 2
        jz no_temp
        inc dword ptr [extra_temp_damage]
        no_temp:
        and eax, 1
        jz skip
        mov ecx, dword ptr [esp]
        push eax
        mov edx, esp
        push eax
        push esp
        call dword ptr ds:elem_damage
        pop ecx
        pop ecx
        skip:
        pop ecx
        pop edx
        add eax, edx
        jmp one_handed
        poison:
        lea eax, [eax+eax*2]
        inc eax
        shr eax, 1
        inc dword ptr [extra_temp_damage]
        one_handed:
        cmp dword ptr [ecx].s_item.bonus, TEMP_ENCH_MARKER
        jne quit
        push eax
        xor edx, edx
        push edx
        push edx
        sub esp, SIZE_ITEM - 4
        push 1
        and dword ptr [esp].s_item.flags, 0
        mov ecx, dword ptr [ecx].s_item.bonus_strength
        mov dword ptr [esp].s_item.bonus2, ecx
        mov ecx, esp
        lea edx, [esp+SIZE_ITEM]
        lea eax, [esp+SIZE_ITEM+4]
        push eax
        call dword ptr ds:elem_damage
        cmp dword ptr [extra_temp_damage], 0
        jz no_extra
        cmp dword ptr [esp+SIZE_ITEM], POISON
        je poison_temp
        mov ecx, esp
        push eax
        push eax
        mov edx, esp
        push eax
        push esp
        call dword ptr ds:elem_damage
        pop ecx
        pop ecx
        pop ecx
        add eax, ecx
        jmp no_extra
        poison_temp:
        lea eax, [eax+eax*2]
        inc eax
        shr eax, 1
        no_extra:
        add esp, SIZE_ITEM
        pop ecx
        pop edx
        or dword ptr [ebp-16], edx
        push eax
        push ecx
        push esi
        call dword ptr ds:monster_resists
        add dword ptr [ebp-12], eax
        pop eax
        quit:
        ret 4
      }
}

// The projectile damage code needs an extra instruction.
static void __declspec(naked) bow_temp_damage(void)
{
    asm
      {
        and dword ptr [ebp-12], 0
        jmp temp_elem_damage
      }
}

// Check for temporary swiftness enchantments.
// Also here: implement Viper and the Perfect Bow's Swift properties.
static void __declspec(naked) temp_swiftness(void)
{
    asm
      {
        cmp dword ptr [edx].s_item.bonus, TEMP_ENCH_MARKER
        jne no_temp
        mov ecx, dword ptr [edx].s_item.bonus_strength
        cmp ecx, SPC_SWIFT
        je swift
        cmp ecx, SPC_DARKNESS
        je swift
        no_temp:
        cmp dword ptr [edx], VIPER
        je swift
        cmp dword ptr [edx], THE_PERFECT_BOW
        je swift
        mov ecx, dword ptr [edx].s_item.bonus2 ; replaced code
        cmp ecx, SPC_SWIFT ; also replaced
        swift:
        ret
      }
}

// Make sure there are no lingering temp enchants
// before checking for undead slaying / spectral / etc.
static void __declspec(naked) expire_weapon(void)
{
    asm
      {
        lea ebx, [edi+eax*4-SIZE_ITEM].s_player.items
        mov ecx, ebx
        push dword ptr [CURRENT_TIME_ADDR+4]
        push dword ptr [CURRENT_TIME_ADDR]
        call dword ptr ds:expire_temp_bonus
        ret
      }
}

// Additional item info paragraphs.
static char enchant_buffer[100], charge_buffer[100];

// Print the temp enchantment description and/or remaining knives.
static void __declspec(naked) display_temp_enchant(void)
{
    asm
      {
        add dword ptr [ebp-8], 100
        skip:
        dec dword ptr [ebp-24]
        jz quit
        cmp dword ptr [ebp-24], 1
        jne not_knives
        mov ecx, dword ptr [ebp-4]
        cmp dword ptr [ecx], THROWING_KNIVES
        je knives
        cmp dword ptr [ecx], LIVING_WOOD_KNIVES
        jne skip
        knives:
        mov dword ptr [ebp-8], offset charge_buffer
        jmp pass
        not_knives:
        cmp dword ptr [ebp-24], 2
        jne quit
        mov ecx, dword ptr [ebp-4]
        cmp dword ptr [ecx+4], TEMP_ENCH_MARKER
        jne skip
        mov dword ptr [ebp-8], offset enchant_buffer
        pass:
        cmp ebx, 1
        quit:
        ret
      }
}

// New buffer for enchantment data.  Mostly used in spcitems_buffer() below.
static struct spcitem spcitems[SPC_COUNT];

// Formats for displaying wand charges or knives.
static const char nonzero_charges[] = "%s: %u/%u";
static const char zero_charges[] = "\f%05d%s: 0/%u";

// Defined below.
static char *__thiscall two_handed_bonus_desc(struct item *, int);

// Adjust description screen height to fit the new lines.
// Also compose the lines themselves while we're at it.
static void __declspec(naked) temp_enchant_height(void)
{
    asm
      {
        add dword ptr [ebp-12], 100
        skip:
        dec dword ptr [ebp-24]
        jz quit
        cmp dword ptr [ebp-24], 1
        jne not_knives
        mov ecx, dword ptr [ebp-4]
        cmp dword ptr [ecx], THROWING_KNIVES
        je knives
        cmp dword ptr [ecx], LIVING_WOOD_KNIVES
        jne skip
        knives:
        movzx eax, byte ptr [ecx].s_item.max_charges
        push eax
        mov edx, dword ptr [ecx].s_item.charges
        test edx, edx
        jz zero
        push edx
        zero:
        push dword ptr [new_strings+STR_KNIVES*4]
        jnz nonzero
        push dword ptr [colors+CLR_RED*4]
#ifdef __clang__
        ; for some reason clang crashes if I try to push offsets directly
        mov eax, offset zero_charges
        jmp buffer
        nonzero:
        mov eax, offset nonzero_charges
        buffer:
        push eax
        mov eax, offset charge_buffer
        push eax
#else
        push offset zero_charges
        jmp buffer
        nonzero:
        push offset nonzero_charges
        buffer:
        push offset charge_buffer
#endif
        call dword ptr ds:sprintf
        add esp, 20
        mov dword ptr [ebp-12], offset charge_buffer
        jmp pass
        not_knives:
        cmp dword ptr [ebp-24], 2
        jne quit
        mov ecx, dword ptr [ebp-4]
        cmp dword ptr [ecx].s_item.bonus, TEMP_ENCH_MARKER
        jne skip
        push ecx
        call two_handed_bonus_desc
        push eax
        push dword ptr [new_strings+STR_TEMPORARY*4]
        push 0x4e2e80
#ifdef __clang__
        mov eax, offset enchant_buffer
        push eax
#else
        push offset enchant_buffer
#endif
        call dword ptr ds:sprintf
        add esp, 16
        mov dword ptr [ebp-12], offset enchant_buffer
        pass:
        cmp ebx, 1
        quit:
        ret
      }
}

// Rules for temporary enchantments: weapons that already
// have a similar elemental/slaying/etc. ability are forbidden;
// items with a numeric bonus also cannot get a temp enchantment.
// Bows of carnage can be enchanted by swift potions only.
static int __thiscall can_add_temp_enchant(struct item *weapon, int enchant)
{
    if (weapon->bonus || weapon->bonus2 == SPC_CARNAGE && enchant != SPC_SWIFT)
        return FALSE;
    int element, old_element, vampiric = FALSE, damage;
    switch (enchant)
      {
        case SPC_FIRE:
        case SPC_FLAME:
        case SPC_INFERNOS:
            element = FIRE;
            goto elemental;
        case SPC_LIGHTNING:
            element = SHOCK;
            goto elemental;
        case SPC_ICE:
            element = COLD;
            goto elemental;
        case SPC_VENOM:
            element = POISON;
            goto elemental;
        case SPC_VAMPIRIC:
            element = 10; // old dark
        elemental:
            damage = elem_damage(weapon, &old_element, &vampiric);
            return element != old_element || !damage && !vampiric;
        case SPC_SPECTRAL:
            if (weapon->id == SWORD_OF_LIGHT || weapon->id == FLATTENER
                || weapon->bonus2 == SPC_WRAITH)
                return FALSE;
            goto dupe;
        case SPC_SWIFT:
            if (weapon->id == PUCK || weapon->bonus2 == SPC_DARKNESS
                || ITEMS_TXT[weapon->id].skill == SKILL_UNARMED)
                return FALSE;
            goto dupe;
        case SPC_UNDEAD_SLAYING:
            if (weapon->id == GHOULSBANE || weapon->id == JUSTICE)
                return FALSE;
            // else fallthrough
        case SPC_DRAGON_SLAYING:
            if (weapon->id == GIBBET)
                return FALSE;
        dupe:
            return weapon->bonus2 != enchant;
        default: // just in case
            return FALSE;
      }
}

// Handle weapon-enchanting spells.  If an artifact or an enchanted item
// is targeted by a GM-level spell, it's enchanted temporarily.
// Also here: nerf price of weapons enchanted by GM Fire Aura.
static void __declspec(naked) enchant_weapon(void)
{
    asm
      {
        jnz temporary
        cmp dword ptr [ebp-24], GM
        jne temporary
        cmp dword ptr [esi].s_item.bonus2, 0
        jnz temporary
        mov eax, dword ptr [esp+4]
        cmp eax, SPC_INFERNOS
        jne ok
        mov eax, SPC_INFERNOS_2
        ok:
        mov dword ptr [esi].s_item.bonus2, eax
        xor eax, eax ; set zf
        ret 4
        temporary:
        mov ecx, esi
        push dword ptr [esp+4]
        call can_add_temp_enchant
        test eax, eax
        jz fail
        mov dword ptr [esi].s_item.bonus, TEMP_ENCH_MARKER
        mov eax, dword ptr [esp+4]
        mov dword ptr [esi].s_item.bonus_strength, eax
        test eax, eax
        ret 4
        fail:
        xor esi, esi
        push 0x4290a7
        ret 12
      }
}

// Rehaul Fire Aura according to the above rules.
// Spectral Weapon code also arrives here.
static void __declspec(naked) fire_aura(void)
{
    asm
      {
        mov esi, dword ptr [ebp-28]
        push dword ptr [ebp-4]
        call enchant_weapon
        ret
      }
}

// Rehaul Vampiric Weapon.
static void __declspec(naked) vampiric_weapon(void)
{
    asm
      {
        mov esi, dword ptr [ebp-12]
        push SPC_VAMPIRIC
        call enchant_weapon
        ret
      }
}

// We need these for the belt bonus.
static const float f1_25 = 1.25;
static const float f1_5 = 1.5;

// Make the new checks for the weapon-enchanting potions.
// Also handles holy water.  Gadgeteer's Belt's bonus is also applied here.
static void __declspec(naked) weapon_potions(void)
{
    asm
      {
        mov ebx, eax
        cmp ebx, SPC_VAMPIRIC
        jae not_elem
        inc ebx ; buff elemental enchants a little
        not_elem:
        push ebx
        mov ecx, esi
        call can_add_temp_enchant
        test eax, eax
        jz fail
        mov dword ptr [esi].s_item.bonus, TEMP_ENCH_MARKER
        mov dword ptr [esi].s_item.bonus_strength, ebx
        fmul dword ptr [0x4d8470]
        mov ecx, dword ptr [CURRENT_PLAYER]
        mov ecx, dword ptr [PC_POINTERS+ecx*4-4]
        mov bh, byte ptr [ecx].s_player.class
        push SLOT_BELT
        push GADGETEERS_BELT
        call dword ptr ds:has_item_in_slot
        test eax, eax
        jz quit
        and bh, -4
        cmp bh, CLASS_THIEF
        je thief
        fmul dword ptr [f1_25]
        ret
        thief:
        fmul dword ptr [f1_5]
        quit:
        ret
        fail:
        fstp st(0)
        push 0x41677e
        ret 4
      }
}

// Let the enchantment aura of weapon potions vary in color.
static void __declspec(naked) potion_aura(void)
{
    asm
      {
        mov eax, dword ptr [ebp-12] ; replaced code
        or al, 8 ; temp bonus bit
        mov cl, 16
        cmp bl, SPC_INFERNOS
        je red
        cmp bl, SPC_LIGHTNING
        je purple
        cmp bl, SPC_ICE
        je blue
        cmp bl, SPC_VENOM
        je green
        cmp bl, SPC_SWIFT
        je green
        cmp bl, SPC_DRAGON_SLAYING
        je red
        cmp bl, SPC_UNDEAD_SLAYING
        je blue
        purple:
        shl cl, 1
        green:
        shl cl, 1
        blue:
        shl cl, 1
        red:
        or al, cl
        ret
      }
}

// Prevent the game from applying the enchantment too early and in the wrong
// place.  This also takes care of magic embers (that are similar in effect).
static void __declspec(naked) slaying_potion_enchantment(void)
{
    asm
      {
        cmp dword ptr [MOUSE_ITEM], MAGIC_EMBER
        jne dragon
        mov eax, SPC_FLAME ; will be increased later
        mov dword ptr [ebp-20], 24 * 60 * 60 * 128 ; one day (divided later)
        ret
        dragon:
        mov eax, SPC_DRAGON_SLAYING
        ret
      }
}

// Allow slaying potions to enchant weapons permanently if possible.
// Also here: do the same for magic embers which reuse this code.
static void __declspec(naked) permanent_slaying(void)
{
    asm
      {
        jnz quit
        mov ecx, ITEMS_TXT_ADDR - 4
        push esi
        call dword ptr ds:is_artifact
        test eax, eax
        jnz quit
        cmp dword ptr [ebp-4], ITEM_TYPE_MISSILE - 1
        jbe ok
        cmp dword ptr [ebp-4], ITEM_TYPE_GAUNTLETS - 1
        jne quit
        mov edx, dword ptr [esi]
        lea edx, [edx+edx*2]
        shl edx, 4
        cmp byte ptr [ITEMS_TXT_ADDR+edx].s_items_txt_item.skill, SKILL_UNARMED
        jne quit
        ok:
        cmp dword ptr [MOUSE_ITEM], MAGIC_EMBER
        jne dragon
        mov dword ptr [esi].s_item.bonus2, SPC_INFERNOS_2 ; as gm fire aura
        jmp aura
        dragon:
        mov dword ptr [esi].s_item.bonus2, SPC_DRAGON_SLAYING
        aura:
        or dword ptr [esi].s_item.flags, 16 ; red aura
        push 0x4168b4
        ret 4
        quit:
        ret
      }
}

// Allow weapons to have two enchantments at once, one permanent
// and one temporary.  Only some temporary enchantments are supported.
static inline void temp_enchants(void)
{
    hook_call(0x456593, ignore_temp_ench_name, 5);
    hook_call(0x41ddb5, ignore_temp_ench_desc, 5);
    hook_call(0x456495, ignore_temp_ench_price, 5);
    hook_call(0x42ab7d, ignore_temp_ench_enchant_item, 9); // GM
    hook_call(0x42ae0d, ignore_temp_ench_enchant_item, 9); // master
    // there's still some MM6 code for expert and normal enchant item,
    // but it's practically unreachable and doesn't enchant weapons anyway
    hook_call(0x43992b, bow_temp_damage, 5); // bow or other projectile
    patch_byte(0x439983, 0x01); // mov -> add
    hook_call(0x4399bc, temp_elem_damage, 5); // melee weapon(s)
    hook_call(0x48e4b4, temp_swiftness, 6);
    patch_word(0x48d20e, 0xdf89); // mov edi, ebx
    hook_call(0x48d210, expire_weapon, 5);
    // melee damage code is repeated for either hand
    hook_call(0x48ce11, expire_weapon, 7);
    hook_call(0x48cf42, expire_weapon, 7);
    hook_call(0x41e025, display_temp_enchant, 7);
    patch_dword(0x41dfe5, 5); // two more cycles
    hook_call(0x41de8d, temp_enchant_height, 7);
    patch_dword(0x41de37, 5); // ditto
    hook_call(0x429122, fire_aura, 15);
    erase_code(0x4290f7, 10); // remove old enchantment checks
    erase_code(0x42901a, 12); // make GM fall through to M WRT duration
    hook_call(0x42de58, vampiric_weapon, 20);
    erase_code(0x42de21, 18); // remove old enchantment checks
    erase_code(0x42dda3, 5); // make GM fall through to M WRT duration
    // erase bonus number instead of special bonus on enchantment expire
    patch_byte(0x4582bc, 8);
    hook_call(0x41688e, weapon_potions, 6);
    hook_call(0x4168a9, potion_aura, 5);
    // remove some of the old restrictions
    erase_code(0x416872, 12); // overwrites an mm7patch change
    erase_code(0x41690b, 9); // ditto
    erase_code(0x416932, 12); // and here
    // pass the enchantment to our code in eax
    hook_call(0x416884, slaying_potion_enchantment, 7);
    hook_call(0x41684e, permanent_slaying, 6); // also ow's mm7patch
    erase_code(0x416953, 3);
}

// Compound buff potions like Bless or Stoneskin always granted the minimal
// possible bonus (+5, corresponding to the spell skill of 0), irrespective
// of the potion's power.  Now this bonus is increased by half the power.
// Also here: increase all buff power and duration if Gadgeteer's Belt is worn.
static void __declspec(naked) buff_potions_power(void)
{
    asm
      {
        push ecx
        mov ecx, esi
        push SLOT_BELT
        push GADGETEERS_BELT
        call dword ptr ds:has_item_in_slot
        pop ecx
        mov ah, byte ptr [esi].s_player.class
        and ah, -4
        mov edx, dword ptr [MOUSE_ITEM].s_item.bonus
        cmp dword ptr [esp+12], MASTER
        jne resistance
        cmp dword ptr [esp+16], 5
        jne resistance
        shr edx, 1
        add dword ptr [esp+16], edx
        jmp bonus
        resistance:
        mov edx, dword ptr [esp+16]
        bonus:
        test al, al
        jz quit
        shr edx, 1
        cmp ah, CLASS_THIEF
        je half
        shr edx, 1
        half:
        add dword ptr [esp+16], edx
        mov edx, dword ptr [MOUSE_ITEM].s_item.bonus
        cmp ah, CLASS_THIEF
        mov eax, 30 * MINUTE / 4 ; quarter of half hour
        jne quarter
        add eax, eax
        quarter:
        mul edx
        add dword ptr [esp+4], eax
        adc dword ptr [esp+8], edx
        quit:
        jmp dword ptr ds:add_buff ; replaced call
      }
}

// From parsing potion.txt and potnotes.txt, sorted by the resulting potion.
static struct recipe {
    int count;
    struct variant {
        int left, right;
        int note;
    } variants[3];
} recipes[LAST_POTION+1-FIRST_COMPLEX_POTION];

// Fill the recipes array.  I wanted to make this fastcall, but clang is buggy.
static void __stdcall add_recipe(int result, int note, int row, int column)
{
#ifdef CHECK_OVERWRITE
    return; // no idea why, but it crashes here
#endif
    struct recipe *this = &recipes[result-FIRST_COMPLEX_POTION];
    for (int i = 0; i < this->count; i++)
        if (note == this->variants[i].note)
            return;
    this->variants[this->count] = (struct variant) { row + FIRST_POTION,
                                                     column + FIRST_POTION,
                                                     note };
    this->count++;
}

// Called for each cell in potnotes.txt.
static void __declspec(naked) maybe_add_recipe(void)
{
    asm
      {
        movzx edx, word ptr [esi]
        test edx, edx
        jz empty
        movzx ecx, word ptr [esi-5000]
        push dword ptr [ebp-4]
        push dword ptr [ebp-12]
        push edx
        push ecx
        call add_recipe
        empty:
        inc dword ptr [ebp-4]
        cmp dword ptr [ebp-4], 50
        ret
      }
}

// Represents a full chain of alchemical mixes.  The resulting potion ID
// is in the function's context.
struct brew {
    uint32_t unused_items[5];
    unsigned int power;
    int used_reagents;
    int used_bottles;
    int produced_bottles;
};

// Guts of the autobrew, called recursively.  Positive return: number of
// alternative brews.  Negative: ID of unbrewable potion.
static int recursive_brew(struct player *player, int potion,
                          uint32_t unused_items[5], struct brew *brews)
{
    if (potion < FIRST_COMPLEX_POTION)
      {
        // gray, red, blue, or yellow potion
        int first_reagent;
        if (potion == CATALYST)
            first_reagent = FIRST_GRAY_REAGENT;
        else
            first_reagent = (potion - FIRST_POTION) * 5 + FIRST_REAGENT;
        for (int i = 1; i <= PLAYER_MAX_ITEMS; i++)
          {
            if (!(unused_items[i>>5] & (1 << (i & 31))))
                continue;
            int id = player->items[i-1].id;
            if (id >= first_reagent && id < first_reagent + 5)
              {
                memcpy(brews[0].unused_items, unused_items, 4*5);
                brews[0].unused_items[i>>5] &= ~(1 << (i & 31));
                int power = ITEMS_TXT[id].mod1_dice_count;
                int skill = get_skill(player, SKILL_ALCHEMY) & SKILL_MASK;
                brews[0].power = power + skill;
                if (power < skill) // like in alchemy_soft_cap()
                    brews[0].power = brews[0].power / 2 + power;
                brews[0].used_reagents = 1;
                brews[0].used_bottles = 1;
                brews[0].produced_bottles = 0;
                return 1;
              }
          }
        return -potion;
      }

    int brew_count = 0;
    // we're relying on the fact that any potion
    // is brewn from potions with lower numeric IDs
    int unbrewable = potion;
    for (int i = 0; i < recipes[potion-FIRST_COMPLEX_POTION].count; i++)
      {
        int note = recipes[potion-FIRST_COMPLEX_POTION].variants[i].note;
        if (!check_bit(AUTONOTES, note))
            continue;
        int left = 0, right = 0;
        int rcleft = recipes[potion-FIRST_COMPLEX_POTION].variants[i].left;
        int rcright = recipes[potion-FIRST_COMPLEX_POTION].variants[i].right;
        // prefer pre-existing potions if present
        for (int j = 1; j <= PLAYER_MAX_ITEMS; j++)
          {
            if (!(unused_items[j>>5] & (1 << (j & 31))))
                continue;
            if (!left && rcleft == player->items[j-1].id)
                left = j;
            else if (!right && rcright == player->items[j-1].id)
                right = j;
            if (left && right)
                break;
          }
        if (right)
          {
            if (!left)
              {
                // swap for simplicity
                left = right;
                right = 0;
                int temp = rcright;
                rcright = rcleft;
                rcleft = temp;
              }
            else
              {
                // no need to recurse
                memcpy(brews[brew_count].unused_items, unused_items, 4*5);
                brews[brew_count].unused_items[left>>5] &= ~(1 << (left & 31));
                brews[brew_count].unused_items[right>>5] &= ~(1 << (right
                                                                    & 31));
                brews[brew_count].power = (player->items[left-1].bonus
                                           + player->items[right-1].bonus) / 2;
                brews[brew_count].used_reagents = 0;
                brews[brew_count].used_bottles = 0;
                brews[brew_count].produced_bottles = 1;
                brew_count++;
                continue;
              }
          }

        struct brew left_buffer[MAX_WHITE_BREWS];
        int left_count = 0;
        if (!left)
          {
            int result = recursive_brew(player, rcleft, unused_items,
                                        left_buffer);
            if (result < 0)
              {
                if (-result < unbrewable)
                    unbrewable = -result;
                continue;
              }
            left_count = result;
          }
        else
          {
            // fill the brew struct for a uniform code
            left_count = 1;
            memcpy(left_buffer[0].unused_items, unused_items, 4*5);
            left_buffer[0].unused_items[left>>5] &= ~(1 << (left & 31));
            left_buffer[0].power = player->items[left-1].bonus;
            left_buffer[0].used_reagents = 0;
            left_buffer[0].used_bottles = 0;
            left_buffer[0].produced_bottles = 0;
          }

        int right_unbrewable = unbrewable;
        struct brew right_buffer[MAX_WHITE_BREWS];
        int right_count = 0;
        for (int j = 0; j < left_count; j++)
          {
            int result = recursive_brew(player, rcright,
                                        left_buffer[j].unused_items,
                                        right_buffer);
            if (result < 0)
              {
                if (-result < right_unbrewable)
                    right_unbrewable = -result;
                continue;
              }
            for (int k = 0; k < result; k++)
              {
                memcpy(brews[brew_count].unused_items,
                       right_buffer[k].unused_items, 4*5);
                brews[brew_count].power = (left_buffer[j].power
                                           + right_buffer[k].power) / 2;
                brews[brew_count].used_reagents = right_buffer[k].used_reagents
                                                + left_buffer[j].used_reagents;
                // bottles count is a bit complicated, as empty bottles
                // produced by the left sub-brew can be utilized in the right
                int used = left_buffer[j].used_bottles;
                int produced = right_buffer[k].produced_bottles + 1;
                int unused = left_buffer[j].produced_bottles
                           - right_buffer[k].used_bottles;
                if (unused > 0)
                    produced += unused;
                else
                    used -= unused;
                brews[brew_count].used_bottles = used;
                brews[brew_count].produced_bottles = produced;
                // or vice versa (by right, in the left)
                used = right_buffer[k].used_bottles;
                produced = left_buffer[k].produced_bottles + 1;
                unused = right_buffer[k].produced_bottles
                       - left_buffer[j].used_bottles;
                if (unused > 0)
                    produced += unused;
                else
                    used -= unused;
                // we want the minimum
                if (used < brews[brew_count].used_bottles)
                  {
                    brews[brew_count].used_bottles = used;
                    brews[brew_count].produced_bottles = produced;
                  }
                brew_count++;
              }
            right_count += result;
          }
        if (!right_count)
            unbrewable = right_unbrewable;
      }
    if (brew_count > 0)
        return brew_count;
    else
        return -unbrewable;
}

// Sets up the recursive brew above and deals with the consequences.
static void __thiscall brew_if_possible(struct player *player, int potion)
{
    static char message[128];

    // allow brewing from a recipe
    if (potion >= FIRST_RECIPE)
        potion = ITEMS_TXT[potion].mod2 + FIRST_REAGENT;

    int alchemy = get_skill(player, SKILL_ALCHEMY);
    if (potion >= FIRST_COMPLEX_POTION && !alchemy
        || potion >= FIRST_LAYERED_POTION && alchemy < SKILL_EXPERT
        || potion >= FIRST_WHITE_POTION && alchemy < SKILL_MASTER
        || potion >= FIRST_BLACK_POTION && alchemy < SKILL_GM)
      {
        // don't have the skill
        show_face_animation(player, ANIM_ID_FAIL, 0);
        sprintf(message, new_strings[STR_ALCH_SKILL], player->name,
                ITEMS_TXT[potion].generic_name);
        show_status_text(message, 2);
        return;
      }

    uint32_t usable[5] = {0};
    int bottles = 0;
    for (int i = 0; i < 14*9; i++)
      {
        int item = player->inventory[i];
        if (item > 0)
          {
            int id = player->items[item-1].id;
            if (id == POTION_BOTTLE)
                bottles++;
            else if (id >= FIRST_POTION && id <= LAST_POTION
                     || id >= FIRST_REAGENT && (id <= LAST_REAGENT
                     || potion == CATALYST && id <= LAST_GRAY_REAGENT))
                usable[item>>5] |= 1 << (item & 31);
          }
      }

    struct brew buffer[MAX_BLACK_BREWS];
    int result = recursive_brew(player, potion, usable, buffer);
    if (result < 0)
      {
        if (-result < FIRST_COMPLEX_POTION)
          {
            // not enough reagents
            show_face_animation(player, ANIM_SHAKE_HEAD, 0);
            make_sound(SOUND_THIS, SOUND_BUZZ, 0, 0, -1, 0, 0, 0, 0);
            show_status_text(new_strings[STR_ALCH_REAGENTS], 2);
          }
        else
          {
            // don't know recipe
            show_face_animation(player, ANIM_ID_FAIL, 0);
            sprintf(message, new_strings[STR_ALCH_RECIPE],
                    ITEMS_TXT[-result].name);
            show_status_text(message, 2);
          }
        return;
      }

    int best_brew = -1;
    int least_reagents = 999;
    for (int i = 0; i < result; i++)
      {
        if (buffer[i].used_bottles > bottles)
            continue;
        if (buffer[i].used_reagents < least_reagents)
          {
            least_reagents = buffer[i].used_reagents;
            best_brew = i;
          }
      }
    if (best_brew == -1)
      {
        // not enough bottles
        show_face_animation(player, ANIM_SHAKE_HEAD, 0);
        make_sound(SOUND_THIS, SOUND_BUZZ, 0, 0, -1, 0, 0, 0, 0);
        show_status_text(new_strings[STR_ALCH_BOTTLES], 2);
        return;
      }

    int delete_bottles = buffer[best_brew].used_bottles
                       - buffer[best_brew].produced_bottles;
    for (int i = 0; i < 5; i++)
        usable[i] &= ~buffer[best_brew].unused_items[i];
    for (int i = 0; i < 14*9; i++)
      {
        int item = player->inventory[i];
        if (item > 0)
          {
            int id = player->items[item-1].id;
            if (id == POTION_BOTTLE && delete_bottles > 0)
                delete_bottles--;
            else if (!(usable[item>>5] & (1 << (item & 31))))
                continue;
            delete_backpack_item(player, i);
          }
      }

    // this function would fail if there were no place for a bottle,
    // but this shouldn't ever happen as bottles come from used potions
    for (int i = 0; i > delete_bottles; i--)
      {
        int slot = put_in_backpack(player, -1, POTION_BOTTLE);
        if (slot)
            player->items[slot-1] = (struct item) { .id = POTION_BOTTLE,
                                                    .flags = IFLAGS_ID };
      }
    struct item brewn_potion = { .id = potion, .flags = IFLAGS_ID,
                                 .bonus = buffer[best_brew].power };
    add_mouse_item(PARTY_BIN, &brewn_potion);
    show_face_animation(player, ANIM_MIX_POTION, 0); // successful brew
}

//Defined below.
static void __thiscall repair_knives(struct player *, struct item *);

// Hooks in the backpack code to implement autobrew on ctrl-click.
// Also calls the knife repair/recharge function.
static void __declspec(naked) autobrew(void)
{
    asm
      {
        lea esi, [ebx+eax*4-SIZE_ITEM].s_player.items
        push VK_CONTROL
        call dword ptr ds:GET_ASYNC_KEY_STATE
        test ax, ax
        js ctrl
        quit:
        mov ecx, 9
        ret
        ctrl:
        mov eax, dword ptr [esi]
        cmp eax, THROWING_KNIVES
        je knives
        cmp eax, LIVING_WOOD_KNIVES
        je knives
        cmp eax, CATALYST
        jb quit
        cmp eax, LAST_POTION
        jbe brewable
        cmp eax, FIRST_RECIPE
        jb quit
        cmp eax, LAST_RECIPE
        ja quit
        brewable:
        mov ecx, ebx
        push eax
        call brew_if_possible
        jmp skip
        knives:
        mov ecx, ebx
        push esi
        call repair_knives
        skip:
        push 0x4220e0
        ret 8
      }
}

// Update autonotes when reading potion recipes.
static void __thiscall read_recipe(void *player, int id)
{
    if (id < FIRST_RECIPE || id > LAST_RECIPE)
        return;
    int potion = ITEMS_TXT[id].mod2 + 200;
    struct recipe *this = &recipes[potion-FIRST_COMPLEX_POTION];
    for (int i = 0; i < this->count; i++)
        if (!check_bit(AUTONOTES, this->variants[i].note))
            evt_set(player, EVT_AUTONOTES, this->variants[i].note);
}

// Hook for the above.
static void __declspec(naked) read_recipe_hook(void)
{
    asm
      {
        mov ecx, dword ptr [esp+4]
        push esi
        call read_recipe
        add esi, -700
        ret
      }
}

// In line with the throwable elemental potions,
// give swift potions an alternative use as well:
// drinking one causes the PC to instantly recover (i.e. get a free turn).
static void __declspec(naked) drink_swift_potion(void)
{
    asm
      {
        mov word ptr [esi].s_player.recovery, bx ; == 0
        cmp dword ptr [TURN_BASED], ebx
        jz quit
        mov ecx, dword ptr [TURN_BASED_THIS+12] ; count of tb actors
        cmp ecx, ebx ; just in case
        jle quit
        mov eax, dword ptr [ebp+8] ; player id
        dec eax
        shl eax, 3
        add eax, TGT_PARTY
        mov edx, TURN_BASED_THIS + 16
        next_actor:
        add edx, 16
        cmp dword ptr [edx], eax ; tb actor id
        loopne next_actor
        jne quit
        mov dword ptr [edx+4], ebx ; tb actor recovery
        quit:
        push 0x4687a8 ; post-drink effects
        ret
      }
}

// Cannot raise base PC stats higher than this.
#define NATURAL_STAT_LIMIT 255

// Let the pure attribute black potions give bonus equal to their power,
// instead of a fixed +50.  This adds a strategic dilemma: do you drink it
// as soon as you find it and enjoy a smaller bonus right now, or wait until
// you have a philosopher's stone and an alchemy-boosting item, which will
// give you a bigger bonus later?  You still cannot drink the potion twice.
static void __declspec(naked) pure_potions_power(void)
{
    asm
      {
        xor ecx, ecx
        sub edx, PURE_LUCK
        je luck
        dec edx
        je speed
        dec edx
        je intellect
        dec edx
        je endurance
        dec edx
        je personality
        dec edx
        je accuracy
        jmp might
        luck:
        inc ecx
        accuracy:
        inc ecx
        speed:
        inc ecx
        endurance:
        inc ecx
        personality:
        inc ecx
        intellect:
        inc ecx
        might:
        mov edx, dword ptr [MOUSE_ITEM].s_item.bonus ; potion power
        test edx, edx ; 0 power potions have no permanent effect
        jnz has_power
        push 0x4687a8 ; skip set-drunk-bit code
        ret 4
        has_power:
        add dx, word ptr [esi+S_PL_STATS+ecx*4]
        cmp dx, NATURAL_STAT_LIMIT
        jle ok
        mov dx, NATURAL_STAT_LIMIT
        ok:
        mov word ptr [esi+S_PL_STATS+ecx*4], dx
        ret
      }
}

// Defined below.
static void wand_price(void);
static void knife_price(void);
static void scroll_price(void);

// Make the price of most potions variable.
// Potion price is arranged so that at the typical potion powers
// (2d4*rarity -- avg. 5*rarity) the old price is mostly unchanged.
// RGB potions are an exception, their "default" price is bumped to 10.
// Holy water: 50 + 10*power (avoid sell price being higher than donation)
// Catalist: 1 + power (also an exception)
// Red and blue: 5 + power
// Yellow: fixed 10 (no variable effect) -- this is a bump
// Green, orange, purple: fixed 50 (no variable effect)
// Layered potions: 75 + 5*power, unless no variable effect
// White: 350 + 20*power, unless no variable effect
// Black: 1000 + 40*power, unless no variable effect
// The hook for the wand price function is also here.
static void __declspec(naked) potion_price(void)
{
    asm
      {
        mov edi, dword ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.value
        mov dl, byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.equip_stat
        cmp dl, ITEM_TYPE_POTION - 1
        je potion
        cmp dl, ITEM_TYPE_SCROLL - 1
        je scroll_price
        cmp dword ptr [esi], FIRST_WAND
        jb not_wand
        cmp dword ptr [esi], LAST_WAND
        jbe wand_price
        not_wand:
        cmp dword ptr [esi], THROWING_KNIVES
        je knife_price
        cmp dword ptr [esi], LIVING_WOOD_KNIVES
        je knife_price
        xor edx, edx ; set zf
        ret
        potion:
        movzx eax, byte ptr [ITEMS_TXT_ADDR+eax] \
                            .s_items_txt_item.mod1_dice_count ; value factor
        mul dword ptr [esi].s_item.bonus ; potion power
        add edi, eax
        ; zf must be unset now
        ret
      }
}

static int have_itemgend;
static char itemgend[LAST_PREFIX+1];

// Parse itemgend.txt (items' grammatical gender list) if available.
// Called from spells_txt_tail() below.
static void parse_itemgend(void)
{
    // Note: this function only checks in *.lod, not in DataFiles.
    // However, the load_from_lod() below does check there.
    // As such, there'll be a false negative if the mod's events.lod
    // isn't present, but its contents are unpacked in DataFiles.
    have_itemgend = exists_in_lod(EVENTS_LOD, "itemgend.txt");
    if (!have_itemgend)
        return;

    char *file = load_from_lod(EVENTS_LOD, "itemgend.txt", TRUE);
    if (strtok(file, "\r\n")) // skip first line
        for (int i = 1; i <= LAST_PREFIX; i++)
          {
            char *line = strtok(0, "\r\n");
            if (!line)
                break;
            // we need first character of third cell
            line = strchr(line, '\t');
            if (line)
                line = strchr(line + 1, '\t');
            if (!line)
                continue;

            char gender;
            switch (line[1])
              {
                case 'm':
                case 'M':
                default:
                    gender = GENDER_MASCULINE;
                    break;
                case 'f':
                case 'F':
                    gender = GENDER_FEMININE;
                    break;
                case 'n':
                case 'N':
                    gender = GENDER_NEUTER;
                    break;
                case 'p':
                case 'P':
                    gender = GENDER_PLURAL;
                    break;
              }
            itemgend[i] = gender;
          }
    mm7_free(file);
}

// Formats item enchantment prefixes according to their grammatical gender.
// The substring "^R[masculine;feminine;neuter;plural]" is replaced
// with one of the four words inside it.
static char *__stdcall prefix_gender(unsigned int item_id, int enchant)
{
    char *prefix = spcitems[enchant-1].name;
    if (!have_itemgend)
        return prefix;
    char *subst = strstr(prefix, "^R[");
    if (!subst)
        return prefix;

    static char buffer[100];
    memcpy(buffer, prefix, subst - prefix);
    buffer[subst - prefix] = 0;
    int gender = GENDER_MASCULINE;
    if (item_id <= LAST_PREFIX)
        gender = itemgend[item_id];
    char *varpart = subst + 3; // strlen("^R[")
    for (int i = 0; i < gender; i++)
      {
        char *next = strchr(varpart, ';');
        if (!next)
            break;
        varpart = next + 1;
      }
    char *end = strpbrk(varpart, ";]");
    if (end)
        strncat(buffer, varpart, end - varpart);
    else
        strcat(buffer, varpart);
    char *rest = strchr(subst, ']');
    if (rest)
        strcat(buffer, rest + 1);
    return buffer;
}

// Hook for the above.  Replaces enchantment name push.
static void __declspec(naked) prefix_hook(void)
{
    asm
      {
        push eax
        push esi
        call prefix_gender
        pop ecx
        push eax
        jmp ecx
      }
}

// For items.txt, allow using any of gender-specific prefix variants.
static int __cdecl compare_special_item_prefix(char *prefix, char *text)
{
    if (have_itemgend)
      {
        char *format = strstr(prefix, "^R[");
        if (format)
          {
            int result = strncmp(text, prefix, format - prefix);
            if (result)
                return result;
            // we assume here that variable parts are word endings
            char *next_word = strchr(format, ' ');
            char *rest_of_text = strchr(text + (format - prefix), ' ');
            if (next_word && rest_of_text)
                return strcmp(rest_of_text, next_word);
            return !!next_word - !!rest_of_text;
          }
      }
    return uncased_strcmp(text, prefix); // replaced call
}

// Exploit fix: barrels in Walls of Mist were refilled on each visit.
// Now the barrel contents are stored in the savefile.
// Called in save_game_hook() below.
// (Note that leaving a map also forces an autosave.)
static void save_wom_barrels(void)
{
    if (uncased_strcmp(CUR_MAP_FILENAME, MAP_WALLS_OF_MIST))
        return;
    static const struct file_header header = { "barrels.bin", WOM_BARREL_CNT };
    save_file_to_lod(SAVEGAME_LOD, &header, MAP_VARS + 75, 0);
}

// Restore the saved barrels, unless a quest bit is set.
// The quest bit should be reset every year.
// Called in load_map_hook() below.
// This is actually called on each savegame reload as well, but it's okay.
static void load_wom_barrels(void)
{
    if (uncased_strcmp(CUR_MAP_FILENAME, MAP_WALLS_OF_MIST))
        return;
    if (check_bit(QBITS, QBIT_REFILL_WOM_BARRELS))
        return;
    void *file = find_in_lod(SAVEGAME_LOD, "barrels.bin", 1);
    // barrel data occupies map vars 75 to 89
    // it would be more proper to dynamically determine barrel count, but eeh
    if (file)
        fread(MAP_VARS + 75, 1, WOM_BARREL_CNT, file);
}

// Add a random item type that only generates robes (for shops).
// Also here: let some monsters drop specific items (but with a % chance).
static void __declspec(naked) rnd_robe_type(void)
{
    asm
      {
        jne quit
        cmp dword ptr [ebp+12], ITEM_TYPE_ROBE - 1
        je robe
        cmp dword ptr [ebp+12], ITEM_TYPE_SPECIAL - 1
        je special
        xor eax, eax ; set zf
        quit:
        mov dword ptr [ebp+16], 1 ; replaced code
        ret
        robe:
        mov dword ptr [ebp+12], ITEM_TYPE_ARMOR - 1
        mov dword ptr [ebp+16], FIRST_ROBE ; just skip over all other armor
        lea eax, [edi+4+FIRST_ROBE*SIZE_ITEM_TXT].s_items_txt_item.equip_stat
        mov dword ptr [ebp-4], eax
        lea eax, [edi+4+FIRST_ROBE*SIZE_ITEM_TXT+ebx].s_items_txt_item.chance
        push 0x456826 ; rnd item by equip stat loop
        ret 4
        special:
        mov eax, dword ptr [ebp+8] ; level
        mov dword ptr [esp], 0x4568b0 ; past rnd item type code
        dec eax
        js ember
        jz sulfur
        dec eax
        jz stone
        mov dword ptr [esi], SHARKTOOTH_DAGGER
        ret
        stone:
        mov dword ptr [esi], PHILOSOPHERS_STONE
        ret
        sulfur:
        mov dword ptr [esi], SULFUR
        ret
        ember:
        mov dword ptr [esi], MAGIC_EMBER
        ret
      }
}

// In addition to vanilla Arms, Dodging, and Fist,
// also halve HP, SP, Thievery, and Disarm enchantments.
static void __declspec(naked) halve_more_ench(void)
{
    asm
      {
        je quit ; replaced jump
        cmp ecx, STAT_UNARMED ; replaced code
        je quit
        cmp ecx, STAT_HP
        je quit
        cmp ecx, STAT_SP
        je quit
        cmp ecx, STAT_THIEVERY
        je quit
        cmp ecx, STAT_DISARM
        quit:
        ret
      }
}

// For halved std enchs, double the price to 200 gold per point.
static void __declspec(naked) double_halved_ench_price(void)
{
    asm
      {
        mov eax, dword ptr [esi].s_item.bonus_strength ; replaced code
        imul eax, eax, 100 ; replaced code
        mov ecx, dword ptr [esi].s_item.bonus
        cmp ecx, STAT_HP + 1
        je doubled
        cmp ecx, STAT_SP + 1
        je doubled
        cmp ecx, STAT_THIEVERY + 1
        je doubled
        cmp ecx, STAT_DISARM + 1
        je doubled
        cmp ecx, STAT_ARMSMASTER + 1
        jb quit
        cmp ecx, STAT_UNARMED + 1
        ja quit
        doubled:
        shl eax, 1
        quit:
        ret
      }
}

// Count robes and knives as breakable.
static void __declspec(naked) break_new_items(void)
{
    asm
      {
        cmp ecx, FIRST_ROBE ; first new equipment
        jge new
        cmp ecx, LAST_OLD_PREFIX ; replaced code
        ret
        new:
        cmp ecx, LAST_PREFIX
        ret
      }
}

// To make Repair more relevant, generate items occasionally broken.
static void __declspec(naked) generate_broken_items(void)
{
    asm
      {
        mov eax, dword ptr [esi] ; replaced code
        cmp eax, LAST_OLD_PREFIX
        jbe breakable
        cmp eax, LAST_PREFIX
        ja skip
        cmp eax, FIRST_ROBE
        jb skip
        breakable:
        call dword ptr ds:random
        xor edx, edx
        mov ecx, 100
        div ecx
        add edx, dword ptr [ebp+8] ; treasure level
        cmp edx, 6 ; 6% - tlvl chance
        jae fail
        or byte ptr [esi].s_item.flags, IFLAGS_BROKEN
        fail:
        mov eax, dword ptr [esi] ; restore
        skip:
        lea eax, [eax+eax*2] ; replaced code
        ret
      }
}

// Starting rings occasionally generated broken.
static void __declspec(naked) repair_starting_items(void)
{
    asm
      {
        jz quit ; replaced jump
        mov dword ptr [eax], IFLAGS_ID ; erase broken flag
        quit:
        ret
      }
}

// Do not repair items on the ground (== in the main screen).
static void __declspec(naked) no_repair_at_distance(void)
{
    asm
      {
        mov edx, eax ; replaced code
        and eax, IFLAGS_BROKEN ; ditto
        jz quit
        cmp dword ptr [CURRENT_SCREEN], ebx ; == 0
        jnz quit
        xor eax, eax ; pretend it`s not broken
        quit:
        ret
      }
}

// Counter for re-trying the genie wish prompt.
static int genie_wish_attempts;

// The new logic for genie lamps.
static void __thiscall genie_lamp(struct player *player)
{
    // Simple PRNG that also depends on the current day.
    unsigned int day = CURRENT_TIME >> 13;
    day /= 256 * 60 * 24 >> 13; // avoid long division dependency
    elemdata.genie = (day * 8u + 1664525u) * elemdata.genie + 1013904223u;
    remove_mouse_item(MOUSE_THIS); // eat lamp
    char buffer[100];
    char *status_text = buffer;
    int good = 0;
    switch (elemdata.genie >> 28)
      {
        case 0:
            good = 1;
            if (!check_bit(QBITS, QBIT_GENIE_ARTIFACT)
                && (elemdata.genie >> 18 & 1023) < get_luck(player))
              {
                struct item artifact;
                if (generate_artifact(&artifact))
                  {
                    add_mouse_item(PARTY_BIN, &artifact);
                    sprintf(status_text, new_strings[STR_GENIE_ARTIFACT],
                            ITEMS_TXT[artifact.id].generic_name);
                    change_bit(QBITS, QBIT_GENIE_ARTIFACT, TRUE);
                    break;
                  }
              }
            byte(0x5b07b8) = 0; // reset message override
            CURRENT_TEXT = new_strings[STR_GENIE_ITEM_INIT];
            strcpy((char *) STATUS_MESSAGE, new_strings[STR_GENIE_ITEM_ASK]);
            message_dialog(MESSAGE_MARKER, 2, MESSAGE_QUESTION);
            genie_wish_attempts = 5;
            status_text = NULL;
            break;
        case 1:
        case 2:
        case 3:
              {
                int stat = (elemdata.genie >> 19 & 511) % 7;
                int bonus = (elemdata.genie >> 15 & 15)
                          + (player->level_base + 3) / 4;
                int new_stat = player->stats[stat][0] + bonus;
                if (new_stat > NATURAL_STAT_LIMIT)
                    new_stat = NATURAL_STAT_LIMIT;
                player->stats[stat][0] = new_stat;
                if (stat == STAT_ACCURACY || stat == STAT_SPEED)
                    stat ^= 1; // names are swapped
                sprintf(status_text, new_strings[STR_GENIE_STAT], player->name,
                        bonus, ((char **) 0x5079f8)[stat]); // stat name ptrs
                good = 2;
              }
            break;
        case 4:
        case 5:
        case 6:
              {
                // TODO: add "resistance"?
                static const int res_names[] = { 87, 71, 43, 166, 142, 138 };
                int resist = (elemdata.genie >> 19 & 511) % 6;
                char *name = GLOBAL_TXT[res_names[resist]];
                if (resist > POISON) resist += 3; // there's a gap
                int bonus = (elemdata.genie >> 15 & 15)
                          + (player->level_base + 3) / 4;
                int new_res = player->res_base[resist] + bonus;
                if (new_res > NATURAL_STAT_LIMIT)
                    new_res = NATURAL_STAT_LIMIT;
                player->res_base[resist] = new_res;
                sprintf(status_text, new_strings[STR_GENIE_STAT], player->name,
                        bonus, name);
                good = 2;
              }
            break;
        case 7:
              {
                int bonus = (elemdata.genie >> 25 & 7) + 1
                          + player->level_base * player->level_base / 200;
                player->skill_points += bonus;
                sprintf(status_text, new_strings[STR_GENIE_STAT], player->name,
                        bonus, GLOBAL_TXT[207]);
                good = 2;
              }
            break;
        case 8:
        case 9:
        case 10:
              {
                static const int curse[] = { COND_CURSED, COND_INSANE,
                                             COND_POISONED_RED,
                                             COND_DISEASED_RED,
                                             COND_PARALYZED, COND_DEAD,
                                             COND_STONED, COND_ERADICATED };
                inflict_condition(player, curse[elemdata.genie>>25&7], FALSE);
                sprintf(status_text, new_strings[STR_GENIE_CURSE],
                        player->name);
                good = -2;
              }
            break;
        case 11:
              {
                int tithe = dword(PARTY_GOLD)
                          / (10 + (elemdata.genie >> 25 & 7));
                if (tithe < 1000) tithe = 1000;
                if (tithe > dword(PARTY_GOLD)) tithe = dword(PARTY_GOLD);
                spend_gold(tithe);
                sprintf(status_text, new_strings[STR_GENIE_TITHE], tithe);
                good = -1;
              }
            break;
        case 12:
        case 13:
        case 14:
            if (dword(MONSTER_COUNT) < 500) // check if can summon
              {
                int dx = dir_cosine(TRIG_THIS, dword(PARTY_DIR)) >> 8;
                int dy = dir_cosine(TRIG_THIS, dword(PARTY_DIR) - 512) >> 8;
                // TODO: check for a wall?
                summon_monster(68, dword(PARTY_X) + dx, dword(PARTY_Y) + dy,
                               dword(PARTY_Z));
                int attitude = elemdata.genie >> 28 & 3;
                if (attitude)
                  {
                    struct map_monster *genie = MAP_MONSTERS
                                              + dword(MONSTER_COUNT) - 1;
                    // the party or wizards
                    genie->ally = attitude > 1 ? 9999 : 32;
                    genie->bits &= ~0x80000; // not hostile
                  }
                status_text = new_strings[STR_GENIE_HOSTILE+attitude];
                good = attitude > 1 ? 1 : -1;
                break;
              }
            // else fallthrough
        case 15:
            status_text = new_strings[STR_GENIE_NOTHING];
            good = -1;
            break;
      }
    if (good)
        show_face_animation(player, good > 0 ? ANIM_SMILE : ANIM_DISMAY, 0);
    if (good > 1 || good < -1)
        spell_face_anim(SPELL_ANIM_THIS,
                        good > 0 ? SPL_INVISIBILITY : SPL_FEATHER_FALL,
                        player - PARTY);
    if (status_text)
        show_status_text(status_text, 2);
}

// Hook for the above.
static void __declspec(naked) genie_lamp_hook(void)
{
    asm
      {
        mov ecx, esi
        call genie_lamp
        mov ecx, 0x468e87 ; end of the parent function
        jmp ecx
      }
}

// ID zero- (or negative) difficulty items when a chest is opened.
static void __declspec(naked) id_zero_chest_items(void)
{
    asm
      {
        test byte ptr [MAP_CHESTS_ADDR+esi+2], 4 ; replaced code
        jnz quit
        mov eax, dword ptr [ebp-4] ; item + 20
        mov eax, dword ptr [eax-20]
        lea eax, [eax+eax*2]
        shl eax, 4
        cmp byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.id_difficulty, 0
        jg skip
        inc eax ; clear zf
        quit:
        ret
        skip:
        xor eax, eax ; set zf
        ret
      }
}

// Adjust bonus descriptions for two-handed weapons to match the effect.
// Called just below and in temp_enchant_height() above.
static char *__thiscall two_handed_bonus_desc(struct item *item, int temp)
{
    int bonus = temp ? item->bonus_strength : item->bonus2;
    char *desc = spcitems[bonus-1].description;
    char *subst = strstr(desc, "^H[");
    if (!subst)
        return desc;
    static char buffer[200];
    memcpy(buffer, desc, subst - desc);
    buffer[subst - desc] = 0;
    char *varpart = subst + 3; // strlen("^H[")
    struct items_txt_item *data = &ITEMS_TXT[item->id];
    if ((data->skill == SKILL_SWORD || data->skill == SKILL_AXE)
        && data->equip_stat + 1 == ITEM_TYPE_WEAPON2)
      {
        char *second = strchr(varpart, ';');
        if (second)
            varpart = second + 1;
      }
    char *end = strpbrk(varpart, ";]");
    if (end)
        strncat(buffer, varpart, end - varpart);
    else
        strcat(buffer, varpart);
    char *rest = strchr(subst, ']');
    if (rest)
        strcat(buffer, rest + 1);
    return buffer;
}

// Hook for the above (one of them, anyway).
static void __declspec(naked) two_handed_bonus_desc_hook(void)
{
    asm
      {
        push ebx ; == 0
        call two_handed_bonus_desc
        pop ecx
        push eax
        jmp ecx
      }
}

// Penalize high alchemy skill combined with low-power reagents.
static void __declspec(naked) alchemy_soft_cap(void)
{
    asm
      {
        movzx eax, byte ptr [ITEMS_TXT_ADDR+eax] \
                            .s_items_txt_item.mod1_dice_count ; replaced code
        cmp eax, edi
        jae skip
        add edi, eax
        shr edi, 1
        skip:
        ret
      }
}

// Let apples (red or golden) cure weakness, because why not.
static void __declspec(naked) apple_cure_weakness(void)
{
    asm
      {
        mov dword ptr [esi+COND_WEAK*8], ebx ; == 0
        mov dword ptr [esi+COND_WEAK*8+4], ebx
        mov ecx, SOUND_THIS_ADDR ; replaced code
        ret
      }
}

// Just impose recovery, either realtime or turn-based.
static void __stdcall recover_player(int id, int amount)
{
    struct player *player = PARTY + id - 1;
    if (dword(TURN_BASED))
      {
        dword(0xae2f78 + id * 4) = amount; // tb recovery??
        set_recovery_delay(player, amount);
        turn_based_pass(TURN_BASED_THIS);
      }
    else
        // the float is an adjustable recovery multiplier, usually 1.0
        set_recovery_delay(player, *(float *) 0x6be224 * amount * 128 / 60);
}

// Impose recovery when repairing an item with PC skill (not hirelings).
static void __declspec(naked) repair_recovery(void)
{
    asm
      {
        ; pre-hook: cmp can_repair vs. 1
        jb fail
        ja ok ; hireling repair
        mov edx, dword ptr [CURRENT_PLAYER]
        mov ecx, dword ptr [PC_POINTERS+edx*4-4]
        cmp word ptr [ecx].s_player.recovery, bx ; ebx == 0
        ja skip
        cmp dword ptr [TURN_BASED], ebx
        jz recover
        mov ecx, PARTY_BIN_ADDR
        call dword ptr ds:find_active_player
        cmp dword ptr [CURRENT_PLAYER], eax
        jne skip
        cmp dword ptr [CURRENT_SCREEN], ebx
        jz recover
        push ebx
        push ebx
        push ACTION_EXIT
        mov ecx, ACTION_THIS_ADDR
        call dword ptr ds:add_action
        cmp dword ptr [CURRENT_SCREEN], 15 ; backpack inside chest screen
        jne recover
        push 1 ; preserve
        push ebx
        push ACTION_EXIT
        mov ecx, ACTION_THIS_ADDR
        call dword ptr ds:add_action
        recover:
        mov ebx, dword ptr [CURRENT_PLAYER]
        push 100
        push ebx
        call recover_player
        mov dword ptr [CURRENT_PLAYER], ebx ; don`t switch the screen
        xor ebx, ebx ; restore
        mov eax, dword ptr [ebp-4] ; ditto
        ok:
        mov ecx, dword ptr [eax].s_item.flags ; replaced code
        ret
        skip:
        add dword ptr [esp], 71 ; skip repair face anim code
        fail:
        add dword ptr [esp], 9 ; replaced jump
        ret
      }
}

// Give more varied items for starting with misc skills.
static void __declspec(naked) new_game_items(void)
{
    asm
      {
        cmp eax, 21
        jbe vanilla
        sub eax, 22
        jz id_item
        dec eax
        jz merchant
        dec eax
        jz repair
        dec eax
        jz bodybuilding
        dec eax
        jz meditation
        dec eax
        jz perception
        dec eax
        jz dodging
        dec eax
        jz id_monster
        dec eax
        jz thievery
        dec eax
        jz learning
        dec eax
        jnz skip
        ; otherwise unarmed
        push BRASS_KNUCKLES
        jmp item
        learning:
        push HORNED_HELM
        jmp item
        thievery:
        push LEATHER_CLOAK
        jmp item
        dodging:
        push PILGRIMS_ROBE
        jmp item
        repair:
        push MAGIC_EMBER
        item:
        push edi ; == -1
        mov ecx, esi ; pc
        call dword ptr ds:put_in_backpack
        jmp skip
        id_item:
        mov eax, ITEM_TYPE_WAND
        jmp random_item
        merchant:
        mov eax, ITEM_TYPE_BELT
        jmp random_item
        perception:
        mov eax, ITEM_TYPE_GEMS
        jmp random_item
        id_monster:
        mov eax, ITEM_TYPE_AMULET
        random_item:
        sub esp, SIZE_ITEM
        push esp
        push eax
        push 2
        mov ecx, ITEMS_TXT_ADDR - 4
        call dword ptr ds:randomize_item
        jmp put_in
        meditation:
        inc edi
        bodybuilding:
        sub esp, SIZE_ITEM
        push esp
        push ITEM_TYPE_POTION
        push 4
        mov ecx, ITEMS_TXT_ADDR - 4
        call dword ptr ds:randomize_item
        add edi, POTION_DIVINE_MAGIC ; cure for bb
        mov dword ptr [esp], edi
        or edi, -1 ; restore
        put_in:
        push esp
        push edi
        mov ecx, esi
        call dword ptr ds:put_item_in_backpack
        add esp, SIZE_ITEM
        skip:
        mov eax, 21 ; skip vanilla code
        vanilla:
        jmp dword ptr [0x4978dd+eax*4] ; replaced code
      }
}

// Fix Expert blaster perk being applied on Normal rank,
// and Master perk discounting skill bonus from Squire etc.
static void __declspec(naked) blaster_fixes(void)
{
    asm
      {
        xor eax, eax ; no bonus below m
        cmp ecx, SKILL_EXPERT
        jb skip
        mov dword ptr [ebp-20], 1 ; replaced code (no range penalty)
        cmp ecx, SKILL_MASTER
        jb skip
        push SKILL_BLASTER
        mov ecx, edi
        call dword ptr ds:get_skill
        skip:
        ret
      }
}

// Instead of Carnage missiles bypassing the attack roll entirely,
// let them have +10 to AC penetration (and be unaffected by Shield).
static void __declspec(naked) carnage_hit_bonus(void)
{
    asm
      {
        add dword ptr [ebp-40], 10 ; penetration
        add dword ptr [esp], 25 ; skip shield code
        ret
      }
}

// For (some) symmetry, allow avoiding Carnage friendly fire like chest traps.
static void __declspec(naked) carnage_dodge(void)
{
    asm
      {
        mov esi, ecx ; preserve
        mov ecx, eax ; target pc
        call dword ptr ds:get_perception_bonus
        lea ebx, [eax+20]
        call dword ptr ds:random
        xor edx, edx
        div ebx
        cmp edx, 20 ; same logic as traps
        ja dodge
        mov ecx, esi
        mov eax, 0x48d1e4 ; replaced call
        jmp eax
        dodge:
        push 0
        push ANIM_DODGE
        mov ecx, dword ptr [ebp+12]
        call dword ptr ds:show_face_animation
        xor eax, eax ; no damage but still oops
        ret 4
      }
}

// Decrease the chance to hit monsters standing in dark areas.
static int __thiscall darkness_penalty(struct map_monster *monster)
{
    int base;
    int room = monster->room;
    int lights = dword(0x51b55c); // current light count
    if (dword(OUTDOORS) == 2)
      {
        if (byte(UNDERWATER))
            base = 0; // shoals seem to be lit at night
        else
            base = *(float *) 0x6bcef4 * 27; // outdoor darkness level
        // outdoor torch light is not added to light sources for some reason
        int power = 1;
        if (PARTY_BUFFS[BUFF_TORCH_LIGHT].expire_time)
            power = PARTY_BUFFS[BUFF_TORCH_LIGHT].power;
        for (struct player *player = PARTY; player < PARTY + 4; player++)
            if (has_item_in_slot(player, GHOULSBANE, SLOT_MAIN_HAND))
              {
                power = 5;
                break;
              }
        // TODO: these XYZ are a bit wrong (light goes from behind and above)
        add_light_source(LIGHT_SOURCE_THIS, dword(PARTY_X), dword(PARTY_Y),
                         dword(PARTY_Z), 0, power * 800, -1, -1, -1, 5);
      }
    else
        base = MAP_ROOMS[room].darkness;
    int dark = get_darkness(base, room, monster->x, monster->y, monster->z);
    dword(0x51b55c) = lights; // undo added light
    return dark > 20; // semi-arbitrary
}

// Hook for the above.
static void __declspec(naked) darkness_penalty_hook(void)
{
    asm
      {
        mov ecx, esi
        call darkness_penalty
        add dword ptr [ebp-20], eax ; range penalty
        mov eax, dword ptr [ebx].s_map_object.spell_type ; replaced code
        cmp eax, SPL_BLASTER ; ditto
        ret
      }
}

// Used just below.
static const char scroll_power_format[] = "%s: %s %d";

// Show the variable scroll power on a right-click (or M5 if none set).
static void __declspec(naked) display_scroll_power(void)
{
    asm
      {
        mov al, byte ptr [edi].s_items_txt_item.equip_stat ; replaced code
        cmp al, ITEM_TYPE_POTION - 1 ; ditto
        je skip
        cmp al, ITEM_TYPE_SCROLL - 1
        jne skip
        movzx eax, byte ptr [edi].s_items_txt_item.mod1_dice_count ; spell id
        xor edx, edx
        cmp eax, LAST_REAL_SPELL
        ja mastery ; fake ones are telepathy and fate, both normal mastery
        cmp eax, SPL_PSYCHIC_SHOCK
        sete dl
        je mastery ; this spell is now expert (berserk can still be expert too)
        dec eax
        mov ecx, 11
        div ecx
        level:
        lea edx, [edx+edx*4]
        shr edx, 4 ; 0-10 to 0-3
        mastery:
        cmp edx, 3
        sbb edx, -1
        shl edx, 6
        mov eax, dword ptr [ebp-4] ; the item
        mov eax, dword ptr [eax].s_item.charges
        test eax, eax
        jnz ok
        mov eax, SKILL_MASTER + 5 ; default
        ok:
        or eax, edx ; max of masteries
        cmp eax, SKILL_EXPERT
        jae skilled
        add dword ptr [esp], 16 ; skip to (potion) power code
        skip:
        ret
        skilled:
        cmp eax, SKILL_MASTER
        cmovb ecx, dword ptr [GLOBAL_TXT_ADDR+433*4] ; "expert"
        cmovae ecx, dword ptr [GLOBAL_TXT_ADDR+432*4] ; "master"
        cmp eax, SKILL_GM
        cmovae ecx, dword ptr [GLOBAL_TXT_ADDR+96*4] ; "grand"
        and eax, SKILL_MASK
        push eax
        push ecx
        push dword ptr [GLOBAL_TXT_ADDR+449*4] ; "power"
#ifdef __clang__
        mov eax, offset scroll_power_format
        push eax
#else
        push offset scroll_power_format
#endif
        lea ecx, [ebp-424] ; buffer
        push ecx
        call dword ptr ds:sprintf
        add esp, 20
        add dword ptr [esp], 10 ; to after print code
        xor eax, eax ; set zf
        ret
      }
}

// Defined below.
static void init_knife_charges(void);

// Give randomly-generated spell scrolls variable power.
// Rolls 1d4 power per tlvl, and tlvl - 4 + 1d4 mastery.
static void __declspec(naked) random_scroll_power(void)
{
    asm
      {
        cmp byte ptr [edi+4+eax].s_items_txt_item.equip_stat, \
            ITEM_TYPE_SCROLL - 1
        jne skip
        call dword ptr ds:random
        xor edx, edx
        lea ecx, [edx+3]
        and eax, ecx
        neg eax
        add eax, dword ptr [ebp+8] ; treasure level (0-5)
        cmp eax, ecx
        cmovl ecx, edx
        cmova eax, ecx
        sbb eax, -1
        shl eax, 6
        mov dword ptr [esi].s_item.charges, eax
        mov ebx, dword ptr [ebp+8]
        loop:
        call dword ptr ds:random
        and eax, 3
        inc eax
        add dword ptr [esi].s_item.charges, eax
        dec ebx
        jge loop
        skip:
        jmp init_knife_charges ; old hook at this address
      }
}

// Adjust scroll price slightly based on its power.
// Called from potion_price() above.
static void __declspec(naked) scroll_price(void)
{
    asm
      {
        movzx eax, byte ptr [ITEMS_TXT_ADDR+eax] \
                            .s_items_txt_item.mod1_dice_count ; spell id
        xor ecx, ecx
        xor edx, edx
        cmp eax, LAST_REAL_SPELL
        ja fake ; fake ones are telepathy and fate, both normal mastery
        cmp eax, SPL_BERSERK
        je berserk ; can be expert on scrolls, but has master rarity
        cmp eax, SPL_PSYCHIC_SHOCK
        je shock ; this spell is now expert
        dec eax
        mov cl, 11
        div ecx
        cmp eax, 7 ; bonus for light/dark
        setae cl
        lea edx, [edx+edx*4]
        shr edx, 4 ; 0-10 to 0-3
        lea ecx, [edx+ecx*2+1]
        jmp power
        berserk:
        inc ecx
        shock:
        inc edx
        inc ecx
        fake:
        inc ecx
        power:
        shl ecx, 2 ; this is base power, roughly the average for random scrolls
        mov eax, dword ptr [esi].s_item.charges
        test eax, eax
        jnz ok
        mov eax, SKILL_MASTER + 5 ; default
        ok:
        mov esi, eax
        and esi, SKILL_MASK
        shr eax, 6
        cmp edx, 3
        sbb edx, -1
        cmp eax, edx
        cmovb eax, edx ; can`t be below base mastery
        lea eax, [esi+eax*2] ;  expert and master = 2 skill points each, gm = 4
        add eax, ecx ; 50% of price is variable
        shl ecx, 1
        mul edi
        div ecx
        mov edi, eax
        test ecx, ecx ; clear zf
        ret
      }
}

// Misc item tweaks.
static inline void misc_items(void)
{
    // phynaxian crown now grants poison instead of water resistance
    patch_byte(0x48f113, STAT_POISON_RES);
    // make blasters ignore resistances like in mm6
    patch_dword(0x43963c, ENERGY); // blaster element
    // remove splitter and forge gauntlets' fire res bonus
    // now that they give an immunity
    patch_dword(0x48f660, dword(0x48f664));
    erase_code(0x48f258, 8);
    hook_call(0x468c58, buff_potions_power, 5);
    hook_call(0x468951, buff_potions_power, 5); // water breathing
    hook_call(0x453e34, maybe_add_recipe, 7);
    hook_call(0x4220b4, autobrew, 7);
    hook_call(0x467f79, read_recipe_hook, 6);
    patch_pointer(0x468f36, drink_swift_potion); // jump table
    hook_call(0x468c7b, pure_potions_power, 8); // pure luck
    hook_call(0x468c98, pure_potions_power, 8); // pure speed
    hook_call(0x468cb5, pure_potions_power, 8); // pure intellect
    hook_call(0x468cd2, pure_potions_power, 8); // pure endurance
    hook_call(0x468cef, pure_potions_power, 8); // pure personality
    hook_call(0x468d0c, pure_potions_power, 8); // pure accuracy
    hook_call(0x468d29, pure_potions_power, 8); // pure might
    hook_call(0x45647e, potion_price, 6);
    erase_code(0x456624, 3); // do not multiply ench id
    hook_call(0x456633, prefix_hook, 6);
    hook_call(0x4578cf, compare_special_item_prefix, 5);
    hook_call(0x4567db, rnd_robe_type, 7);
    // Let some armor shops sell robes.
    ARMOR_SHOP_STD[0][1][3] = ITEM_TYPE_ROBE; // ei
    ARMOR_SHOP_SPC[0][1][3] = ITEM_TYPE_ROBE;
    ARMOR_SHOP_SPC[3][1][2] = ITEM_TYPE_ROBE; // tularean
    ARMOR_SHOP_SPC[4][1][4] = ITEM_TYPE_ROBE; // celeste
    ARMOR_SHOP_STD[6][1][3] = ITEM_TYPE_ROBE; // nighon
    ARMOR_SHOP_STD[6][1][4] = ITEM_TYPE_ROBE;
    ARMOR_SHOP_SPC[6][1][3] = ITEM_TYPE_ROBE;
    ARMOR_SHOP_SPC[6][1][4] = ITEM_TYPE_ROBE;
    ARMOR_SHOP_STD[10][1][3] = ITEM_TYPE_ROBE; // castle
    ARMOR_SHOP_SPC[10][1][3] = ITEM_TYPE_ROBE;
    hook_call(0x456b57, halve_more_ench, 5);
    patch_dword(0x48f3da, 0x48f532 - 0x48f3de); // of earth: 10 -> 5 HP
    patch_byte(0x48f42e, 39); // of life: 10 -> 5 HP
    patch_byte(0x48f442, 19); // of eclipse/sky: 10 -> 5 SP
    hook_call(0x45649a, double_halved_ench_price, 6);
    hook_call(0x41611a, break_new_items, 6); // alchemy explosion
    hook_call(0x48dd6f, break_new_items, 6); // monster attack
    hook_call(0x456a15, generate_broken_items, 5);
    erase_code(0x41da49, 3); // do not auto-id repaired items
    hook_call(0x497873, repair_starting_items, 5);
    hook_call(0x41d948, no_repair_at_distance, 5);
    // Treat negative ID difficulty as auto-ID (but abs() repair).
    patch_byte(0x4165f4, 0x7f); // jnz -> jg (new potion)
    patch_byte(0x41d93c, 0x7f); // ditto (item rmb)
    patch_byte(0x456a06, 0x7e); // jz -> jle (random item)
    patch_byte(0x48c6fa, 0x7f); // also jnz -> jg (pick up item)
    hook_jump(0x46825f, genie_lamp_hook);
    hook_call(0x420304, id_zero_chest_items, 7);
    hook_call(0x41ddf5, two_handed_bonus_desc_hook, 6);
    hook_call(0x4162f8, alchemy_soft_cap, 7);
    hook_call(0x468243, apple_cure_weakness, 5);
    hook_call(0x41da41, repair_recovery, 5);
    hook_jump(0x49773e, new_game_items);
    // Add the new entries to the vanilla jumptable.
    patch_byte(0x497935 + SKILL_IDENTIFY_ITEM, 22);
    patch_byte(0x497935 + SKILL_MERCHANT, 23);
    patch_byte(0x497935 + SKILL_REPAIR, 24);
    patch_byte(0x497935 + SKILL_BODYBUILDING, 25);
    patch_byte(0x497935 + SKILL_MEDITATION, 26);
    patch_byte(0x497935 + SKILL_PERCEPTION, 27);
    patch_byte(0x497935 + SKILL_DISARM_TRAPS, 19); // old dodging (boots)
    patch_byte(0x497935 + SKILL_DODGING, 28);
    patch_byte(0x497935 + SKILL_IDENTIFY_MONSTER, 29);
    patch_byte(0x497935 + SKILL_ARMSMASTER, 20); // old unarmed (gloves)
    patch_byte(0x497935 + SKILL_THIEVERY, 30);
    patch_byte(0x497935 + SKILL_ALCHEMY, 18); // vanilla bottle + reagent
    patch_byte(0x497935 + SKILL_LEARNING, 31);
    patch_byte(0x497935 + SKILL_UNARMED, 32);
    hook_call(0x439614, blaster_fixes, 23);
    hook_call(0x43967b, carnage_hit_bonus, 7);
    hook_call(0x43a92c, carnage_dodge, 5);
    hook_call(0x439605, darkness_penalty_hook, 6);
    hook_call(0x41dd77, display_scroll_power, 5);
    hook_call(0x456a2c, random_scroll_power, 5);
}

// Used to store variable scroll power for the scroll cast event.
static uint32_t scroll_power;

// Allow using Flaming, Freezing, Shocking and Noxious potions
// to deal splash elemental damage at a short range.
static void __declspec(naked) throw_potions_jump(void)
{
    asm
      {
        cmp dword ptr [CURRENT_SCREEN], 23
        je fail
        cmp dword ptr [CURRENT_SCREEN], 13 ; inside a house
        jne pass
        fail:
        push 0x468e87
        ret
        pass:
        mov ecx, esi
        mov eax, dword ptr [0x4685ee]
        add eax, 0x4685f2
        call eax ; mm7patch`s active player check
        test eax, eax
        jnz active
        push 0x4685f6
        ret
        active:
        mov eax, dword ptr [MOUSE_ITEM].s_item.bonus
        mov dword ptr [scroll_power], eax
        mov eax, dword ptr [MOUSE_ITEM] ; item type
        ; both the four potions and their four spells are contiguous,
        ; but the order is different.  thus, we shuffle them a bit
        mov esi, eax
        sub esi, FLAMING_POTION
        jz flaming
        dec esi
        jz freezing
        dec esi
        jz noxious
        dec esi
        jz shocking
        ; but the holy water stands aside
        mov esi, SPL_HOLY_WATER
        jmp quit
        noxious:
        inc esi
        freezing:
        inc esi
        shocking:
        inc esi
        flaming:
        add esi, SPL_FLAMING_POTION
        quit:
        push 0x46867e
        ret
      }
}

// A hack for Alchemist hirelings pretending to be recharge scrolls.
static int hireling_recharge = FALSE;

// Provide the proper spell power for the potion throw event.
// We hijacked the scroll cast event for this,
// which uses a fixed power, so we store the power in a static var.
// Update: as scroll power is now variable, all scrolls use this.
// Also here: allow Alchemist NPCs to cast Recharge Item with no PC recovery.
static void __declspec(naked) throw_potions_power(void)
{
    asm
      {
        cmp dword ptr [hireling_recharge], ebx
        jne alchemist
        pop eax
        push dword ptr [scroll_power]
        jmp eax
        alchemist:
        mov dword ptr [hireling_recharge], ebx ; reset
        pop eax
        mov dword ptr [esp], 32 ; no recovery
        push SKILL_MASTER + 10 ; 80%
        dec dword ptr [esp+56] ; casting pc (was 1-based)
        jmp eax
      }
}

static void aim_remove_fear(void); // defined below

// Pretend that the thrown potion is Fire Bolt for aiming purposes.
// There's also a Remove Fear aiming hook here now.
// Also handles the new Fate and Telepathy spell ID, and the quick heal key.
static void __declspec(naked) aim_potions_type(void)
{
    asm
      {
        cmp ecx, SPL_REMOVE_FEAR
        je aim_remove_fear
        cmp ecx, SPL_FATE
        je debuff
        cmp ecx, SPL_TELEPATHY
        jne not_debuff
        debuff:
        mov ecx, SPL_PARALYZE ; same aiming mode
        not_debuff:
        cmp ecx, SPL_QUICK_HEAL
        jne not_heal
        mov ecx, SPL_REGENERATION ; single-pc buff/cure
        not_heal:
        cmp ecx, SPL_FLAMING_POTION
        jb ordinary
        cmp ecx, SPL_HOLY_WATER
        ja quit
        mov ecx, SPL_FIRE_BOLT
        ordinary:
        sub ecx, 2
        cmp ecx, 95
        quit:
        ret
      }
}

// Give back the potion if aiming prompt is cancelled.
// Note: this will fail if the PC's backpack is full.
static void __thiscall aim_potions_refund(struct spell_queue_item *spell)
{
    int item_id;
    switch (spell->spell)
      {
    case SPL_FLAMING_POTION:
        item_id = FLAMING_POTION;
        break;
    case SPL_SHOCKING_POTION:
        item_id = SHOCKING_POTION;
        break;
    case SPL_FREEZING_POTION:
        item_id = FREEZING_POTION;
        break;
    case SPL_NOXIOUS_POTION:
        item_id = NOXIOUS_POTION;
        break;
    case SPL_HOLY_WATER:
        item_id = HOLY_WATER;
        break;
    default:
        return;
      }
    int slot = put_in_backpack(&PARTY[spell->caster], -1, item_id);
    if (slot)
        PARTY[spell->caster].items[slot-1] = (struct item) { .id = item_id,
                                                         .bonus = spell->skill,
                                                          .flags = IFLAGS_ID };
    return;
}

// Hook for the above.
static void __declspec(naked) aim_potions_refund_hook(void)
{
    asm
      {
        mov ecx, dword ptr [DIALOG7]
        cmp ecx, ebx
        jz quit
        mov ecx, dword ptr [ecx+28] ; dialog param
        call aim_potions_refund
        mov ecx, dword ptr [DIALOG7]
        quit:
        ret
      }
}

// Supply the objlist ID for thrown potions.
static void __declspec(naked) cast_potions_object(void)
{
    asm
      {
        cmp eax, SPL_FLAMING_POTION
        jb ordinary
        cmp eax, SPL_HOLY_WATER
        ja ordinary
        lea eax, [eax+eax*4]
        lea eax, [OBJ_FLAMING_POTION-SPL_FLAMING_POTION*10+eax*2]
        ret
        ordinary:
        mov ax, word ptr [SPELL_OBJ_IDS+eax*4-4]
        ret
      }
}

// Defined below.
static void forbid_spell(void);
static void __fastcall quick_heal(int caster, int target);

// Used in damage_messages() below.
static int last_hit_player;

// Redirect potion pseudo-spell code to the attack spell code.
// Potion power is fixed here too (with possible Gadgeteer's Belt bonus).
// This hook is also reused for spell disabling.
// The new Fate and Telepathy spell ID are also handled here.
static void __declspec(naked) cast_potions_jump(void)
{
    asm
      {
        mov dword ptr [last_hit_player], esi ; reset to 0
        jna forbid_spell
        cmp eax, SPL_FATE - 1
        je fate
        cmp eax, SPL_TELEPATHY - 1
        je telepathy
        cmp eax, SPL_QUICK_HEAL - 1
        je heal
        cmp eax, SPL_FLAMING_POTION - 1
        jb not_it
        cmp eax, SPL_HOLY_WATER - 1
        ja not_it
        mov dword ptr [ebp-0xb4], 100 ; recovery
        movzx edi, word ptr [ebx+10] ; raw spell (potion) power
        mov ecx, dword ptr [ebp-32] ; PC
        push SLOT_BELT
        push GADGETEERS_BELT
        call dword ptr ds:has_item_in_slot
        test eax, eax
        jz no_belt
        mov edx, edi
        shr edx, 1
        mov ecx, dword ptr [ebp-32]
        mov al, byte ptr [ecx].s_player.class
        and al, -4
        cmp al, CLASS_THIEF
        je bonus
        shr edx, 1
        bonus:
        add edi, edx
        no_belt:
        push 0x4289c6
        ret 4
        not_it:
        push 0x428295
        ret 4
        fate:
        mov word ptr [ebx], SPL_SPECTRAL_WEAPON ; for the sound
        mov dword ptr [ebp-0xb4], 90 ; recovery
        push 0x42b91d ; fate code
        ret 4
        telepathy:
        mov word ptr [ebx], SPL_AURA_OF_CONFLICT ; sound
        xor ecx, 7 ; mastery
        lea ecx, [ecx+ecx*4]
        lea ecx, [50+ecx+ecx] ; 110 to 80
        mov dword ptr [ebp-0xb4], ecx ; recovery
        mov dword ptr [ebp-168], 6030 ; anim
        mov dword ptr [esp], 0x42c2ca
        ret
        heal:
        movsx ecx, word ptr [ebx+2] ; caster
        movsx edx, word ptr [ebx+4] ; target
        mov dword ptr [esp], 0x42e8a4 ; past all the spell code
        jmp quick_heal
      }
}

// Let the throw velocity depend on strength.
static void __declspec(naked) cast_potions_speed(void)
{
    asm
      {
        movzx eax, word ptr [eax+ecx+48] ; default obj speed
        cmp word ptr [ebx], SPL_FLAMING_POTION
        jb ordinary
        cmp word ptr [ebx], SPL_HOLY_WATER
        ja ordinary
        push eax
        push edx
        mov ecx, dword ptr [ebp-32]
        call dword ptr ds:get_might
        push eax
        call dword ptr ds:get_effective_stat
        imul eax, 100
        pop edx
        pop ecx
        add eax, ecx
        ordinary:
        ret
      }
}

// Make a thrown potion sound (or something alike it, anyway).
static void __declspec(naked) cast_potions_sound(void)
{
    asm
      {
        cmp eax, SPL_FLAMING_POTION
        jb ordinary
        cmp eax, SPL_HOLY_WATER
        ja ordinary
        mov eax, 108 ; wood weapon vs leather01l
        ret
        ordinary:
        movsx eax, word ptr [SPELL_SOUNDS+eax*2]
        ret
      }
}

// Redirect the explode action for the new potions to fireball.
// Also here: treat knives like arrows.
static void __declspec(naked) explode_potions_jump(void)
{
    asm
      {
        cmp cx, OBJ_FLAMING_POTION
        je potion
        cmp cx, OBJ_SHOCKING_POTION
        je potion
        cmp cx, OBJ_FREEZING_POTION
        je potion
        cmp cx, OBJ_NOXIOUS_POTION
        je potion
        cmp cx, OBJ_THROWN_HOLY_WATER 
        je potion
        cmp cx, OBJ_KNIFE
        jne not_knife
        mov cx, OBJ_ARROW
        not_knife:
        mov eax, OBJ_ACID_BURST ; replaced code
        ret
        potion:
        push 0x46c887
        ret 4
      }
}

// Potions have a smaller radius than a fireball.
static void __declspec(naked) explode_potions_radius(void)
{
    asm
      {
        pop edx
        cmp word ptr [esi], OBJ_FLAMING_EXPLOSION
        je potion
        cmp word ptr [esi], OBJ_SHOCKING_EXPLOSION
        je potion
        cmp word ptr [esi], OBJ_FREEZING_EXPLOSION
        je potion
        cmp word ptr [esi], OBJ_NOXIOUS_EXPLOSION
        je potion
        cmp word ptr [esi], OBJ_HOLY_EXPLOSION
        je potion
        push 0x200
        push edx
        ret
        potion:
        push 0x100
        push edx
        ret
      }
}

// Provide sounds for exploding/shattering potions.
static void __declspec(naked) explode_potions_sound(void)
{
    asm
      {
        cmp eax, SPL_FLAMING_POTION
        je flaming
        cmp eax, SPL_SHOCKING_POTION
        je shocking
        cmp eax, SPL_FREEZING_POTION
        je freezing
        cmp eax, SPL_NOXIOUS_POTION
        je noxious
        cmp eax, SPL_HOLY_WATER
        je holy
        movsx eax, word ptr [SPELL_SOUNDS+eax*2]
        ret
        flaming:
        mov eax, 10011 - 1 ; 04firebolt03
        ret
        shocking:
        mov eax, 17040 - 1 ; Sparks
        ret
        freezing:
        mov eax, 12091 - 1 ; iceblast2
        ret
        noxious:
        mov eax, 1371 - 1 ; Ooze_die
        ret
        holy:
        mov eax, 14040 - 1 ; 49RemoveCurse03
        ret
      }
}

// Calculate the potion damage and element for monsters.
// Also here: add a stun effect to Lightning Bolt.
static void __declspec(naked) damage_potions_monster(void)
{
    asm
      {
        cmp eax, SPL_FLAMING_POTION
        jb ordinary
        cmp eax, SPL_HOLY_WATER
        ja ordinary
        jne not_holy
        add eax, 2 ; it`s number 4, but the holy element is 6
        not_holy:
        sub eax, SPL_FLAMING_POTION
        mov dword ptr [ebp-8], eax ; element
        mov ecx, dword ptr [ebx].s_map_object.spell_power
        mov edx, 3
        and eax, 1
        sub edx, eax ; d2 for elec and poison, d3 for fire, cold, and holy
        call dword ptr ds:roll_dice
        push 0x439767
        ret 8
        ordinary:
        cmp eax, SPL_LIGHTNING_BOLT
        jne quit
        mov eax, dword ptr [ebx].s_map_object.spell_power
        not eax ; mark negative to distinguish from stun spell
        mov dword ptr [ebp-32], eax ; stun flag/power
        quit:
        push 0x48e189 ; replaced function call
        ret
      }
}

static void absorb_other_spell(void); // defined below

// Ditto, for players.  Also here: jump to M Leather effect handler.
static void __declspec(naked) damage_potions_player(void)
{
    asm
      {
        mov eax, dword ptr [ebx].s_map_object.spell_type
        cmp eax, SPL_FLAMING_POTION
        jb ordinary
        cmp eax, SPL_HOLY_WATER
        ja ordinary
        jne not_holy
        add eax, 2 ; it`s number 4, but the holy element is 6
        not_holy:
        sub eax, SPL_FLAMING_POTION
        push eax
        ; the higher bits of the potion`s power are here:
        mov ecx, dword ptr [ebx].s_map_object.spell_mastery
        ; this will only work properly with power < 192
        ; thankfully, potions with power > 135 are not legitimately brewable
        dec ecx
        shl ecx, 6
        add ecx, dword ptr [ebx].s_map_object.spell_power ; the rest of it
        mov edx, 3
        and eax, 1
        sub edx, eax ; d2 for elec and poison, d3 for fire, cold, and holy
        call dword ptr ds:roll_dice
        pop ecx
        push 0x43a95a
        ret 4
        ordinary:
        jmp absorb_other_spell
      }
}

// Redirect applied holy water to the weapon potions code.
// Also here: pretend magic embers are slaying potions.
static void __declspec(naked) holy_water_jump(void)
{
    asm
      {
        cmp ecx, HOLY_WATER
        je quit
        cmp ecx, MAGIC_EMBER
        jne skip
        mov ecx, SLAYING_POTION
        skip:
        cmp ecx, SWIFT_POTION ; replaced code
        quit:
        ret
      }
}

// Supply the Undead Slaying enchantment when applying holy water.
// Also reduce enchantment time from 30 minutes/power to 10.
static void __declspec(naked) holy_water_enchant(void)
{
    asm
      {
        cmp eax, HOLY_WATER
        je holy
        mov eax, dword ptr [0x4e28fc+eax*4-FLAMING_POTION*4] ; replaced code
        ret
        holy:
        mov eax, edi
        xor edx, edx
        mov edi, 3
        div edi
        mov edi, eax
        mov eax, SPC_UNDEAD_SLAYING
        ret
      }
}

// Add the pseudo-button-thing corresponding
// to the "bless water" dialog option.
static void __declspec(naked) add_bless_water_reply(void)
{
    asm
      {
        call dword ptr ds:add_reply
        mov ecx, 2
        mov edx, 12
        call dword ptr ds:add_reply
        push 96 ; learn skills action
        push 0x4b3cfc ; four-reply branch
        ret
      }
}

static char reply_buffer[100];

// Supply the text to the new "bless water" reply
// when calculating text position.
static void __declspec(naked) bless_water_reply_sizing(void)
{
    asm
      {
        inc edi
        lea eax, [ebp-336] ; donate string
        cmp dword ptr [ebp-24], eax
        je new_reply
        cmp dword ptr [ebp-24], offset reply_buffer
        jne ordinary
        mov dword ptr [ebp-24], eax
        ordinary:
        add dword ptr [ebp-24], 100
        ret
        new_reply:
        mov eax, dword ptr [DIALOG2]
        mov eax, dword ptr [eax+28] ; param = temple id
        ; cheapest temples won`t sell holy water
        ; to avoid buy price being lower than sell price
        ; besides, it wouldn`t be too strong anyway
        cmp eax, 74 ; emerald island healer
        je skip
        cmp eax, 86 ; castle harmondale inner temple
        je skip
        ; also no holy water in dark temples
        cmp eax, 78 ; deyja temple
        je skip
        cmp eax, 81 ; the pit temple
        je skip
        cmp eax, 82 ; nighon temple
        je skip
        cmp eax, 87 ; temple in a bottle
        jne not_dark
        skip:
        and dword ptr [reply_buffer], 0
        inc edi
        jmp ordinary
        not_dark:
        push ecx
        imul eax, eax, SIZE_EVENT2D
        fld dword ptr [EVENTS2D_ADDR+eax].s_event2d.multiplier ; temple cost
        push 10
        fimul dword ptr [esp]
        fistp dword ptr [esp]
        push dword ptr [new_strings+STR_BLESS_WATER*4]
#ifdef __clang__
        ; for some reason clang crashes if I try to push offsets directly
        mov eax, offset reply_buffer
        push eax
#else
        push offset reply_buffer
#endif
        call dword ptr ds:sprintf
        add esp, 12
        pop ecx
        mov dword ptr [ebp-24], offset reply_buffer
        ret
      }
}

// Print the "bless water" reply.
static void __declspec(naked) bless_water_reply_text(void)
{
    asm
      {
        inc dword ptr [ebp-24]
        lea eax, [ebp-336] ; donate string
        cmp dword ptr [ebp-4], eax
        je new_reply
        cmp dword ptr [ebp-4], offset reply_buffer
        jne ordinary
        mov dword ptr [ebp-4], eax
        ordinary:
        add dword ptr [ebp-4], 100
        ret
        new_reply:
        cmp dword ptr [reply_buffer], 0
        jnz have_reply
        inc dword ptr [ebp-24]
        inc dword ptr [ebp-8]
        mov eax, dword ptr [esi+52] ; next (disabled) reply
        and dword ptr [eax+20], 0 ; bottom = 0 (prevent clicking)
        jmp ordinary
        have_reply:
        mov dword ptr [ebp-4], offset reply_buffer
        ret
      }
}

// Generate the holy water item for a donation.
static void __declspec(naked) bless_water_action(void)
{
    asm
      {
        jne not_donate
        push 0x4b7324 ; replaced je
        ret 4
        not_donate:
        cmp eax, 1
        je bless
        ret
        bless:
        mov eax, dword ptr [DIALOG2]
        mov eax, dword ptr [eax+28] ; param = temple id
        imul eax, eax, SIZE_EVENT2D
        fld dword ptr [EVENTS2D_ADDR+eax].s_event2d.multiplier ; temple cost
        fistp dword ptr [esp] ; don`t need the return address anymore
        pop ebx
        lea ecx, [ebx*4+ebx] ; price = heal cost x 10
        shl ecx, 1
        cmp dword ptr [PARTY_GOLD], ecx
        jae can_pay
        push 0x4b75bc ; not enough gold branch
        ret
        can_pay:
        call dword ptr ds:spend_gold
        mov eax, ebx
        xor edx, edx
        mov ecx, 5
        div ecx ; temple power = cost / 5
        mov ebx, eax
        mov eax, dword ptr [0xacd550] ; day of month
        add ecx, 2 ; ecx = 7
        div ecx
        lea ebx, [ebx*2+edx+1] ; water power = temple power * 2 + weekday
        sub esp, SIZE_ITEM
        mov ecx, esp
        call dword ptr ds:init_item
        mov dword ptr [esp], HOLY_WATER ; id
        mov dword ptr [esp].s_item.bonus, ebx ; power
        mov dword ptr [esp].s_item.flags, IFLAGS_ID
        mov ecx, PARTY_BIN_ADDR
        push esp
        call dword ptr ds:add_mouse_item
        mov ecx, esi
        ; second dword parameter is unused
        push ANIM_SMILE
        call dword ptr ds:show_face_animation
        push 0x4b749f ; return to main menu branch (I think)
        ret 32
      }
}

// Allow using the four elemental damage potions as throwing weapons.
// Also adds throwable (and appliable) holy water.
static inline void throw_potions(void)
{
    // the next four rewrite the potion jump table
    // holy water jump is in new_potion_effects() above
    patch_pointer(0x468f26, throw_potions_jump);
    patch_pointer(0x468f2a, throw_potions_jump);
    patch_pointer(0x468f2e, throw_potions_jump);
    patch_pointer(0x468f32, throw_potions_jump);
    hook_call(0x434723, throw_potions_power, 5);
    hook_call(0x42777e, aim_potions_type, 6);
    hook_call(0x432809, aim_potions_refund_hook, 6);
    hook_call(0x427eda, cast_potions_object, 8);
    hook_call(0x4280c7, cast_potions_jump, 6);
    hook_call(0x428c30, cast_potions_speed, 5);
    hook_call(0x42e891, cast_potions_sound, 8);
    hook_call(0x46c0c2, explode_potions_jump, 5);
    hook_call(0x46c902, explode_potions_radius, 5);
    hook_call(0x46cc01, explode_potions_sound, 8);
    hook_call(0x43974c, damage_potions_monster, 5);
    hook_call(0x43a938, damage_potions_player, 5);
    // there are two potion ID checks
    hook_call(0x4167a2, holy_water_jump, 6);
    hook_call(0x416802, holy_water_jump, 6);
    hook_call(0x416946, holy_water_enchant, 7);
    // applied holy water effect is in temp_enchants() above
    hook_jump(0x4b3d1f, add_bless_water_reply);
    hook_call(0x4b777b, bless_water_reply_sizing, 5);
    hook_call(0x4b785a, bless_water_reply_text, 7);
    // instead of unused reply's height (offset 12), erase its bottom
    // (offset 20), which is the one that's checked for collision.
    // before I added a new reply, this somehow worked as is,
    // but now the unused heal reply overlaps the donate reply,
    // preventing it from being selected without this fix.
    patch_byte(0x4b76dc, 20);
    hook_call(0x4b7059, bless_water_action, 6);
}

// Some spell elements are hardcoded.  I could just re-hardcode them to
// my new elements, but it's much cooler to use the data from spells.txt.
// Thus, this function is called just after spells.txt is parsed.
static void spell_elements(void)
{
    patch_byte(0x439c48, ELEMENT(SPL_STUN));
    patch_byte(0x428dc6, ELEMENT(SPL_SLOW));
    patch_byte(0x428748, ELEMENT(SPL_MASS_DISTORTION));
    patch_byte(0x428cce, ELEMENT(SPL_PARALYZE));
    patch_byte(0x46bf8c, ELEMENT(SPL_SHRINKING_RAY));
    patch_byte(0x42e0be, ELEMENT(SPL_CONTROL_UNDEAD));
    // Not sure if the next two do anything, but just in case.
    patch_byte(0x46c9ea, ELEMENT(SPL_PARALYZE));
    patch_byte(0x46c9e6, ELEMENT(SPL_SHRINKING_RAY));
#ifdef CHECK_OVERWRITE
    fclose(owlog);
    fclose(binary);
#endif
}

// Defined below.
static void parse_statrate(void);
static void set_colors(void);
static void parse_clsskill(void);
static void more_visible_facets(void);

// Let's ride on the tail of the spells.txt parsing function.
static void __declspec(naked) spells_txt_tail(void)
{
    asm
      {
        pop ebx
        add esp, 16
        call spell_elements
        call parse_itemgend
        call parse_statrate
        call set_colors
        call parse_clsskill
        call more_visible_facets
        ret
      }
}

static const float jump_multiplier = 0.2f; // +20% per effect

// Let GM Feather Fall boost normal jump slightly.
// Also handles boots of leaping (including Hermes' Sandals).
static void __declspec(naked) feather_fall_jump(void)
{
    asm
      {
        fld1
        cmp word ptr [PARTY_BUFF_ADDR+BUFF_FEATHER_FALL*SIZE_BUFF] \
                     .s_spell_buff.skill, GM
        jne no_ff
        fadd dword ptr [jump_multiplier]
        no_ff:
        mov ecx, 4
        check_boots:
        mov eax, dword ptr [PC_POINTERS+ecx*4-4]
        mov edx, dword ptr [eax+SLOT_BOOTS*4].s_player.equipment
        test edx, edx
        jz next_pc
        lea edx, [edx+edx*8]
        cmp dword ptr [eax+edx*4-SIZE_ITEM].s_player.items, HERMES_SANDALS
        je leaping
        cmp dword ptr [eax+S_PL_ITEM0+edx*4].s_item.bonus2, SPC_LEAPING
        jne next_pc
        leaping:
        fadd dword ptr [jump_multiplier]
        next_pc:
        loop check_boots
        fmulp
        fmul dword ptr [0x4d873c] ; replaced code
        ret
      }
}

// Make GM Torch Light even brighter than M.
static void __declspec(naked) torch_light_gm(void)
{
    asm
      {
        cmp dword ptr [ebp-24], GM ; spell school mastery
        jne master
        mov dword ptr [ebp-4], 5
        ret
        master:
        mov dword ptr [ebp-4], 4 ; replaced code
        ret
      }
}

static int enchant_item_gm_noon;

// Buff allowed special enchantments for GM Enchant Item, esp. at noon.
static void __declspec(naked) enchant_item_lvl45(void)
{
    asm
      {
        cmp al, 1
        jz quit
        cmp al, 2
        jz quit
        cmp dword ptr [enchant_item_gm_noon], 0
        jnz noon
        test al, al
        jmp quit
        noon:
        cmp al, 3
        quit:
        ret
      }
}

// At noon (11:00 to 12:59), Enchant Item is more powerful.
// Master casts as GM, and GM uses treasure level 5 instead of 4.
// Clanker's Amulet grants this effect at any time of day.
static void __declspec(naked) enchant_item_noon_check(void)
{
    asm
      {
        mov dword ptr [enchant_item_gm_noon], esi ; esi == 0
        cmp dword ptr [HOUR_OF_DAY], 11
        jb not_noon
        cmp dword ptr [HOUR_OF_DAY], 13
        jb bonus
        not_noon:
        push SLOT_AMULET
        push CLANKERS_AMULET
        mov ecx, dword ptr [ebp-32]
        call dword ptr ds:has_item_in_slot
        test eax, eax
        bonus:
        mov ecx, dword ptr [ebp-24] ; replaced code (mastery)
        jz quit
        cmp ecx, GM
        jae gm
        inc ecx
        jmp quit
        gm:
        inc dword ptr [enchant_item_gm_noon]
        quit:
        lea eax, [edi+edi] ; calculate price reduction (used below)
        ret
      }
}

// Let GM Enchant Item use treasure level 4
// for numeric enchantments, except at noon.
static void __declspec(naked) enchant_item_noon_numeric(void)
{
    asm
      {
        cmp dword ptr [enchant_item_gm_noon], 0
        jz lvl4
        mov ecx, dword ptr [0x5e3f88] ; replaced code
        ret
        lvl4:
        mov ecx, dword ptr [0x5e3f80] ; lvl 4 min
        mov esi, dword ptr [0x5e3f84] ; lvl 4 max
        ret
      }
}

// Halve certain standard bonuses that are penalized when generated normally.
// This branch of code may be unused in practice, but whatever.
static void __declspec(naked) enchant_item_halve_expert(void)
{
    asm
      {
        add edx, ecx ; replaced code
        mov ecx, dword ptr [esi].s_item.bonus
        cmp ecx, STAT_HP + 1
        je halve
        cmp ecx, STAT_SP + 1
        je halve
        cmp ecx, STAT_THIEVERY + 1
        je halve
        cmp ecx, STAT_DISARM + 1
        je halve
        cmp ecx, STAT_ARMSMASTER + 1
        jb normal
        cmp ecx, STAT_UNARMED + 1
        ja normal
        halve:
        ; note that the minimum is 3, so we don`t need to check for zero
        shr edx, 1
        normal:
        mov dword ptr [esi].s_item.bonus_strength, edx ; replaced code
        ret
      }
}

// Halve certain standard bonuses that are penalized when generated normally.
// Covers both the Master and GM cases, and also the unused Normal case.
static void __declspec(naked) enchant_item_halve_others(void)
{
    asm
      {
        add edx, ecx ; replaced code
        mov ecx, dword ptr [edi].s_item.bonus
        cmp ecx, STAT_HP + 1
        je halve
        cmp ecx, STAT_SP + 1
        je halve
        cmp ecx, STAT_THIEVERY + 1
        je halve
        cmp ecx, STAT_DISARM + 1
        je halve
        cmp ecx, STAT_ARMSMASTER + 1
        jb normal
        cmp ecx, STAT_UNARMED + 1
        ja normal
        halve:
        ; note that the minimum is 3, so we don`t need to check for zero
        shr edx, 1
        normal:
        mov dword ptr [edi].s_item.bonus_strength, edx ; replaced code
        ret
      }
}

// Allow the Berserk spell to be cast on a PC to trigger the Insane condition.
// Currently respects undead-ness and other immunities.
static void __declspec(naked) berserk_pc(void)
{
    asm
      {
        jne not_monster ; we replaced a jne
        ret
        not_monster:
        cmp dword ptr [ebp-8], esi ; target monster == 0 (just to be sure)
        jnz quit
        movzx ecx, word ptr [ebx+4] ; target player
        imul ecx, ecx, SIZE_PLAYER
        add ecx, PARTY_ADDR
        mov esi, ecx
        call dword ptr ds:player_active ; exclude dead etc. players
        test eax, eax
        jz quit
        push 1 ; can resist -- arguable, but avoids abuse
        push COND_INSANE
        mov ecx, esi
        call inflict_condition
        quit:
        push 0x42deaa ; post-cast code
        ret 4
      }
}

// Store up to 100 nearby monsters on the stack,
// abort the spell if there are none.
static void __declspec(naked) spirit_lash_count_targets(void)
{
    asm
      {
        mov eax, 0x100 ; radius
        cmp dword ptr [ebp-24], GM
        jne master
        mov eax, 0x200 ; larger radius
        master:
        sub esp, 400 ; buffer
        mov ecx, esp
        mov edx, 100 ; buffer size
        push eax
        call dword ptr ds:get_monsters_around_party
        cmp eax, 0
        jle fail
        mov esi, eax ; monsters count
        push 0x429687 ; projectile init code
        ret
        fail:
        add esp, 400
        push 0x429655 ; spell fail code
        ret
      }
}

// Origin the Spirit Lash (bogus) projectile at the party instead of target.
// That way we don't need to recalculate it for each monster.
// This chunk deals with X coordinate.
static void __declspec(naked) spirit_lash_x_chunk(void)
{
    asm
      {
        mov eax, dword ptr [PARTY_X]
        nop
        nop
      }
}

// This chunk deals with Y coordinate.
static void __declspec(naked) spirit_lash_y_chunk(void)
{
    asm
      {
        mov eax, dword ptr [PARTY_Y]
        nop
        nop
      }
}

// This chunk deals with Z coordinate.  Some further code is erased.
static void __declspec(naked) spirit_lash_z_chunk(void)
{
    asm
      {
        mov ecx, dword ptr [PARTY_Z]
      }
}

// Damage each nearby monster.
static void __declspec(naked) spirit_lash_damage(void)
{
    asm
      {
        mov ebx, ecx ; projectile
        lea edi, [esi*4-400] ; (-edi) == excess length of buffer
        pop ecx ; undo an earlier push
        loop:
        pop edx ; next monster in the buffer
        mov ecx, ebx
        lea eax, [ebp-284] ; force vector
        push eax
        call dword ptr ds:damage_monster_from_party
        dec esi
        jnz loop
        sub esp, edi ; discard rest of buffer
        push 0x42977b ; return address
        ret
      }
}

// Direct calls from assembly are not relocated properly.
static funcptr_t memset_ptr = memset;

// Bug fix: Sacrifice didn't cure conditions or aging, despite the description.
// It still doesn't cure zombification, but neither does DI.
static void __declspec(naked) sacrifice_conditions(void)
{
    asm
      {
        push COND_ZOMBIE * 8 ; all conditions EXCEPT zombie
        push 0 ; zero out
        push edi ; conditions are at beginning of struct player
        call dword ptr ds:memset_ptr
        add esp, 12
        and word ptr [edi].s_player.age_bonus, 0
        ret
      }
}

// A bitfield to store spells disabled by scripts.
static uint8_t disabled_spells[(LAST_REAL_SPELL+7)/8];

// Reset disabled spell on map reload.
static void reset_disabled_spells(void)
{
    memset(disabled_spells, 0, sizeof(disabled_spells));
}

// Check the disabled spells bitfield.
static int __stdcall check_spell_disabled(unsigned spell)
{
    if (spell > LAST_REAL_SPELL)
        return 0;
    return !!(disabled_spells[spell/8] & (1 << (spell & 7)));
}

// Check if a spell is disabled on this map; if so, fail.
// Called from cast_potions_jump() above.
static void __declspec(naked) forbid_spell(void)
{
    asm
      {
        inc eax
        push eax
        call check_spell_disabled
        test eax, eax
        jnz disabled
        ; restore registers
        movsx eax, word ptr [ebx]
        dec eax
        mov ecx, dword ptr [ebp-24]
        mov edx, 3
        ret
        disabled:
        push 0x4290c1
        ret 4
      }
}

// Set the disabled spell bit.
static void __stdcall disable_spell(unsigned spell)
{
    if (spell <= LAST_REAL_SPELL)
        disabled_spells[spell/8] |= 1 << (spell & 7);
}

// Unset the disabled spell bit.
static void __stdcall enable_spell(unsigned spell)
{
    if (spell <= LAST_REAL_SPELL)
        disabled_spells[spell/8] &= ~(1 << (spell & 7));
}

// Disregard duration when determining if GM Wizard Eye is active.
static void __declspec(naked) wizard_eye_functionality(void)
{
    asm
      {
        movzx eax, word ptr [PARTY_BUFF_ADDR+BUFF_WIZARD_EYE*SIZE_BUFF] \
                            .s_spell_buff.skill ; replaced code
        cmp eax, GM
        jne quit
        mov dword ptr [ebp-24], 1 ; wizard eye active
        quit:
        ret
      }
}

// Do not ever dispel GM Wizard Eye.
static void __declspec(naked) wizard_eye_permanence(void)
{
    asm
      {
        cmp esi, PARTY_BUFF_ADDR + BUFF_WIZARD_EYE * SIZE_BUFF
        jne not_eye
        cmp word ptr [esi].s_spell_buff.skill, GM
        je quit ; caller will also check zf later
        not_eye:
        mov word ptr [esi].s_spell_buff.skill, bx ; replaced code
        cmp ax, bx ; replaced code
        quit:
        ret
      }
}

// Disregard duration when displaying GM Wizard Eye animation.
static void __declspec(naked) wizard_eye_animation(void)
{
    asm
      {
        cmp word ptr [PARTY_BUFF_ADDR+BUFF_WIZARD_EYE*SIZE_BUFF] \
                     .s_spell_buff.skill, MASTER
        jg quit ; caller will also check flags
        cmp dword ptr [PARTY_BUFF_ADDR+BUFF_WIZARD_EYE*SIZE_BUFF+4], 0 ; repl.
        quit:
        ret
      }
}

// Handle durationless GM Wizard Eye when counting buffs to display.
static void __declspec(naked) wizard_eye_display_count(void)
{
    asm
      {
        cmp eax, PARTY_BUFF_ADDR + BUFF_WIZARD_EYE * SIZE_BUFF
        jne not_eye
        cmp word ptr [eax].s_spell_buff.skill, MASTER
        jg quit ; caller will also check flags
        not_eye:
        cmp dword ptr [eax+4], ebx ; replaced code
        jl skip
        quit:
        ret
        skip:
        push 0x41d712 ; replaced jump
        ret 4
      }
}

// Always display GM Wizard Eye, regardless of duration.
static void __declspec(naked) wizard_eye_display(void)
{
    asm
      {
        cmp ecx, PARTY_BUFF_ADDR + BUFF_WIZARD_EYE * SIZE_BUFF
        jne not_eye ; note that WE is last buff so it`ll never be greater
        cmp word ptr [ecx].s_spell_buff.skill, MASTER
        not_eye:
        mov ecx, dword ptr [ecx+4] ; replaced code
        jg quit ; caller will also check flags
        test ecx, ecx ; replaced code
        quit:
        ret
      }
}

// Direct calls from assembly are not relocated.
static const funcptr_t strcpy_ptr = strcpy;
static const funcptr_t strcat_ptr = strcat;
static const funcptr_t strcmp_ptr = strcmp;
static const funcptr_t strchr_ptr = strchr;

// Display GM Wizard Eye duration as "Permanent".
static void __declspec(naked) wizard_eye_display_duration(void)
{
    asm
      {
        cmp dword ptr [ebp-8], PARTY_BUFF_ADDR + BUFF_WIZARD_EYE * SIZE_BUFF
        jne not_eye
        cmp word ptr [PARTY_BUFF_ADDR+BUFF_WIZARD_EYE*SIZE_BUFF] \
                     .s_spell_buff.skill, GM
        je permanent
        not_eye:
        push 0x41d1b6 ; replaced function call
        ret
        permanent:
        push 0x4e323c ; right-align code
        push 0x5c5c30 ; buffer used by the replaced function
        call dword ptr ds:strcpy_ptr
        push dword ptr [GLOBAL_TXT_ADDR+121*4] ; "permanent"
        push 0x5c5c30
        call dword ptr ds:strcat_ptr
        push 32 ; a single space
        push esp ; as a string
        push 0x5c5c30
        call dword ptr ds:strcat_ptr
        add esp, 28
        ; no, I don`t know what most of these params do
        xor eax, eax
        push eax
        push eax
        push eax
        push 0x5c5c30
        push eax
        push esi
        push 32
        mov edx, dword ptr [ebp-12]
        mov ecx, edi
        call dword ptr ds:print_string
        ret 12
      }
}

// GM Wizard Eye is applied permanently.
// Ctrl-clicking on it in the spellbook will cancel it.
// TODO: cancelling could have a different sound?
static void __declspec(naked) wizard_eye_cast(void)
{
    asm
      {
        test byte ptr [ebx+9], 4 ; turn off flag
        jnz remove
        cmp dword ptr [ebp-24], GM
        je remove ; but then re-add
        shl eax, 7 ; replaced code
        mov dword ptr [ebp-20], eax ; replaced code
        ret
        remove:
        mov ecx, PARTY_BUFF_ADDR + BUFF_WIZARD_EYE * SIZE_BUFF
        call dword ptr ds:remove_buff
        mov dx, GM
        test byte ptr [ebx+9], 4 ; turn off flag
        cmovnz dx, si ; si == 0
        mov word ptr [PARTY_BUFF_ADDR+BUFF_WIZARD_EYE*SIZE_BUFF] \
                     .s_spell_buff.skill, dx
        push 0x42deaa ; post-cast code
        ret 8
      }
}

// Day of Protection always applies Wizard Eye at Master skill.
// Do not overwrite existing permanent Eye, though.
static void __declspec(naked) wizard_eye_from_day_of_protection(void)
{
    asm
      {
        cmp word ptr [PARTY_BUFF_ADDR+BUFF_WIZARD_EYE*SIZE_BUFF] \
                     .s_spell_buff.skill, GM
        je skip
        mov dword ptr [ebp-24], MASTER ; no GM
        fild qword ptr [CURRENT_TIME_ADDR] ; replaced code
        ret
        skip:
        push 0x42deaa ; post-cast code
        ret 4
      }
}

// When ctrl-clicking Immolation or GM Wizard Eye to switch them off,
// do not charge spell points.  Same for Storm Trident's free spell.
// Also here: Eloquence Talisman's spell recovery bonus,
// and the difficulty-dependent spell cost increase.
static void __declspec(naked) switch_off_spells_for_free(void)
{
    asm
      {
        mov dword ptr [ebp-180], eax ; replaced code
        jnz quit ; not casting from a spellbook
        cmp dword ptr [elemdata.difficulty], esi ; == 0
        jz easy
        shr edx, 1
        cmp dword ptr [elemdata.difficulty], 2
        jae costly
        shr edx, 1
        costly:
        add dword ptr [ebp-36], edx ; sp cost
        easy:
        mov ecx, dword ptr [ebp-32] ; PC
        push SLOT_AMULET
        push ELOQUENCE_TALISMAN
        call dword ptr ds:has_item_in_slot
        test eax, eax
        jz no_talisman
        mov eax, dword ptr [ebp-180]
        shr eax, 2
        sub dword ptr [ebp-180], eax ; -25% of base recovery
        no_talisman:
        cmp word ptr [ebx], SPL_LIGHTNING_BOLT
        jne not_trident
        mov ecx, dword ptr [ebp-32] ; PC
        push SLOT_MAIN_HAND
        push STORM_TRIDENT
        call dword ptr ds:has_item_in_slot
        test eax, eax
        jz not_trident
        xor byte ptr [ebx+9], 4 ; before this, flag meant 'cast normally' here
        not_trident:
        mov ecx, dword ptr [ebp-24] ; restore
        test byte ptr [ebx+9], 4 ; turn off flag
        quit:
        ret
      }
}

// Allow cancelling Immolation by ctrl-clicking on it in the spellbook.
// Also here: remember Immolation caster for damage messages.
static void __declspec(naked) switch_off_immolation(void)
{
    asm
      {
        test byte ptr [ebx+9], 4 ; turn off flag
        jnz remove
        cast:
        shl eax, 7 ; replaced code
        mov dword ptr [ebp-44], eax ; replaced code
        movsx eax, word ptr [ebx+2] ; caster
        mov dword ptr [esp+4], eax ; last pushed
        ret
        remove:
        mov ecx, PARTY_BUFF_ADDR + BUFF_IMMOLATION * SIZE_BUFF
        call dword ptr ds:remove_buff
        push 0x42deaa ; post-cast code
        ret 8
      }
}

// Make HoP duration equivalent to its component spells
// when cast separately at the same skill and mastery.
static void __declspec(naked) hour_of_power_duration(void)
{
    asm
      {
        imul eax, eax, 75
        add eax, 60 * 60
        imul ecx, ecx, 15
        add ecx, 60 * 60
        ret
      }
}

// Redirect GM Day of Protection cast to old Master code.
static void __declspec(naked) day_of_protection_chunk(void)
{
    asm
      {
        cmp ecx, GM
        nop
        nop
      }
}

// Increase GM Flight duration instead of removing mana drain.
static void __declspec(naked) flight_duration(void)
{
    asm
      {
        jnz quit ; if not GM
        imul edi, edi, 6
        mov dword ptr [ebp-16], edi ; duration multiplier
        quit:
        ret
      }
}

// Spectral Weapon spell reuses Fire Aura code, sans enchantment ID.
static void __declspec(naked) spectral_weapon(void)
{
    asm
      {
        mov dword ptr [ebp-4], SPC_SPECTRAL
        push 0x42903f ; fire aura code
        ret
      }
}

// Also, SW has a purple enchantment aura instead of red.
static void __declspec(naked) spectral_aura(void)
{
    asm
      {
        cmp word ptr [ebx], SPL_SPECTRAL_WEAPON
        je spectral
        or dword ptr [esi].s_item.flags, 0x10 ; replaced code
        push 0x42dea0 ; replaced jump
        ret
        spectral:
        push 0x42de9c ; vamp weapon purple aura
        ret
      }
}

// We replaced Fate with SW for players, but not for monsters,
// so monster info should display the old spell name.
static void __declspec(naked) monster_fate(void)
{
    asm
      {
        pop edx
        cmp eax, SPL_SPECTRAL_WEAPON * 9
        je spectral
        push dword ptr [0x5cbeb4+eax*4] ; replaced code
        jmp edx
        spectral:
        push dword ptr [GLOBAL_TXT_ADDR+221*4] ; "fate"
        jmp edx
      }
}

// Let the scrolls cast a spell according to mod1 in items.txt,
// as opposed to their item ID.  Allows retaining Fate scrolls.
// Also here: calculate variable scroll power (with the belt bonus).
static void __declspec(naked) scroll_spell_id(void)
{
    asm
      {
        lea ecx, [eax+eax*2]
        shl ecx, 4
        movzx esi, byte ptr [ITEMS_TXT_ADDR+ecx] \
                            .s_items_txt_item.mod1_dice_count
        mov ecx, dword ptr [ebp+8] ; PC 1-4
        mov ecx, dword ptr [PC_POINTERS+ecx*4-4]
        mov bl, byte ptr [ecx].s_player.class
        push SLOT_BELT
        push GADGETEERS_BELT
        call dword ptr ds:has_item_in_slot
        mov ecx, dword ptr [MOUSE_ITEM].s_item.charges
        test ecx, ecx
        jnz ok
        mov ecx, SKILL_MASTER + 5 ; default power just in case
        ok:
        test eax, eax
        jz no_belt
        mov edx, ecx
        and edx, SKILL_MASK
        shr edx, 1
        and bl, -4
        cmp bl, CLASS_THIEF
        je thief
        shr edx, 1
        thief:
        add ecx, edx
        xor edx, edx
        cmp esi, LAST_REAL_SPELL
        ja mastery ; fake ones are telepathy and fate, both normal mastery
        cmp esi, SPL_PSYCHIC_SHOCK
        sete dl
        je mastery ; this spell is now expert (berserk can still be expert too)
        lea eax, [esi-1]
        mov ebx, 11
        div ebx
        level:
        lea edx, [edx+edx*4]
        shr edx, 4 ; 0-10 to 0-3
        mastery:
        cmp edx, 3
        sbb edx, -1
        shl edx, 6
        cmp ecx, edx
        cmovae edx, ecx
        cmp edx, SKILL_GM
        jae no_belt
        and edx, ~SKILL_MASK
        jnz skilled
        add edx, SKILL_EXPERT / 2
        skilled:
        and ecx, SKILL_MASK
        lea ecx, [edx*2+ecx] ; normal -> expert -> master -> gm
        no_belt:
        mov dword ptr [scroll_power], ecx
        mov eax, dword ptr [MOUSE_ITEM] ; restore
        ret
      }
}

// Reduce SW duration below Master.  Also reused for Vampiric Weapon.
static void __declspec(naked) spectral_weapon_duration(void)
{
    asm
      {
        cmp word ptr [ebx], SPL_FIRE_AURA ; it reuses same code
        je skip
        cmp dword ptr [ebp-24], EXPERT ; skill rank
        ja master
        jb normal
        lea eax, [eax+eax*2] ; 5 or 15 min/skill
        normal:
        add eax, 12 ; + one hour
        imul eax, eax, 5 * 60
        ret
        master:
        inc eax ; also + one hour for description clarity
        skip:
        imul eax, eax, 60 * 60 ; replaced code (1 hour/skill)
        ret
      }
}

// Item-targeting spells sometimes got confused when targeting the first item
// in the PC's inventory, as its ID of 0 was mistaken for no chosen target,
// and with software 3D the game sometimes attempted to target a nearby
// monster instead, which resulted in a wrong item being chosen.
// Update: this is fixed in the patch now, but not for Spectral Weapon.
static void __declspec(naked) zero_item_spells(void)
{
    asm
      {
        mov eax, dword ptr [ebx].s_item.bonus2 ; replaced code
        cmp eax, esi ; replaced code
        jnz quit
        cmp word ptr [ebx], SPL_SPECTRAL_WEAPON
        jne not_spectral
        cmp ebx, esi ; clear zf
        quit:
        ret
        not_spectral:
        xor eax, eax ; set zf
        ret
      }
}

// Replace Telepathy with an aggro-affecting buff.
static void __declspec(naked) aura_of_conflict(void)
{
    asm
      {
        mov eax, dword ptr [ebp-32]
        mov edx, dword ptr [ebp-36]
        sub dword ptr [eax].s_player.sp, edx ; spell cost
        test byte ptr [ebx+9], 4 ; turn off flag
        cmovnz eax, dword ptr ds:remove_buff
        jnz remove
        mov eax, 15 * MINUTE
        mul edi ; spell power
        add eax, ONE_HOUR
        push esi
        push esi
        push ecx
        push ecx
        add eax, dword ptr [CURRENT_TIME_ADDR]
        adc edx, dword ptr [CURRENT_TIME_ADDR+4]
        push edx
        push eax
        mov eax, dword ptr ds:add_buff
        remove:
        movzx edi, word ptr [ebx+4] ; target pc
        imul ecx, edi, NBUFF_COUNT * SIZE_BUFF
        add ecx, offset elemdata.new_pc_buffs \
                 + NBUFF_AURA_OF_CONFLICT * SIZE_BUFF
        call eax ; add or remove
        push edi
        push SPL_INVISIBILITY
        mov ecx, dword ptr [CGAME]
        mov ecx, dword ptr [ecx+0xe50]
        call dword ptr ds:spell_face_anim
        push 0x42deaa ; after casting a spell
        ret
      }
}

// For batch casting.
static int accumulated_recovery;

// Give some spells different effects on a Ctrl-click.
// TODO: should we disable permanent weapon enchantment here?
static int __stdcall alternative_spell_mode(int player_id, int spell)
{
    int unsafe = byte(STATE_BITS) & 0x30;
    struct player *player = PARTY + player_id;
    int enchant, flags = 0x820, items[8] = { 0 },
        pcs[8] = { 0, 1, 2, 3 }, count = 4;
    switch (spell)
      {
        case SPL_FIRE_AURA:
            enchant = SPC_FIRE; // approximate
            goto weapon;
        case SPL_SPECTRAL_WEAPON:
            enchant = SPC_SPECTRAL;
            goto weapon;
        case SPL_VAMPIRIC_WEAPON:
            enchant = SPC_VAMPIRIC;
        weapon:
            count = 0;
            for (int pc = 0; pc < 4; pc++)
              {
                struct player *current = PARTY + pc;
                int unarmed = TRUE;
                int right = current->equipment[SLOT_MAIN_HAND];
                if (right)
                  {
                    struct item *weapon = &current->items[right-1];
                    unarmed = ITEMS_TXT[weapon->id].skill == SKILL_STAFF;
                    expire_temp_bonus(weapon, CURRENT_TIME);
                    if (can_add_temp_enchant(weapon, enchant))
                      {
                        pcs[count] = pc;
                        items[count] = right - 1;
                        count++;
                      }
                  }
                int left = current->equipment[SLOT_OFFHAND];
                if (left)
                  {
                    struct item *weapon = &current->items[left-1];
                    if (ITEMS_TXT[weapon->id].equip_stat < ITEM_TYPE_MISSILE)
                      {
                        unarmed = FALSE;
                        expire_temp_bonus(weapon, CURRENT_TIME);
                        if (can_add_temp_enchant(weapon, enchant))
                          {
                            pcs[count] = pc;
                            items[count] = left - 1;
                            count++;
                          }
                      }
                  }
                int gaunt = current->equipment[SLOT_GAUNTLETS];
                if (unarmed && gaunt)
                  {
                    struct item *weapon = &current->items[gaunt-1];
                    expire_temp_bonus(weapon, CURRENT_TIME);
                    if (ITEMS_TXT[weapon->id].skill == SKILL_UNARMED
                        && can_add_temp_enchant(weapon, enchant))
                      {
                        pcs[count] = pc;
                        items[count] = gaunt - 1;
                        count++;
                      }
                  }
              }
            if (!count)
                for (int pc = 0; pc < 4; pc++)
                  {
                    struct player *current = PARTY + pc;
                    int missile = current->equipment[SLOT_MISSILE];
                    if (missile)
                      {
                        struct item *bow = &current->items[missile-1];
                        expire_temp_bonus(bow, CURRENT_TIME);
                        if (ITEMS_TXT[bow->id].equip_stat < ITEM_TYPE_MISSILE
                            && ITEMS_TXT[bow->id].skill != SKILL_BLASTER
                            && can_add_temp_enchant(bow, enchant))
                          {
                            pcs[count] = pc;
                            items[count] = missile - 1;
                            count++;
                          }
                      }
                  }
            if (!count)
                return FALSE;
            break;
        case SPL_WIZARD_EYE:
            if (PARTY_BUFFS[BUFF_WIZARD_EYE].skill < GM)
                return FALSE;
            goto turn_off;
        case SPL_IMMOLATION:
            if (!PARTY_BUFFS[BUFF_IMMOLATION].expire_time)
                return FALSE;
        turn_off:
            count = 1;
            flags = 0x400; // turn off for free
            goto past_checks; // allow unsafe, don't check SP
        case SPL_AURA_OF_CONFLICT:
            count = 0;
            for (int pc = 0; pc < 4; pc++)
                if (elemdata.new_pc_buffs[pc][NBUFF_AURA_OF_CONFLICT].power)
                    pcs[count++] = pc;
            if (!count) return FALSE;
            flags = 0x420; // blaze it
            goto past_checks; // as above
        case SPL_BLESS:
            if (player->skills[SKILL_SPIRIT] >= SKILL_EXPERT)
                return FALSE;
            break;
        case SPL_LIGHTNING_BOLT:
            if (has_item_in_slot(player, STORM_TRIDENT, SLOT_MAIN_HAND))
                return 0x400; // gotta call aim_spell(), but with extra flags
            return FALSE;
            break;
        case SPL_PRESERVATION:
            if (player->skills[SKILL_SPIRIT] >= SKILL_MASTER)
                return FALSE;
            break;
        case SPL_REGENERATION:
            break;
        case SPL_HAMMERHANDS:
            if (player->skills[SKILL_BODY] >= SKILL_GM)
                return FALSE;
            break;
        case SPL_PAIN_REFLECTION:
            if (player->skills[SKILL_DARK] >= SKILL_MASTER)
                return FALSE;
            break;
        default:
            return FALSE;
      }
    if (unsafe)
        return FALSE;
    // this relies on the fact none of these spells have a mastery-varied cost
    int cost = SPELL_INFO[spell].cost_gm * (elemdata.difficulty + 4) / 4;
    int max_count = player->sp / cost;
    if (max_count <= 0)
        return FALSE;
    if (count > max_count)
        count = max_count;
    past_checks:
    accumulated_recovery = 0;
    int id = 0;
    for (int target = 0; target < count; target++)
      {
        while (SPELL_QUEUE[id].spell)
            if (++id >= 10)
                goto skip;
        SPELL_QUEUE[id].spell = spell;
        SPELL_QUEUE[id].caster = player_id;
        SPELL_QUEUE[id].target_pc = pcs[target];
        SPELL_QUEUE[id].flags = flags;
        SPELL_QUEUE[id].skill = 0; // use the caster's skill
        SPELL_QUEUE[id].target_object = items[target];
      }
    skip:
    SPELL_QUEUE[id].flags &= ~0x20; // last spell induces recovery
    return TRUE;
}

// Hook for the above.
static void __declspec(naked) alternative_spell_mode_hook(void)
{
    asm
      {
        cmp dword ptr [0x4f86dc], 3 ; replaced code
        jz quit
        cmp dword ptr [0x507a18], 1 ; ctrl pressed
        jne quit
        push dword ptr [esp+24] ; spell
        push dword ptr [esp+52] ; player id
        call alternative_spell_mode
        cmp eax, 1 ; skip vanilla code if true
        ja trident ; > 1 is special case
        quit:
        ret
        trident:
        pop edx
        push ebx ; == 0
        push eax ; extra flags
        push ebx
        add edx, 11 ; past old push-ebx-es
        jmp edx
      }
}

// When batch casting, accumulate recovery until the last spell.
static void __declspec(naked) cumulative_recovery(void)
{
    asm
      {
        xor esi, esi ; replaced code
        test byte ptr [ebx+9], 8 ; our flag
        jz skip
        mov eax, dword ptr [ebp-180] ; recovery
        test eax, eax
        cmovs eax, esi
        add eax, dword ptr [accumulated_recovery]
        mov dword ptr [accumulated_recovery], eax
        mov dword ptr [ebp-180], eax
        skip:
        test byte ptr [ebx+8], 0x20 ; replaced code
        ret
      }
}

// Make EI min value variable, at 500 - 8 * skill.
// NB: reduction is calculated partly in enchant_item_noon_check().
static void __declspec(naked) enchant_item_min_value(void)
{
    asm
      {
        add eax, dword ptr [ebp-12] ; only 4 * skill here
        add eax, dword ptr [ebp-12] ; hence twice
        cmp eax, 500
        ret
      }
}

// Ditto, but for weapons: 250 - 4 * skill.
static void __declspec(naked) enchant_item_weapon_value(void)
{
    asm
      {
        add eax, dword ptr [ebp-12] ; calculated earlier
        cmp eax, 250
        ret
      }
}

// Buff Immolation duration to 5/15 min/skill now that it's toggleable.
static void __declspec(naked) immolation_duration_chunk(void)
{
    asm
      {
        lea eax, [eax+eax*2] ; gm
        nop
        nop
        imul eax, eax, 5 * 60 ; master
      }
}

// Same, but for gamescript (pedestal) code.
static void __declspec(naked) immolation_duration_pedestal_chunk(void)
{
    asm
      {
        lea esi, [esi+esi*2] ; gm
        nop
        nop
        imul esi, esi, 5 * 60 ; master
      }
}

// Legacy MM6 code (apparently) didn't display GM spell cost properly.
static void __declspec(naked) fix_gm_spell_cost_display(void)
{
    asm
      {
        movzx ecx, word ptr [edi+SKILL_FIRE*2+eax*2].s_player.skills
        test ch, ch
        jz skip
        sub ecx, SKILL_EXPERT ; so that gm == 3 << 6
        skip:
        ret
      }
}

// For the two hooks below.
static void *souldrinker_hp_pointer;
static int souldrinker_old_hp;

// Before damaging each monster, take note of its HP.
static void __declspec(naked) souldrinker_remember_monster_hp(void)
{
    asm
      {
        add edi, MAP_MONSTERS_ADDR + S_MM_HP
        mov dword ptr [souldrinker_hp_pointer], edi
        movzx eax, word ptr [edi]
        mov dword ptr [souldrinker_old_hp], eax
        jmp dword ptr ds:launch_object ; replaced call
      }
}

// Now compare with HP after damage and update stolen HP pool accordingly.
static void __declspec(naked) souldrinker_calculate_damage(void)
{
    asm
      {
        mov ecx, dword ptr [souldrinker_hp_pointer]
        xor eax, eax
        cmp word ptr [ecx], ax
        cmovg ax, word ptr [ecx]
        sub eax, dword ptr [souldrinker_old_hp]
        jae skip
        sub dword ptr [ebp-44], eax ; hp pool
        skip:
        mov dword ptr [ebp-8], edi ; replaced code
        cmp edi, dword ptr [ebp-12] ; ditto
        ret
      }
}

// Paralysis nerf: each time a monster is hit, it has a 20% chance to wear off.
static void __declspec(naked) wear_off_paralysis(void)
{
    asm
      {
        call dword ptr ds:random
        xor edx, edx
        mov ecx, 5
        div ecx
        test edx, edx
        jnz skip
        lea ecx, [ebx+MBUFF_PARALYSIS*SIZE_BUFF].s_map_monster.spell_buffs
        call dword ptr ds:remove_buff
        skip:
        lea ecx, [ebx+MBUFF_FEAR*SIZE_BUFF].s_map_monster.spell_buffs ; repl.
        ret
      }
}

// Effective Town Portal spell cost.  Used just below.
static int town_portal_cost;

// On Master, always town portal to the last visited region like in MM6.
// Also here: remember the current spell cost (for scrolls or hard difficulty).
static void __declspec(naked) master_town_portal(void)
{
    asm
      {
        mov eax, dword ptr [ebp-36] ; spell cost
        mov dword ptr [town_portal_cost], eax
        cmp dword ptr [ebp-24], GM
        jae skip
        mov eax, dword ptr [elemdata.last_region]
        test eax, eax
        js fail
        mov dword ptr [esp+4], 183 ; town portal teleport action
        mov dword ptr [esp+8], eax ; param 1 (town id)
        skip:
        jmp dword ptr ds:add_action ; replaced call
        fail:
        mov dword ptr [esp], 0x4290c1 ; fail without wasting a turn
        ret 12
      }
}

// When adding a town portal quest bit, also update last TP region.
// Also here: track quest items when their corresponding qbit is set.
static void __declspec(naked) update_new_tp_region(void)
{
    asm
      {
        cmp eax, 211 ; last TP qbit
        ja lost
        sub eax, 206 ; first TP qbit
        jb skip
        jz update
        cmp eax, 2
        je decrease
        cmp eax, 5
        jne increase
        dec eax
        decrease:
        dec eax
        dec eax
        increase:
        inc eax
        update:
        mov dword ptr [elemdata.last_region], eax
        skip:
        mov eax, dword ptr [ebp+12] ; restore
        lost:
        mov ecx, LOST_QBIT_COUNT
        loop:
        cmp ax, word ptr [LOST_QBITS+ecx*4-4]
        loopne loop
        cmove cx, word ptr [LOST_QBITS+ecx*4+2]
        test ecx, ecx
        jz quit
        cmp byte ptr [elemdata.lost_items+ecx-FIRST_LOST_ITEM], LOST_NOTRACK
        jne quit
        mov byte ptr [elemdata.lost_items+ecx-FIRST_LOST_ITEM], LOST_GONE
        quit:
        cmp dword ptr [0x722d90+eax*4], 0 ; replaced code
        ret
      }
}

// Do not issue exit action if already in main screen.
// Also here: use the stored spell cost.
static void __declspec(naked) town_portal_from_main_screen(void)
{
    asm
      {
        mov eax, dword ptr [town_portal_cost]
        mov dword ptr [esp+4], eax ; was always 20
        cmp dword ptr [CURRENT_SCREEN], ebx ; == 0
        jnz skip
        mov dword ptr [esp], 0x4314ca ; skip exit action
        skip:
        jmp dword ptr ds:spend_sp ; replaced call
      }
}

// Fix a segfault if Master Town Portal is cast with no active dialog.
static void __declspec(naked) town_portal_without_dialog(void)
{
    asm
      {
        cmp eax, ebx ; == 0 if no dialog
        jz skip
        mov eax, dword ptr [eax+72] ; replaced code
        cmp eax, ebx ; ditto
        skip:
        ret
      }
}

// On a beacon recall, increase caster's recall counter,
// and activate any mana anchors present on party members.
static void __thiscall beacon_recall_effects(struct player *caster)
{
    if (caster)
        caster->beacon_casts++;
    for (int p = 0; p < 4; p++)
      {
        struct spell_buff *anchor
            = &elemdata.new_pc_buffs[p][NBUFF_ANCHORED_MANA];
        if (anchor->expire_time)
          {
            int power = anchor->power;
            struct player *player = PARTY + p;
            remove_buff(anchor);
            if (player->sp < power)
                power = player->sp;
            if (!power)
                continue;
            player->sp -= power;
            damage_player(player, power * (elemdata.difficulty + 1), MAGIC);
            show_status_text(new_strings[STR_MANA_ANCHOR_TRIGGERED], 5);
          }
      }
}

// Hook for the above.
static void __declspec(naked) beacon_recall_effects_hook(void)
{
    asm
      {
        mov ecx, dword ptr [esp+20] ; pc
        call beacon_recall_effects
        mov eax, dword ptr [ACTION_THIS_ADDR] ; replaced code
        ret
      }
}

// Set to 1 if the recall page should be disabled.
static int cannot_recall;

// If already at the recall limit, always show the place beacon tab.
static void __declspec(naked) lloyd_starting_tab(void)
{
    asm
      {
        xor edx, edx
        mov dword ptr [cannot_recall], edx
        movzx eax, byte ptr [eax].s_player.beacon_casts
        inc eax
        lea eax, [eax+eax*2]
        cmp eax, dword ptr [ebp-56] ; spell skill
        jbe ok
        mov byte ptr [0x5063ec], dl ; lloyd page flag
        inc edx
        mov dword ptr [cannot_recall], edx
        ok:
        mov ecx, 0x50ba60 ; replaced code
        ret
      }
}

// Disable switching to the recall tab if our flag is set.
static void __declspec(naked) lloyd_disable_recall(void)
{
    asm
      {
        test dword ptr [cannot_recall], eax
        jnz disable ; if both == 1
        mov byte ptr [0x5063ec], al ; replaced code
        ret
        disable:
        mov ecx, dword ptr [new_strings+STR_CANNOT_RECALL*4]
        mov edx, 2
        call dword ptr ds:show_status_text
        mov eax, SOUND_BUZZ - SOUND_TURN_PAGE_UP
        ret
      }
}

// Clear water walk bit before checking for lava.
static void __declspec(naked) reset_lava_walking(void)
{
    asm
      {
        and word ptr [STATE_BITS], ~0x280 ; both ww and lava flags
        ret
      }
}

// Let GM Water Walking protect from lava damage.
static void __declspec(naked) lava_walking(void)
{
    asm
      {
        test byte ptr [ecx+eax+47], 0x40 ; replaced code
        jz quit
        cmp word ptr [PARTY_BUFF_ADDR+BUFF_WATER_WALK*SIZE_BUFF] \
                     .s_spell_buff.skill, GM
        jb quit
        or byte ptr [STATE_BITS], 0x80 ; water walk state flag
        xor eax, eax ; set zf
        quit:
        ret
      }
}

// Don't limit stun knockback at 10 (it's now set at 40).
static void __declspec(naked) increase_stun_knockback(void)
{
    asm
      {
        jle skip ; replaced jump
        cmp dword ptr [ebp-32], 0 ; stun flag
        jnz skip
        mov dword ptr [ebp-28], eax ; replaced code (set kb to 10)
        skip:
        ret
      }
}

// Greatly increase monster recovery after stun, but prevent it from stacking.
static void __declspec(naked) stun_recovery(void)
{
    asm
      {
        lea eax, [eax+eax*4] ; 20 -> 100
        mov ecx, dword ptr [esi].s_map_monster.recovery
        shr ecx, 1
        sub eax, ecx ; diminishing returns, always below 200
        jbe skip
        add dword ptr [esi].s_map_monster.recovery, eax
        skip:
        cmp dword ptr [TURN_BASED], ebx
        jz quit
        mov edx, dword ptr [ebp-24] ; monster id
        shl edx, 3
        add edx, TGT_MONSTER
        mov eax, TURN_BASED_THIS + 16 ; tb queue
        mov ecx, dword ptr [eax-4]
        test ecx, ecx
        jle quit
        next_actor:
        add eax, 16
        cmp dword ptr [eax], edx ; tb actor id
        loopne next_actor
        jne quit
        mov edx, dword ptr [eax+4] ; current recovery
        shr edx, 1
        sub edx, 100
        jae quit
        neg edx
        mov dword ptr [eax+4], edx
        quit:
        cmp dword ptr [0x6be1f8], ebx ; replaced code
        ret
      }
}

// Remember the power of Stun spell.
static void __declspec(naked) stun_power_chunk(void)
{
    asm
      {
        mov eax, dword ptr [ebx].s_map_object.spell_power
        inc eax
        mov dword ptr [ebp-32], eax ; stun flag - now stores power
      }
}

// The same resist roll is shared by weapon stun and the Stun spell.
// We need to change the element to Physical for the former.
// Also here: use yet another element for Lightning Bolt stun.
static void __declspec(naked) stun_element(void)
{
    asm
      {
        cmp dword ptr [ebp-32], 1 ; stun flag / power
        jg skip
        mov dword ptr [esp+8], PHYSICAL
        cmp dword ptr [ebp-32], ebx ; == 0
        jge skip
        neg dword ptr [ebp-32] ; lb uses negative values as a marker
        mov dword ptr [esp+8], SHOCK
        skip:
        jmp dword ptr ds:monster_resists_condition ; replaced call
      }
}

// Do not raise flying monsters during the Armageddon sequence.
static void __declspec(naked) armageddon_flyers(void)
{
    asm
      {
        cmp byte ptr [esi].s_map_monster.flight, 0
        jnz skip
        add word ptr [esi].s_map_monster.speed_z, dx ; replaced code
        skip:
        ret
      }
}

// Remove XP reward for killing monsters through Armageddon
// and instead enable the check for killing peasants and guards.
static void __declspec(naked) armageddon_rep(void)
{
    asm
      {
        push 0x401bc1 ; after xp code
        mov ecx, dword ptr [ebp-8] ; monster id
        jmp dword ptr ds:kill_civilian
      }
}

// Heal all monsters after party spends a whole day in the same map,
// specifically to curb prolonged Armageddon camping.
static void armageddon_heal(void)
{
    if (CURRENT_TIME - elemdata.map_enter_time < ONE_DAY)
        return;
    elemdata.map_enter_time = CURRENT_TIME;
    for (int i = 0; i < dword(MONSTER_COUNT); i++)
        if (monster_active(MAP_MONSTERS + i)
            || MAP_MONSTERS[i].ai_state == AI_INVISIBLE)
            MAP_MONSTERS[i].hp = MAP_MONSTERS[i].max_hp;
}

// Hook for the above.
static void __declspec(naked) armageddon_heal_hook(void)
{
    asm
      {
        test byte ptr [STATE_BITS], 0x30 ; if enemies are near
        jnz skip
        call armageddon_heal
        skip:
        cmp dword ptr [PARTY_BUFF_ADDR+BUFF_IMMOLATION*SIZE_BUFF+4], esi ; repl
        ret
      }
}

// Blink mass buff icons when they've got less than 10 minutes left.
static void __declspec(naked) blink_mass_buffs(void)
{
    asm
      {
        mov ecx, dword ptr [PARTY_BUFF_ADDR+eax]
        mov edx, dword ptr [PARTY_BUFF_ADDR+eax+4]
        sub ecx, dword ptr [CURRENT_TIME_ADDR]
        sbb edx, dword ptr [CURRENT_TIME_ADDR+4]
        jb skip
        ja ok
        cmp ecx, 10 * MINUTE
        jae ok
        test byte ptr [ANIM_TIMER], 0x40
        jnz ok
        mov dword ptr [REFRESH_SCREEN], 1
        skip:
        cmp ebx, esi ; set flags
        ret
        ok:
        xor ecx, ecx ; set zf
        ret
      }
}

// Same, but with per-PC buffs.  Called four times with different eax.
static void __declspec(naked) blink_pc_buffs(void)
{
    asm
      {
        mov ecx, dword ptr [edi+eax].s_player.spell_buffs
        mov edx, dword ptr [edi+eax+4].s_player.spell_buffs
        sub ecx, dword ptr [CURRENT_TIME_ADDR]
        sbb edx, dword ptr [CURRENT_TIME_ADDR+4]
        jb skip
        ja ok
        cmp ecx, 10 * MINUTE
        jae ok
        mov dword ptr [REFRESH_SCREEN], 1
        test byte ptr [ANIM_TIMER], 0x40
        jnz ok
        skip:
        xor ecx, ecx ; set zf
        ret
        ok:
        cmp edi, ebp ; set flags
        ret
      }
}

// When browsing guild shelves, mark which spells are or can be learned.
// Berserk and Psychic Shock have to be swapped as they're out of order now.
static void __declspec(naked) mark_learned_guild_spells(void)
{
    asm
      {
        mov ecx, dword ptr [CURRENT_PLAYER]
        test ecx, ecx
        jz skip
        mov ecx, dword ptr [PC_POINTERS+ecx*4-4]
        cmp byte ptr [ecx+esi-1].s_player.spells_known, 0
        jnz known
        cmp esi, SPL_BERSERK
        sete al
        cmp esi, SPL_PSYCHIC_SHOCK
        sete ah
        sub al, ah
        movsx eax, al
        lea eax, [eax+eax*2]
        add esi, eax
        mov eax, dword ptr [ebp-20] ; school x 4
        lea edx, [eax+eax*2]
        shr eax, 2
        sub edx, eax
        mov ax, word ptr [ecx+SKILL_FIRE*2+eax*2].s_player.skills
        test eax, eax
        jz cannot
        sub esi, edx
        cmp esi, 4
        jbe can
        cmp eax, SKILL_EXPERT
        jb cannot
        cmp esi, 7
        jbe can
        cmp eax, SKILL_MASTER
        jb cannot
        cmp esi, 10
        jbe can
        cmp eax, SKILL_GM
        jb cannot
        can:
        mov eax, dword ptr [new_strings+STR_CAN_LEARN*4]
        jmp print
        cannot:
        mov eax, dword ptr [new_strings+STR_CANNOT_LEARN*4]
        jmp print
        known:
        mov eax, dword ptr [new_strings+STR_ALREADY_LEARNED*4]
        print:
        push 3
        push eax
        push edi
        push 14
        push 12
        mov edx, dword ptr [0x5c3488] ; font
        lea ecx, [ebp-104]
        call dword ptr ds:print_text
        skip:
        mov edx, dword ptr [0x5c3484] ; replaced code
        ret
      }
}

// Do not drain SP for Water Walk cast from a scroll.
static void __declspec(naked) ww_scroll_chunk(void)
{
    asm
      {
        cmp word ptr [ebx+10], 0
        jz skip + 7
        nop
        nop
        nop
        skip:
      }
}

// Allow casting WW or Fly from a scroll without a SP pool.
static void __declspec(naked) ww_fly_scroll_no_sp(void)
{
    asm
      {
        cmp word ptr [ebx+10], si ; == 0
        jnz skip
        jmp dword ptr ds:get_full_sp ; replaced call
        skip:
        xor eax, eax
        inc eax
        ret
      }
}

// Do not drain SP for Fly cast from a scroll.
static void __declspec(naked) fly_scroll_chunk(void)
{
    asm
      {
        cmp word ptr [ebx+10], si
        jz skip
        mov byte ptr [PARTY_BUFF_ADDR+BUFF_FLY*SIZE_BUFF].s_spell_buff.bits, 1
        skip:
      }
}

// Increase HH bonus to skill*2 for unarmed and skill/2 for other melee.
static void __declspec(naked) improved_hammerhands(void)
{
    asm
      {
        test eax, eax ; true if unarmed
        movzx eax, word ptr [edi+PBUFF_HAMMERHANDS*SIZE_BUFF+S_SB_POWER] \
                            .s_player.spell_buffs ; replaced code
        jz halve
        add eax, eax
        ret
        halve:
        shr eax, 1
        ret
      }
}

static char immutability_buffer[24];
static char *const immbuffer_ptr = immutability_buffer;

// Display remaining uses of Immutability along with the duration.
static void __declspec(naked) display_immutability_charges(void)
{
    asm
      {
        mov eax, dword ptr [ebp-16] ; replaced code
        mov dword ptr [ebp-20], ecx ; also replaced code
        mov ecx, dword ptr [ebp-8]
        cmp ecx, PARTY_BUFF_ADDR + BUFF_IMMUTABILITY * SIZE_BUFF
        jne quit
        movzx ecx, word ptr [ecx].s_spell_buff.power
        push ecx
        push dword ptr [eax]
#ifdef __clang__
        push dword ptr [immbuffer_ptr]
#else
        push offset immutability_buffer
#endif
        call dword ptr ds:sprintf
        add esp, 12
        movzx edx, byte ptr [ebx] ; restore
        mov eax, offset immbuffer_ptr
        quit:
        ret
      }
}

// Add damage to Turn Undead, and skip fear if no damage dealt.
static void __declspec(naked) turn_undead_damage(void)
{
    asm
      {
        test eax, eax ; -1 if no object created
        js skip
        push dword ptr [edi].s_map_monster.hp
        push esi
        push esi
        push esi
        push esp
        mov edx, dword ptr [ebp-8]
        mov edx, dword ptr [0x50bdb0+edx*4] ; target list
        lea ecx, [eax*8+2]
        call dword ptr ds:damage_monster_from_party
        add esp, 12
        pop eax
        cmp word ptr [edi].s_map_monster.hp, ax ; not hurt, not scared
        je skip
        cmp word ptr [edi].s_map_monster.hp, si ; check if dead
        jle skip
        mov eax, dword ptr [ebp-16] ; replaced code
        shl eax, 7 ; ditto
        pop ecx
        push esi ; also replaced
        jmp ecx
        skip:
        mov dword ptr [esp], 0x42bd87 ; after fear code
        ret
      }
}

// Make some conditions more "expensive" to prevent through Immutability.
static void __declspec(naked) immutability_double_cost(void)
{
    asm
      {
        sub word ptr [PARTY_BUFF_ADDR+BUFF_IMMUTABILITY*SIZE_BUFF] \
                     .s_spell_buff.power, 2
        jg ok
        mov ecx, PARTY_BUFF_ADDR + BUFF_IMMUTABILITY * SIZE_BUFF
        call dword ptr ds:remove_buff
        ok:
        mov eax, 0x4930f6 ; resisted code path
        jmp eax
      }
}

// Instadeath protection at GM should be even more expensive.
static void __declspec(naked) immutability_triple_cost(void)
{
    asm
      {
        sub word ptr [PARTY_BUFF_ADDR+BUFF_IMMUTABILITY*SIZE_BUFF] \
                     .s_spell_buff.power, 3
        jg ok
        mov ecx, PARTY_BUFF_ADDR + BUFF_IMMUTABILITY * SIZE_BUFF
        call dword ptr ds:remove_buff
        ok:
        mov eax, 0x4930f6 ; resisted code path
        jmp eax
      }
}

// Swap Berserk and Psychic Shock books in Mind guilds.
static void __declspec(naked) mind_guild_spell_reorder(void)
{
    asm
      {
        mov ebp, dword ptr [DIALOG2] ; replaced code
        cmp esi, FIRST_BOOK + SPL_BERSERK - 1
        sete al
        cmp esi, FIRST_BOOK + SPL_PSYCHIC_SHOCK - 1
        sete ah
        sub al, ah
        movsx eax, al
        lea eax, [eax+eax*2]
        add esi, eax
        ret
      }
}

// Also swap them when learning a new spell.
static void __declspec(naked) learned_mind_spell_reorder(void)
{
    asm
      {
        lea eax, [esi+edi].s_player.spells_known ; replaced code
        cmp edi, SPL_BERSERK - 1
        sete cl
        cmp edi, SPL_PSYCHIC_SHOCK - 1
        sete ch
        sub cl, ch
        movsx ecx, cl
        lea ecx, [ecx+ecx*2]
        add edi, ecx
        ret
      }
}

// Allow releasing spells in any direction on a Shift-click.
static int __thiscall free_aim_spell(int shower)
{
    int id = dword(MONSTER_COUNT);
    if (id >= 500) return 0; // TODO: could search for a removed monster
    // the rotation code is almost verbatim from mmpatch (CastRay)
    double x0 = patch_options->mouse_dx + MOUSE_X - dword(0xf8babc);
    double y0 = dword(OUTDOORS) == 2 ? dword(0x6bdf04)
                             : *(float *) (dword(DRAW_IMAGE_THIS_ADDR)
                                           ? dword(dword(CGAME) + 0xe54) + 0xc4
                                           : 0x507b7c);
    int middle_y = dword(0xf8bac0);
    double z0 = middle_y - patch_options->mouse_dy - MOUSE_Y + 0.5;
    double s = 5120 / 2; // half green gem distance
    double z, m;
    if (shower)
      {
        // vertical mouse position = distance here, not direction
        s += s * z0 / middle_y;
        z = 0; // will add to it later
        m = y0;
      }
    else // projectile, aim to mouse
      {
        double la = dword(PARTY_LOOK_ANGLE) * M_PI / 1024;
        z = z0 * cos(la) + y0 * sin(la);
        m = y0 * cos(la) - z0 * sin(la);
      }
    double dir = dword(PARTY_DIR) * M_PI / 1024;
    double x = x0 * sin(dir) + m * cos(dir);
    double y = m * sin(dir) - x0 * cos(dir);
    s /= sqrt(x * x + y * y + z * z);
    MAP_MONSTERS[id].x = dword(PARTY_X) + (int) (x * s);
    MAP_MONSTERS[id].y = dword(PARTY_Y) + (int) (y * s);
    MAP_MONSTERS[id].z = dword(PARTY_Z) + (shower ? 2500 : (int) (z * s));
    MAP_MONSTERS[id].height = dword(0xacce3c) / 2;
    return id * 8 + 3;
}

// Hook for the above.
static void __declspec(naked) free_aim_spell_hook(void)
{
    asm
      {
        cmp dword ptr [esp+44], 70 ; aim monster action
        jne skip
        push VK_SHIFT
        call dword ptr ds:GET_ASYNC_KEY_STATE
        test ax, ax
        jns skip
        mov ecx, dword ptr [DIALOG7]
        mov ecx, dword ptr [ecx+28]
        mov ax, word ptr [ecx]
        xor ecx, ecx
        ; rule out no-projectile spells
        cmp ax, SPL_IMPLOSION
        je skip
        cmp ax, SPL_SLOW
        je skip
        cmp ax, SPL_MASS_DISTORTION
        je skip
        cmp ax, SPL_CHARM
        je skip
        cmp ax, SPL_BERSERK
        je skip
        cmp ax, SPL_ENSLAVE
        je skip
        cmp ax, SPL_DESTROY_UNDEAD
        je skip
        cmp ax, SPL_PARALYZE
        je skip
        cmp ax, SPL_CONTROL_UNDEAD
        je skip
        cmp ax, SPL_METEOR_SHOWER
        je shower
        cmp ax, SPL_STARBURST
        jne aim
        shower:
        inc ecx
        aim:
        call free_aim_spell
        test eax, eax
        jnz got_it
        skip:
        cmp dword ptr [0xe31af0], ebx ; replaced code
        ret
        got_it:
        mov dword ptr [esp], 0x433daa ; past the mouse target code
        xor ecx, ecx ; pass the distance check
        ret
      }
}

// Adjust Death Blossom shoot angle so that it hits its target.
static int __stdcall death_blossom(int angle, int target)
{
    int id = target >> 3;
    if (id >= dword(MONSTER_COUNT) || (target & 7) != TGT_MONSTER)
        return angle + 256; // fake or invalid target
    struct map_monster *monster = &MAP_MONSTERS[id];
    int dx = monster->x - dword(PARTY_X);
    int dy = monster->y - dword(PARTY_Y);
    // TODO: unhardcode projectile speed (1500)
    double k = 2 * 1500 * 1500 / sqrt(dx * dx + dy * dy) / 128
               / get_game_speed();
    double a = tan(angle * M_PI / 1024);
    double d = k * (k - 4 * a) - 4;
    if (d < 0) d = 0; // too far, try our best anyway
    return atan2(k - sqrt(d), 2) / M_PI * 1024;
}

// Hook for the above.
static void __declspec(naked) death_blossom_hook(void)
{
    asm
      {
        cmp dword ptr [OUTDOORS], 2
        mov eax, 0x4290c1 ; fail message
        jne skip
        push dword ptr [ebp-8] ; target
        push dword ptr [ebp-200] ; angle
        call death_blossom
        mov dword ptr [ebp-200], eax
        mov eax, 0x4289b3 ; generic projectile code
        skip:
        jmp eax
      }
}

// Increase Death Blossom shards, esp. at GM.
static void __declspec(naked) death_blossom_gm(void)
{
    asm
      {
        xor eax, eax
        inc eax
        mov ecx, dword ptr [esi].s_map_object.spell_mastery
        shl eax, cl
        mov dword ptr [ebp-12], eax ; shard count
        ret
      }
}

// Make the spc/std bonus relative chance when using Enchant Item equal
// to their normal generaion odds.  This hook is for GM (tlvl 4/5).
// Also here: treat brass knuckles as weapons for enchanting purposes.
static void __declspec(naked) enchant_item_spc_chance_gm(void)
{
    asm
      {
        cmp byte ptr [esi].s_items_txt_item.equip_stat, ITEM_TYPE_GAUNTLETS - 1
        jne ok
        cmp byte ptr [esi].s_items_txt_item.skill, SKILL_UNARMED
        je skip
        ok:
        mov edx, dword ptr [enchant_item_gm_noon]
        mov ecx, dword ptr [0x5e3f14+edx*4+3*4] ; spc chance
        mov edx, dword ptr [0x5e3efc+edx*4+3*4] ; std chance
        add ecx, edx
        jz skip ; sanity check
        push edx
        xor edx, edx
        div ecx
        pop ecx
        cmp edx, ecx
        skip:
        ret
      }
}

// This hook is for Master and (unused) Expert (tlvl 3).
static void __declspec(naked) enchant_item_spc_chance_master(void)
{
    asm
      {
        mov esi, dword ptr [ebp-48] ; needed for master hook
        cmp byte ptr [esi].s_items_txt_item.equip_stat, ITEM_TYPE_GAUNTLETS - 1
        jne ok
        cmp byte ptr [esi].s_items_txt_item.skill, SKILL_UNARMED
        je skip
        ok:
        mov ecx, dword ptr [0x5e3efc+2*4] ; std chance
        add ecx, dword ptr [0x5e3f14+2*4] ; spc chance
        jz skip ; sanity check
        xor edx, edx
        div ecx
        cmp edx, dword ptr [0x5e3efc+2*4]
        skip:
        ret
      }
}

// Make Fire Spikes multiple-use when fully deployed.
static void __declspec(naked) preserve_fire_spike(void)
{
    asm
      {
        cmp word ptr [esi], OBJ_FIRE_SPIKE
        jne skip
        mov ax, word ptr [esi].s_map_object.speed_x
        or ax, word ptr [esi].s_map_object.speed_y
        or ax, word ptr [esi].s_map_object.speed_z
        jnz skip
        dec dword ptr [esi].s_map_object.spell_mastery ; hit counter
        jz skip
        mov dword ptr [esp], 0x46cbec ; skip past proj removal
        skip:
        jmp dword ptr ds:projectile_hit
      }
}

// Make Fire Spike limit depend on spell skill value, not mastery.
static void __declspec(naked) variable_spike_count(void)
{
    asm
      {
        mov eax, edi ; skill value
        xor edx, edx
        mov ecx, 3
        div ecx
        dec eax
        cmp dword ptr [ebp-12], eax ; replaced code (spike count)
        ret
      }
}

// For completeness, let monsters instakill other monsters with Incinerate.
// Also here: fetch an alternative spell if necessary.
static void __declspec(naked) mvm_incinerate(void)
{
    asm
      {
        add edi, dword ptr [ebp+12] ; attack type (2 or 3)
        mov edx, dword ptr [elemdata.difficulty]
        cmp dl, byte ptr [edi-2].s_map_monster.alter_flag1
        jno got_spell
        movzx ecx, byte ptr [edi-2].s_map_monster.alter_spell1
        lea ecx, [ecx+ecx*8]
        got_spell:
        cmp ecx, SPL_SUNRAY * 9
        jne no_sun
        cmp dword ptr [HOUR_OF_DAY], 5
        jb night
        cmp dword ptr [HOUR_OF_DAY], 21
        jb no_sun
        night:
        mov ecx, SPL_LIGHT_BOLT * 9
        no_sun:
        cmp ecx, SPL_INCINERATE * 9
        movzx ecx, byte ptr [ELEMENT_ADDR+ecx*4] ; replaced code
        jne skip
        push eax ; preserve
        push ecx ; ditto
        push ecx
        push esi
        call dword ptr ds:monster_resists_condition
        test eax, eax
        jz ok
        call dword ptr ds:random
        xor edx, edx
        mov ecx, 100
        div ecx
        mov ecx, dword ptr [ebp+12] ; note it`s already added once
        mov ax, word ptr [edi+ecx-4].s_map_monster.spell1_skill
        and eax, SKILL_MASK
        lea eax, [eax+eax*2] ; 3% per level
        cmp eax, edx
        jbe ok
        and word ptr [esi].s_map_monster.hp, 0
        ok:
        pop ecx
        pop eax
        skip:
        ret
      }
}

// Whether to attempt stunning a hit PC (+80 hit recovery).  Used below.
static char lightning_bolt_stun;

// Reset the above flag on function entry.
static void __declspec(naked) init_stun_flag(void)
{
    asm
      {
        mov esi, ecx ; replaced code
        and ecx, 7 ; ditto
        mov byte ptr [lightning_bolt_stun], 0 ; reset
        ret
      }
}

// Increase hit recovery if the PC gets stunned.  Used twice.
static void __declspec(naked) lb_stun_recovery(void)
{
    asm
      {
        test byte ptr [lightning_bolt_stun], 1
        jz skip
        push ecx
        push STAT_SHOCK_RES
        call dword ptr ds:get_resistance
        pop ecx
        push eax
        call dword ptr ds:get_luck
        push eax
        call dword ptr ds:get_effective_stat
        pop ecx
        lea ecx, [ecx+eax*4+30] ; the usual debuff resistance roll
        push ecx
        call dword ptr ds:random
        pop ecx
        xor edx, edx
        div ecx
        cmp edx, 30
        jb stun
        skip:
        jmp dword ptr ds:get_effective_stat ; replaced call
        stun:
        push dword ptr [esp+4] ; endurance value
        call dword ptr ds:get_effective_stat
        sub eax, 80 ; extra recovery
        ret 4
      }
}

// Misc spell tweaks.
static inline void misc_spells(void)
{
    // Let's swap the effects of earth (now poison) and body
    // (now magic) resistance spells.  (In MM6 poison res
    // was a Body spell, and magic res was an Earth spell.)
    uint32_t poison = dword(0x48f7ec);
    patch_dword(0x48f7ec, dword(0x48f81c));
    patch_dword(0x48f81c, poison);
    poison = dword(0x48f7f3);
    patch_dword(0x48f7f3, dword(0x48f823));
    patch_dword(0x48f823, poison);
    // Shift the mind resistance icon a few pixels (for aesthetic reasons).
    dword(0x4e5d58) += 4;
    // Change the elements of some hardcoded spell effects.
    // This cannot be done on startup, but is delayed until spells.txt is read.
    hook_jump(0x453b35, spells_txt_tail);
    // Poison chest traps are also hardcoded.
    patch_dword(0x438f11, POISON); // was body (8)
    // Buff Ice Blast to its MM8 version (d3 -> d6 damage).
    SPELL_INFO[SPL_ICE_BLAST].damage_dice = 6;
    // But remove the extra shards on GM (which doubled damage in practice).
    erase_code(0x46c51e, 5);
    hook_call(0x4742bd, feather_fall_jump, 6); // outdoors
    hook_call(0x47301e, feather_fall_jump, 6); // indoors
    // Remove the shorter delay from GM Feather Fall.
    SPELL_INFO[SPL_FEATHER_FALL].delay_gm = 120;
    hook_call(0x428466, torch_light_gm, 7);
    // Remove the shorter delay from GM Torch Light.
    SPELL_INFO[SPL_TORCH_LIGHT].delay_gm = 60;
    // Let's adjust Enchant item slightly.  Firstly, numerical enchantments
    // will be as powerful as vanilla only at noon, otherwise they're one TL
    // lower (so, TL3 at M and TL4 at GM).  On the other hand, special
    // enchantments now improve along with the numerical ones instead of being
    // stuck at TL 3, which was likely a bug.
    patch_dword(0x42b1f7, 0x5e3f7c); // TL3 max number for E
    patch_dword(0x42b1fe, 0x5e3f78); // TL3 min number for E
    patch_dword(0x42af9b, 0x5e3f7c); // TL3 max number for M
    patch_dword(0x42afa1, 0x5e3f78); // TL3 min number for M
    hook_call(0x42ad3b, enchant_item_lvl45, 6);
    hook_call(0x42ab11, enchant_item_noon_check, 6);
    hook_call(0x42ad0f, enchant_item_noon_numeric, 6);
    // Bug fix: let EI halve some numeric enchs like when naturally generated.
    hook_call(0x42b208, enchant_item_halve_expert, 5); // expert
    hook_call(0x42b468, enchant_item_halve_others, 5); // all others
    // Remove double resistance check from Mass Distortion.
    erase_code(0x428769, 8); // ignore result of the resistance check
    // Allow casting Berserk on a PC.
    patch_byte(0x427c9f + SPL_BERSERK - 2, 5); // can target monsters and pcs
    // TODO: instead of a call we could substitute the jne address
    hook_call(0x42c4d7, berserk_pc, 6);
    // Upgrade Spirit Lash to its MM8 version.
    patch_byte(0x427c9f + SPL_SPIRIT_LASH - 2, 11); // immediate
    hook_jump(0x42958f, spirit_lash_count_targets);
    patch_bytes(0x429708, spirit_lash_x_chunk, 7);
    patch_bytes(0x429715, spirit_lash_y_chunk, 7);
    patch_bytes(0x429722, spirit_lash_z_chunk, 6);
    erase_code(0x429728, 27); // unneeded monster z-coord calculation
    hook_jump(0x429776, spirit_lash_damage);
    // Nerf Regeneration spell like in MM8.
    // Instead of 5/15/50 HP per 5 min (E/M/G), restore only 2/3/4.
    erase_code(0x493d51, 3); // it multiplied the spell's power 5x
    patch_dword(0x429190, 2); // expert
    // master is already 3
    patch_dword(0x429182, 4); // GM
    // The below hook also erases SP restoration code.
    hook_call(0x42e357, sacrifice_conditions, 11);
    erase_code(0x428b0d, 19); // enable sun ray in (some) dungeons
    // Make GM Wizard Eye permanent and not dispellable.
    hook_call(0x441dc3, wizard_eye_functionality, 7);
    hook_call(0x4585c8, wizard_eye_permanence, 7);
    hook_call(0x44155d, wizard_eye_animation, 7);
    hook_call(0x41d704, wizard_eye_display_count, 5);
    hook_call(0x41d7b6, wizard_eye_display, 5);
    hook_call(0x41d819, wizard_eye_display_duration, 5);
    hook_call(0x429e6f, wizard_eye_cast, 6);
    hook_call(0x42d892, wizard_eye_from_day_of_protection, 6);
    SPELL_INFO[SPL_WIZARD_EYE].cost_gm = 1; // remove previous GM bonus
    hook_call(0x428037, switch_off_spells_for_free, 6);
    hook_call(0x429937, switch_off_immolation, 6);
    // Nerf Day of Gods from x3/x4/x5 to x2/x3/x4.
    patch_byte(0x42d440, 6); // E jump -> changed GM code
    patch_byte(0x42d443, 36); // M jump -> E
    patch_word(0x42d445, 0x0f74); // GM check: jnz E -> jz M
    patch_dword(0x42d449, 7200); // new duration constant for GM
    patch_byte(0x42d452, 0x3f); // GM power: x5 -> x2
    // Same for DoG cast from pedestals.
    patch_byte(0x449664, 6); // E jump -> changed GM code
    patch_byte(0x449667, 30); // M jump -> E
    patch_word(0x449669, 0x0c74); // GM check: jnz E -> jz M
    patch_dword(0x44966d, 7200); // new duration constant for GM
    patch_byte(0x449673, 0); // GM power: x5 -> x2
    // Make Hour of Power duration more consistent.
    patch_dword(0x42d8bd, 48); // GM duration multiplier for most spells
    patch_dword(0x42d8c4, 16); // GM duration multiplier for haste
    hook_call(0x42d8f6, hour_of_power_duration, 6);
    erase_code(0x42d8fc, 9); // old duration code
    // Nerf Day of Protection from x4/x5 to x3/x4.
    patch_bytes(0x42d6ab, day_of_protection_chunk, 5);
    erase_code(0x42d6b2, 3); // old not-GM jump
    patch_byte(0x42d6b7, 0x7f); // x5 -> x3
    patch_dword(0x42d6bf, 60*60*3); // duration (was 5 hours)
    // Nerf Flight a bit.
    patch_dword(0x42a285, 60*10); // reduce M flight duration to 10 min/skill
    hook_call(0x42a294, flight_duration, 5);
    // Implement the Spectral Weapon spell (replaces Fate).
    patch_pointer(0x42ea21, spectral_weapon);
    patch_byte(0x427ccc, 1); // targets an item
    hook_jump(0x429161, spectral_aura);
    hook_call(0x41f0ec, monster_fate, 7); // first spell
    hook_call(0x41f13c, monster_fate, 7); // second spell
    hook_call(0x468654, scroll_spell_id, 6); // for fate scrolls
    hook_call(0x429041, spectral_weapon_duration, 6); // nerf it a little
    hook_call(0x42ddaa, spectral_weapon_duration, 6); // same for vamp weapon
    // Set the same delay as Fire Aura.
    SPELL_INFO[SPL_SPECTRAL_WEAPON].delay_normal = 120;
    SPELL_INFO[SPL_SPECTRAL_WEAPON].delay_expert = 120;
    SPELL_INFO[SPL_SPECTRAL_WEAPON].delay_master = 120;
    SPELL_INFO[SPL_SPECTRAL_WEAPON].delay_gm = 120;
    // Same for Vampiric Weapon (for some reason it was already 120 at GM):
    SPELL_INFO[SPL_VAMPIRIC_WEAPON].delay_expert = 120;
    SPELL_INFO[SPL_VAMPIRIC_WEAPON].delay_master = 120;
    // Another MM8 idea: buff Flying Fist a little.
    SPELL_INFO[SPL_FLYING_FIST].damage_fixed = 20;
    SPELL_INFO[SPL_FLYING_FIST].damage_dice = 10;
    hook_call(0x427e6a, zero_item_spells, 5);
    patch_pointer(0x42ea51, aura_of_conflict);
    patch_byte(0x427cd8, 2); // targets a pc
    dword(0x4e22b8) = 276; // spellbook icon x
    dword(0x4e22bc) = 5; // spellbook icon y
    // generic buff recovery value
    SPELL_INFO[SPL_AURA_OF_CONFLICT].delay_normal = 120;
    SPELL_INFO[SPL_AURA_OF_CONFLICT].delay_expert = 120;
    SPELL_INFO[SPL_AURA_OF_CONFLICT].delay_master = 120;
    SPELL_INFO[SPL_AURA_OF_CONFLICT].delay_gm = 120;
    hook_call(0x434702, alternative_spell_mode_hook, 7);
    hook_call(0x428295, cumulative_recovery, 6);
    hook_call(0x42abbf, enchant_item_min_value, 5); // GM
    hook_call(0x42abcd, enchant_item_weapon_value, 5); // GM
    erase_code(0x42abde, 23); // remove old failure chance (GM)
    hook_call(0x42ae4f, enchant_item_min_value, 5); // Master
    hook_call(0x42ae5d, enchant_item_weapon_value, 5); // Master
    erase_code(0x42ae6e, 23); // remove old failure chance (Master)
    hook_call(0x42b0f3, enchant_item_min_value, 5); // Expert (unused)
    erase_code(0x42b101, 23); // remove old failure chance (Expert)
    hook_call(0x42b367, enchant_item_min_value, 5); // Normal (unused)
    erase_code(0x42b378, 23); // remove old failure chance (Normal)
    patch_bytes(0x4298b3, immolation_duration_chunk, 11);
    patch_byte(0x4298ac, 11); // expert jump
    patch_byte(0x4298af, 8); // master jump
    patch_byte(0x4298b2, 5); // non-gm jump
    patch_bytes(0x4495c6, immolation_duration_pedestal_chunk, 11);
    patch_byte(0x4495bf, 11); // expert jump
    patch_byte(0x4495c2, 8); // master jump
    patch_byte(0x4495c5, 5); // non-gm jump
    patch_dword(0x42a17d, 15 * 60); // nerf invisibility gm duration
    patch_dword(0x42a197, 5 * 60); // and master, too
    // Shotgun spells were too cheap for their potential damage at high ranks.
    SPELL_INFO[SPL_SPARKS].cost_expert = 5;
    SPELL_INFO[SPL_SPARKS].cost_master = 6;
    SPELL_INFO[SPL_SPARKS].cost_gm = 7;
    SPELL_INFO[SPL_POISON_SPRAY].cost_expert = 4;
    SPELL_INFO[SPL_POISON_SPRAY].cost_master = 6;
    SPELL_INFO[SPL_POISON_SPRAY].cost_gm = 8;
    hook_call(0x410d45, fix_gm_spell_cost_display, 8);
    // Remove variable delay b/c increased projectile count is a change enough.
    SPELL_INFO[SPL_SPARKS].delay_normal = 100;
    SPELL_INFO[SPL_SPARKS].delay_master = 100;
    SPELL_INFO[SPL_SPARKS].delay_gm = 100;
    SPELL_INFO[SPL_POISON_SPRAY].delay_normal = 100;
    SPELL_INFO[SPL_POISON_SPRAY].delay_master = 100;
    SPELL_INFO[SPL_POISON_SPRAY].delay_gm = 100;
    erase_code(0x42e591, 13); // old souldrinker healed hp
    hook_call(0x42e60c, souldrinker_remember_monster_hp, 5);
    hook_call(0x42e630, souldrinker_calculate_damage, 6);
    hook_call(0x403100, wear_off_paralysis, 6);
    // Rehaul Town Portal.
    erase_code(0x42b4d9, 2); // 10% -> 5% success chance per skill
    patch_byte(0x42b4f7, 0x75); // jz -> jnz (nearby enemies check)
    hook_jump(0x42b4f9, (void *) 0x42b51c); // always succeed if no enemies
    hook_jump(0x42b512, (void *) 0x42a8aa); // waste a turn on failure
    hook_call(0x42b530, master_town_portal, 5);
    hook_call(0x44b2b4, update_new_tp_region, 8);
    hook_call(0x4339f4, town_portal_from_main_screen, 5);
    hook_call(0x4339d0, town_portal_without_dialog, 5);
    hook_call(0x4336ee, beacon_recall_effects_hook, 5);
    hook_call(0x42b570, lloyd_starting_tab, 5);
    hook_call(0x433433, lloyd_disable_recall, 5);
    // Reduce Lloyd's Beacon duration to 2 days/skill.
    patch_dword(0x42b543, 2 * 24 * 60 * 60);
    hook_call(0x4737f2, reset_lava_walking, 7);
    hook_call(0x473828, lava_walking, 5);
    patch_dword(0x429972, 10); // nerf master meteor shower (16 -> 10 rocks)
    patch_dword(0x439c64, 40); // stun knockback
    hook_call(0x439d74, increase_stun_knockback, 5);
    hook_call(0x439c7b, stun_recovery, 9);
    hook_jump(0x439744, (void *) 0x43989e); // skip to-hit roll for stun spell
    // Let Earth rank actually do something.
    SPELL_INFO[SPL_STUN].delay_expert = 70;
    SPELL_INFO[SPL_STUN].delay_master = 60;
    SPELL_INFO[SPL_STUN].delay_gm = 50;
    patch_bytes(0x43973d, stun_power_chunk, 7);
    hook_call(0x439c4f, stun_element, 5);
    hook_call(0x470b17, armageddon_flyers, 7);
    hook_jump(0x401b9d, armageddon_rep);
    hook_call(0x493a34, armageddon_heal_hook, 6);
    hook_call(0x441688, blink_mass_buffs, 6);
    erase_code(0x441690, 10); // rest of old duration check
    patch_byte(0x4417c2, 0xb8); // mov eax, dword
    patch_dword(0x4417c3, PBUFF_HAMMERHANDS * SIZE_BUFF);
    hook_call(0x4417c7, blink_pc_buffs, 11);
    patch_byte(0x441800, 0xb8); // mov eax, dword
    patch_dword(0x441801, PBUFF_BLESS * SIZE_BUFF);
    hook_call(0x441805, blink_pc_buffs, 11);
    patch_byte(0x44183e, 0xb8); // mov eax, dword
    patch_dword(0x44183f, PBUFF_PRESERVATION * SIZE_BUFF);
    hook_call(0x441843, blink_pc_buffs, 11);
    patch_byte(0x44187c, 0xb8); // mov eax, dword
    patch_dword(0x44187d, PBUFF_PAIN_REFLECTION * SIZE_BUFF);
    hook_call(0x441881, blink_pc_buffs, 11);
    hook_call(0x4b16be, mark_learned_guild_spells, 6);
    patch_bytes(0x42a9c7, ww_scroll_chunk, 10);
    hook_call(0x42a8a1, ww_fly_scroll_no_sp, 5); // WW
    hook_call(0x42a273, ww_fly_scroll_no_sp, 5); // Fly
    patch_bytes(0x42a2d4, fly_scroll_chunk, 13);
    erase_code(0x42a2e1, 13); // rest of pointless old code
    // Buff the LOS damage spells a little.
    SPELL_INFO[SPL_INFERNO].damage_dice = 2;
    SPELL_INFO[SPL_PRISMATIC_LIGHT].damage_dice = 3;
    // Buff Hammerhands a bit.
    erase_code(0x4398df, 4); // do not skip for weapon melee
    hook_call(0x4398f5, improved_hammerhands, 7);
    hook_call(0x41d7e2, display_immutability_charges, 6);
    // Some spells didn't have the stated recovery reduction.
    SPELL_INFO[SPL_FIRE_BOLT].delay_expert = 100;
    SPELL_INFO[SPL_FIRE_BOLT].delay_master = 90;
    SPELL_INFO[SPL_FIRE_BOLT].delay_gm = 80;
    // reducing GM to 70 would be too much I think
    SPELL_INFO[SPL_ICE_BLAST].delay_normal = 90;
    SPELL_INFO[SPL_ICE_BLAST].delay_expert = 90;
    SPELL_INFO[SPL_ICE_BLAST].delay_master = 90;
    SPELL_INFO[SPL_SPIRIT_LASH].delay_gm = 90;
    SPELL_INFO[SPL_MIND_BLAST].delay_expert = 100;
    SPELL_INFO[SPL_MIND_BLAST].delay_master = 90;
    SPELL_INFO[SPL_MIND_BLAST].delay_gm = 80;
    SPELL_INFO[SPL_HAMMERHANDS].delay_master = 100;
    SPELL_INFO[SPL_HAMMERHANDS].delay_gm = 100;
    // Let Turn Undead deal minor damage.
    SPELL_INFO[SPL_TURN_UNDEAD].damage_dice = 1;
    hook_call(0x42bd51, turn_undead_damage, 7);
    // Let Immutability wear off more quickly against dangerous conditions.
    // paralyzed
    patch_dword(0x492f6e, (int) immutability_double_cost - 0x492f72);
    patch_dword(0x492f7a, (int) immutability_double_cost - 0x492f7e);
    // dead
    patch_dword(0x492ff9, (int) immutability_triple_cost - 0x492ffd);
    // stoned -- also fixes a bug wherein it wasn't decremented at all
    patch_dword(0x493014, (int) immutability_double_cost - 0x493018);
    patch_dword(0x493020, (int) immutability_double_cost - 0x493024);
    // eradicated
    patch_dword(0x49309a, (int) immutability_triple_cost - 0x49309e);
    // Shift Berserk, Psychic Shock and Cure Insanity around.
    for (int i = 0; i < 4; i++)
      {
        SPELL_INFO[SPL_BERSERK].cost[i] = 20;
        SPELL_INFO[SPL_CURE_INSANITY].cost[i] = 25;
        SPELL_INFO[SPL_PSYCHIC_SHOCK].cost[i] = 10;
      }
    SPELL_INFO[SPL_PSYCHIC_SHOCK].damage_fixed = 8;
    SPELL_INFO[SPL_PSYCHIC_SHOCK].damage_dice = 8;
    SPELL_INFO[SPL_PSYCHIC_SHOCK].delay_master = 100;
    SPELL_INFO[SPL_PSYCHIC_SHOCK].delay_gm = 90;
    erase_code(0x42c8a8, 28); // no weakness anim for cure instanity
    hook_jump(0x42c91a, (void *) 0x42deaa); // and no actual weakness
    // berserk disables spellcasting in consider_new_spells() below
    hook_call(0x4bc915, mind_guild_spell_reorder, 6);
    hook_call(0x4684f3, learned_mind_spell_reorder, 7);
    hook_call(0x433d4c, free_aim_spell_hook, 6);
    patch_byte(0x427c9f + SPL_ROCK_BLAST - 2, 0); // make it aimed
    patch_dword(0x42e965 + SPL_ROCK_BLAST * 4,
                dword(0x42e965 + SPL_FIRE_BOLT * 4)); // respect aim
    patch_byte(0x427c9f + SPL_METEOR_SHOWER - 2, 0); // outdoor spells too
    patch_byte(0x427c9f + SPL_STARBURST - 2, 0); // (aiming is different here)
    patch_byte(0x427c9f + SPL_DEATH_BLOSSOM - 2, 0); // hits monsters at an arc
    patch_pointer(0x42e965 + SPL_DEATH_BLOSSOM * 4, death_blossom_hook);
    hook_call(0x46c6e8, death_blossom_gm, 7);
    hook_call(0x42ac79, enchant_item_spc_chance_gm, 9);
    hook_call(0x42af09, enchant_item_spc_chance_master, 9); // master
    hook_call(0x42b181, enchant_item_spc_chance_master, 9); // expert (unused)
    hook_call(0x46cbb3, preserve_fire_spike, 5);
    patch_byte(0x428552, -4); // spike durability = old spike limit
    hook_call(0x42851a, variable_spike_count, 6);
    erase_code(0x43b00e, 2); // remove variable damage dice
    // Reduce Sunray recovery to more reasonable values.
    SPELL_INFO[SPL_SUNRAY].delay_normal = 110;
    SPELL_INFO[SPL_SUNRAY].delay_expert = 110;
    SPELL_INFO[SPL_SUNRAY].delay_master = 110;
    SPELL_INFO[SPL_SUNRAY].delay_gm = 100;
    // PvM Incinerate in blaster_eradicate(), MvP in absorb_monster_spell()
    hook_call(0x43b2d6, mvm_incinerate, 8);
    // Remove SP restoration from Divine Intervention.
    erase_code(0x42dad9, 6);
    // PvM LB stun in damage_potions_monster() and stun_element()
    hook_call(0x439ff6, init_stun_flag, 5);
    // stun flag set in alter_spell_element() below
    hook_call(0x43a366, lb_stun_recovery, 5); // melee attack (unnecessary?)
    hook_call(0x43a88c, lb_stun_recovery, 5); // projectile hit
}

// For consistency with players, monsters revived with Reanimate now have
// their resistances changed the same way as zombie players
// (immune to poison and mind, not immune to holy).
// Further, instead of being set to peaceful zombies now start enslaved,
// so they won't turn on you if you hit them now.
// Also, zombies now don't give XP but do give loot.
// Finally, zombies' max HP is lowered to their HP on reanimation.
static void __declspec(naked) zombify(void)
{
    asm
      {
        mov byte ptr [edi].s_map_monster.poison_resistance, IMMUNE
        mov byte ptr [edi].s_map_monster.mind_resistance, IMMUNE
        cmp byte ptr [edi].s_map_monster.holy_resistance, IMMUNE
        jne not_immune
        mov byte ptr [edi].s_map_monster.holy_resistance, 0
        not_immune:
        mov dword ptr [edi].s_map_monster.experience, 0
        or byte ptr [edi].s_map_monster.mod_flags, MMF_ZOMBIE
        mov eax, dword ptr [ebp-4] ; reanimate power
        lea eax, [eax+eax*4]
        add eax, eax
        cmp eax, dword ptr [edi].s_map_monster.max_hp
        jg low_hp
        mov dword ptr [edi].s_map_monster.max_hp, eax
        low_hp:
        lea ecx, [edi+MBUFF_ENSLAVE*SIZE_BUFF].s_map_monster.spell_buffs
        xor eax, eax
        push eax
        push eax
        push eax
        push eax
        dec eax
        push eax
        shr dword ptr [esp], 1
        push eax
        call dword ptr ds:add_buff
        ret
      }
}

// Replace the call to the "monster type" function with a check
// for holy immunity, so the zombified monsters will be affected.
static void __declspec(naked) destroy_undead_chunk(void)
{
    asm
      {
        cmp byte ptr [eax].s_map_monster.holy_resistance, IMMUNE
        nop
        nop
        nop
      }
}

// Ditto.
static void __declspec(naked) control_undead_chunk(void)
{
    asm
      {
        cmp byte ptr [MAP_MONSTERS_ADDR+eax].s_map_monster.holy_resistance, \
            IMMUNE
      }
}

// This is actually redundant now as any immune monster will resist all
// damage and thus avoid the debuff too, but we do still avoid a lot of
// useless calculations by performing this check in advance.
static void __declspec(naked) turn_undead_chunk(void)
{
    asm
      {
        cmp byte ptr [edi].s_map_monster.holy_resistance, IMMUNE
        nop
        nop
        nop
      }
}

// Change the conditions for zombification in the dark temples.
// Previously, stoned, dead or eradicated players became zombies.
// Now, liches and stoned players are exempt.
static void __declspec(naked) zombificable_chunk(void)
{
    asm
      {
        cmp byte ptr [esi].s_player.class, CLASS_LICH
        _emit 0x74
        _emit 0x0d
        mov eax, dword ptr [ebp-0x2c]
        or eax, dword ptr [ebp-0x28]
        or eax, dword ptr [ebp-0x24]
        or eax, dword ptr [ebp-0x20]
        nop
      }
}

// Save monster HP before instadeath effects for later.
static int old_monster_hp;

// Let the Undead Slaying weapons attack with Holy instead of Physical
// when it's preferable.  Together with ghosts now immune to Physical,
// makes holy water useful.  If dual-wielding, only 50% of damage is affected.
// The new Spectral/Wraith weapons are also handled here.  Undead Slaying
// always takes precedence over Spectral, which is okay since
// all undead are at least as vulnerable to Holy as to Magic.
// Sword of Light is also handled by this routine.
static void __declspec(naked) undead_slaying_element(void)
{
    asm
      {
        movsx edx, word ptr [esi].s_map_monster.hp
        mov dword ptr [old_monster_hp], edx ; store for later
        and dword ptr [ebp-20], 0 ; zero out the damage just in case
        cmp dword ptr [ebp-8], PHYSICAL ; main attack element
        jne skip
        mov al, byte ptr [esi].s_map_monster.physical_resistance
        cmp al, byte ptr [esi].s_map_monster.holy_resistance
        seta dl
        cmp dword ptr [esi+MBUFF_DAY_OF_PROTECTION*SIZE_BUFF] \
                      .s_map_monster.spell_buffs, 0
        jnz protected
        cmp dword ptr [esi+MBUFF_DAY_OF_PROTECTION*SIZE_BUFF+4] \
                      .s_map_monster.spell_buffs, 0
        jz compare
        protected:
        sub al, byte ptr [esi+MBUFF_DAY_OF_PROTECTION*SIZE_BUFF+S_SB_POWER] \
                         .s_map_monster.spell_buffs
        jb negative
        compare:
        cmp al, byte ptr [esi].s_map_monster.magic_resistance
        negative:
        seta dh
        test ebx, ebx ; projectile
        jz prepare
        cmp dword ptr [ebx].s_map_object.spell_type, SPL_ARROW
        je prepare
        cmp dword ptr [ebx].s_map_object.spell_type, SPL_KNIFE
        jne skip
        prepare:
        push ebx ; backup
        push 0 ; count of swords of light (we do support two of them)
        push 0 ; count of weapons
        push 0 ; count of undead slaying weapons
        push 0 ; count of spectral weapons
        test ebx, ebx
        movzx ebx, dx
        jz weapon
        ; bow
        mov ecx, 1 ; no looping
        mov eax, dword ptr [edi+SLOT_MISSILE*4].s_player.equipment
        jmp check_slot
        weapon:
        mov ecx, 2 ; main hand first
        check_hand:
        mov eax, dword ptr [edi+ecx*4-4].s_player.equipment
        check_slot:
        test eax, eax
        jz other_hand
        lea eax, [eax+eax*8]
        lea eax, [edi+eax*4-SIZE_ITEM].s_player.items
        test byte ptr [eax].s_item.flags, IFLAGS_BROKEN
        jnz other_hand
        mov edx, dword ptr [eax] ; id
        lea edx, [edx+edx*2]
        shl edx, 4
        mov ch, byte ptr [ITEMS_TXT_ADDR+edx].s_items_txt_item.equip_stat
        movzx edx, byte ptr [ITEMS_TXT_ADDR+edx].s_items_txt_item.skill
        xchg ch, dh
        cmp dl, SKILL_UNARMED
        jne not_caestus
        cmp dh, ITEM_TYPE_GAUNTLETS - 1
        je got_weapon
        not_caestus:
        cmp dh, ITEM_TYPE_MISSILE - 1
        ja other_hand
        got_weapon:
        inc dword ptr [esp+8] ; have a weapon
        cmp dl, SKILL_STAFF
        jne no_staff
        cmp word ptr [edi+SKILL_STAFF*2].s_player.skills, SKILL_GM
        jb no_staff
        neg dword ptr [esp+8] ; mark it
        no_staff:
        cmp dword ptr [eax], SWORD_OF_LIGHT
        jne skip_light
        inc dword ptr [esp+12] ; have sword of light
        jmp other_hand
        skip_light:
        test bl, bl
        jz skip_undead
        cmp dword ptr [eax], GHOULSBANE
        je undead
        cmp dword ptr [eax], GIBBET
        je undead
        cmp dword ptr [eax], JUSTICE
        je undead
        cmp dword ptr [eax].s_item.bonus2, SPC_UNDEAD_SLAYING
        je undead
        cmp dword ptr [eax].s_item.bonus, TEMP_ENCH_MARKER
        jne skip_undead
        cmp dword ptr [eax].s_item.bonus_strength, SPC_UNDEAD_SLAYING
        jne skip_undead
        undead:
        inc dword ptr [esp+4] ; have an undead slaying weapon
        jmp other_hand
        skip_undead:
        test bh, bh
        jz other_hand
        cmp dword ptr [eax], FLATTENER
        je spectral
        cmp dword ptr [eax].s_item.bonus2, SPC_SPECTRAL
        je spectral
        cmp dword ptr [eax].s_item.bonus2, SPC_WRAITH
        je spectral
        cmp dword ptr [eax].s_item.bonus, TEMP_ENCH_MARKER
        jne other_hand
        cmp dword ptr [eax].s_item.bonus_strength, SPC_SPECTRAL
        je spectral
        cmp dword ptr [eax].s_item.bonus_strength, SPC_WRAITH
        jne other_hand
        spectral:
        inc dword ptr [esp] ; have a spectral weapon
        other_hand:
        dec ecx
        jg check_hand
        cmp dword ptr [esp+8], ecx ; 0 for unarmed, -1 for gm staff
        jg done
        neg dword ptr [esp+8]
        mov eax, dword ptr [edi+SLOT_GAUNTLETS*4].s_player.equipment
        jmp check_slot
        done:
        pop edx ; spectral
        pop ebx ; undead sl.
        pop ecx ; total
        cmp dword ptr [esp], 0
        jz no_energy
        cmp dword ptr [esp], ecx
        jb halve
        just_energy:
        mov dword ptr [ebp-8], ENERGY
        jmp quit
        no_energy:
        test ebx, ebx
        jnz holy
        test edx, edx
        jz quit
        cmp edx, ecx
        je just_magic
        holy:
        cmp ebx, ecx
        je just_holy
        halve:
        ; split the damage in half
        mov eax, dword ptr [ebp-12]
        shr eax, 1
        sub dword ptr [esp+12], eax ; pushed damage
        cmp dword ptr [esp], 0
        push eax
        jz holy_or_magic
        cmp ebx, edx ; 0,1 or 1,0 or 0,0
        je physical
        jb part_magic
        push HOLY
        jmp either
        holy_or_magic:
        cmp ebx, edx ; only equal here if both == 1 and two weapons
        je part_magic
        physical:
        push PHYSICAL
        jmp either
        part_magic:
        push MAGIC
        either:
        push esi
        call dword ptr ds:monster_resists
        mov dword ptr [ebp-20], eax ; lesser half of damage
        cmp dword ptr [esp], 0
        jnz just_energy
        test ebx, ebx
        jz just_magic
        just_holy:
        mov dword ptr [ebp-8], HOLY
        jmp quit
        just_magic:
        mov dword ptr [ebp-8], MAGIC
        quit:
        pop ebx
        pop ebx
        skip:
        ret
      }
}

// Since the damage can now be split in halves, we need to
// add them together, and relocate an above comparison.
// Also here: zero the extra damage var (will be used for Hammerhands).
static void __declspec(naked) add_damage_half(void)
{
    asm
      {
        add dword ptr [ebp-20], eax ; was mov
        mov dword ptr [ebp-12], 0
        test ebx, ebx ; was above
        ret
      }
}

// Possibly raise the monster killed by Ethric's staff as a loyal zombie.
static void __stdcall ethrics_staff_zombie(struct player *player,
                                           struct map_monster *monster)
{
    int staff = get_skill(player, SKILL_STAFF);
    int power = (staff & SKILL_MASK) * (skill_mastery(staff) + 1);
    int dark = get_skill(player, SKILL_DARK);
    int power2 = (dark & SKILL_MASK) * (skill_mastery(dark) + 1);
    if (power2 > power)
        power = power2;
    if (power < monster->level)
        return;
    power *= 10;
    if (monster->max_hp > power)
        monster->max_hp = power;
    monster->mod_flags |= MMF_REANIMATE | MMF_ZOMBIE;
    monster->poison_resistance = IMMUNE;
    monster->mind_resistance = IMMUNE;
    if (monster->holy_resistance == IMMUNE)
        monster->holy_resistance = 0;
}

// Reanimate the monster as soon as it finishes its death animation.
static void __declspec(naked) delayed_reanimation(void)
{
    asm
      {
        test byte ptr [esi].s_map_monster.mod_flags, MMF_REANIMATE
        jnz reanimate
        mov word ptr [esi].s_map_monster.ai_state, 5 ; replaced code
        ret
        reanimate:
        and byte ptr [esi].s_map_monster.mod_flags, ~MMF_REANIMATE
        mov dword ptr [esi].s_map_monster.experience, 0
        mov dword ptr [esi].s_map_monster.group, 0
        mov dword ptr [esi].s_map_monster.ally, 9999
        mov ecx, dword ptr [ebp-12] ; monster num
        call dword ptr ds:resurrect_monster
        lea ecx, [esi+MBUFF_ENSLAVE*SIZE_BUFF].s_map_monster.spell_buffs
        xor eax, eax
        push eax
        push eax
        push eax
        push eax
        dec eax
        push eax
        shr dword ptr [esp], 1
        push eax
        call dword ptr ds:add_buff
        push 0x401e26 ; skip dead gfx code
        ret 4
      }
}

// Bug fix: PCs would become stuck with zombie faces on TPK.
static void __declspec(naked) zombie_face_on_tpk(void)
{
    asm
      {
        mov ecx, dword ptr [eax+COND_ZOMBIE*8]
        or ecx, dword ptr [eax+COND_ZOMBIE*8+4]
        jz skip
        mov edx, dword ptr [eax].s_player.old_voice
        mov dword ptr [eax].s_player.voice, edx
        mov edx, dword ptr [eax].s_player.old_face
        mov byte ptr [eax].s_player.face, dl
        mov ecx, 4
        get_pc_id:
        cmp eax, dword ptr [PC_POINTERS+ecx*4-4]
        loopne get_pc_id
        call dword ptr ds:update_face
        skip:
        jmp dword ptr ds:memset_ptr ; replaced call
      }
}

// Tweaks of zombie players and monsters.
static inline void zombie_stuff(void)
{
    hook_call(0x42dcaa, zombify, 5);
    erase_code(0x42dcaf, 19); // old reanimate code
    erase_code(0x42dccc, 10); // ditto
    erase_code(0x42dcdc, 27); // same
    patch_bytes(0x428987, destroy_undead_chunk, 7);
    patch_bytes(0x42e0ad, control_undead_chunk, 7);
    patch_bytes(0x42bce1, turn_undead_chunk, 7);
    patch_bytes(0x4b75e3, zombificable_chunk, 22);
    hook_call(0x4398c3, undead_slaying_element, 5);
    hook_call(0x4398d1, add_damage_half, 5);
    hook_call(0x401dea, delayed_reanimation, 9);
    // Make charmed and enslaved monsters (incl. zombies) friendly.
    erase_code(0x422485, 10); // chat with enslaved etc. monsters
    erase_code(0x46a4f7, 10); // ditto, but space instead of mouse
    erase_code(0x4015d5, 2); // minimap and danger gem
    erase_code(0x401808, 2); // ditto, but indoors
    hook_call(0x463603, zombie_face_on_tpk, 5);
}

// Extra parameters for the below call.
static uint8_t *alter_spell = NULL;
static int only_alter_spell = FALSE;

// Parse a bunch of new monster spells in monsters.txt.
// Also here: recursively parse an alternative spell if present.
static int __fastcall parse_new_spells(char **words, int *extra_words)
{
    char *first_word = words[1];
    if (!first_word)
        return 0;
    int result;
    if (only_alter_spell)
      {
        --*extra_words; // will be 0 now
        result = 0;
      }
    else
      {
        static const struct { char *word; int spell, extra; } new_spells[] = {
              { "turn", SPL_TURN_UNDEAD, 1 },
              { "destroy", SPL_DESTROY_UNDEAD, 1 },
              { "flying", SPL_FLYING_FIST, 1 },
              { "poison", SPL_POISON_SPRAY, 1 },
              { "deadly", SPL_DEADLY_SWARM, 1 },
              { "sunray", SPL_SUNRAY, 0 },
              { "starburst", SPL_STARBURST, 0 },
              { "regeneration", SPL_REGENERATION, 0 },
              { "jump", SPL_JUMP, 0 },
              { "prismatic", SPL_PRISMATIC_LIGHT, 1 },
              { "telekinesis", SPL_TELEKINESIS, 0 },
              { NULL, 0 },
        };
        for (int i = 0;; i++)
            if (!new_spells[i].word)
              {
                result = parse_spell(words, extra_words);
                if (result == SPL_MASS_DISTORTION
                    && !uncased_strcmp(words[2], "fear"))
                    result = SPL_MASS_FEAR;
                break;
              }
            else if (!uncased_strcmp(first_word, new_spells[i].word))
              {
                result = new_spells[i].spell;
                *extra_words += new_spells[i].extra;
                break;
              }
      }
    if (result && alter_spell || only_alter_spell)
      {
        int offset = *extra_words;
        char *backup = words[offset];
        words[offset] = words[0] - offset;
        uint8_t *alter = alter_spell;
        alter_spell = NULL; // avoid infinite loop
        only_alter_spell = FALSE; // ditto
        ++*extra_words;
        *alter = parse_new_spells(words + offset, extra_words);
        words[offset] = backup;
      }
    return result;
}

// Monsters can now cast turn undead (only on party, only if liches or zombies
// present) and destroy undead (on any undead PC or monster).
// Also here: fix dispel magic on party from non-hostile monsters.
static int __fastcall consider_new_spells(void *this, int first,
                                          struct map_monster *monster,
                                          int spell)
{
    if (monster->spell_buffs[MBUFF_BERSERK].expire_time)
        return FALSE; // too angry to cast
    int monster_id = monster - MAP_MONSTERS;
    unsigned int target = MON_TARGETS[monster_id];

    // maybe substitute an alternative spell
    int marker = first ? monster->alter_flag1 : monster->alter_flag2;
    if (marker & 0x80 && elemdata.difficulty >= (marker & 0x7f))
        spell = first ? monster->alter_spell1 : monster->alter_spell2;

    if (!spell) return FALSE; // in case only alter spell exists
    if (spell == SPL_TURN_UNDEAD || spell == SPL_MASS_FEAR)
      {
        // Make sure we're targeting the party (no effect on monsters so far).
        if (target != TGT_PARTY)
            return FALSE;

        if (!(monster->bits & MBIT_LOS))
            return FALSE;

        for (int i = 0; i < 4; i++)
            if ((spell != SPL_TURN_UNDEAD) == !is_undead(&PARTY[i])
                && player_active(&PARTY[i])
                // TODO: may remove the below requirement if damage ever rises
                && !PARTY[i].conditions[COND_AFRAID])
                return TRUE;
        return FALSE;
      }
    else if (spell == SPL_DESTROY_UNDEAD)
      {
        if (target == TGT_PARTY)
          {
            if (!(monster->bits & MBIT_LOS))
                return FALSE;
            for (int i = 0; i < 4; i++)
                if (is_undead(&PARTY[i]) && player_active(&PARTY[i]))
                    return TRUE;
            return FALSE;
          }
        else if ((target & 7) == TGT_MONSTER) 
            return MAP_MONSTERS[target>>3].holy_resistance < IMMUNE;
        else // shouldn't happen
            return FALSE;
      }
    else if (spell == SPL_DISPEL_MAGIC && target != TGT_PARTY)
        return FALSE; // would target the party even if not hostile
    else if (spell == SPL_INFERNO || spell == SPL_PRISMATIC_LIGHT)
        return target == TGT_PARTY // mvm not implemented for now
               && dword(OUTDOORS) != 2 && monster->bits & MBIT_LOS;
    else if (spell == SPL_TELEKINESIS)
        return target == TGT_PARTY && monster->bits & MBIT_LOS; // same
    else if (spell == SPL_REGENERATION) // less often if not too wounded
        return monster->hp * 2 <= monster->max_hp + random() % monster->max_hp;
    else if (spell == SPL_JUMP)
      {
        if (elemdata.difficulty < 2 && random() & 1)
            return FALSE; // less sprinting on medium
        int ai = monster->ai_type;
        if (ai == 1 /* wimp */ || monster->spell_buffs[MBUFF_FEAR].expire_time
            || ai && !monster->spell_buffs[MBUFF_BERSERK].expire_time
                  && !(monster->bits & 0x20000) // no flee bit
                  && monster->hp * (ai == 2 ? 5 : 10) <= monster->max_hp)
            return FALSE; // no speed boost for fleeing!
        int tx, ty, tz;
        int melee = 300;
        if (target == TGT_PARTY)
          {
            tx = dword(PARTY_X);
            ty = dword(PARTY_Y);
            tz = dword(PARTY_Z);
            melee >>= 1; // for some reason mvp vs. mvm melee radius differs
          }
        else if ((target & 7) == TGT_MONSTER)
          {
            struct map_monster *tarmon = &MAP_MONSTERS[target>>3];
            tx = tarmon->x;
            ty = tarmon->y;
            tz = tarmon->z;
          }
        else return FALSE; // just in case
        int dx = tx - monster->x;
        int dy = ty - monster->y;
        int dz = monster->flight ? tz - monster->z : 0;
        return sqrt(dx * dx + dy * dy + dz * dz) > monster->radius + melee
                                                 + 200 + random() % 600;
      }
    else
      {
        // for aoe spells, chance to cast if an ally can be affected
        int result = monster_considers_spell(this, monster, spell);
        if (result || !elemdata.difficulty) return result;
        int reach = 1000 * 1000 * elemdata.difficulty * elemdata.difficulty;
        int mastery = skill_mastery(first ? monster->spell1_skill
                                          : monster->spell2_skill);
        switch (spell)
          {
            case SPL_HAMMERHANDS: // should be gm, but let's buff enemy monks
            case SPL_PAIN_REFLECTION:
                if (mastery < MASTER) return FALSE;
                // else fallthrough
            case SPL_HASTE:
            case SPL_SHIELD:
            case SPL_STONE_SKIN:
            case SPL_BLESS:
            case SPL_HEROISM:
                // restrict some monsters to self-buff only
                if (mastery < EXPERT) return FALSE;
                // else fallthrough
            case SPL_POWER_CURE:
            case SPL_DAY_OF_PROTECTION:
            case SPL_HOUR_OF_POWER:
                // about 1/2 chance to hit a given monster
                for (int i = dword(MONSTER_COUNT) * 2 / 3; i > 0; i--)
                  {
                    int id = random() % dword(MONSTER_COUNT);
                    struct map_monster *target = &MAP_MONSTERS[id];
                    int dx = monster->x - target->x;
                    int dy = monster->y - target->y;
                    int dz = monster->z - target->z;
                    if (dx * dx + dy * dy + dz * dz > reach
                        || !monster_active(target)
                        || is_hostile_to(monster, target))
                        continue;
                    if (spell == SPL_HAMMERHANDS // monks only
                        && (monster->id - 1) / 3 != (target->id - 1) / 3)
                        continue;
                    return monster_considers_spell(this, target, spell);
                  }
                // else fallthrough
            default:
                return FALSE;
          }
      }
}

// Hook for the above (for spell 1).
static void __declspec(naked) consider_first_spell(void)
{
    asm
      {
        xor edx, edx
        inc edx
        jmp consider_new_spells
      }
}

// Same, but for spell 2.
static void __declspec(naked) consider_second_spell(void)
{
    asm
      {
        xor edx, edx
        jmp consider_new_spells
      }
}

//Defined below.
static int __thiscall absorb_spell(struct player *player, int spell, int rank);
static int weighted_monster_preference(struct map_monster *monster, int mask);
static void adjust_aim(int attacker, int speed, int *buffer);
// Used to properly calculate MvM Mass Distortion damage.
static int mass_distortion_target_hp = 0;

// Turn undead damages and scares all undead PCs.
// Destroy undead damages one undead PC or monster with Holy.
// We also handle the Cursed monster debuff here.
static int __fastcall cast_new_spells(int monster_id, void *vector, int spell,
                                      int action, int skill)
{
    struct map_monster *monster = &MAP_MONSTERS[monster_id];
    if (monster->spell_buffs[MBUFF_CURSED].expire_time && random() & 1) // 50%
      {
        make_sound(SOUND_THIS, SOUND_SPELL_FAIL, 0, 0, -1, 0, 0, 0, 0);
        return FALSE;
      }

    // maybe substitute an alternative spell
    int first = action == 2;
    int marker = first ? monster->alter_flag1 : monster->alter_flag2;
    if (marker & 0x80 && elemdata.difficulty >= (marker & 0x7f))
        spell = first ? monster->alter_spell1 : monster->alter_spell2;

    if (spell == SPL_SUNRAY // like for pcs, no casting it at night
        && (dword(HOUR_OF_DAY) < 5 || dword(HOUR_OF_DAY) >= 21))
        spell = SPL_LIGHT_BOLT; // instead of forbidding, cast a weaker spell

    // improve monster aim at medium+
    unsigned int target = MON_TARGETS[monster_id];
    if (target == TGT_PARTY && elemdata.difficulty)
      {
        int object = dword(SPELL_OBJ_IDS + (spell - 1) * 4);
        int line = find_objlist_item(OBJLIST_THIS, object);
        int speed = word(dword(OBJLIST_THIS_ADDR + 4) + line * 56 + 48);
        if (speed) adjust_aim(monster_id, speed, vector);
      }

    int result = FALSE;
    if (spell == SPL_TURN_UNDEAD || spell == SPL_INFERNO
        || spell == SPL_PRISMATIC_LIGHT)
      {
        // we must be targeting the party
        int mastery = skill_mastery(skill);
        skill &= SKILL_MASK;
        int turn = spell == SPL_TURN_UNDEAD;
        for (struct player *p = PARTY; p < PARTY + 4; p++)
            if ((!turn || is_undead(p)) && !p->conditions[COND_ERADICATED]
                && !p->conditions[COND_DEAD] && !p->conditions[COND_STONED]
                && !absorb_spell(p, spell, mastery))
              {
                int damage = spell_damage(spell, skill, mastery, 0);
                if (damage_player(p, damage, ELEMENT(spell)) && turn
                    && player_active(p) && !p->conditions[COND_AFRAID])
                    inflict_condition(p, COND_AFRAID, FALSE);
              }
      }
    else if (spell == SPL_MASS_FEAR)
      {
        for (struct player *p = PARTY; p < PARTY + 4; p++)
            if (player_active(p) && !p->conditions[COND_AFRAID]
                && !absorb_spell(p, spell, MASTER))
                do_monster_bonus(p, 23, monster); // afraid
      }
    else if (spell == SPL_DESTROY_UNDEAD || spell == SPL_IMPLOSION
             || spell == SPL_MASS_DISTORTION)
      {
        if (target == TGT_PARTY)
          {
            int mask = 0;
            for (int i = 0; i < 4; i++)
                if ((spell != SPL_DESTROY_UNDEAD || is_undead(&PARTY[i]))
                    && player_active(&PARTY[i]))
                    mask |= 1 << i;
            if (mask)
              {
                struct player *target_player
                    = PARTY + weighted_monster_preference(monster, mask);
                int mastery = skill_mastery(skill);
                if (!absorb_spell(target_player, spell, mastery))
                  {
                    int damage = spell_damage(spell, skill & SKILL_MASK,
                                              mastery, target_player->hp);
                    damage_player(target_player, damage, ELEMENT(spell));
                  }
              }
          }
        else if ((target & 7) == TGT_MONSTER)
          {
            struct map_monster *tarmon = &MAP_MONSTERS[target>>3];
            uint32_t force[3];
            memset(force, 0, 12); // no knockback so far
            if (spell == SPL_IMPLOSION)
              {
                struct map_object anim = { OBJ_IMPLOSION,
                                           find_objlist_item(OBJLIST_THIS,
                                                             OBJ_IMPLOSION),
                                           tarmon->x, tarmon->y, tarmon->z };
                launch_object(&anim, 0, 0, 0, 0);
              }
            else if (spell == SPL_MASS_DISTORTION)
              {
                add_buff(tarmon->spell_buffs + MBUFF_MASS_DISTORTION,
                         dword(ANIM_TIMER) + 128, 0, 0, 0, 0);
                mass_distortion_target_hp = tarmon->hp;
              }
            attack_monster(monster_id * 8 + TGT_MONSTER, target >> 3,
                           force, first ? 2 : 3);
            mass_distortion_target_hp = 0; // reset just in case
          }
        make_sound(SOUND_THIS, word(SPELL_SOUNDS + spell * 2),
                   target, 0, -1, 0, 0, 0, 0);
        return FALSE;
      }
    else if (spell == SPL_REGENERATION)
      {
        // it's really just heal self, but stronger than heal/power cure
        monster->hp += (skill & SKILL_MASK) * 10;
        if (monster->hp > monster->max_hp)
            monster->hp = monster->max_hp;
        magic_sparkles(monster, 0xff8000); // body magic orange color
      }
    else if (spell == SPL_JUMP)
      {
        int tx, ty, tz;
        int melee = 300;
        if (target == TGT_PARTY)
          {
            tx = dword(PARTY_X);
            ty = dword(PARTY_Y);
            tz = dword(PARTY_Z);
            melee >>= 1; // for some reason mvp vs. mvm melee radius differs
          }
        else if ((target & 7) == TGT_MONSTER)
          {
            struct map_monster *tarmon = &MAP_MONSTERS[target>>3];
            tx = tarmon->x;
            ty = tarmon->y;
            tz = tarmon->z;
          }
        else return FALSE; // just in case
        int dx = tx - monster->x;
        int dy = ty - monster->y;
        int dz = monster->flight ? tz - monster->z : 0;
        int slow = 1;
        if (monster->spell_buffs[MBUFF_SLOW].expire_time)
          {
            slow = monster->spell_buffs[MBUFF_SLOW].power;
            if (!slow) slow = 2; // vanilla has this check too
          }
        int length = (sqrt(dx * dx + dy * dy + dz * dz) - monster->radius
                      - melee) * 16 * slow / monster->velocity;
        int limit = 128 + (skill & SKILL_MASK) * 16;
        monster->ai_state = AI_PURSUE;
        monster->gfx_state = 1; // moving
        monster->mod_flags |= MMF_JUMPING;
        monster->action_time = 0;
        monster->action_length = length < limit ? length : limit;
        monster->direction = atan2(dy, dx) / M_PI * 1024;
        if (monster->flight)
            monster->look_angle = atan2(dz, sqrt(dx * dx + dy * dy))
                                / M_PI * 1024;
        monster->recovery = 0; // attack as soon as possible
        if (dword(TURN_BASED)) // tb tracks recovery in a separate stack
            for (int i = dword(TURN_BASED_THIS + 12); i > 0; i--)
                if (dword(TURN_BASED_THIS + 16 + i * 16)
                    == monster_id * 8 + TGT_MONSTER)
                  {
                    // can't set recovery too low or it resets/glitches
                    dword(TURN_BASED_THIS + 20 + i * 16) = 20;
                    break;
                  }
        result = TRUE; // skip ai code
      }
    else if (spell == SPL_TELEKINESIS)
      {
        struct item *stash = NULL;
        if (!monster->items[0].id)
            stash = &monster->items[0];
        else if (!monster->items[1].id)
            stash = &monster->items[1];
        else for (int i = 0; i < MAX_STOLEN_ITEMS; i++)
            if (!elemdata.stolen_items[i].id)
              {
                stash = &elemdata.stolen_items[i];
                break;
              }
        if (stash)
          {
            int mask = 0;
            for (int i = 0; i < 4; i++)
                if (player_active(&PARTY[i]))
                    mask |= 1 << i;
            struct player *mark
                = PARTY + weighted_monster_preference(monster, mask);
            int slot, count = 0;
            for (int s = SLOT_OFFHAND; s <= SLOT_MISSILE; s++)
                if (mark->equipment[s] && !(random() % ++count))
                    slot = s;
            int chance = (get_effective_stat(get_accuracy(mark))
                          + get_effective_stat(get_luck(mark))) * 4;
            if (count && random() % (chance + 30) < 30)
              {
                struct item *swag = &mark->items[mark->equipment[slot]-1];
                mark->equipment[slot] = 0;
                *stash = *swag;
                stash->body_slot = 0;
                init_item(swag);
                show_face_animation(mark, ANIM_DISMAY, 0);
                spell_face_anim(SPELL_ANIM_THIS, SPAN_DEBUFF, mark - PARTY);
              }
          }
      }
    else
      {
        monster_casts_spell(monster_id, vector, spell, action, skill);
        // make most buffs aoe on normal+
        if (!elemdata.difficulty) return FALSE;
        int reach = 1000 * 1000 * elemdata.difficulty * elemdata.difficulty;
        int mastery = skill_mastery(skill);
        switch (spell)
          {
            case SPL_HAMMERHANDS: // should be gm, but let's buff enemy monks
            case SPL_PAIN_REFLECTION:
                if (mastery < MASTER) return FALSE;
                // else fallthrough
            case SPL_HASTE:
            case SPL_SHIELD:
            case SPL_STONE_SKIN:
            case SPL_BLESS:
            case SPL_HEROISM:
                // restrict some monsters to self-buff only
                if (mastery < EXPERT) return FALSE;
                // else fallthrough
            case SPL_POWER_CURE:
            case SPL_DAY_OF_PROTECTION:
            case SPL_HOUR_OF_POWER:
                for (int id = 0; id < dword(MONSTER_COUNT); id++)
                  {
                    struct map_monster *ally = &MAP_MONSTERS[id];
                    int dx = monster->x - ally->x;
                    int dy = monster->y - ally->y;
                    int dz = monster->z - ally->z;
                    if (dx * dx + dy * dy + dz * dz > reach
                        || !monster_active(ally)
                        || is_hostile_to(monster, ally))
                        continue;
                    if (spell == SPL_HAMMERHANDS // monks only
                        && (monster->id - 1) / 3 != (ally->id - 1) / 3)
                        continue;
                    monster_casts_spell(id, vector, spell, action, skill);
                  }
          }
        return FALSE; // sound handled in vanilla
      }
    make_sound(SOUND_THIS, word(SPELL_SOUNDS + spell * 2),
               monster_id * 8 + TGT_MONSTER, 0, -1, 0, 0, 0, 0);
    return result;
}

// Hook for the above.  Skips over AI/gfx state if Jump was cast.
static void __declspec(naked) cast_new_spells_hook(void)
{
    asm
      {
        push dword ptr [esp+12]
        push dword ptr [esp+12]
        push dword ptr [esp+12]
        call cast_new_spells
        test eax, eax
        jz quit
        mov eax, 0x402606
        cmp dword ptr [esp], 0x406648 ; the hook is reused in two places
        jb skip
        mov eax, 0x406808
        skip:
        mov dword ptr [esp], eax
        quit:
        ret 12
      }
}

// Pretend Poison Spray is Shrapmetal when a monster casts it.
// Also here: use Meteor Shower code for Starburst, and re-implement
// an MM7Patch hook at this address that enables some projectile spells.
static void __declspec(naked) cast_poison_blast(void)
{
    asm
      {
        mov edx, 3 ; replaced code, basically
        cmp ecx, SPL_POISON_SPRAY
        jne not_spray
        mov ecx, SPL_SHRAPMETAL
        not_spray:
        cmp ecx, SPL_DEADLY_SWARM
        je projectile
        cmp ecx, SPL_ICE_BLAST
        je projectile
        cmp ecx, SPL_FLYING_FIST
        je projectile
        cmp ecx, SPL_SUNRAY
        jne not_proj
        projectile:
        mov ecx, SPL_LIGHTNING_BOLT ; earliest jump to projectile code
        not_proj:
        cmp ecx, SPL_STARBURST
        jne skip
        mov ecx, SPL_METEOR_SHOWER
        skip:
        cmp ecx, SPL_SPECTRAL_WEAPON ; replaced (actually fate)
        ret
      }
}

// Correct the projectile count (two less than Shrapmetal).
static void __declspec(naked) poison_blast_count(void)
{
    asm
      {
        mov edi, 360 ; replaced code
        cmp dword ptr [ebp+8], SPL_POISON_SPRAY
        jne skip
        sub ecx, 2
        skip:
        ret
      }
}

// Supply the correct projectile ID.
static void __declspec(naked) poison_blast_projectile(void)
{
    asm
      {
        mov edx, dword ptr [ebp+8] ; spell id
        mov dx, word ptr [SPELL_OBJ_IDS+edx*4-4]
        ret
      }
}

// Also set the proper spell ID for the projectile.
static void __declspec(naked) poison_blast_id(void)
{
    asm
      {
        mov ecx, dword ptr [ebp+8] ; spell id
        mov dword ptr [ebp-60], ecx ; was constant
        ret
      }
}

// Vanilla bug fix: MvM spells could miss like regular attacks.
// TODO: make an exception for Blades?
static void __declspec(naked) never_miss_monster_spells(void)
{
    asm
      {
        xor eax, eax
        inc eax
        cmp dword ptr [ebp+12], eax ; attack type
        jbe ok ; attack 1 or attack 2
        ret 16 ; otherwise force hit
        ok:
        mov eax, 0x427372 ; replaced call
        jmp eax
      }
}

// Setup an alternative spell to be parsed if pipe sign(s) is present.
static void __declspec(naked) detect_alter_spell(void)
{
    asm
      {
        xor ecx, ecx
        inc eax ; first symbol is always space
        cmp byte ptr [eax], '|'
        sete cl
        mov dword ptr [only_alter_spell], ecx
        je only
        push '|'
        push eax ; spell spec
        call dword ptr ds:strchr_ptr
        add esp, 8
        test eax, eax
        jz skip
        only:
        mov byte ptr [eax], ','
        mov cl, 0x81
        cmp byte ptr [eax+1], '|'
        jne one
        mov byte ptr [eax+1], ','
        inc cl
        one:
        mov edx, dword ptr [ebp-4] ; line id
        imul edx, edx, 88 ; sizeof monsters.txt item
        add edx, dword ptr [ebp-8] ; this
        xor eax, eax
        cmp dword ptr [esp], 0x455e07 ; second spell code
        setae al
        mov byte ptr [edx-44+eax].s_map_monster.alter_flag1, cl
        lea eax, [edx-44+eax].s_map_monster.alter_spell1
        mov dword ptr [alter_spell], eax
        skip:
        mov eax, 0x4caff0 ; replaced call
        jmp eax
      }
}

// Show difficulty-appropriate spells when examining a monster.
// Also here: display the second spell properly when it's the only one.
static void __declspec(naked) show_alter_spells(void)
{
    asm
      {
        mov dl, byte ptr [ecx].s_map_monster.spell1 ; replaced code
        mov eax, dword ptr [elemdata.difficulty]
        cmp al, byte ptr [ecx].s_map_monster.alter_flag1
        jno one
        mov dl, byte ptr [ecx].s_map_monster.alter_spell1
        one:
        cmp al, byte ptr [ecx].s_map_monster.alter_flag2
        mov al, byte ptr [ecx].s_map_monster.spell2
        jno two
        mov al, byte ptr [ecx].s_map_monster.alter_spell2
        two:
        cmp dl, bl ; == 0
        jnz ok
        mov dl, al
        mov al, bl
        ok:
        cmp dword ptr [HOUR_OF_DAY], 5
        jb night
        cmp dword ptr [HOUR_OF_DAY], 21
        jb day
        night:
        cmp dl, SPL_SUNRAY
        jne no_sun
        mov dl, SPL_LIGHT_BOLT
        no_sun:
        cmp al, SPL_SUNRAY
        jne day
        mov al, SPL_LIGHT_BOLT
        day:
        mov byte ptr [ebp-46], al ; hopefully unused
        ret
      }
}

// Substitute an alternative spell when calculating monster damage.
static void __declspec(naked) alter_spell_damage(void)
{
    asm
      {
        mov eax, dword ptr [elemdata.difficulty]
        cmp al, byte ptr [ecx+edx-2].s_map_monster.alter_flag1
        jno ok
        movzx edi, byte ptr [ecx+edx-2].s_map_monster.alter_spell1
        ok:
        cmp edi, SPL_SUNRAY
        jne no_sun
        cmp dword ptr [HOUR_OF_DAY], 5
        jb night
        cmp dword ptr [HOUR_OF_DAY], 21
        jb no_sun
        night:
        mov edi, SPL_LIGHT_BOLT
        no_sun:
        mov ecx, esi ; replaced code
        jmp dword ptr ds:skill_mastery ; replaced call
      }
}

// Also get the right spell element (this hook is used twice).
// Also here: set the Lightning Bolt stun flag.
static void __declspec(naked) alter_spell_element(void)
{
    asm
      {
        mov ecx, dword ptr [ebp-16] ; attack type (2 or 3)
        mov edx, dword ptr [elemdata.difficulty]
        cmp dl, byte ptr [esi+ecx-2].s_map_monster.alter_flag1
        jno ok
        movzx eax, byte ptr [esi+ecx-2].s_map_monster.alter_spell1
        lea eax, [eax+eax*8]
        ok:
        cmp eax, SPL_LIGHTNING_BOLT * 9
        sete byte ptr [lightning_bolt_stun] ; 1 if lb
        cmp eax, SPL_SUNRAY * 9
        jne no_sun
        cmp dword ptr [HOUR_OF_DAY], 5
        jb night
        cmp dword ptr [HOUR_OF_DAY], 21
        jb no_sun
        night:
        mov eax, SPL_LIGHT_BOLT * 9
        no_sun:
        movzx eax, byte ptr [SPELLS_TXT+eax*4+28] ; replaced code, almost
        cmp dword ptr [esp], 0x43a402 ; tell the two hooks apart
        cmovb edi, eax ; different output registers
        cmovae ebx, eax
        ret
      }
}

// Distinguish between Meteor Shower and Starburst rocks.
static void __declspec(naked) starburst_projectile(void)
{
    asm
      {
        mov eax, dword ptr [ebp+8] ; spell id
        mov ax, word ptr [SPELL_OBJ_IDS+eax*4-4] ; was fixed [8]
        ret
      }
}

// Also get the correct sound.
static void __declspec(naked) starburst_sound(void)
{
    asm
      {
        mov eax, dword ptr [ebp+8] ; spell id
        movsx eax, word ptr [SPELL_SOUNDS+eax*2] ; was fixed [9]
        ret
      }
}

// Replace some outdoor-only monster spells when indoors.
static void __declspec(naked) indoor_monster_spells(void)
{
    asm
      {
        push dword ptr [esp+12]
        push dword ptr [esp+12]
        push dword ptr [esp+12]
        mov eax, 0x4ca780 ; replaced memmove call
        call eax
        add esp, 12
        cmp dword ptr [OUTDOORS], 2
        je skip
        mov eax, dword ptr [esp+4] ; copied monster data
        cmp byte ptr [eax-44].s_map_monster.alter_spell2, SPL_STARBURST
        jne not_starburst
        mov byte ptr [eax-44].s_map_monster.alter_spell2, 0
        mov byte ptr [eax-44].s_map_monster.alter_flag2, 0
        not_starburst:
        cmp byte ptr [eax-44].s_map_monster.spell2, SPL_METEOR_SHOWER
        jne skip
        mov byte ptr [eax-44].s_map_monster.spell2, 0
        mov byte ptr [eax-44].s_map_monster.alter_spell2, SPL_INFERNO
        mov byte ptr [eax-44].s_map_monster.alter_flag2, 0x81 ; normal+
        skip:
        ret
      }
}

// Supply target monster HP for Mass Distortion.
static void __declspec(naked) mvm_mass_distortion_damage(void)
{
    asm
      {
        mov eax, dword ptr [mass_distortion_target_hp]
        mov dword ptr [esp+8], eax ; hp param
        jmp dword ptr ds:spell_damage ; replaced call
      }
}

// Increase monster speed after casting Jump.
static void __declspec(naked) monster_jump_speed(void)
{
    asm
      {
        test byte ptr [esi].s_map_monster.mod_flags, MMF_JUMPING
        jz skip
        shl ebx, 2
        ret
        skip:
        cmp ebx, eax ; replaced code
        jle quit ; ditto
        mov ebx, eax ; and this
        quit:
        ret
      }
}

// Remove the extra speed after the walk animation ends.
static void __declspec(naked) reset_jump_flag(void)
{
    asm
      {
        movsx edx, word ptr [ecx].s_map_monster.ai_state ; replaced code
        and byte ptr [ecx].s_map_monster.mod_flags, ~MMF_JUMPING
        ret
      }
}

// While sprinting, allow monsters to pass through non-hostiles.
static void __declspec(naked) jump_past_allies(void)
{
    asm
      {
        test byte ptr [esi].s_map_monster.mod_flags, MMF_JUMPING
        jz skip
        push ecx
        imul edx, ecx, SIZE_MONSTER
        mov ecx, esi
        add edx, MAP_MONSTERS_ADDR
        call dword ptr ds:is_hostile_to
        test eax, eax
        pop ecx
        jnz restore
        ret ; do not register a collision
        restore:
        mov edx, 40
        skip:
        jmp dword ptr ds:check_monster_in_hitbox ; replaced call
      }
}

// Disable Prismatic Light on summoned elementals as MvM isn't implemented.
static void __declspec(naked) summon_elemental_no_spell(void)
{
    asm
      {
        mov word ptr [esi].s_map_monster.radius, ax ; replaced code
        mov byte ptr [esi].s_map_monster.alter_flag1, 0 ; disable
        ret
      }
}

// Make Turn Undead and Destroy Undead castable by monsters.
// Also enable Poison Spray, Starburst, and some others.
// Also here: implement difficulty-dependent alternative monster spells.
static inline void new_monster_spells(void)
{
    hook_call(0x455d70, parse_new_spells, 5); // first spell
    hook_call(0x455e86, parse_new_spells, 5); // second spell
    hook_call(0x42703a, consider_first_spell, 5);
    hook_call(0x427049, consider_second_spell, 5);
    hook_call(0x40213b, cast_new_spells_hook, 5); // realtime
    hook_call(0x40676e, cast_new_spells_hook, 5); // turn-based
    hook_call(0x404b02, cast_poison_blast, 6);
    hook_call(0x504614, poison_blast_count, 5);
    patch_byte(0x405624, 12); // don't overwrite spell id
    patch_byte(0x4056d8, 12); // read from the changed stack var
    patch_byte(0x4056ed, 12); // ditto
    hook_call(0x40562e, poison_blast_projectile, 7);
    hook_call(0x40566f, poison_blast_id, 7);
    hook_jump(0x405756, (void *) 0x40586c); // get the correct sound
    hook_call(0x43b25e, never_miss_monster_spells, 5);
    hook_call(0x455d0c, detect_alter_spell, 5); // first spell
    hook_call(0x455e22, detect_alter_spell, 5); // second spell
    hook_call(0x41f0c8, show_alter_spells, 5);
    // Use the stored spells in the code below:
    erase_code(0x41f0d2, 5); // we already check the second spell
    patch_word(0x41f130, 0xd255); // (mov dl,) byte ptr [ebp-46]
    patch_word(0x41f17d, 0xd35d); // (cmp) byte ptr [ebp-45], (bl)
    erase_code(0x41f181, 5); // again, no need to check second spell
    hook_call(0x43b4d8, alter_spell_damage, 7);
    hook_call(0x43a154, alter_spell_element, 8); // no projectile
    hook_call(0x43a672, alter_spell_element, 8); // projectile
    // also alter element in mvm_incinerate() above
    erase_code(0x402394, 4); // erase spell existence checks
    erase_code(0x4069bc, 4); // (we check the CURRENT spell ourselves)
    // Use (modified) Meteor Shower code for Starburst.
    patch_byte(0x404d59, 10); // bugfix: 10 rocks on M
    patch_byte(0x404d6d, 20); // and 20 on GM
    patch_byte(0x404d6b, 20); // and skip N/E code
    static const int addr[] = { 0xd89, 0xdbc, 0xdeb, 0xe00, 0xe03, 0xe66,
                                0xeae, 0xecb, 0xed1, 0xf5b, 0xff1 };
    for (int i = 0; i < sizeof(addr) / sizeof(int); i++)
        patch_byte(0x404000 + addr[i], 12); // don't overwrite spell id (again)
    hook_call(0x404e9d, starburst_projectile, 6);
    hook_call(0x404fc9, starburst_sound, 7);
    hook_call(0x44f850, indoor_monster_spells, 5); // random monster
    hook_call(0x4bbf74, indoor_monster_spells, 5); // summoned monster
    hook_call(0x43b4e7, mvm_mass_distortion_damage, 5);
    hook_call(0x46facf, monster_jump_speed, 6); // first hook
    hook_call(0x470876, monster_jump_speed, 6); // second hook
    hook_call(0x4597a6, reset_jump_flag, 7);
    hook_call(0x46fe7a, jump_past_allies, 5); // indoors
    hook_call(0x470cb9, jump_past_allies, 5); // outdoors
    hook_call(0x44fb90, summon_elemental_no_spell, 7);
}

// Calling atoi directly from assembly doesn't seem to work,
// probably because it's not relocated.
static const funcptr_t atoi_ptr = atoi;

// Parse the new "reputation group" column in mapstats.txt.
static void __declspec(naked) parse_mapstats_rep(void)
{
    asm
      {
        mov eax, dword ptr [ebp-12] ; replaced code
        dec eax ; replaced code
        cmp eax, 8 ; new column
        je reput
        jl fixed
        dec eax
        fixed:
        cmp eax, 28 ; replaced code
        ret
        reput:
        push edi
        call dword ptr ds:atoi_ptr
        pop ecx
        imul ecx, ebx, SIZE_MAPSTAT
        mov byte ptr [esi+ecx].s_mapstats_item.reputation_group, al
        push 0x45472a ; default case
        ret 4
      }
}

#define REP_STACK_SIZE 8
// Current reputation group.  Stores multiple values
// to be pushed/popped by the game script.
static int reputation_group[REP_STACK_SIZE];
// Top of the reputation group stack.
static int reputation_index;

// The extra chest that currently replaces chest 0 (-1 == none).
static int replaced_chest;

// To remember the current music track.
static int current_track = 0;

// Don't run HP/SP change checks just after a reload.
static int reset_hp_temp, reset_sp_temp;

// Reset all new savegame data on a new game.
static void new_game_data(void)
{
    memset(&elemdata, 0, sizeof(elemdata));
    elemdata.version = 410; // v4.1.0
    for (int i = 0; i < EXTRA_CHEST_COUNT; i++)
      {
        elemdata.extra_chests[i].picture = i ? 6 : 3; // [0] is bank safe
        elemdata.extra_chests[i].bits = 2;
      }
    reputation_group[0] = 0; // will be set on map load
    reputation_index = 0;
    replaced_chest = -1;
    elemdata.last_region = -1;
    elemdata.genie = random() << 16 | random(); // only 15 bytes per call
    current_track = 0; // since the music has stopped at this point
    reset_hp_temp = reset_sp_temp = 0xf;
}

// Hook for the above.
static void __declspec(naked) new_game_hook(void)
{
    asm
      {
        call dword ptr ds:save_game ; replaced call
        call new_game_data
        ret
      }
}

// For bank_interest() below, stores the last week the interest was applied.
// On a reload it's reset to 0 and then overwriten properly on the next tick.
// On a new game it's lowered to the current week, which is also 0.
static int last_bank_week;

// Load mod data from the savegame, if said data exists.
// Also reset some vars and fix recovery after saving in TB mode.
static void load_game_data(void)
{
    void *file = find_in_lod(SAVEGAME_LOD, "elemdata.bin", 1);
    if (file)
      {
        fread(&elemdata, sizeof(elemdata), 1, file);
        if (elemdata.version <= 403) // save file compatibility
          {
            // The old data structure.
            enum { OLD_LAST_LOST_ITEM = 702 }; // vanilla scroll of waves
            struct elemdata_v403
              {
                int version;
                int reputation[12];
                char artifacts_found[LAST_ARTIFACT-FIRST_ARTIFACT+1];
                int training[4][SKILL_COUNT];
                struct beacon bottle;
                struct map_chest extra_chests[EXTRA_CHEST_COUNT];
                int difficulty;
                int last_region;
                int last_tax_month, last_tax_fame;
                int current_player;
                struct item guild_scrolls[32][12];
                struct item current_orders[42];
                uint64_t order_timers[42];
                uint32_t genie;
                int current_map;
                uint64_t map_enter_time;
                struct spell_buff new_pc_buffs[4][NBUFF_COUNT];
                int last_bank_gold;
                int quick_spells[4][4];
                int arena_points;
                struct beacon beacon_masters[2];
                int street_npc_seed[MAP_COUNT], street_npc_time[MAP_COUNT];
                int bard_xp[12], bard_bonus[12];
                int monster_loot_seed[MAP_COUNT];
                uint64_t last_rest_time;
                int next_refill_day[MAP_COUNT];
                char lost_items[OLD_LAST_LOST_ITEM-FIRST_LOST_ITEM+1];
                struct item stolen_items[MAX_STOLEN_ITEMS];
                int shop_wariness[53];
              } *old_elemdata = (struct elemdata_v403 *) &elemdata;
            if (elemdata.version < 402) // wariness added in 4.0.2
                memset(elemdata.shop_wariness, 0,
                       sizeof(elemdata.shop_wariness));
            else
                memmove(elemdata.shop_wariness, old_elemdata->shop_wariness,
                        sizeof(elemdata.shop_wariness));
            memmove(elemdata.stolen_items, old_elemdata->stolen_items,
                    sizeof(elemdata.stolen_items));
            memset(&elemdata.lost_items[OLD_LAST_LOST_ITEM-FIRST_LOST_ITEM+1],
                   LOST_NOTRACK, LAST_LOST_ITEM - OLD_LAST_LOST_ITEM);
            // For 4.0.2 or below we have another fix in load_map_rep().
            elemdata.version = 410 - (elemdata.version < 403);
          }
      }
    else // probably won't happen; reset all data just in case
        new_game_data();
    reputation_group[0] = 0; // will be set on map load
    reputation_index = 0;
    last_bank_week = 0;
    last_hit_player = 0;
    replaced_chest = -1;
    dword(CURRENT_PLAYER) = elemdata.current_player;
    if (dword(TURN_BASED)) // game was saved in TB mode
      {
        for (struct player *player = PARTY; player < PARTY + 4; player++)
            player->recovery = player->recovery * 32 * 32 / 15 / 15; // adjust
        dword(TURN_BASED) = 0; // reset it to prevent garbage recovery
      }
    reset_hp_temp = reset_sp_temp = 0xf;
}

// Hook for the above.
static void __declspec(naked) load_game_hook(void)
{
    asm
      {
        call load_game_data
        pop eax
        push 0x4e958c ; replaced code
        jmp eax
      }
}

// Defined below.
static void __thiscall replace_chest(int id);

// Save mod data into the savefile.
static void save_game_data(void)
{
    static const struct file_header header = { "elemdata.bin",
                                               sizeof(elemdata) };
    int group = reputation_group[reputation_index];
    if (group) // do not store group 0
        elemdata.reputation[group] = CURRENT_REP;
    replace_chest(-1); // we don't want swapped chests in the savefile
    elemdata.current_player = dword(CURRENT_PLAYER);
    save_file_to_lod(SAVEGAME_LOD, &header, &elemdata, 0);
}

// Hook for the above.  Also handles WoM barrels.
static void __declspec(naked) save_game_hook(void)
{
    asm
      {
        call save_game_data
        call save_wom_barrels
        lea eax, [ebp-68] ; replaced code
        ret 8
      }
}

// Used by fountain_timers() below.
static int loading_different_map;

// Set the map's default reputation group and update current reputation.
// Also here: update the Master Town Portal destination, and track map changes.
static void load_map_rep(void)
{
    reputation_index = 0;
    int map_index = dword(CURRENT_MAP_ID) - 1;
    int group = MAPSTATS[map_index].reputation_group;
    reputation_group[0] = group;
    CURRENT_REP = elemdata.reputation[group];
    static const int tp_qbits[12] = { 0, 0, 206, 207, 208, 210, 209, 0, 211 };
    static const int tp_order[9] = { -1, -1, 0, 2, 1, 5, 4, -1, 3 };
    int qbit = tp_qbits[group];
    if (qbit && check_bit(QBITS, qbit))
        elemdata.last_region = tp_order[group];
    loading_different_map = map_index != elemdata.current_map;
    if (loading_different_map)
      {
        elemdata.current_map = map_index;
        elemdata.map_enter_time = CURRENT_TIME;
        // Provide hints about a recent or upcoming map refill.
        if (!MAPSTATS[map_index].refill_days) // not in proving grounds
            return;
        int visit_addr = dword(OUTDOORS) == 2 ? OUTDOOR_LAST_VISIT_TIME
                                              : INDOOR_LAST_VISIT_TIME;
        // refill count, starts at 1
        if (dword(visit_addr - 40) > 1 && !*(uint64_t *) visit_addr)
            show_status_text(new_strings[STR_MAP_REFILL], 4);
        // these two never refill
        else if (map_index != castle_id && map_index != bottle_id)
          {
            unsigned int day = CURRENT_TIME >> 13;
            day /= 256 * 60 * 24 >> 13; // avoid long division dependency
            int left = MAPSTATS[map_index].refill_days - day - 1
                     + dword(visit_addr - 36); // last refill day
            if (left <= 28)
              {
                int text = STR_MAP_REFILL_SOON_1 + (left <= 14) + (left <= 7)
                                                 + (left <= 3);
                show_status_text(new_strings[text], 4);
              }
          }
      }
    // can't do it on game load, as that hook is before npcs are loaded
    if (elemdata.version < 410 && !(NPCS[399].bits & NPC_HIRED))
      {
        // update for a game in progress, unless in party
        NPCS[399].profession = NPCDATA[399].profession;
        elemdata.version = 410;
      }
}

// Used below to track the bow GM mini-quest.
static int bow_kill_player, bow_kill_time;

// Defined below.
static void set_walking_speed(void);

// Hook for the above.  It's somewhat awkward, but Grayface has
// already claimed all good places to fit a call into.
// Also handles WoM barrels, resetting disabled spells, and weather,
// which was not initialized properly on visiting a new map.
// Movement hirelings are also re-checked here (as they disappear in Shoals).
// Finally, it resets the double-kill-tracking bow quest vars.
static void __declspec(naked) load_map_hook(void)
{
    asm
      {
        jg load
        mov dword ptr [esp], 0x444380 ; replaced jump
        load:
        call load_map_rep
        call load_wom_barrels
        call reset_disabled_spells
        call set_walking_speed
        mov dword ptr [bow_kill_player], esi ; == 0
        mov dword ptr [bow_kill_time], esi
        cmp dword ptr [OUTDOORS], 2
        jne quit
        cmp dword ptr [OUTDOOR_LAST_VISIT_TIME], esi ; 0 if just refilled
        jnz quit
        cmp dword ptr [OUTDOOR_LAST_VISIT_TIME+4], esi ; second half
        jnz quit
        call dword ptr ds:change_weather
        quit:
        ret
      }
}

// Store the current reputation as the map is offloaded.
// Somewhat redundant, as every map change induces an autosave,
// and we sync rep on saving, but better safe than sorry.
static void leave_map_rep(void)
{
    int group = reputation_group[reputation_index];
    if (group) // do not store group 0
        elemdata.reputation[group] = CURRENT_REP;
}

// Defined below.
static int get_active_chests(void);

// Update the current status of all tracked quest items.
static void track_lost_items(int left)
{
    int map = dword(CURRENT_MAP_ID);
    char *lost = elemdata.lost_items - FIRST_LOST_ITEM;
#define FIND(what, where) \
    if ((what) >= FIRST_LOST_ITEM && (what) <= LAST_LOST_ITEM \
        && lost[what] != LOST_NOTRACK) \
        lost[what] = (where)
    for (int i = FIRST_LOST_ITEM; i <= LAST_LOST_ITEM; i++)
        if (i == BAG_OF_HOLDING || lost[i] == map || lost[i] == LOST_INV)
            lost[i] = LOST_GONE; // assume the worst
    for (int i = 0; i < 20; i++)
        if (MAP_CHESTS[i].bits & 2) // has been opened
            for (int j = 0; j < CHEST_MAX_ITEMS; j++)
                FIND(MAP_CHESTS[i].items[j].id, map);
    int objmask = MO_MISSILE | !!left * MO_DROPPED;
    for (int i = 0; i < dword(0x6650ac); i++) // map obj count
        if (!(MAP_OBJECTS[i].bits & objmask))
            FIND(MAP_OBJECTS[i].item.id, map);
    for (int i = 0; i < dword(MONSTER_COUNT); i++)
        if (MAP_MONSTERS[i].ai_state != AI_REMOVED
            && MAP_MONSTERS[i].ai_state != AI_INVISIBLE)
          {
            FIND(MAP_MONSTERS[i].item, map);
            for (int j = 0; j < 4; j++)
                FIND(MAP_MONSTERS[i].items[j].id, map);
          }
    int chests = get_active_chests();
    if (check_bit(QBITS, QBIT_DEPOSIT_BOX))
        chests |= 1 << 0; // count bank chest as party inventory here
    for (int p = -1; p < 4 + EXTRA_CHEST_COUNT; p++)
      {
        int limit = PLAYER_MAX_ITEMS;
        int loc = LOST_INV;
        if (p < 0)
            limit = 1; // no inner loop
        else if (p >= 4)
          {
            if (p - 4 == BOH_CHEST_ID)
              {
                loc = lost[BAG_OF_HOLDING];
                if (loc == LOST_GONE)
                    continue;
              }
            else if (~chests & 1 << (p - 4))
                continue;
            limit = CHEST_MAX_ITEMS;
          }
        for (int i = limit - 1; i >= 0; i--)
          {
            struct item *check;
            if (p < 0)
                check = (void *) MOUSE_ITEM;
            else if (p < 4)
                check = &PARTY[p].items[i];
            else
                check = &elemdata.extra_chests[p-4].items[i];
            FIND(check->id, loc);
          }
      }
    lost[BAG_OF_HOLDING] = LOST_NOTRACK; // restore
}

// Call the above (which is also called from gm_teaching_conditions() below).
// Also here: sync extra chests, which otherwise break in Arena.
// Also also: store the next refill day for later.
// Finally, we track lost items here.
static void leave_map(void)
{
    leave_map_rep();
    replace_chest(-1);
    int map = dword(CURRENT_MAP_ID) - 1;
    elemdata.next_refill_day[map] = MAPSTATS[map].refill_days - 1
                        + dword(dword(OUTDOORS) == 2 ? OUTDOOR_LAST_REFILL_DAY
                                                     : INDOOR_LAST_REFILL_DAY);
    track_lost_items(TRUE);
}

// Hook for the above.  Again, inserted in a somewhat inconvenient place.
static void __declspec(naked) leave_map_hook(void)
{
    asm
      {
        jle quit
        call leave_map
        pop eax
        push esi ; replaced code
        mov esi, 0x5b645c ; replaced code
        jmp eax
        quit:
        call leave_map
        push 0x443ffd ; replaced jump
        ret 4
      }
}

// Always display zero reputation in unpopulated areas.
// Technically it still can be changed, but since there are no shops etc.,
// it can be safely ignored.  It also resets to zero on reload.
static void __declspec(naked) show_zero_rep(void)
{
    asm
      {
        xor eax, eax
        mov ecx, dword ptr [reputation_index]
        cmp dword ptr [reputation_group+ecx*4], eax
        jz zero
        call dword ptr ds:get_eff_reputation
        zero:
        ret
      }
}

// Allow accessing reputation group in the game script (as varnum 0x190).
// Cmp checks if the current group equals the given value.
static void __declspec(naked) cmp_rep(void)
{
    asm
      {
        mov ecx, dword ptr [reputation_index]
        mov edx, offset reputation_group
        mov edx, dword ptr [edx+ecx*4]
        xor eax, eax
        cmp dword ptr [ebp+12], edx
        sete al
        ret
      }
}

// For the variable events.
static int evt_variable_id = 0;

// Hook for the new gamescript cmp code.
static void __declspec(naked) evt_cmp_hook(void)
{
    asm
      {
        cmp eax, EVT_REP_GROUP
        je rep
        cmp eax, EVT_DISABLED_SPELL
        je spell
        cmp eax, EVT_VARIABLE
        je variable
        lea ecx, [eax-0xe0] ; replaced code
        ret
        rep:
        call cmp_rep
        jmp quit
        spell:
        push dword ptr [ebp+12]
        call check_spell_disabled
        quit:
        push 0x44a3e6
        ret 4
        variable:
        mov eax, dword ptr [evt_variable_id] ; substitute
        mov dword ptr [esp], 0x449bea ; back to the first branching
        ret
      }
}

// Add pushes new group on the stack, while preserving the original value.
// Useful for temporarily changing the group.
static void __stdcall add_rep(int new_group)
{
    int old_group = reputation_group[reputation_index];
    if (old_group) // do not store group 0
        elemdata.reputation[old_group] = CURRENT_REP;
    if (reputation_index < REP_STACK_SIZE - 1) // guard from overflow
        reputation_index++;
    reputation_group[reputation_index] = new_group;
    CURRENT_REP = elemdata.reputation[new_group];
}

// Hook for the new gamescript add code.
static void __declspec(naked) evt_add_hook(void)
{
    asm
      {
        cmp eax, EVT_REP_GROUP
        je rep
        cmp eax, EVT_DISABLED_SPELL
        je spell
        cmp eax, EVT_VARIABLE
        je variable
        cmp eax, EVT_LOST_ITEM
        je lost
        sub eax, 307 ; replaced code
        ret
        rep:
        push dword ptr [ebp+12]
        call add_rep
        jmp quit
        spell:
        push dword ptr [ebp+12]
        call disable_spell
        jmp quit
        lost:
        mov eax, dword ptr [ebp+12]
        mov byte ptr [elemdata.lost_items+eax-FIRST_LOST_ITEM], LOST_GONE
        quit:
        push 0x44b90d
        ret 4
        variable:
        mov eax, dword ptr [evt_variable_id] ; substitute
        mov dword ptr [esp], 0x44b057 ; back to the first branching
        ret
      }
}

// Sub removes the given value from the stack, if found.
// Can be used to restore the original group after using Add.
static void __stdcall sub_rep(int group_to_remove)
{
    for (int i = reputation_index; i >= 1; i--) // do not remove rep_group[0]
        if (reputation_group[i] == group_to_remove)
          {
            if (i == reputation_index)
              {
                // current group changes
                if (group_to_remove) // do not store group 0
                    elemdata.reputation[group_to_remove] = CURRENT_REP;
                CURRENT_REP = elemdata.reputation[reputation_group[i-1]];
              }
            else
              {
                // remove by shifting the rest of stack one left
                for (int j = i; j < reputation_index; j++)
                    reputation_group[j] = reputation_group[j+1];
              }
            reputation_index--;
            break;
          }
}

// Hook for the new gamescript subtract code.
static void __declspec(naked) evt_sub_hook(void)
{
    asm
      {
        cmp eax, EVT_REP_GROUP
        je rep
        cmp eax, EVT_DISABLED_SPELL
        je spell
        cmp eax, EVT_VARIABLE
        je variable
        cmp eax, EVT_LOST_ITEM
        je lost
        sub eax, 308 ; replaced code
        ret
        rep:
        push dword ptr [ebp+12]
        call sub_rep
        jmp quit
        spell:
        push dword ptr [ebp+12]
        call enable_spell
        jmp quit
        lost:
        mov eax, dword ptr [ebp+12]
        mov byte ptr [elemdata.lost_items+eax-FIRST_LOST_ITEM], LOST_NOTRACK
        quit:
        push 0x44bb0d
        ret 4
        variable:
        mov eax, dword ptr [evt_variable_id] ; substitute
        mov dword ptr [esp], 0x44ba23 ; back to the first branching
        ret
      }
}

// Set discards the stack and changes the current group to the given value.
// Can be used to "permanently" change the group,
// as long as it's done on every game/map reload.
static void __stdcall set_rep(int new_group)
{
    int old_group = reputation_group[reputation_index];
    if (old_group) // do not store group 0
        elemdata.reputation[old_group] = CURRENT_REP;
    reputation_index = 0;
    reputation_group[0] = new_group;
    CURRENT_REP = elemdata.reputation[new_group];
}

// Hook for the new gamescript set code.
static void __declspec(naked) evt_set_hook(void)
{
    asm
      {
        cmp eax, EVT_REP_GROUP
        je rep
        cmp eax, EVT_DISABLED_SPELL
        je spell
        cmp eax, EVT_MOUSE_ITEM_CONDITION
        je condition
        cmp eax, EVT_VARIABLE
        je variable
        sub eax, 307 ; replaced code
        ret
        rep:
        push dword ptr [ebp+12]
        call set_rep
        jmp quit
        spell:
        push dword ptr [ebp+12]
        call disable_spell
        jmp quit
        condition:
        mov eax, dword ptr [ebp+12]
        mov dword ptr [MOUSE_ITEM].s_item.flags, eax
        quit:
        mov dword ptr [esp], 0x44af3b
        ret
        variable:
        mov eax, dword ptr [evt_variable_id] ; substitute
        mov dword ptr [esp], 0x44a628 ; back to the first branching
        ret
      }
}

// Only decrease rep if the PC was caught stealing.
static void __declspec(naked) pickpocket_rep(void)
{
    asm
      {
        test eax, eax
        jnz skip
        inc dword ptr [esi+8] ; reputation
        skip:
        mov ecx, edi ; replaced code
        ret
      }
}

// Let the town hall bounties affect reputation slightly.
// Also, Bounty Hunters may get a small skill point bonus.
static void __stdcall bounty_rep(int level)
{
    int rep = (level + 10) / 20; // 0 to 5
    if (!rep)
        return;
    CURRENT_REP -= rep;
    for (int i = 0; i < 4; i++)
        if (PARTY[i].class == CLASS_BOUNTY_HUNTER)
          {
            PARTY[i].skill_points += rep;
            spell_face_anim(SPELL_ANIM_THIS, SPL_FEATHER_FALL, i);
            show_face_animation(PARTY + i, ANIM_SMILE, 0);
          }
}

// Hook for the above.
static void __declspec(naked) bounty_hook(void)
{
    asm
      {
        movzx ebx, byte ptr [MONSTERS_TXT+eax-44].s_map_monster.level
        push ebx
        call bounty_rep
        mov eax, ebx
        ret
      }
}

// (Re)set the map and XYZ a beacon master will teleport to.
static void set_npc_beacon(int id)
{
    elemdata.beacon_masters[id] = (struct beacon) {
        dword(PARTY_X), dword(PARTY_Y), dword(PARTY_Z), dword(PARTY_DIR),
        dword(PARTY_LOOK_ANGLE), dword(CURRENT_MAP_ID) - 1,
    };
}

// Change "evil" hireable NPC penalty: instead of temporary -5 rep
// in all regions, give a permanent -5 in their home region.
// Also here: init beacon master recall coords to hire location.
static void __stdcall hire_npc_rep(int profession)
{
    if (profession == NPC_PIRATE || profession == NPC_GYPSY
        || profession == NPC_DUPER || profession == NPC_BURGLAR
        || profession == NPC_FALLEN_WIZARD
        || profession >= NPC_MOON_ACOLYTE && profession <= NPC_MOON_PRELATE)
      {
        CURRENT_REP += 5;
        if (CURRENT_REP > 10000) // vanilla rep code often has this limit
            CURRENT_REP = 10000;
      }
    else if (profession == NPC_BEACON_MASTER)
        set_npc_beacon(!!dword(HIRED_NPC_1));
}

// Hook for the above.
static void __declspec(naked) hire_npc_hook(void)
{
    asm
      {
        push dword ptr [ebp+24] ; npc profession
        call hire_npc_rep
        cmp dword ptr [HIRED_NPC_1], 0 ; replaced code, almost
        ret
      }
}

// Instead of a global reputation penalty for (successfull) shoplifting,
// just make stealing from this particular shopkeeper harder in the future.
static void __declspec(naked) increase_shop_wariness(void)
{
    asm
      {
        mov ecx, dword ptr [DIALOG2]
        mov ecx, dword ptr [ecx+28] ; shop id
        shl esi, 2 ; vanilla reputation change
        add dword ptr [elemdata.shop_wariness+ecx*4-4], esi
        mov edi, PC_POINTERS ; replaced code
        ret
      }
}

// Actually check the current shop wariness when trying to steal.
static void __declspec(naked) account_for_shop_wariness(void)
{
    asm
      {
        call dword ptr ds:get_eff_reputation ; replaced call
        mov ecx, dword ptr [DIALOG2]
        mov ecx, dword ptr [ecx+28] ; shop id
        mov ecx, dword ptr [elemdata.shop_wariness+ecx*4-4]
        sar ecx, 2
        add eax, ecx
        ret
      }
}

// Also decrease wariness slightly for each sold party item.
static void __declspec(naked) decrease_shop_wariness(void)
{
    asm
      {
        mov eax, dword ptr [esp+32] ; replaced code (shop id)
        cmp dword ptr [elemdata.shop_wariness+eax*4-4], 0
        jle skip
        dec dword ptr [elemdata.shop_wariness+eax*4-4]
        skip:
        imul eax, eax, SIZE_EVENT2D ; also replaced code
        ret
      }
}

// Make the max price of an item that can be stolen while being caught
// double that of the usual limit, to make up for the large penalties.
static void __declspec(naked) open_shoplift_chunk(void)
{
    asm
      {
        cmp esi, edi
        setle al
      }
}

// Let the reputation values be shared between different locations
// in the same region.  Among other things, this makes quests
// completed in castles affect your reputation properly.
static inline void reputation(void)
{
    hook_call(0x45403c, parse_mapstats_rep, 7);
    patch_byte(0x454739, 30); // one more column
    hook_call(0x460a9c, new_game_hook, 5);
    hook_call(0x45f0f2, load_game_hook, 5);
    hook_call(0x45f911, save_game_hook, 5);
    hook_call(0x444011, load_map_hook, 6);
    hook_call(0x443fc1, leave_map_hook, 8);
    hook_call(0x41ab0f, show_zero_rep, 5);
    hook_call(0x44a111, evt_cmp_hook, 6);
    hook_call(0x44b85f, evt_add_hook, 5);
    hook_call(0x44bff0, evt_sub_hook, 5);
    hook_call(0x44ae96, evt_set_hook, 5);

    // Some further reputation tweaks.
    hook_call(0x42ec41, pickpocket_rep, 5);
    // Do not decrease rep on successful shoplift.
    patch_byte(0x4b13c2, byte(0x4b13c2) + 9);
    hook_call(0x4bd223, bounty_hook, 7);
    hook_call(0x4bc695, hire_npc_hook, 6); // from street
    hook_call(0x4b230e, hire_npc_hook, 6); // from house
    // Remove an ongoing NPC rep penalty.
    erase_code(0x477549, 72);
    hook_call(0x4b1445, increase_shop_wariness, 5);
    hook_call(0x4be061, account_for_shop_wariness, 5);
    // decrease for bought items in faster_shop_restock() below
    hook_call(0x4be250, decrease_shop_wariness, 7);
    patch_bytes(0x48d861, open_shoplift_chunk, 5);
}

// Instead of copying the entire lines buffer, just store a pointer.
// Note that MMExt 2.3 will overwrite this with an identical hook.
static void __declspec(naked) remember_evt_lines(void)
{
    asm
      {
        mov eax, dword ptr [esp+4] ; destination
        mov edx, dword ptr [esp+8] ; source
        mov dword ptr [eax], edx
        ret
      }
}

// And now, restore the pointed buffer and adjust the register accordingly.
// We must check for MMExt: if the call is relocated, then it's 2.3 which
// does this already; if event is 0x7fff, it's 2.2 which doesn't expect this.
static void __declspec(naked) recall_evt_lines(void)
{
    asm
      {
        lea edx, [esi+esi*2] ; replaced code
        shl edx, 2 ; ditto
        cmp dword ptr [esp], 0x44694a ; false if inside a mmext 2.3 hook
        jne quit ; which does the below already
        cmp edi, 0x7fff ; true if called from evt.lua
        je quit ; must be 2.2 code, also skip for compatibility
        sub edx, 0x5840b8 ; old buffer
        add edx, dword ptr [0x5840b8] ; which now holds the pointer
        quit:
        ret
      }
}

// With all the reputation-related script changes,
// global.evt now has slightly more commands than the game can hold.
// I could try to remove something, but it'll probably only grow over time,
// so I might as well manually increase the limit already.
static inline void expand_global_evt(void)
{
    // The easiest way is to supply a bigger buffer.
    static uint32_t global_evt_lines[GLOBAL_EVT_LINES*3];
    // Just replace the buffer address and the size constant everywhere.
    patch_dword(0x443de5, GLOBAL_EVT_LINES * 12);
    patch_pointer(0x443def, global_evt_lines);
    patch_pointer(0x443e0e, global_evt_lines + 1);
    patch_pointer(0x4468e9, global_evt_lines);
    // Both times the buffer was read, it was copied into another
    // statically allocated buffer, but why not use the original one?
    erase_code(0x446708, 15); // pushes for memmove
    erase_code(0x446726, 5); // memmove call
    erase_code(0x44672d, 3); // call fixup
    patch_pointer(0x446754, global_evt_lines);
    patch_pointer(0x44675c, global_evt_lines + 1);
    patch_pointer(0x446764, global_evt_lines + 2);
    // The next two hooks are duplicated by MMExtension v2.3.
    // Using the same behavior is essential to retain compatibility.
    hook_call(0x44690d, remember_evt_lines, 5);
    hook_call(0x446945, recall_evt_lines, 6);
    // After tweaking barrels, I also ran out of the buffer that holds
    // global.evt raw data.  Let's replace it here as well!
    static uint8_t global_evt_buffer[GLOBAL_EVT_SIZE];
    patch_dword(0x443dc6, GLOBAL_EVT_SIZE);
    patch_pointer(0x443dcb, global_evt_buffer);
    patch_pointer(0x443e15, global_evt_buffer + 2);
    patch_pointer(0x443e1c, global_evt_buffer + 1);
    patch_pointer(0x443e2c, global_evt_buffer + 3);
    patch_pointer(0x443e38, global_evt_buffer);
    patch_pointer(0x44671d, global_evt_buffer);
    patch_pointer(0x4468e4, global_evt_buffer);
}

// If a PC's health is above maximum, cancel all health regeneration
// and decrease excess HP by 25% instead.  Zombies and jar-less liches
// are considered to only have half their normal maximum HP.
// Also here: let GM Bodybuilding grant regeneration.
static void __declspec(naked) hp_burnout(void)
{
    asm
      {
        mov ecx, esi
        call dword ptr ds:get_full_hp
        mov ecx, dword ptr [ebp-16] ; lich wo jar
        or ecx, dword ptr [ebp-24] ; zombie
        jz healthy
        shr eax, 1 ; undead max hp penalty
        healthy:
        sub eax, dword ptr [esi].s_player.hp
        jge no_burnout
        sar eax, 2 ; 25%, rounded up
        add dword ptr [esi].s_player.hp, eax ; burnout
        mov dword ptr [ebp-4], 1 ; hp changed
        push 0x493d93 ; skip hp regen code
        ret 4
        no_burnout:
        mov ecx, esi
        push SKILL_BODYBUILDING
        call dword ptr ds:get_skill
        cmp eax, SKILL_GM
        jb no_bb_regen
        and eax, SKILL_MASK
        shr eax, 1
        add ebx, eax
        no_bb_regen:
        test ebx, ebx
        jz no_regen
        mov eax, dword ptr [esi+COND_DEAD*8] ; replaced code
        ret
        no_regen:
        push 0x493d1e ; replaced jump
        ret 4
      }
}

// Instead of lowering SP to maximum if above, simply decrease it back.
static void __declspec(naked) mp_regen_chunk(void)
{
    asm
      {
        dec dword ptr [edi]
      }
}

// Like with HP above, decrease excess SP by 25% instead of regeneration.
// Jar-less liches have halved maximum, zombies can hold no SP.
// Also here: handle SP regen from GM Meditation
// and Grim Reaper (only near hostiles) and Eloquence Talisman's SP drain.
static void __declspec(naked) sp_burnout(void)
{
    asm
      {
        cmp dword ptr [esi].s_player.sp, 0
        jz no_drain
        test byte ptr [STATE_BITS], 0x30 ; if enemies are near
        jz no_reaper
        mov ecx, esi
        push SLOT_MAIN_HAND
        push GRIM_REAPER
        call dword ptr ds:has_item_in_slot
        or dword ptr [ebp-4], eax ; sp maybe changed
        sub dword ptr [esi].s_player.sp, eax
        jz no_drain
        no_reaper:
        mov ecx, esi
        push SLOT_AMULET
        push ELOQUENCE_TALISMAN
        call dword ptr ds:has_item_in_slot
        or dword ptr [ebp-4], eax
        sub dword ptr [esi].s_player.sp, eax
        no_drain:
        xor eax, eax ; zombies have no sp
        cmp dword ptr [ebp-24], 0 ; zombie
        jnz compare_sp
        mov ecx, esi
        call dword ptr ds:get_full_sp
        cmp dword ptr [ebp-16], 0 ; lich wo jar
        jz compare_sp
        shr eax, 1 ; jar-less liches have half sp
        compare_sp:
        sub eax, dword ptr [esi].s_player.sp
        jg meditation_regen
        je quit
        sar eax, 2 ; 25%, rounded up
        add dword ptr [esi].s_player.sp, eax ; burnout
        mov dword ptr [ebp-4], 1 ; sp changed
        quit:
        push 0x493f3a ; skip old lich/zombie code
        ret
        meditation_regen:
        mov edi, eax
        mov ecx, esi
        push SKILL_MEDITATION
        call dword ptr ds:get_skill
        cmp eax, SKILL_GM
        jb quit
        and eax, SKILL_MASK
        xor edx, edx
        mov ecx, 5
        div ecx
        cmp eax, edi
        cmova eax, edi
        add dword ptr [esi].s_player.sp, eax
        mov dword ptr [ebp-4], 1 ; sp changed
        jmp quit
      }
}

// Do not remove HP above maximum when healing.
// Allow healing potions to cure above max HP (only if HP wasn't full before).
static void __declspec(naked) healing_potions(void)
{
    asm
      {
        cmp dword ptr [esi].s_player.hp, eax
        jge skip
        add dword ptr [esi].s_player.hp, ecx ; replaced code
        cmp dword ptr [esp+8], 0x4687a8 ; check if called from potion code
        je skip
        ret
        skip:
        push 0x48dbe8 ; skip extra HP shredding
        ret 4
      }
}

// Preserve the amount of restored SP instead of adding it right away.
static void __declspec(naked) magic_potion_chunk_1(void)
{
    asm
      {
        mov ebx, eax
      }
}

// Allow magic potions to restore SP above max (only if it was below before).
static void __declspec(naked) magic_potion_chunk_2(void)
{
    asm
      {
        jge skip ; current sp was compared to full sp
        add dword ptr [edi], ebx ; restore sp
        skip:
        xor ebx, ebx ; ebx was zero before
      }
}

// Do not lower HP to maximum during a Divine Intervention.
static void __declspec(naked) divine_intervention_hp(void)
{
    asm
      {
        cmp dword ptr [edx].s_player.hp, eax ; current vs max
        jge quit
        mov dword ptr [edx].s_player.hp, eax ; replaced code
        quit:
        ret
      }
}

// Do not lower HP to maximum after a Sacrifice.
static void __declspec(naked) sacrifice_hp(void)
{
    asm
      {
        cmp dword ptr [edi].s_player.hp, eax ; current vs max
        jge quit
        mov dword ptr [edi].s_player.hp, eax ; replaced code
        quit:
        ret
      }
}

// Prevent healer NPC from lowering HP to maximum.
// Also reused in temple code to similar effect.
static void __declspec(naked) healer_or_temple_hp(void)
{
    asm
      {
        cmp dword ptr [esi].s_player.hp, eax ; current vs max hp
        jge quit
        mov dword ptr [esi].s_player.hp, eax ; replaced code
        quit:
        ret
      }
}

// Prevent expert healer NPC from lowering HP to maximum.
static void __declspec(naked) expert_healer_hp(void)
{
    asm
      {
        cmp dword ptr [esi-120].s_player.hp, eax ; current vs max
        jge quit
        mov dword ptr [esi-120].s_player.hp, eax ; replaced code
        quit:
        ret
      }
}

// Prevent master healer NPC from lowering HP to maximum.
static void __declspec(naked) master_healer_hp(void)
{
    asm
      {
        cmp dword ptr [esi-280].s_player.hp, eax ; current vs max
        jge quit
        mov dword ptr [esi-280].s_player.hp, eax ; replaced code
        quit:
        ret
      }
}


// Preserve HP/SP bonus instead of adding it right away.
static void __declspec(naked) evt_add_hp_sp_chunk_1(void)
{
    asm
      {
        mov esi, eax
      }
}

// Do not decrease HP/SP if it's above maximum.
static void __declspec(naked) evt_add_hp_sp_chunk_2(void)
{
    asm
      {
        jge quit
        add dword ptr [ebx], esi
        cmp dword ptr [ebx], eax
        jle quit
        mov dword ptr [ebx], eax
        quit:
      }
}

// Allow raising HP and SP above maximum, but drain the excess quickly.
static inline void hp_sp_burnout(void)
{
    hook_call(0x493cc5, hp_burnout, 5);
    // SP regeneration no longer erases SP above maximum.
    patch_bytes(0x493dac, mp_regen_chunk, 2); // regular regen
    erase_code(0x493dae, 7);
    // lich jar regen is completely removed in class_changes() below
    // Instead, extra SP quickly burns out.
    // We jump over the old undead code here (which drains hp and sp
    // if above 50% or so), but it's incorporated in the new code.
    // TODO: wouldn't it be simpler to adjust max HP and SP directly?
    hook_jump(0x493e98, sp_burnout);
    // Now we patch all major sources of healing to preserve HP/SP above max.
    hook_call(0x48dbd4, healing_potions, 6);
    patch_bytes(0x4687c5, magic_potion_chunk_1, 2);
    patch_bytes(0x468d82, magic_potion_chunk_2, 6);
    erase_code(0x468d88, 9); // old shred-sp-above-max code
    erase_code(0x42bf80, 36); // allow Shared Life to heal above maximum
    hook_call(0x42dac4, divine_intervention_hp, 6);
    hook_call(0x42e351, sacrifice_hp, 6);
    erase_code(0x42e6c4, 36); // allow Souldrinker to heal above maximum
    erase_code(0x4399e2, 26); // allow vampiric melee weapons to overheal
    erase_code(0x439951, 26); // allow vampiric bows to overheal
    hook_call(0x4bb83f, healer_or_temple_hp, 6); // healer
    hook_call(0x4bb816, expert_healer_hp, 6);
    hook_call(0x4bb76c, master_healer_hp, 6);
    hook_call(0x4b755e, healer_or_temple_hp, 6); // temple
    // Dealing with the gamescript add HP/SP commands below.
    patch_bytes(0x44b123, evt_add_hp_sp_chunk_1, 2); // hp
    patch_bytes(0x44b12c, evt_add_hp_sp_chunk_2, 10); // hp
    erase_code(0x44b136, 5); // old hp code
    patch_bytes(0x44b16b, evt_add_hp_sp_chunk_1, 2); // sp
    patch_bytes(0x44b174, evt_add_hp_sp_chunk_2, 10); // sp
    erase_code(0x44b17e, 3); // old sp code
}

// Recognize fire arrows as valid projectiles for the Shield spell.
// Also overwrite the old arrow-only jump to GM Unarmed dodge.
static void __declspec(naked) shield_fire_arrow(void)
{
    asm
      {
        jz quit
        cmp ax, OBJ_FIREARROW
        jz quit
        cmp ax, OBJ_LASER ; replaced code
        quit:
        ret
      }
}

// Make temple donation spells more powerful, depending on the
// donation cost.  Wizard Eye (5 rep) needs special handling
// because of the differently arranged code.
static void __declspec(naked) temple_wizard_eye_power(void)
{
    asm
      {
        lea edx, [ecx-1]
        mov ecx, SPL_WIZARD_EYE
        mov eax, dword ptr [DIALOG2]
        mov eax, dword ptr [eax+28] ; param = temple id
        imul eax, eax, SIZE_EVENT2D
        fld dword ptr [EVENTS2D_ADDR+eax].s_event2d.multiplier ; temple cost
        push 5
        fidiv dword ptr [esp] ; temple power = cost / 5
        fistp dword ptr [esp]
        pop eax
        add dword ptr [esp+4], eax ; add temple power to spell power
        ret
      }
}

// Make temple donation spells more powerful, depending on the
// donation cost.  10+ rep spells can all be patched the same way.
static void __declspec(naked) temple_other_spells_power(void)
{
    asm
      {
        div edi
        mov eax, dword ptr [DIALOG2]
        mov eax, dword ptr [eax+28] ; param = temple id
        imul eax, eax, SIZE_EVENT2D
        fld dword ptr [EVENTS2D_ADDR+eax].s_event2d.multiplier ; temple cost
        push 5
        fidiv dword ptr [esp] ; temple power = cost / 5
        fistp dword ptr [esp]
        pop eax
        lea edx, [edx+1+eax+SKILL_GM] ; spell pwr = temple pwr + weekday
        ret
      }
}

// Provide more detailed info for elemental resistances.
static char *__stdcall resistance_hint(char *description, int resistance)
{
    static char buffer[400];
    struct player *current = &PARTY[dword(CURRENT_PLAYER)-1];
    int element;
    int base;
    int race = get_race(current);
    int racial_bonus = 0;
    int base_immune = 0;

    switch (resistance)
      {
        case 19:
            element = FIRE;
            base = current->fire_res_base;
            if (race == RACE_GOBLIN)
                racial_bonus = 5 + current->level_base / 2;
            break;
        case 20:
            element = SHOCK;
            base = current->shock_res_base;
            if (race == RACE_GOBLIN)
                racial_bonus = 5 + (current->level_base - 1) / 2;
            break;
        case 21:
            element = COLD;
            base = current->cold_res_base;
            if (race == RACE_DWARF)
                racial_bonus = 5 + current->level_base / 2;
            break;
        case 22:
            element = POISON;
            base = current->poison_res_base;
            if (race == RACE_DWARF)
                racial_bonus = 5 + (current->level_base - 1) / 2;
            base_immune = current->class == CLASS_LICH;
            break;
        case 23:
            element = MIND;
            base = current->mind_res_base;
            if (race == RACE_ELF)
                racial_bonus = 9 + current->level_base;
            base_immune = current->class == CLASS_LICH;
            break;
        case 24:
            element = MAGIC;
            base = current->magic_res_base;
            if (race == RACE_HUMAN)
                racial_bonus = 5 + current->level_base / 2;
            break;
        default:
            return description;
      }
    int total = get_resistance(current, resistance - 9);
    if (total)
        total += get_effective_stat(get_luck(current)) * 4;
    strcpy(buffer, description);
    if (total > 0 && !is_immune(current, element))
      {
        // the math is complicated, but it should be correct
        double chance = total / 2.0 / (total + 30);
        double square = chance * chance;
        double percent = (chance + square) * (square + 1) * 100;
        sprintf(buffer + strlen(buffer), "\n\n%s: %.1f%%",
                new_strings[STR_AVERAGE_DAMAGE], percent);
      }
    else if (!base_immune)
        strcat(buffer, "\n");
    if (!base_immune)
      {
        sprintf(buffer + strlen(buffer), "\n%s: %d",
                new_strings[STR_BASE_VALUE], base);
        if (racial_bonus)
            sprintf(buffer + strlen(buffer), " (%d %s)",
                    base + racial_bonus, new_strings[STR_ACCOUNT_RACE]);
      }
    return buffer;
}

// Shared subroutine that calculates melee or ranged critical hit/miss chance.
static int __thiscall get_critical_chance(struct player *player,
                                          struct map_monster *monster,
                                          int ranged)
{
    int crit = get_effective_stat(get_luck(player));
    int dagger = get_skill(player, SKILL_DAGGER);
    if (dagger > SKILL_MASTER)
        dagger &= SKILL_MASK;
    else dagger = 0;
    int slot = ranged ? SLOT_MISSILE : SLOT_OFFHAND;
    int caestus = !ranged;
    for (int i = !!ranged; i < 3; i++)
      {
        int equip = player->equipment[slot];
        if (equip)
          {
            struct item *weapon = &player->items[equip-1];
            if (!(weapon->flags & IFLAGS_BROKEN))
              {
                struct items_txt_item *data = &ITEMS_TXT[weapon->id];
                int two_handed = data->equip_stat + 1 == ITEM_TYPE_WEAPON2
                                 && (data->skill == SKILL_SWORD
                                     || data->skill == SKILL_AXE);
                caestus = caestus && data->equip_stat + 1 == ITEM_TYPE_SHIELD;
                if (data->skill == SKILL_DAGGER)
                    crit += dagger;
                else if (data->skill == SKILL_STAFF)
                    caestus = player->skills[SKILL_STAFF] >= SKILL_GM;
                if (weapon->bonus2 == SPC_KEEN)
                    crit += two_handed ? 8 : 5;
                else if (weapon->bonus2 == SPC_VORPAL)
                    crit += two_handed ? 15 : 10;
                if (monster)
                  {
                    int id = weapon->id;
                    int bonus = weapon->bonus2;
                    int ench = 0;
                    if (weapon->bonus == TEMP_ENCH_MARKER)
                        ench = weapon->bonus_strength;
                    int slay;
                    switch ((monster->id + 2) / 3)
                      {
                        case 8: // devils
                            slay = bonus == SPC_DEMON_SLAYING || id == GIBBET;
                            break;
                        case 9: // dragons
                            slay = bonus == SPC_DRAGON_SLAYING
                                   || ench == SPC_DRAGON_SLAYING
                                   || id == GIBBET;
                            break;
                        case 12: // air elementals
                        case 13: // earth elementals
                        case 14: // fire elementals
                        case 15: // light elementals
                        case 16: // water elementals
                            slay = bonus == SPC_ELEMENTAL_SLAYING
                                   || id == MEKORIGS_HAMMER;
                            break;
                        case 17: // elven archers
                        case 18: // elven spearmen
                        case 45: // elven peasants female a
                        case 46: // elven peasants female b
                        case 47: // elven peasants female c
                        case 48: // elven peasants male a
                        case 49: // elven peasants male b
                        case 50: // elven peasants male c
                            slay = bonus == SPC_ELF_SLAYING || id == ELFBANE;
                            break;
                        case 71: // titans
                            slay = bonus == SPC_DAVID;
                            break;
                        default:
                            slay = FALSE;
                            break;
                      }
                    if (slay)
                        crit += two_handed ? 45 : 30;
                    else if (monster->holy_resistance < IMMUNE
                             && (bonus == SPC_UNDEAD_SLAYING
                                 || ench == SPC_UNDEAD_SLAYING
                                 || id == GHOULSBANE || id == GIBBET
                                 || id == JUSTICE))
                        crit += two_handed ? 30 : 20;
                  }
                if (weapon->id == THE_PERFECT_BOW)
                    crit += 25;
                else if (weapon->id == CHARELE)
                    crit += 20;
                else if (weapon->id == FENCERS_FRIEND)
                    crit += 10;
                else if (weapon->id == CLOVER && crit > 0)
                    crit *= 2; // must be applied last
              }
          }
        if (!i)
            slot = SLOT_MAIN_HAND;
        else if (caestus)
            slot = SLOT_GAUNTLETS;
        else break;
      }
    if (crit > 100) // can happen with stupid high dagger skill
        crit = 100;
    return crit;
}

// Similar, but for backstabs (melee only).
static int __thiscall get_backstab_chance(struct player *player)
{
    int skill = get_skill(player, SKILL_THIEVERY);
    int chance = skill & SKILL_MASK;
    if (skill >= SKILL_MASTER)
        chance *= 3;
    else if (skill >= SKILL_EXPERT)
        chance *= 2;
    for (int slot = SLOT_MAIN_HAND; slot >= SLOT_OFFHAND; slot--)
      {
        int equip = player->equipment[slot];
        if (!equip)
            continue;
        struct item *weapon = &player->items[equip-1];
        if (weapon->flags & IFLAGS_BROKEN)
            continue;
        if (weapon->bonus2 == SPC_BACKSTABBING
            || weapon->bonus2 == SPC_ASSASSINS)
          {
            struct items_txt_item *data = &ITEMS_TXT[weapon->id];
            if ((data->skill == SKILL_SWORD || data->skill == SKILL_AXE)
                && data->equip_stat + 1 == ITEM_TYPE_WEAPON2)
                chance += 23;
            else chance += 15;
          }
        else if (weapon->id == OLD_NICK)
            chance += 13;
      }
    return chance;
}

// Provide additional info for melee and ranged damage, too.
static char *__stdcall damage_hint(char *description, int ranged)
{
    static char buffer[400];
    struct player *player = &PARTY[dword(CURRENT_PLAYER)-1];
    int display_damage = !ranged;
    if (ranged && has_anything_in_slot(player, SLOT_MISSILE))
      {
        if (equipped_item_type(player, SLOT_MISSILE) == ITEM_TYPE_WAND - 1)
          {
            strcpy(buffer, description);
            int power = 5 + (get_effective_stat(get_intellect(player)) >> 1);
            if (has_item_in_slot(player, GADGETEERS_BELT, SLOT_BELT))
                power += (player->class & -4) == CLASS_THIEF ? 10 : 5;
            sprintf(buffer + strlen(buffer), "\n\n%s: %d",
                    new_strings[STR_SPELL_POWER], power);
            return buffer;
          }
        display_damage = TRUE;
      }
    int crit = get_critical_chance(player, NULL, ranged);
    if (!crit && !display_damage)
        return description;
    strcpy(buffer, description);
    if (crit > 0)
        sprintf(buffer + strlen(buffer), "\n\n%s: %d%%",
                new_strings[STR_CRIT_HIT_CHANCE], crit);
    else if (crit < 0)
        sprintf(buffer + strlen(buffer), "\n\n%s: %d%%",
                new_strings[STR_CRIT_MISS_CHANCE], -crit);
    else strcat(buffer, "\n");
    if (!display_damage)
        return buffer;
    if (!ranged && player->skills[SKILL_THIEVERY] >= SKILL_GM)
      {
        // essentially also crits at this point
        int chance = get_backstab_chance(player);
        if (chance >= 100)
            crit = 100;
        else
            crit += chance - crit * chance / 100; // rounding is negligible
      }
    int avg;
    if (ranged)
      {
        avg = get_min_ranged_damage(player) + get_max_ranged_damage(player);
        if (equipped_item_skill(player, SLOT_MISSILE) == SKILL_BOW
            && get_skill(player, SKILL_BOW) >= SKILL_MASTER)
            avg *= 2;
      }
    else
        avg = get_min_melee_damage(player) + get_max_melee_damage(player);
    // TODO: maybe account for regular hit chance somehow
    double dpr = avg / 2.0 * (100 + crit) / get_attack_delay(player, ranged);
    sprintf(buffer + strlen(buffer), "\n%s: %.1f",
            new_strings[STR_AVERAGE_DPR], dpr);
    return buffer;
}

// Hook for the above.
// TODO: could also call stat_hint()
static void __declspec(naked) display_melee_recovery_hook(void)
{
    asm
      {
        cmp edi, 19 ; fire
        jb not_resistance
        cmp edi, 24 ; body
        ja not_resistance
        push edi
        push ebx
        call resistance_hint
        mov ebx, eax
        not_resistance:
        xor edx, edx
        cmp edi, 16 ; melee damage
        je damage
        inc edx
        cmp edi, 18 ; ranged damage
        jne skip
        damage:
        push edx
        push ebx
        call damage_hint
        mov ebx, eax
        skip:
        mov ecx, dword ptr [ebp-4] ; replaced code
        test ecx, ecx ; replaced code
        ret
      }
}

// When calculating skill damage bonus, use mainhand weapon if present.
static void __declspec(naked) melee_damage_check_main_weapon_first(void)
{
    asm
      {
        inc edi
        lea edx, [esi+SLOT_MAIN_HAND*4].s_player.equipment
        ret
      }
}

// Continuation of the previous hook; ensures the offhand is checked later.
static void __declspec(naked) melee_damage_weapon_loop_chunk(void)
{
    asm
      {
        sub edx, 4
        dec edi
        nop
        nop
        nop
        _emit 0x74 ; jz
      }
}

// Let the bank account grow by 1% per week.
// First time this code is reached (after each reload),
// the last week var is initialised instead.
// It's probably possible to miss out on a weekly interest
// by reloading one tick before a week change, but it's quite unlikely.
static void __declspec(naked) bank_interest(void)
{
    asm
      {
        cmp dword ptr [last_bank_week], 1
        jb update_week
        sub eax, dword ptr [last_bank_week]
        je no_interest
        update_week:
        mov dword ptr [last_bank_week], esi
        jb no_interest
        mov ecx, eax
        mov ebx, dword ptr [BANK_GOLD]
        mov eax, dword ptr [elemdata.last_bank_gold]
        push 100
        interest:
        xor edx, edx
        div dword ptr [esp]
        add ebx, eax
        mov eax, ebx
        loop interest
        mov dword ptr [BANK_GOLD], ebx
        mov dword ptr [elemdata.last_bank_gold], ebx
        pop eax
        no_interest:
        mov ebx, esi ; replaced code
        shr ebx, 2 ; replaced code
        ret
      }
}

// Ditto, but the code here uses different registers.
static void __declspec(naked) bank_interest_2(void)
{
    asm
      {
        call bank_interest
        mov edi, ebx
        ret
      }
}

// Only add 1% to the money that stayed in the bank for a full week.
// In particular, check if this amount should be reduced on a withdraw.
static void __declspec(naked) bank_withdraw(void)
{
    asm
      {
        sub esi, dword ptr [BANK_GOLD]
        neg esi
        cmp esi, dword ptr [elemdata.last_bank_gold]
        jae ok
        mov dword ptr [elemdata.last_bank_gold], esi
        ok:
        mov dword ptr [BANK_GOLD], esi ; almost the replaced code
        ret
      }
}

// Also update this value on a gamescript-triggered bank gold reset.
// TODO: could also hook add and subtract, but for now that's unnecessary
static void __declspec(naked) evt_set_bank_gold(void)
{
    asm
      {
        mov dword ptr [BANK_GOLD], eax ; replaced code
        cmp eax, dword ptr [elemdata.last_bank_gold]
        jae ok
        mov dword ptr [elemdata.last_bank_gold], eax
        ok:
        ret
      }
}

static struct statrate statrates[MAX_STATRATE_COUNT];
static int statrate_count;

// Parse statrate.txt, which contains skill rating titles.
// Also it's now used for storing rebalanced stat thresholds.
static void parse_statrate(void)
{
    char *file = load_from_lod(EVENTS_LOD, "statrate.txt", FALSE);
    if (strtok(file, "\r\n")) // skip first line
      {
        int i;
        for (i = 0; i < MAX_STATRATE_COUNT; i++)
          {
            char *line = strtok(0, "\r\n");
            if (!line)
                break;
            // field order: value bonus rating
            statrates[i].value = atoi(line);
            line = strchr(line, '\t');
            if (!line)
                continue;
            statrates[i].bonus = atoi(++line);
            line = strchr(line, '\t');
            if (line)
                statrates[i].rating = line + 1;
          }
        statrate_count = i;
      }
}

// Display skill bonus and base skill value in the tooltip.
static char *__stdcall stat_hint(char *description, int stat)
{
    static char buffer[400];
    struct player *current = &PARTY[dword(CURRENT_PLAYER)-1];
    int total, base, potion;

    switch (stat)
      {
        case STAT_MIGHT:
            total = get_might(current);
            base = current->might_base;
            potion = 6;
            break;
        case STAT_INTELLECT:
            total = get_intellect(current);
            base = current->intellect_base;
            potion = 2;
            break;
        case STAT_PERSONALITY:
            total = get_personality(current);
            base = current->personality_base;
            potion = 4;
            break;
        case STAT_ENDURANCE:
            total = get_endurance(current);
            base = current->endurance_base;
            potion = 3;
            break;
        case STAT_ACCURACY:
            total = get_accuracy(current);
            base = current->accuracy_base;
            potion = 5;
            break;
        case STAT_SPEED:
            total = get_speed(current);
            base = current->speed_base;
            potion = 1;
            break;
        case STAT_LUCK:
            total = get_luck(current);
            base = current->luck_base;
            potion = 0;
            break;
        default:
            return description;
      }
    int bonus = get_effective_stat(total);
    int rating;
    for (rating = 0; rating < statrate_count; rating++)
        if (statrates[rating].bonus == bonus)
            break;
    strcpy(buffer, description);
    sprintf(buffer + strlen(buffer), "\n\n%s: %s (%+d)\n%s: %d",
            new_strings[STR_RATING], statrates[rating].rating, bonus,
            new_strings[STR_BASE_VALUE], base);
    int race = get_race(current);
    int adj = base * RACE_STATS[race][stat][3] / RACE_STATS[race][stat][2];
    if (adj != base)
        sprintf(buffer + strlen(buffer), " (%d %s)", adj,
                new_strings[STR_ACCOUNT_RACE]);
    if (current->black_potions[potion])
      {
        strcat(buffer, "\n");
        strcat(buffer, new_strings[STR_BLACK_POTION]);
      }
    return buffer;
}

// Hook for the above.
static void __declspec(naked) stat_hint_hook(void)
{
    asm
      {
        mov ebx, ecx
        push edi
        push dword ptr [0x5c85f8+eax]
        call stat_hint
        mov ecx, ebx
        mov ebx, eax
        ret
      }
}

// Our replacement for get_effective_stat().
static int __stdcall new_stat_thresholds(int stat)
{
    for (int i = statrate_count - 1; i > 0; i--)
        if (stat >= statrates[i].value)
            return statrates[i].bonus;
    return statrates[0].bonus;
}

// Make it so rest encounters are only triggered if there are hostile
// monsters on the map.  Also exclude all types of peasants.
static void __declspec(naked) rest_encounters(void)
{
    asm
      {
        cmp eax, 38 ; first peasant
        jl not_peasant
        cmp eax, 61 ; last peasant
        jg not_peasant
        xor eax, eax ; set zf
        ret
        not_peasant:
        test byte ptr [esi+2].s_map_monster.bits, 8 ; hostile
        jnz quit
        mov ecx, esi
        xor edx, edx
        call dword ptr ds:is_hostile_to
        test eax, eax
        quit:
        ret
      }
}

// Display AC in red if the PC wears a broken item.
static void __declspec(naked) color_broken_ac(void)
{
    asm
      {
        call dword ptr ds:color_stat ; replaced call
        mov ecx, 16
        check_broken:
        mov edx, dword ptr [ebp+ecx*4-4].s_player.equipment
        test edx, edx
        jz next
        lea edx, [edx+edx*8]
        lea edx, [ebp+edx*4-SIZE_ITEM].s_player.items
        test byte ptr [edx].s_item.flags, IFLAGS_BROKEN
        jz next
        mov eax, dword ptr [colors+CLR_RED*4]
        ret
        next:
        loop check_broken
        ret
      }
}

// Same, but for the stats screen.
static void __declspec(naked) color_broken_ac_2(void)
{
    asm
      {
        mov ebp, edi
        jmp color_broken_ac
      }
}

// Use a new, separately localizable, name string for Monk NPCs.
static void __declspec(naked) monk_npc_name(void)
{
    asm
      {
        mov ecx, dword ptr [new_strings+STR_MONK*4]
        mov dword ptr [0x73c110+NPC_MONK*4], ecx ; replaced code
        ret
      }
}

// Same, but for Merchants.
static void __declspec(naked) merchant_npc_name(void)
{
    asm
      {
        mov edx, dword ptr [new_strings+STR_MERCHANT*4]
        mov dword ptr [0x73c110+NPC_MERCHANT*4], edx ; replaced code
        ret
      }
}

// Implement the CheckSkill 0x2b command properly.  From what I understand,
// it's supposed to check for effective skill (multiplied by mastery).
// Learning is special, as its bonus (from NPCs etc.) is not multiplied.
static int __stdcall check_skill(int player, int skill, int level, int mastery)
{
    if (player == 5)
      {
        for (int each = 0; each < 4; each++)
            if (check_skill(each, skill, level, mastery))
                return TRUE;
        return FALSE;
      }
    if (player == 4)
        player = dword(CURRENT_PLAYER) - 1;
    if (player < 0 || player > 3)
        player = random() & 3;

    int current_skill = get_skill(&PARTY[player], skill);
    int current_mastery = skill_mastery(current_skill);
    if (current_mastery < mastery + 1)
        return FALSE;
    current_skill &= SKILL_MASK;
    switch (skill)
      {
        // skills that are 100% at GM
        case SKILL_IDENTIFY_ITEM:
        case SKILL_REPAIR:
        case SKILL_DISARM_TRAPS:
        case SKILL_MERCHANT:
        case SKILL_IDENTIFY_MONSTER:
            if (current_mastery == GM)
                return TRUE;
            /* else fall through */
        // these cap at x3 now
        case SKILL_BODYBUILDING:
        case SKILL_MEDITATION:
        case SKILL_THIEVERY:
            if (current_mastery == GM)
                current_mastery = MASTER;
            /* fall through */
        // skills that are x1/2/3/5 dep. on mastery
        case SKILL_PERCEPTION:
            if (current_mastery == GM)
                current_mastery++;
            current_skill *= current_mastery;
            break;
        // special case (only base skill is x1/2/3/5)
        case SKILL_LEARNING:
            if (current_mastery != GM)
                current_mastery--;
            current_skill += PARTY[player].skills[skill] * current_mastery;
            break;
      }
    return current_skill >= level;
}

// Hook for the above.
static void __declspec(naked) check_skill_hook(void)
{
    asm
      {
        movzx eax, byte ptr [esi+6] ; mastery
        push eax
        push dword ptr [esi+7] ; level
        movzx eax, byte ptr [esi+5] ; skill
        push eax
        push dword ptr [esp+44] ; player
        call check_skill
        test eax, eax
        jz fail
        push 0x446c33 ; cmd jump
        ret
        fail:
        push 0x448356 ; next cmp
        ret
      }
}

// Initialise specitems spawned through Add gamescript command.
// Necessary for the new Barrow Knife.
// Also initialise throwing knife charges, just in case.
static void __declspec(naked) evt_add_specitem(void)
{
    asm
      {
        mov esi, eax
        call init_knife_charges
        push esi
        mov ecx, ITEMS_TXT_ADDR - 4
        call dword ptr ds:set_specitem_bonus
        mov eax, esi ; restore
        mov ecx, PARTY_BIN_ADDR ; replaced code
        ret
      }
}

// Initalise pickpocketed specitems, e.g. Lady Carmine's Dagger.
// Also initialise throwing knife charges.
static void __declspec(naked) pickpocket_specitem(void)
{
    asm
      {
        lea esi, [ebp-52] ; replaced code
        call init_knife_charges
        mov ebx, dword ptr [esi] ; restore
        push esi
        mov ecx, ITEMS_TXT_ADDR - 4
        call dword ptr ds:set_specitem_bonus
        mov ecx, 9 ; replaced code
        ret
      }
}

// Brand the title screen with current version of the mod.
static void __declspec(naked) print_version(void)
{
    asm
      {
        mov eax, dword ptr [esi+24] ; replaced code
        cmp eax, 1 ; if in main menu
        jne quit
        cmp dword ptr [CURRENT_SCREEN], 0
        jz version
        quit:
        cmp eax, 70 ; replaced code
        ret
        version:
        xor eax, eax
        push eax
        push eax
        push eax
        push dword ptr [new_strings+STR_VERSION*4]
        push eax
        push 450
        push 10
        mov edx, dword ptr [0x5c3488] ; font
        mov ecx, dword ptr [0x506dcc] ; dialog
        call dword ptr ds:print_string
        push 0x4160a3 ; next cycle
        ret 4
      }
}

// Allow replacing an offhand weapon with a spear (into main hand)
// if the spear skill is below Master,
// by treating it as a two-handed weapon.
static void __declspec(naked) th_spear(void)
{
    asm
      {
        cmp eax, MASTER
        jae quit
        mov dword ptr [ebp-12], 1 ; two-handed weapon
        quit:
        push 0x469062
        ret
      }
}

// Whether it makes sense to check a map for refill.
static int can_refill_map(int id)
{
    static int house; // the small house for assassination quests
    if (!house) house = get_map_index(MAPSTATS, "mdt15.blv") - 1;
    if (id == dword(CURRENT_MAP_ID) - 1
        || id == castle_id || id == bottle_id // never refilled
        || !MAPSTATS[id].refill_days // proving grounds/arena
        || !elemdata.next_refill_day[id]) // not visited yet
        return 0; // nothing to refill
    if (id == house && !check_bit(QBITS, QBIT_KILL_TOLBERTI)
                    && !check_bit(QBITS, QBIT_KILL_ROBERT)
        || MAPSTATS[id].reputation_group == 1
           && check_bit(QBITS, QBIT_LEFT_EMERALD_ISLAND))
        return -1; // no longer visitable
    return 1; // ok to check
}

// For the "winds of change" hireling hint text.
static char *map_refill_reply;

// Let's give some hirelings new abilities.
static int __thiscall new_hireling_action(int id)
{
    switch (id)
      {
        case NPC_PORTER:
            add_action(ACTION_THIS, ACTION_EXIT, 0, 0);
            add_action(ACTION_THIS, ACTION_EXTRA_CHEST, 1, 1);
            return TRUE;
        case NPC_QUARTER_MASTER:
            add_action(ACTION_THIS, ACTION_EXIT, 0, 0);
            add_action(ACTION_THIS, ACTION_EXTRA_CHEST, 2, 1);
            return TRUE;
        case NPC_GYPSY:
            add_action(ACTION_THIS, ACTION_EXIT, 0, 0);
            add_action(ACTION_THIS, ACTION_EXTRA_CHEST, 4, 1);
            return TRUE;
        case NPC_GUIDE:
        case NPC_TRACKER:
        case NPC_PATHFINDER:
        case NPC_SAILOR:
        case NPC_NAVIGATOR:
        case NPC_HORSEMAN:
        case NPC_EXPLORER:
        case NPC_PIRATE:
          {
            unsigned int day = CURRENT_TIME >> 13;
            day /= 256 * 60 * 24 >> 13; // avoid long division dependency
            int refilled = -1;
            for (int i = 0, c = 0; i < MAP_COUNT; i++)
              {
                if (can_refill_map(i) > 0
                    && elemdata.next_refill_day[i] <= day && !(random() % ++c))
                    refilled = i;
              }
            static char buffer[160];
            if (refilled >= 0)
              {
                sprintf(buffer, new_strings[STR_REFILLED_MAP],
                        MAPSTATS[refilled].name);
                map_refill_reply = buffer;
              }
            else map_refill_reply = new_strings[STR_NO_REFILL];
          }
            // fallthrough
        case NPC_COOK:
        case NPC_CHEF:
            byte(HIRELING_REPLY) = 2;
            dword(NPC_COMMAND) = 77; // enable reply code
            return TRUE;
        case NPC_NINJA:
            if (byte(STATE_BITS) & 0x30)
              {
                show_status_text(GLOBAL_TXT[638], 2); // "hostiles nearby"
                return TRUE;
              }
            aim_spell(SPL_INVISIBILITY, 0, SKILL_GM + 4, 32, 0); // one hour
            return FALSE;
        case NPC_ALCHEMIST:
          {
            // must cast from an active pc, otherwise glitches
            int player = dword(CURRENT_PLAYER);
            if (!player)
                for (player = 1; player <= 4; player++)
                    if (player_active(&PARTY[player-1]))
                        break;
            hireling_recharge = TRUE; // increased power and no pc recovery
            add_action(ACTION_THIS, ACTION_EXIT, 0, 0);
            add_action(ACTION_THIS, ACTION_SCROLL, SPL_RECHARGE_ITEM, player);
            return FALSE;
          }
        case NPC_BEACON_MASTER:
            set_npc_beacon(CURRENT_HIRELING);
            make_sound(SOUND_THIS, word(SPELL_SOUNDS + SPL_LLOYDS_BEACON * 2),
                       0, 0, -1, 0, 0, 0, 0);
            add_action(ACTION_THIS, ACTION_EXIT, 0, 0);
            return TRUE;

        default:
            return hireling_action(id);
      }
}

// Actually print the dialog option for new NPCs.
static void __declspec(naked) enable_new_hireling_action(void)
{
    asm
      {
        mov eax, dword ptr [ebp+24] ; replaced code
        cmp eax, NPC_PORTER
        je enable
        cmp eax, NPC_QUARTER_MASTER
        je enable
        cmp eax, NPC_GYPSY
        je enable
        cmp eax, NPC_NINJA
        je enable
        cmp eax, NPC_ALCHEMIST
        je enable
        cmp eax, NPC_BEACON_MASTER
        je enable
        cmp eax, NPC_GUIDE
        je enable
        cmp eax, NPC_TRACKER
        je enable
        cmp eax, NPC_PATHFINDER
        je enable
        cmp eax, NPC_SAILOR
        je enable
        cmp eax, NPC_NAVIGATOR
        je enable
        cmp eax, NPC_HORSEMAN
        je enable
        cmp eax, NPC_EXPLORER
        je enable
        cmp eax, NPC_PIRATE
        je enable
        cmp eax, 10 ; replaced code
        ret
        enable:
        xor eax, eax ; this will pass the checks
        ret
      }
}

// Also allow using the ability text string.
static void __declspec(naked) new_hireling_action_text(void)
{
    asm
      {
        jz quit ; replaced jump
        cmp ecx, 11 ; replaced code
        jz quit
        cmp ecx, NPC_PORTER
        jz quit
        cmp ecx, NPC_QUARTER_MASTER
        jz quit
        cmp ecx, NPC_GYPSY
        jz quit
        cmp ecx, NPC_NINJA
        jz quit
        cmp ecx, NPC_ALCHEMIST
        jz quit
        cmp ecx, NPC_BEACON_MASTER
        jz quit
        cmp ecx, NPC_GUIDE
        jz quit
        cmp ecx, NPC_TRACKER
        jz quit
        cmp ecx, NPC_PATHFINDER
        jz quit
        cmp ecx, NPC_SAILOR
        jz quit
        cmp ecx, NPC_NAVIGATOR
        jz quit
        cmp ecx, NPC_HORSEMAN
        jz quit
        cmp ecx, NPC_EXPLORER
        jz quit
        cmp ecx, NPC_PIRATE
        quit:
        ret
      }
}

// When firing an NPC, remove everything from their bags.
static void __thiscall empty_extra_chest(int id)
{
    if (id == replaced_chest)
        replace_chest(-1); // sync chest data
    struct map_chest *chest = elemdata.extra_chests + id;
    for (int i = 0; i < 9 * 9; i++)
      {
        int item = chest->slots[i] - 1;
        if (item >= 0)
            add_mouse_item(PARTY_BIN, chest->items + item);
      }
    memset(chest->items, 0, sizeof(chest->items));
    memset(chest->slots, 0, sizeof(chest->slots));
}

// Now the dismiss hireling option must be pressed twice.
static int confirm_hireling_dismiss = 0;

// Hook for the above.  Also here: show hireling dismiss reply on firing them.
static void __declspec(naked) empty_extra_chest_hook(void)
{
    asm
      {
        cmp dword ptr [confirm_hireling_dismiss], 0
        jnz ok
        inc dword ptr [confirm_hireling_dismiss]
        mov ecx, dword ptr [new_strings+STR_CONFIRM_DISMISS*4]
        mov dword ptr [NPC_COMMAND], 77 ; enable reply
        mov byte ptr [HIRELING_REPLY], 0 ; choose reply
        mov dword ptr [esp], 0x4bc6f0 ; show statusline text
        ret
        ok:
        mov eax, dword ptr [HIRED_NPC_1].s_npc.profession
        cmp eax, dword ptr [HIRED_NPC_2].s_npc.profession
        je skip ; if another porter etc. remains, do not empty
        cmp dword ptr [ebp+24], NPC_PORTER
        jne not_porter
        mov ecx, 1
        call empty_extra_chest
        not_porter:
        cmp dword ptr [ebp+24], NPC_QUARTER_MASTER
        jne not_qm
        mov ecx, 2
        call empty_extra_chest
        mov ecx, 3
        call empty_extra_chest
        not_qm:
        cmp dword ptr [ebp+24], NPC_GYPSY
        jne skip
        mov ecx, 4
        call empty_extra_chest
        skip:
        cmp dword ptr [NPCS_LENGTH], edi ; replaced code
        ret
      }
}

// Add a second action dialog option for quartermasters.
// Also for beacon masters, but only if they can still cast.
static void __declspec(naked) quartermaster_extra_dialog(void)
{
    asm
      {
        mov edx, 10 ; right bag subaction
        cmp dword ptr [ebp+24], NPC_QUARTER_MASTER
        je ok
        cmp dword ptr [ebp+24], NPC_BEACON_MASTER
        jne skip
        cmp dword ptr [ebp+68], ebx ; used ability flag
        jnz skip
        inc edx ; recall beacon subaction
        ok:
        mov eax, dword ptr [ARRUS_FNT]
        movzx eax, byte ptr [eax+5]
        add eax, 140 - 3
        push ebx
        push esi
        push ebx
        push edx ; our new subactions
        push 136 ; interact with npc action
        push ebx
        push 1
        push eax
        push 140
        push 250
        push edi
        push ecx
        call dword ptr ds:add_button
        add esp, 48
        mov ecx, dword ptr [DIALOG1] ; restore
        inc dword ptr [esp+4] ; one more dialog line
        skip:
        push 0x41d038 ; replaced call
        ret
      }
}

// Supply actual text to the new dialog options.
static void __declspec(naked) quartermaster_extra_dialog_text(void)
{
    asm
      {
        mov eax, dword ptr [edi+36] ; replaced text
        cmp eax, 10 ; right bag subaction
        je qm
        cmp eax, 11 ; recall beacon subaction
        je beacon
        cmp eax, 24 ; replaced text
        ret
        qm:
        mov eax, dword ptr [new_strings+STR_OPEN_RIGHT_BAG*4]
        jmp quit
        beacon:
        mov eax, dword ptr [GLOBAL_TXT_ADDR+523*4] ; "recall beacon"
        quit:
        mov dword ptr [esp], 0x44581d ; code after fetching a string
        ret
      }
}

// Code for moving between maps using the beacon master NPC ability.
static void recall_npc_beacon(void)
{
    struct beacon *beacon = elemdata.beacon_masters + CURRENT_HIRELING;
    if (beacon->map_index + 1 == dword(CURRENT_MAP_ID))
      {
        memcpy((void *) PARTY_X, beacon, 4 * 5);
        dword(0xacd538) = beacon->z; // smth flight-related
      }
    else
      {
        memcpy((void *) 0x5b6428, beacon, 4 * 5); // movemap coords
        dword(0x5b6440) = TRUE; // respect the coords
        dword(MOVEMAP_STYLE) = 0; // small progress box to avoid glitches
        on_map_leave();
        change_map(MAPSTATS[beacon->map_index].file_name, 0);
      }
    make_sound(SOUND_THIS, word(SPELL_SOUNDS + SPL_LLOYDS_BEACON * 2),
               0, 0, -1, 0, 0, 0, 0);
    beacon_recall_effects(NULL);
}

// Actually open the second bag (or recall a beacon).
static void __declspec(naked) quartermaster_extra_action(void)
{
    asm
      {
        cmp eax, 10 ; right bag subaction
        je right_bag
        cmp eax, 11 ; recall beacon subaction
        je beacon
        mov ecx, eax ; replaced code
        sub ecx, 9 ; replaced code
        ret
        right_bag:
        push 0
        push 0
        push ACTION_EXIT
        mov ecx, ACTION_THIS_ADDR
        call dword ptr ds:add_action
        push 1
        push 3
        push ACTION_EXTRA_CHEST
        mov ecx, ACTION_THIS_ADDR
        call dword ptr ds:add_action
        xor ecx, ecx
        inc ecx ; this will skip the vanilla code
        ret
        beacon:
        mov dword ptr [esp], 0x4bc4e2 ; to used npc ability code
        jmp recall_npc_beacon
      }
}

// Let Intellect and Gadgeteer's Belt affect wand power.
static void __declspec(naked) variable_wand_power(void)
{
    asm
      {
        push ecx
        mov ecx, esi
        push SLOT_BELT
        push GADGETEERS_BELT
        call dword ptr ds:has_item_in_slot
        test eax, eax
        jz no_belt
        add dword ptr [esp+8], SKILL_GM + 5 ; spell skill
        mov al, byte ptr [esi].s_player.class
        and al, -4
        cmp al, CLASS_THIEF
        jne no_belt
        add dword ptr [esp+8], 5 ; extra bonus
        no_belt:
        mov ecx, esi
        call dword ptr ds:get_intellect
        push eax
        call dword ptr ds:get_effective_stat
        sar eax, 1
        sub eax, 3 ; equal to vanilla at 30 Int
        add dword ptr [esp+8], eax
        pop ecx
        lea edx, [ebx-1]
        jmp dword ptr ds:aim_spell ; replaced call
      }
}

// Let Personality affect merchant prices.
static void __declspec(naked) personality_trading_bonus(void)
{
    asm
      {
        mov ecx, edi
        call dword ptr ds:get_personality
        push eax
        call dword ptr ds:get_effective_stat
        mov edi, eax
        call dword ptr ds:get_eff_reputation ; replaced call
        sub eax, edi
        mov edi, ebx ; moved here from earlier
        and edi, SKILL_MASK; ditto
        ret
      }
}

// When using a recharge spell/potion, degrade
// a portion of spent charges rather than of total charges.
static void __declspec(naked) recharge_spent_charges_sub_spell(void)
{
    asm
      {
        sub eax, dword ptr [ecx].s_item.charges ; discount remaining ones
        mov dword ptr [ebp-20], eax ; replaced code
        fild dword ptr [ebp-20] ; replaced code
        ret
      }
}

// Second part of above.
static void __declspec(naked) recharge_spent_charges_add_spell(void)
{
    asm
      {
        movzx eax, al ; replaced code
        add eax, dword ptr [ecx].s_item.charges
        mov byte ptr [ecx].s_item.max_charges, al ; replaced code
        ret
      }
}

// Ditto, but for the recharge potion.
static void __declspec(naked) recharge_spent_charges_sub_potion(void)
{
    asm
      {
        sub eax, dword ptr [esi].s_item.charges ; discount remaining ones
        mov dword ptr [ebp-20], eax ; replaced code
        fild dword ptr [ebp-20] ; replaced code
        ret
      }
}

// Second part of above.  Also here: do not lower max charges below 1.
static void __declspec(naked) recharge_spent_charges_add_potion(void)
{
    asm
      {
        movzx eax, al ; replaced code
        add eax, dword ptr [esi].s_item.charges
        jle min
        mov byte ptr [esi].s_item.max_charges, al ; replaced code
        ret
        min:
        mov byte ptr [esi].s_item.max_charges, 1
        ret
      }
}

// Instead of monsters always attacking their preferred targets,
// use a weighted random that considers preferences and aggro effects.
static int weighted_monster_preference(struct map_monster *monster, int mask)
{
    int preference = monster->preference;
    int weights[4];
    for (int i = 0; i < 4; i++)
      {
        if (!(mask & 1 << i))
          {
            weights[i] = 0;
            continue;
          }
        struct player *player = PARTY + i;
        weights[i] = 1;
        for (int slot = 0; slot < SLOT_COUNT; slot++)
          {
            int equipment = player->equipment[slot];
            if (!equipment)
                continue;
            struct item *item = &player->items[equipment-1];
            if ((item->bonus2 == SPC_TAUNTING || item->bonus2 == SPC_JESTER
                 || item->id == GIBBET) && !(item->flags & IFLAGS_BROKEN))
              {
                weights[i]++;
                if (ITEMS_TXT[item->id].equip_stat + 1 == ITEM_TYPE_SHIELD
                    && player->skills[SKILL_SHIELD] >= SKILL_MASTER)
                    weights[i]++; // double bonus
              }
          }
        weights[i] += elemdata.new_pc_buffs[i][NBUFF_AURA_OF_CONFLICT].power;
        if (monster->spell_buffs[MBUFF_BERSERK].expire_time)
            continue; // too angry to tell pcs apart
        if (has_item_in_slot(player, SHADOWS_MASK, SLOT_HELM))
            continue; // race/class/gender hidden
        static const int class_pref[9] = { 0x1, 0x80, 0x100, 0x2, 0x4,
                                           0x40, 0x10, 0x8, 0x20 };
        if (preference & class_pref[player->class/4])
            weights[i] += 3;
        static const int race_pref[4] = { 0x800, 0x1000, 0x4000, 0x2000 };
        if (preference & 0x7800 && preference & race_pref[get_race(player)])
            weights[i] += 2;
        if (preference & (player->gender ? 0x400 : 0x200))
            weights[i] += 1;
      }
    int sum = weights[0] + weights[1] + weights[2] + weights[3];
    if (!sum)
        return random() & 3;
    int roll = random() % sum;
    for (int i = 0; i < 3; i++)
      {
        roll -= weights[i];
        if (roll < 0)
            return i;
      }
    return 3;
}

// Use the above logic for a vanilla monster attack.
static int __stdcall monster_chooses_player(void *monster)
{
    int mask = 0;
    for (int i = 0; i < 4; i++)
      {
        struct player *player = PARTY + i;
        if (player->conditions[COND_PARALYZED]
            || player->conditions[COND_UNCONSCIOUS]
            || player->conditions[COND_DEAD] || player->conditions[COND_STONED]
            || player->conditions[COND_ERADICATED])
            continue;
        mask |= 1 << i;
      }
    return weighted_monster_preference(monster, mask);
}

// Allow monsters to attack their non-default enemies on sight.
// Necessary for the ring of aggravate monster encounter.
static void __declspec(naked) better_monster_hostility_chunk(void)
{
    asm
      {
        lea edx, [MAP_MONSTERS_ADDR+eax]
        mov ecx, ebx
        call dword ptr ds:is_hostile_to
        nop ; just in case
      }
}

// Buffs granted by resting in taverns.  Thematically chosen.
static const short tavern_buffs[14][15] = {
    //  Mig Int Per End Acc Spe Luc Arm Lev Fir Sho Col Poi Min Mag
      {  0,  0,  0,  0,  0,  0, 10,  0,  0, 20,  0,  0,  0,  0,  0 }, // Emera
      {  0,  0,  0, 20,  0,  0,  0, 10,  0,  0,  0,  0,  0,  0,  0 }, // Harmo
      { 20,  0, 20,  0,  0,  0,  0,  5,  0,  0,  0,  0,  0,  0,  0 }, // Erath
      {  0, 20,  0,  0, 20,  0,  0,  0,  0,  0,  0,  0, 10,  0,  0 }, // Tular
      {  0,  0,  0, 20,  0, 20,  0, 10,  0,  0,  0,  0,  0,  0, 20 }, // Deyja
      {  0, 10, 10,  0,  0,  0, 20,  0,  0,  0,  0,  0, 10, 10, 10 }, // Braca
      {  0,  0, 30, 30, 30,  0, 10, 20,  5, 40,  0,  0, 40, 40,  0 }, // Celes
      { 30, 30,  0,  0,  0, 30, 30, 10,  5,  0, 40, 40,  0,  0, 40 }, // T.Pit
      {  0,  0,  0,  0,  0,  0,  0, 10,  0,  0,  0,  0,  0, 20, 20 }, // Evenm
      { 15, 30, 30, 15, 15, 15, 15, 10,  5, 20, 20, 20, 20, 20, 20 }, // Nigho
      { 10, 10, 10, 20,  0,  0,  0,  0,  0,  0,  0,  0,  0, 20, 20 }, // Barro
      { 20,  0,  0, 20, 20, 20,  0, 20,  0,  0,  0, 10,  0,  0,  0 }, // Tatal
      {  0, 20,  0,  0, 20,  0, 10,  0,  0, 10, 20, 20, 10,  0,  0 }, // Avlee
      { 20,  0,  0, 10, 10, 10, 10, 10,  0, 20,  0,  0, 20,  0,  0 }, // Stone
};
// Buffs by the cook and/or chef NPCs.  Each is picked with a 20% chance.
static const short cook_chef_buffs[15][15] = {
    //  Mig Int Per End Acc Spe Luc Arm Lev Fir Sho Col Poi Min Mag
      {  0,  0, 20,  0,  0,  0, 20,  0,  0,  0,  0,  0,  0,  0,  0 }, // cook
      {  0,  0,  0, 20,  0,  0,  0,  0,  0,  0,  0,  0, 20,  0,  0 },
      {  0, 20,  0,  0, 20,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
      {  0,  0,  0,  0,  0, 20,  0,  0,  0,  0, 20,  0,  0,  0,  0 },
      { 20,  0,  0,  0,  0,  0,  0,  0,  0, 20,  0,  0,  0,  0,  0 },
      {  0,  0,  0, 10,  0, 30,  0, 10,  0, 30,  0,  0,  0,  0,  0 }, // chef
      {  0, 20,  0,  0, 30,  0,  0,  0,  0,  0,  0, 30,  0,  0,  0 },
      {  0, 30, 20,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 30,  0 },
      { 25,  0,  0, 25,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 25 },
      {  0,  0,  0,  0,  0,  0, 20, 20,  0,  0, 20,  0, 20,  0,  0 },
      { 10, 10, 10, 10, 10, 10, 10, 10,  3,  0,  0,  0,  0,  0,  0 }, // both
      { 20,  0,  0, 20,  0,  0,  0, 20,  0, 30, 30, 30,  0,  0,  0 },
      {  0, 30, 30,  0,  0,  0, 30,  0,  0,  0,  0,  0,  0, 30, 30 },
      {  0,  0,  0,  0, 40, 40,  0, 40,  0,  0,  0,  0, 40,  0,  0 },
      {  0,  0,  0,  0,  0,  0, 20,  0,  0, 20, 20, 20, 20, 20, 20 },
};
// In lieu of a passed parameter.
static int tavern_buff_ptr = -1;

// Let resting at taverns or with cooks buff stats, a la MMX "well rested".
static void __declspec(naked) tavern_rest_buff(void)
{
    asm
      {
        cmp dword ptr [esp+44], 409 ; tavern rest action
        jne not_tavern
        mov edx, dword ptr [esp+24] ; tavern id
        sub edx, 107 ; first tavern
        lea edx, [edx+edx*2]
        lea edx, [edx+edx*4]
        add edx, edx
        add edx, offset tavern_buffs
        mov dword ptr [tavern_buff_ptr], edx
        xor edx, edx
        jmp dish
        not_tavern:
        cmp dword ptr [esp+44], 97 ; ordinary rest
        jne skip
        mov ecx, NPC_CHEF
        call dword ptr ds:have_npc_hired
        lea ebx, [eax+eax]
        mov ecx, NPC_COOK
        call dword ptr ds:have_npc_hired
        add ebx, eax
        jz restore
        call dword ptr ds:random
        xor edx, edx
        mov ecx, 5
        div ecx
        dec ebx
        mov ecx, ebx
        shr ecx, 1
        lea ebx, [ebx+ebx*4]
        add ebx, edx
        lea ebx, [ebx+ebx*2]
        lea ebx, [ebx+ebx*4]
        add ebx, ebx
        add ebx, offset cook_chef_buffs
        mov dword ptr [tavern_buff_ptr], ebx
        xor ebx, ebx
        lea ecx, [ecx+ecx*4]
        inc edx
        add edx, ecx
        dish:
        cmp dword ptr [HIRED_NPC_1].s_npc.profession, NPC_COOK
        je left
        cmp dword ptr [HIRED_NPC_1].s_npc.profession, NPC_CHEF
        jne not_left
        left:
        mov dword ptr [HIRED_NPC_1].s_npc.used_ability, edx
        not_left:
        cmp dword ptr [HIRED_NPC_2].s_npc.profession, NPC_COOK
        je right
        cmp dword ptr [HIRED_NPC_2].s_npc.profession, NPC_CHEF
        jne restore
        right:
        mov dword ptr [HIRED_NPC_2].s_npc.used_ability, edx
        restore:
        mov ecx, PARTY_BIN_ADDR
        skip:
        call dword ptr ds:rest_party ; replaced call
        mov dword ptr [tavern_buff_ptr], -1 ; restore
        ret
      }
}

// Actually apply the buff.  This needs to be between stat and HP/SP reset.
static void __declspec(naked) tavern_buff_on_rest(void)
{
    asm
      {
        mov edx, dword ptr [tavern_buff_ptr]
        test edx, edx
        js skip
        mov ax, word ptr [edx]
        mov word ptr [esi+S_PL_STATS+2], ax
        mov ax, word ptr [edx+2]
        mov word ptr [esi+S_PL_STATS+6], ax
        mov ax, word ptr [edx+4]
        mov word ptr [esi+S_PL_STATS+10], ax
        mov ax, word ptr [edx+6]
        mov word ptr [esi+S_PL_STATS+14], ax
        mov ax, word ptr [edx+8]
        mov word ptr [esi+S_PL_STATS+22], ax
        mov ax, word ptr [edx+10]
        mov word ptr [esi+S_PL_STATS+18], ax
        mov ax, word ptr [edx+12]
        mov word ptr [esi+S_PL_STATS+26], ax
        mov ax, word ptr [edx+14]
        mov word ptr [esi].s_player.ac_bonus, ax
        mov ax, word ptr [edx+16]
        mov word ptr [esi].s_player.level_bonus, ax
        mov ax, word ptr [edx+18]
        mov word ptr [esi].s_player.fire_res_bonus, ax
        mov ax, word ptr [edx+20]
        mov word ptr [esi].s_player.shock_res_bonus, ax
        mov ax, word ptr [edx+22]
        mov word ptr [esi].s_player.cold_res_bonus, ax
        mov ax, word ptr [edx+24]
        mov word ptr [esi].s_player.poison_res_bonus, ax
        mov ax, word ptr [edx+26]
        mov word ptr [esi].s_player.mind_res_bonus, ax
        mov ax, word ptr [edx+28]
        mov word ptr [esi].s_player.magic_res_bonus, ax
        skip:
        mov ecx, esi ; replaced code
        mov dword ptr [esi+COND_UNCONSCIOUS*8], edi ; replaced code
        ret
      }
}

// Only disable cooks' dialogue if their buff is to expire (3 days awake).
static void __declspec(naked) dont_reset_cooks(void)
{
    asm
      {
        cmp byte ptr [0xacd59c], 3 ; days awake
        jae left
        cmp dword ptr [HIRED_NPC_1].s_npc.profession, NPC_COOK
        je skip_left
        cmp dword ptr [HIRED_NPC_1].s_npc.profession, NPC_CHEF
        je skip_left
        left:
        mov dword ptr [HIRED_NPC_1].s_npc.used_ability, edx ; replaced code
        cmp byte ptr [0xacd59c], 3
        jae right
        skip_left:
        cmp dword ptr [HIRED_NPC_2].s_npc.profession, NPC_COOK
        je skip_right
        cmp dword ptr [HIRED_NPC_2].s_npc.profession, NPC_CHEF
        je skip_right
        right:
        mov dword ptr [HIRED_NPC_2].s_npc.used_ability, edx ; replaced code
        skip_right:
        cmp dword ptr [NPCS_LENGTH], edx ; replaced code
        ret
      }
}

// For cooks and chefs, show the ability line only if the used field is NOT 0.
// For beacon masters, just always show the first (unlimited) ability.
static void __declspec(naked) invert_cook_check(void)
{
    asm
      {
        jz skip ; replaced jump
        cmp dword ptr [ebp+24], NPC_BEACON_MASTER
        je ok
        cmp dword ptr [ebp+24], NPC_COOK
        je invert
        cmp dword ptr [ebp+24], NPC_CHEF
        je invert
        cmp dword ptr [ebp+68], ebx ; replaced code
        ret
        invert:
        cmp dword ptr [ebp+68], ebx ; used ability flag
        jz skip
        ok:
        xor eax, eax ; set zf
        ret
        skip:
        test ebp, ebp ; clear zf
        ret
      }
}

// Now that the reply flag can be 2, we can't just xor it.
static void __declspec(naked) toggle_cook_reply(void)
{
    asm
      {
        cmp byte ptr [HIRELING_REPLY], bl ; == 1
        setne dl
        mov byte ptr [HIRELING_REPLY], dl
        ret
      }
}

// Storage for the new NPC text entries.
static char *new_npc_text[NEW_TEXT_COUNT];

// Print the decription for the applied buff, or a refilled map name.
static void __declspec(naked) print_cook_reply(void)
{
    asm
      {
        mov ecx, dword ptr [npcprof+eax*4+4] ; replaced code, almost
        cmp byte ptr [HIRELING_REPLY], 2
        jne quit
        cmp eax, NPC_GUIDE * 5
        je refill
        cmp eax, NPC_TRACKER * 5
        je refill
        cmp eax, NPC_PATHFINDER * 5
        je refill
        cmp eax, NPC_SAILOR * 5
        je refill
        cmp eax, NPC_NAVIGATOR * 5
        je refill
        cmp eax, NPC_HORSEMAN * 5
        je refill
        cmp eax, NPC_EXPLORER * 5
        je refill
        cmp eax, NPC_PIRATE * 5
        je refill
        sub eax, NPC_COOK * 5
        jz cook
        cmp eax, 5 ; chef is next
        jne quit
        cook:
        add eax, eax
        add eax, dword ptr [ebx+68] ; ability/dish flag
        mov ecx, dword ptr [new_npc_text+810*4-790*4+eax*4] ; decriptions
        quit:
        ret
        refill:
        mov ecx, dword ptr [map_refill_reply]
        ret
      }
}

// Make training sessions always last 8 days, like in MM6.
static void __declspec(naked) reduce_training_time(void)
{
    asm
      {
        cmp ecx, 1
        jb skip
        xor ecx, ecx
        dec ecx
        shr ecx, 1
        skip:
        mov eax, dword ptr [CURRENT_PLAYER] ; replaced code
        ret
      }
}

// After level 20, training cost grows as level squared, just like XP delta.
static void __declspec(naked) increase_training_price(void)
{
    asm
      {
        movzx eax, word ptr [ebx].s_player.level_base
        cmp eax, 20
        jbe skip
        mov dword ptr [ebp-20], eax ; unused at this point
        fimul dword ptr [ebp-20]
        mov dword ptr [ebp-20], 20
        fidiv dword ptr [ebp-20]
        skip:
        jmp dword ptr ds:ftol ; replaced call
      }
}

// Used below and also in id_monster_master().
static const int const_ten = 10;

// Let temple heal price depend on PC level.
static void __declspec(naked) temple_heal_price(void)
{
    asm
      {
        cmp word ptr [edi].s_player.level_base, 10
        jbe skip
        fild word ptr [edi].s_player.level_base
        fidiv dword ptr [const_ten]
        fmul st(0), st(0)
        fmulp
        skip:
        jmp dword ptr ds:ftol ; replaced call
      }
}

// Multiply Arena money reward by 3.
// Also, reduce the reward proportionately when below level 30.
static void __declspec(naked) increase_arena_reward(void)
{
    asm
      {
        lea eax, [eax+eax*2]
        lea ecx, [ebx+30] ; ebx == 0
        cmp dword ptr [ebp-12], ecx
        jae ok
        mul dword ptr [ebp-12]
        div ecx
        ok:
        mov dword ptr [NEW_SKILL_COST], eax ; replaced code
        ret
      }
}

// For Harmondale town hall, add an option to collect taxes.
static void __declspec(naked) add_tax_reply(void)
{
    asm
      {
        cmp dword ptr [0xae3060], 0 ; replaced code
        jz no_fine
        mov edx, 100 ; fine payment reply
        mov ecx, esi
        inc esi
        call dword ptr ds:add_reply
        no_fine:
        mov ecx, dword ptr [DIALOG2]
        cmp dword ptr [ecx+28], 102 ; harmondale townhall id
        jne skip
        mov edx, 101 ; hitherto unused
        mov ecx, esi
        inc esi
        call dword ptr ds:add_reply
        skip:
        xor eax, eax ; set zf
        ret
      }
}

// Actually print the taxes reply.
static void __declspec(naked) print_tax_reply(void)
{
    asm
      {
        mov ecx, dword ptr [DIALOG2]
        cmp dword ptr [ecx+28], 102 ; harmondale townhall id
        jne skip
        mov eax, dword ptr [new_strings+STR_TAXES*4]
        mov dword ptr [0xf8b038+ebx*4], eax ; replies array
        inc ebx
        skip:
        xor esi, esi ; replaced code
        ret
      }
}

// Used below.
static char tax_text[500];
static int in_tax_dialog;

// Generate the tax status reply (and perhaps add tax money to bank).
static void generate_tax_text(void)
{
    int month = (dword(0xacd544) - 1168) * 12 + dword(0xacd548) + 1;
    int fame = get_fame(PARTY_BIN);
    if (!elemdata.last_tax_month) // first time ever
      {
        elemdata.last_tax_month = month;
        strcpy(tax_text, new_npc_text[835-790]);
        return;
      }
    if (elemdata.last_tax_month == month || elemdata.last_tax_fame == fame)
      {
        strcpy(tax_text, new_npc_text[836-790]);
        return;
      }
    elemdata.last_tax_month = month;
    int attitude = 0;
    int reputation = CURRENT_REP;
    if (reputation >= 25)
        attitude = -2;
    else if (reputation > 5)
        attitude = -1;
    else if (reputation <= -25)
        attitude = 2;
    else if (reputation < -5)
        attitude = 1;
    int fealty = 0;
    if (check_bit(QBITS, QBIT_ELVES_WON))
        fealty = 1;
    else if (check_bit(QBITS, QBIT_HARMONDALE_INDEPENDENT))
        fealty = 2;
    int tax_money = (fame - elemdata.last_tax_fame) * 5;
    elemdata.last_tax_fame = fame;
    if (fealty == 2)
        tax_money *= 2;
    if (elemdata.difficulty == 2)
        tax_money /= 2;
    else if (elemdata.difficulty == 1)
        tax_money -= tax_money / 4;
    if (reputation > 0)
        tax_money = tax_money * 10 / (10 + reputation);
    else if (reputation < 0)
        tax_money += tax_money * -reputation / 20;
    char buffer[200];
    sprintf(buffer, new_npc_text[843+fealty-790], tax_money);
    sprintf(tax_text, "%s  %s  %s  %s", new_npc_text[837-790],
            new_npc_text[840+attitude-790], buffer, new_npc_text[846-790]);
    dword(BANK_GOLD) += tax_money;
}

// Print the tax status reply (called each tick).
static void __declspec(naked) tax_dialog(void)
{
    asm
      {
        mov eax, dword ptr [CURRENT_CONVERSATION] ; replaced code
        cmp eax, 1 ; main dialog
        jne no_reset
        and dword ptr [in_tax_dialog], 0
        no_reset:
        cmp eax, 101 ; our reply
        jne quit
        cmp dword ptr [in_tax_dialog], 0
        jnz repeat
        call generate_tax_text
        inc dword ptr [in_tax_dialog]
        repeat:
        mov ebx, offset tax_text
        mov esi, dword ptr [DIALOG1] ; skipped instruction
        mov dword ptr [esp], 0x4b7acb ; print dialog code
        quit:
        ret
      }
}

// Do not allow flight above max altitude or in turn-based mode,
// except in movement phase wherein it'll consume one step.
static void __declspec(naked) restrict_flying_up(void)
{
    asm
      {
        jge disable ; if too high
        cmp dword ptr [TURN_BASED], ecx ; == 0
        jz ok
        cmp dword ptr [0x4f86dc], 3 ; TB phase
        jne fail
        cmp dword ptr [0x4f86ec], ecx ; remaining movement
        jle fail
        sub dword ptr [0x4f86ec], 26 ; one step
        ok:
        test ebp, ebp ; clear zf
        ret
        disable:
        cmp dword ptr [ebp-76], ecx ; replaced code
        jnz fail
        mov dword ptr [FLYING], ecx
        fail:
        test ecx, ecx ; set zf
        ret
      }
}

// Same for flying down.
static void __declspec(naked) restrict_flying_down(void)
{
    asm
      {
        cmp dword ptr [PARTY_Z], 4000
        jl low
        cmp dword ptr [FLYING], ecx ; == 0
        jz fail
        low:
        cmp dword ptr [TURN_BASED], ecx
        jz ok
        cmp dword ptr [0x4f86dc], 3 ; TB phase
        jne fail
        cmp dword ptr [0x4f86ec], ecx ; remaining movement
        jle fail
        sub dword ptr [0x4f86ec], 26 ; one step
        ok:
        sub dword ptr [ebp-32], 30 ; replaced code
        sub dword ptr [ebp-72], 30 ; ditto
        ret
        fail:
        mov dword ptr [esp], 0x4742ce ; no action
        ret
      }
}

// Turning off flight instead consumes the entire move for the turn.
static void __declspec(naked) restrict_free_fall(void)
{
    asm
      {
        cmp dword ptr [FLYING], eax ; replaced code
        jz quit
        cmp dword ptr [TURN_BASED], eax ; == 0
        jz ok
        cmp dword ptr [0x4f86dc], 3 ; TB phase
        jne fail
        cmp dword ptr [0x4f86ec], 130 ; remaining movement
        jl fail
        mov dword ptr [0x4f86ec], eax ; consume all of it
        ok:
        test ebp, ebp ; clear zf
        quit:
        ret
        fail:
        mov dword ptr [esp], 0x4742ce ; no action
        ret
      }
}

// Disable flight conditionally instead of enabling it conditionally later.
static void __declspec(naked) disable_flight(void)
{
    asm
      {
        cmp dword ptr [PARTY_ADDR+eax-SIZE_PLAYER].s_player.sp, ecx ; replaced
        jg skip
        mov dword ptr [FLYING], ecx ; == 0
        skip:
        ret
      }
}

// Cap vampiric weapon heal at 20% of monster's remaining HP.
static void __declspec(naked) vampiric_cap(void)
{
    asm
      {
        mov eax, dword ptr [ebp-20] ; damage dealt
        cmp eax, dword ptr [old_monster_hp]
        cmovg eax, dword ptr [old_monster_hp]
        ret
      }
}

// Prevent berserked monsters (except peasants) from fleeing due to low HP.
static void __declspec(naked) berserk_no_run_away(void)
{
    asm
      {
        movzx eax, byte ptr [ebx].s_map_monster.ai_type ; replaced code
        dec eax ; ditto
        jz quit
        cmp dword ptr [ebx+MBUFF_BERSERK*SIZE_BUFF] \
                      .s_map_monster.spell_buffs, 0
        jnz berserk
        cmp dword ptr [ebx+MBUFF_BERSERK*SIZE_BUFF+4] \
                      .s_map_monster.spell_buffs, 0
        jz skip
        berserk:
        xor eax, eax ; suicidal
        dec eax
        quit:
        ret
        skip:
        test eax, eax ; clear zf
        ret
      }
}

// Some areas have 0/0 charge wands on the ground.  Charge these wands.
// NB: this will run on every map reload, but normal wands can't get to 0/0.
static void __declspec(naked) charge_zero_wands(void)
{
    asm
      {
        cmp byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.equip_stat, \
            ITEM_TYPE_WAND - 1
        je wand
        cmp byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.equip_stat, \
            ITEM_TYPE_POTION - 1 ; replaced code
        ret
        wand:
        cmp eax, DRAGONS_WRATH * SIZE_ITEM_TXT ; inited separately, a bit later
        je skip
        cmp byte ptr [edi].s_item.max_charges, 0
        jnz quit
        mov al, byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.mod2 ; max chrgs
        inc al
        mov byte ptr [edi].s_item.max_charges, al
        call dword ptr ds:random
        mov ecx, 6
        xor edx, edx
        div ecx
        add byte ptr [edi].s_item.max_charges, dl ; + 0 to 5
        call dword ptr ds:random
        movzx ecx, byte ptr [edi].s_item.max_charges
        mov dword ptr [edi].s_item.charges, ecx
        xor edx, edx
        shr ecx, 1 ; preused up to 50%
        div ecx
        inc edx
        sub dword ptr [edi].s_item.charges, edx
        skip:
        test edi, edi ; clear zf
        quit:
        ret
      }
}

// Temporary age was colored green, even though it's bad.
// Redo this so that a small aging is yellow, and 50+ is red.
static void __declspec(naked) age_color(void)
{
    asm
      {
        cmp ecx, edx
        jb green ; hypothetical
        je white
        cmp ecx, 50
        jb yellow
        mov eax, dword ptr [colors+CLR_RED*4]
        ret
        yellow:
        mov eax, dword ptr [colors+CLR_PALE_YELLOW*4]
        ret
        green:
        mov eax, dword ptr [colors+CLR_GREEN*4]
        ret
        white:
        xor eax, eax
        ret
      }
}

// Liches should never get stat penalties for old age.
static void __declspec(naked) lich_physical_age(void)
{
    asm
      {
        cmp byte ptr [esi].s_player.class, CLASS_LICH
        je lich
        movsx ecx, word ptr [esi].s_player.age_bonus ; replaced code
        ret
        lich:
        mov eax, 25 ; young age
        xor ecx, ecx
        ret
      }
}

// And for mental stats, they get the bonus at 50+, and it stays.
static void __declspec(naked) lich_mental_age(void)
{
    asm
      {
        movsx ecx, word ptr [esi].s_player.age_bonus ; replaced code
        add eax, ecx ; replaced code
        cmp byte ptr [esi].s_player.class, CLASS_LICH
        je lich
        ret
        lich:
        mov ecx, 50 ; no more than this
        cmp eax, ecx
        cmova eax, ecx
        ret
      }
}

// Do not make the PC smile when subtracting a QBit that was unset or hidden.
// Also here: stop tracking quest items when their bit is unset.
static void __declspec(naked) check_subtracted_qbit(void)
{
    asm
      {
        call dword ptr ds:check_bit
        mov edx, dword ptr [ebp+12] ; the bit
        test eax, eax
        jz skip
        cmp dword ptr [0x722d90+edx*4], ebx ; quest log msg?
        jnz ok
        skip:
        add dword ptr [esp], 15 ; skip the smile
        ok:
        mov ecx, LOST_QBIT_COUNT
        loop:
        cmp dx, word ptr [LOST_QBITS+ecx*4-4]
        loopne loop
        cmove cx, word ptr [LOST_QBITS+ecx*4+2]
        test ecx, ecx
        jz quit
        mov byte ptr [elemdata.lost_items+ecx-FIRST_LOST_ITEM], LOST_NOTRACK
        quit:
        mov ecx, QBITS_ADDR ; restore
        jmp dword ptr ds:change_bit ; replaced call
      }
}

// A small fix: reset the 'more information' hireling flag on dialog exit.
// Also here: reset the var that delays the 'dismiss' reply until it's clicked.
static void __declspec(naked) reset_hireling_reply(void)
{
    asm
      {
        mov dword ptr [DIALOG_NPC], ecx ; replaced code
        mov byte ptr [HIRELING_REPLY], bl ; ebx == 0
        mov dword ptr [confirm_hireling_dismiss], ebx
        ret
      }
}

// ID Item and ID Monster were both shortened to "Identify" as optional picks
// in the new game screen.  Let's give them distinguishable, but short, names.
static void __declspec(naked) short_id_skill_names(void)
{
    asm
      {
        cmp edi, SKILL_IDENTIFY_ITEM
        je id_item
        cmp edi, SKILL_IDENTIFY_MONSTER
        je id_monster
        mov eax, 0x4caff0 ; replaced call
        jmp eax
        id_item:
        push dword ptr [new_strings+STR_ID_ITEM*4]
        jmp replace
        id_monster:
        push dword ptr [new_strings+STR_ID_MONSTER*4]
        replace:
        push eax
        call dword ptr ds:strcpy_ptr
        add esp, 8
        xor eax, eax ; skip the space cutoff
        ret
      }
}

// Do not use the discount merchant dialog line if the discount is negative.
// Also here: buy/sell all (incl. stolen) items in the black market.
static void __declspec(naked) check_for_negative_discount(void)
{
    asm
      {
        push ecx
        push SKILL_MERCHANT
        call dword ptr ds:get_skill ; replaced call
        pop ecx
        test eax, eax
        jz skip
        call dword ptr ds:get_merchant_bonus
        test eax, eax
        jge skip
        xor eax, eax
        skip:
        mov edx, dword ptr [ebp+8] ; item
        mov edx, dword ptr [edx] ; id, was set below hook in vanilla
        mov ecx, dword ptr [ebp+16] ; house id
        cmp ecx, BLACK_MARKET_1
        je black
        cmp ecx, BLACK_MARKET_2
        jne quit
        black:
        and dword ptr [ebp+12], 0 ; skip shop type checks
        cmp dword ptr [ebp+20], 2 ; sell action
        jne quit
        xor edx, edx ; skip item id checks
        quit:
        ret 4
      }
}

// Align the stack for the following jump.
static void __declspec(naked) hireling_dismiss_reply_fix_stack_chunk(void)
{
    asm
      {
        add esp, 16
      }
}

// Only show the dismiss dialog if the dismiss command was clicked once.
static void __declspec(naked) delay_dismiss_hireling_reply(void)
{
    asm
      {
        cmp dword ptr [confirm_hireling_dismiss], 0
        jnz ok
        mov dword ptr [esp], 0x4456fa ; skip any reply
        ret
        ok:
        mov ecx, dword ptr [npcprof+eax*4].s_npcprof.dismiss ; replaced, almost
        ret
      }
}

// Register the '5' key for our purposes when a chest is open.
static void __declspec(naked) add_chest_hotkey(void)
{
    asm
      {
        mov ebp, 0x5063f0 ; replaced code (empty string)
        cmp ecx, 20 ; check for chest dialog (others come here)
        jne quit
        push edi ; == 0
        push ebp
        push 0x35 ; number 5 key
        push 5 ; our bogus parameter
        push 110 ; click on portrait action
        push edi
        push 1
        push edi
        push edi
        push edi
        push edi
        push esi ; dialog
        call dword ptr ds:add_button
        add esp, 48
        quit:
        ret
      }
}

// Move items into an open chest by pressing '5'.
static void chest_hotkey(void)
{
    if (dword(MOUSE_ITEM))
      {
        if (add_chest_item(-1, (struct item *) MOUSE_ITEM,
                           dword(dword(0x507a4c)+28))) // chest id in dialog
          {
            remove_mouse_item(MOUSE_THIS);
          }
        else
          {
            if (dword(CURRENT_PLAYER)
                && player_active(PARTY + dword(CURRENT_PLAYER) - 1))
              {
                show_face_animation(PARTY + dword(CURRENT_PLAYER) - 1,
                                    ANIM_WONT_FIT, 0);
              }
            if (dword(CURRENT_SCREEN) == 15) // in backpack
              {
                add_action(ACTION_THIS, ACTION_EXIT, 0, 0);
              }
          }
      }
    else if (dword(CURRENT_SCREEN) == 15) // in backpack
      {
        add_action(ACTION_THIS, ACTION_EXIT, 0, 0);
      }
}

// Hook for the above.
static void __declspec(naked) chest_hotkey_hook(void)
{
    asm
      {
        cmp ecx, 5 ; our parameter
        jne skip
        jmp chest_hotkey
        skip:
        jmp dword ptr ds:click_on_portrait ; replaced call
      }
}

// Do not restart music on reloads if the track would be the same.
// Best used with infinite looping from MM7Patch.
static void __declspec(naked) dont_restart_music(void)
{
    asm
      {
        mov edx, dword ptr [esp+4] ; new music
        cmp dword ptr [esp+8], 0x3000000 ; if called from the patch
        jae ok
        cmp edx, dword ptr [current_track]
        je quit
        ok:
        mov dword ptr [current_track], edx
        jmp dword ptr ds:start_new_music
        quit:
        ret 4
      }
}

// Title screen also restarts music without calling the above,
// so zero out the track number to prevent subsequent weirdness.
static void __declspec(naked) reset_current_track(void)
{
    asm
      {
        mov dword ptr [current_track], edi ; == 0
        test byte ptr [0x6be1e4], 16 ; replaced code
        ret
      }
}

// Add the safe deposit button/reply to banks.
// Also remove the buy deposit button if still present.
static void __declspec(naked) add_deposit_box_reply(void)
{
    asm
      {
        mov eax, dword ptr [DIALOG1]
        cmp dword ptr [eax+32], 3 ; button count
        jne ok
        mov ecx, dword ptr [eax+80] ; the button
        mov edx, dword ptr [ecx+48] ; next button
        mov dword ptr [eax+80], edx
        and dword ptr [edx+52], 0 ; link to the extra button
        dec dword ptr [eax+32]
        push ecx
        mov ecx, REMOVE_BUTTON_THIS
        call dword ptr ds:remove_button
        xor ecx, ecx ; restore
        mov edx, 7 ; ditto
        ok:
        call dword ptr ds:add_reply ; replaced code
        mov ecx, 1
        mov edx, 8
        call dword ptr ds:add_reply ; skipped code
        push 9 ; new subaction
        mov eax, 0x4b3d26 ; three-reply branch
        jmp eax
      }
}

// Print the deposit box reply text and/or the buy box message.
static void __declspec(naked) print_deposit_box_reply(void)
{
    asm
      {
        mov eax, dword ptr [CURRENT_CONVERSATION] ; replaced code
        cmp eax, 9 ; our new conversation node
        je buy
        cmp eax, 1
        jne quit
        push ebx
        push dword ptr [new_strings+STR_DEPOSIT_BOX*4]
        mov eax, dword ptr [DIALOG1]
        cmp dword ptr [eax+44], 4 ; highlighted reply
        cmove eax, dword ptr [ebp-4] ; hl color
        cmovne eax, dword ptr [ebp-8] ; regular color
        push eax
        push 206
        push edi
        mov edx, dword ptr [ARRUS_FNT]
        lea ecx, [ebp-92]
        call dword ptr ds:print_text
        mov eax, 1 ; restore
        quit:
        ret
        buy:
        push ebx
        push dword ptr [new_strings+STR_BUY_DEPOSIT_BOX*4]
        push dword ptr [ebp-4] ; hl color
        push 146
        push edi
        mov edx, dword ptr [ARRUS_FNT]
        lea ecx, [ebp-92]
        call dword ptr ds:print_text
        pop eax
        pop edi
        pop esi
        pop ebx
        sub esp, 180 ; make space for the new stack vars
        push ebx
        push esi
        push edi
        mov esi, dword ptr [DIALOG2]
        mov ebx, dword ptr [new_npc_text+856*4-790*4] ; buy dep. box text
        mov eax, 0x4b7acb ; town hall print bottom text code
        jmp eax
      }
}

// Actually open the box when clicked.
static void __declspec(naked) open_deposit_box(void)
{
    asm
      {
        mov esi, dword ptr [DIALOG2] ; replaced code
        cmp ecx, 22 ; bank
        jne quit
        cmp dword ptr [esp+20], 9 ; open box subaction
        jne quit
        mov ecx, QBITS_ADDR
        mov edx, QBIT_DEPOSIT_BOX
        call dword ptr ds:check_bit
        xor ecx, ecx ; just in case
        test eax, eax
        jz quit
        push edi ; == 0
        push edi
        push ACTION_EXIT
        mov ecx, ACTION_THIS_ADDR
        call dword ptr ds:add_action
        push 1 ; preserve action
        push edi
        push ACTION_EXTRA_CHEST
        mov ecx, ACTION_THIS_ADDR
        call dword ptr ds:add_action
        mov dword ptr [esp], 0x4bd810 ; skip calling code
        quit:
        ret
      }
}

// Add a button for buying a deposit box, and also process its click.
static void __declspec(naked) buy_deposit_box(void)
{
    asm
      {
        mov eax, dword ptr [CURRENT_CONVERSATION] ; replaced code
        cmp eax, 9 ; our buy box node
        jne quit
        cmp dword ptr [esp+20], 10 ; buy box subaction
        je buy
        xor ecx, ecx
        mov edx, 10 ; the above subaction
        call dword ptr ds:add_reply
        mov eax, dword ptr [DIALOG1]
        mov eax, dword ptr [eax+80] ; the new button
        add dword ptr [eax+12], 30 ; fix height
        add dword ptr [eax+20], 30 ; also bottom
        jmp restore
        buy:
        mov eax, dword ptr [PARTY_GOLD]
        sub eax, 2500
        jge ok
        add eax, dword ptr [BANK_GOLD]
        jl no_gold
        mov dword ptr [BANK_GOLD], eax
        xor eax, eax
        ok:
        mov dword ptr [PARTY_GOLD], eax
        push 1
        mov ecx, QBITS_ADDR
        mov edx, QBIT_DEPOSIT_BOX
        call dword ptr ds:change_bit
        push edi
        push edi
        push edi
        push edi
        push -1
        push edi
        push edi
        push SOUND_GOLD
        mov ecx, SOUND_THIS_ADDR
        call dword ptr ds:make_sound
        mov ecx, dword ptr [CURRENT_PLAYER]
        jecxz escape
        mov ecx, dword ptr [PC_POINTERS+ecx*4-4]
        push edi
        push ANIM_SMILE
        call dword ptr ds:show_face_animation
        jmp escape
        no_gold:
        mov ecx, dword ptr [DIALOG2]
        mov edx, SHOP_VOICE_NO_GOLD
        mov ecx, dword ptr [ecx+28] ; bank house id
        call dword ptr ds:shop_voice
        escape:
        push edi
        push edi
        push ACTION_EXIT
        mov ecx, ACTION_THIS_ADDR
        call dword ptr ds:add_action
        restore:
        mov eax, 9 ; restore
        quit:
        ret
      }
}

// Give Scholars +5 to ID Item, stacking with Sages.
static void __declspec(naked) new_scholar_bonus(void)
{
    asm
      {
        call dword ptr ds:have_npc_hired ; replaced code (sage)
        lea eax, [eax+eax*2]
        lea esi, [esi+eax*2]
        mov ecx, NPC_SCHOLAR
        call dword ptr ds:have_npc_hired
        lea eax, [eax+eax*4]
        add esi, eax
        xor eax, eax ; skip old esi = 6 code
        ret
      }
}

// Draw the unique quest manticore 2x bigger.
static void __declspec(naked) the_largest_manticore(void)
{
    asm
      {
        mov eax, dword ptr [ebp-40] ; replaced code
        cmp dword ptr [ecx].s_map_monster.name_id, 16 ; check placemon name
        jne skip
        shl eax, 1 ; height
        shl dword ptr [esi], 1 ; width
        skip:
        mov dword ptr [esi+4], eax ; also replaced code
        ret
      }
}

// Reduce the stacking of several concurrent shielding effects.
// Also fix the actual Shield spell which didn't work in vanilla.
static int __thiscall shield_stacking(struct player *player, int damage)
{
    int divisor = 1;
    if (PARTY_BUFFS[BUFF_SHIELD].expire_time)
        divisor++;
    if (player->spell_buffs[PBUFF_SHIELD].expire_time)
        divisor++;
    if (has_enchanted_item(player, SPC_SHIELDING)
        || has_enchanted_item(player, SPC_STORM))
        divisor++; // these two don't stack anymore
    if (has_item_in_slot(player, GOVERNORS_ARMOR, SLOT_BODY_ARMOR))
        divisor++;
    if (has_item_in_slot(player, KELEBRIM, SLOT_OFFHAND))
        divisor++;
    if (has_item_in_slot(player, ELFBANE, SLOT_MAIN_HAND))
        divisor++;
    if (has_item_in_slot(player, LADYS_ESCORT, SLOT_ANY))
        divisor++;
    if (has_item_in_slot(player, SNIPERS_QUIVER, SLOT_BELT))
        divisor++;
    return damage / divisor;
}

// Hook for the above.
static void __declspec(naked) shield_stacking_hook(void)
{
    asm
      {
        push dword ptr [ebp-4] ; damage
        mov ecx, edi ; player
        call shield_stacking
        mov dword ptr [ebp-4], eax
        mov eax, 0x43a5ac ; past shielding code
        jmp eax
      }
}

// Add a new gamescript command, that calls another event.
static void __declspec(naked) new_event_command(void)
{
    asm
      {
        movzx edx, byte ptr [esi+4] ; replaced code
        cmp edx, 64 ; the new command id
        jne old
        movsx eax, word ptr [esi+7] ; variable
        movzx edx, word ptr [esi+5] ; event
        push eax
        push edx
        push ACTION_VARIABLE_EVENT
        mov ecx, ACTION_THIS_ADDR
        call dword ptr ds:add_action
        xor edx, edx ; fall through to default code
        old:
        dec edx ; also replaced
        ret
      }
}

// Allow the trumpet-related gamescript to spawn Erathian soldiers,
// despite them now being replaced by dragonflies in mapstats.txt.
static void __declspec(naked) summon_soldiers(void)
{
    asm
      {
        mov eax, 0x44f5a8 ; replaced call
        cmp edi, 4 ; our marker, normally 1-3
        jne skip
        dec word ptr [ebp-8] ; now it`s 3
        mov edi, dword ptr [MAPSTATS_ADDR+SIZE_MAPSTAT*23] \
                           .s_mapstats_item.monster2 ; riverstride soldiers
        xchg edi, dword ptr [ecx].s_mapstats_item.monster3 ; was dragonflies
        mov esi, ecx ; preserve
        push 0
        push dword ptr [ebp+8]
        push 0
        call eax
        mov dword ptr [esi].s_mapstats_item.monster3, edi ; restore
        ret 12
        skip:
        jmp eax
      }
}

// Remember the current prize for the NPC text code.
static int arena_prize = 0;

// Reward 10 Lord Arena wins (or more at lower tiers) with an artifact.
// Also award a magic hourglass (for yet more fighting!) ocassionally.
static void __declspec(naked) special_arena_prize(void)
{
    asm
      {
        mov dword ptr [arena_prize], ebx ; reset (ebx == 0)
        movzx ecx, byte ptr [ARENA_TOPIC]
        sub ecx, 84 ; now it`s earned points
        add dword ptr [elemdata.arena_points], ecx
        cmp ecx, 4
        jne not_champion
        cmp dword ptr [elemdata.arena_points], 40
        jb not_champion
        mov ecx, QBITS_ADDR
        mov edx, QBIT_ARENA_CHAMPION
        call dword ptr ds:check_bit
        test eax, eax
        jnz not_champion
        sub esp, 36
        mov ecx, esp
        call dword ptr ds:generate_artifact
        test eax, eax
        jz restore
        mov eax, dword ptr [esp] ; art id
        mov dword ptr [arena_prize], eax
        push 1
        mov ecx, QBITS_ADDR
        mov edx, QBIT_ARENA_CHAMPION
        call dword ptr ds:change_bit
        or byte ptr [esp].s_item.flags, IFLAGS_ID ; we print the name anyway
        push esp
        mov ecx, PARTY_BIN_ADDR
        call dword ptr ds:add_mouse_item
        mov ebx, SIZE_PLAYER * 4
        award_loop:
        lea ecx, [PARTY_ADDR+ebx-SIZE_PLAYER]
        push 107 ; new arena award
        push EVT_AWARDS
        call dword ptr ds:evt_set
        sub ebx, SIZE_PLAYER
        jnz award_loop
        restore:
        add esp, 36
        not_champion:
        cmp dword ptr [arena_prize], ebx
        jnz skip
        mov eax, dword ptr [elemdata.arena_points]
        xor edx, edx
        lea ecx, [edx+5]
        div ecx
        add edx, 84
        cmp dl, byte ptr [ARENA_TOPIC] ; below if just passed a multiple of 5
        jae skip
        mov dword ptr [arena_prize], HOURGLASS_OF_IMPATIENCE
        push HOURGLASS_OF_IMPATIENCE
        push EVT_ITEMS
        call dword ptr ds:evt_set
        skip:
        mov ecx, SOUND_THIS_ADDR ; replaced code
        ret
      }
}

// Also print the Arena NPC reply corresponding to the reward.
static void __declspec(naked) arena_prize_text(void)
{
    asm
      {
        mov eax, dword ptr [arena_prize]
        test eax, eax
        jnz prize
        jmp dword ptr ds:sprintf ; replaced call
        prize:
        push dword ptr [esp+12] ; gold amount
        lea ecx, [eax+eax*2]
        shl ecx, 4
        push dword ptr [ITEMS_TXT_ADDR+ecx].s_items_txt_item.name
        cmp eax, HOURGLASS_OF_IMPATIENCE
        cmovne edx, dword ptr [new_strings+STR_ARENA_CHAMPION*4]
        cmove edx, dword ptr [new_strings+STR_ARENA_HOURGLASS*4]
        push edx
        push esi
        call dword ptr ds:sprintf
        add esp, 16
        ret
      }
}

// Make sure not to break randomness.
static int saved_random_seed = 0;
// A division constant used just below.  Determines how often hirelings change.
static const int two_weeks = ONE_DAY * 14;

// Let random hireling professions persist on reload, at least for a while.
static void __declspec(naked) fixed_street_npcs(void)
{
    asm
      {
        cmp dword ptr [saved_random_seed], ebp ; == 0
        jnz ok ; second+ npc for the map
        call dword ptr ds:get_thread_context
        mov ecx, dword ptr [eax+20] ; random seed
        mov dword ptr [saved_random_seed], ecx
        mov eax, dword ptr [CURRENT_TIME_ADDR]
        mov edx, dword ptr [CURRENT_TIME_ADDR+4]
        div dword ptr [two_weeks]
        mov edx, dword ptr [CURRENT_MAP_ID]
        inc eax ; let starting 0 be overwritten
        cmp eax, dword ptr [elemdata.street_npc_time+edx*4-4]
        je ok
        mov dword ptr [elemdata.street_npc_time+edx*4-4], eax
        mov dword ptr [elemdata.street_npc_seed+edx*4-4], ecx
        ok:
        mov edx, dword ptr [CURRENT_MAP_ID]
        mov eax, dword ptr [elemdata.street_npc_seed+edx*4-4]
        mov edx, dword ptr [esp+36] ; peasant monster num
        inc edx ; avoid multiplying by 0
        mul edx
        push eax
        call dword ptr ds:srandom
        mov ecx, NPCDATA_ADDR ; restore
        mov dword ptr [esp], 0x477330 ; replaced call
        ret
      }
}

// Make sure we don't destroy randomness of the game with the above hook.
// Also here: initialize the corpse loot seed on the first visit.
static void __declspec(naked) restore_random_seed(void)
{
    asm
      {
        mov edi, dword ptr [saved_random_seed]
        test edi, edi ; zero if the above hook never ran
        jz clear
        push edi
        call dword ptr ds:srandom
        pop eax
        mov dword ptr [saved_random_seed], ebp ; == 0
        clear:
        mov edx, OUTDOOR_LAST_VISIT_TIME
        mov ecx, INDOOR_LAST_VISIT_TIME
        cmp dword ptr [OUTDOORS], 2
        cmove ecx, edx
        cmp dword ptr [ecx], ebp ; 0 if just refilled
        jnz quit
        cmp dword ptr [ecx+4], ebp ; second half
        jnz quit
        test edi, edi
        jnz seed
        call dword ptr ds:get_thread_context
        mov eax, dword ptr [eax+20] ; random seed
        seed:
        mov ecx, dword ptr [CURRENT_MAP_ID]
        mov dword ptr [elemdata.monster_loot_seed+ecx*4-4], eax
        quit:
        mov eax, dword ptr [MOUSE_ITEM] ; replaced code
        ret
      }
}

// The party's current speed.  Used just below and also for predictive aim.
static struct { int x, y, z; } party_speed;

// Only apply recovery penalty for running when the party actually moves.
// This will lag one tick behind actual movement, but it doesn't matter much.
static void __declspec(naked) running_recovery(void)
{
    asm
      {
        test byte ptr [0xacd6bc], 2 ; replaced code (running bit)
        jz skip
        cmp dword ptr [party_speed.x], 0
        jnz skip
        cmp dword ptr [party_speed.y], 0
        skip:
        ret
      }
}

// Prevent "of Power" items in stat screen from overwriting the base level.
static int __thiscall get_raw_level(struct player *player)
{
    return player->level_base;
}

// Allow some random chest items to ignore the map-wide treasure level.
static void __declspec(naked) fixed_chest_tlvl(void)
{
    asm
      {
        mov eax, dword ptr [esp+4] ; we replaced an abs call
        neg eax ; always negative here
        cmp eax, 7
        ja fixed
        ret
        fixed:
        lea edx, [eax-7]
        add dword ptr [esp], 56 ; skip over map tlvl code
        ret 4
      }
}

// Same, but for random ground items.
static void __declspec(naked) fixed_ground_tlvl(void)
{
    asm
      {
        cmp eax, 7
        jg fixed
        imul eax, eax, 7 ; replaced code
        add eax, ecx ; ditto
        ret
        fixed:
        lea ebx, [eax-7]
        add dword ptr [esp], 41 ; skip random tlvl code
        ret
      }
}

// Hack buff fountain reset timers to trigger on rest instead of daily.
static void __declspec(naked) fountain_timers(void)
{
    asm
      {
        mov eax, dword ptr [ebp-52] ; replaced code
        mov edx, dword ptr [ebp-48] ; same, but in spirit only
        movsx ecx, word ptr [ebx+8] ; current evt command
        cmp dword ptr [MAP_EVT_DATA+ecx+4], 38 ; check for no periodic bits
        jne skip
        cmp dword ptr [MAP_EVT_DATA+ecx+8], 1 ; fountain iff starts at 01:00:00
        je fountain
        skip:
        or eax, edx ; we replaced an or
        ret
        fountain:
        xor esi, esi ; it must be 0 after we jump
        cmp dword ptr [loading_different_map], esi
        jz early
        cmp edx, dword ptr [elemdata.last_rest_time+4]
        jb trigger
        ja early
        cmp eax, dword ptr [elemdata.last_rest_time]
        ja early
        trigger:
        add dword ptr [esp], 28 ; to onloadmap code
        ret
        early:
        mov dword ptr [esp], 0x444366 ; skip setting the timer
        ret
      }
}

// Trigger said timers for the current map when actually resting.
static void fountain_timers_rest(void)
{
    for (int line = 0; line < dword(MAP_EVT_LINE_COUNT); line++)
      {
        int cmd = MAP_EVT_DATA + word(MAP_EVT_LINES + line * 12 + 8);
        // checks as in the hook above, plus for no half-minute period field
        if (dword(cmd + 4) == 38 && dword(cmd + 8) == 1 && !byte(cmd + 12))
          {
            dword(PROC_EVENT_LABEL_ID) = dword(MAP_EVT_LINES + line * 12 + 4);
            process_event(dword(MAP_EVT_LINES + line * 12), 0, FALSE);
            dword(PROC_EVENT_LABEL_ID) = 0; // reset
          }
      }
    elemdata.last_rest_time = CURRENT_TIME;
}

// Hook for the above.
static void __declspec(naked) fountain_timers_rest_hook(void)
{
    asm
      {
        mov esi, PARTY_BUFF_ADDR ; replaced code
        call fountain_timers_rest
        ret
      }
}

// Movement speed multipliers.  Set just below.
static const float flying_speed = 1.0;
static float walking_speed, water_speed;

// (Re)calculate current (water-)walking speed based on hired NPCs and horses.
// Called on map load (above) and on a hireling update.
static void set_walking_speed(void)
{
    int walking = 0, water = 0;
    if (have_npc_hired(NPC_GUIDE))
        walking += 1;
    if (have_npc_hired(NPC_TRACKER))
        walking += 2;
    if (have_npc_hired(NPC_PATHFINDER))
        walking += 3;
    if (have_npc_hired(NPC_SAILOR))
        water += 2;
    if (have_npc_hired(NPC_NAVIGATOR))
        water += 3;
    if (have_npc_hired(NPC_PIRATE))
        water += 2;
    int has_horse = FALSE;
    // Corresponds to the travel reduction time, as for hirelings.
    static const int horse_speed[] = { 0, 2, 3, 0, 3, 2, 2 };
    for (int horse = HORSE_HARMONDALE; horse <= HORSE_AVLEE; horse++)
        if (NPCS[horse].bits & NPC_HIRED)
          {
            has_horse = TRUE;
            walking += horse_speed[horse-HORSE_HARMONDALE];
          }
    if (has_horse && have_npc_hired(NPC_HORSEMAN))
        walking += 2;
    if (have_npc_hired(NPC_EXPLORER))
      {
        walking += has_horse ? 2 : 1;
        water += 1;
      }
    walking_speed = 1 + walking / 10.0;
    water_speed = 1 + water / 10.0;
}

// (One of the) hooks for the above.
static void __declspec(naked) set_walking_speed_hook(void)
{
    asm
      {
        call set_walking_speed
        cmp dword ptr [NPCS_LENGTH], edi ; replaced code
        ret
      }
}

// On every tick, use one of the speeds calculated above.
static void __declspec(naked) apply_walking_speed(void)
{
    asm
      {
        test word ptr [STATE_BITS], 0x284 ; in liquid
        cmovz eax, dword ptr [walking_speed]
        cmovnz eax, dword ptr [water_speed]
        cmp dword ptr [FLYING], 0
        cmovnz eax, dword ptr [flying_speed]
        mov dword ptr [0x6bdfc4], eax ; vanilla movement speed multiplier
        mov eax, dword ptr [0xacd520] ; replaced code
        ret
      }
}

// Some uncategorized gameplay changes.
static inline void misc_rules(void)
{
    // Now that archers have fire arrows, we need to handle them properly.
    hook_call(0x43a48f, shield_fire_arrow, 10);
    // Make temple donation rewards stronger.
    hook_call(0x4b73a9, temple_wizard_eye_power, 6); // wizard eye (5 rep)
    hook_call(0x4b73cd, temple_other_spells_power, 6); // preservation (10 rep)
    hook_call(0x4b73fb, temple_other_spells_power, 6); // immutability (15 rep)
    hook_call(0x4b7429, temple_other_spells_power, 6); // hour of pow. (20 rep)
    hook_call(0x4b7457, temple_other_spells_power, 6); // day of prot. (25 rep)
    // Remove the old recovery limit of 30.
    erase_code(0x406498, 8); // turn based recovery limit
    erase_code(0x42efcb, 7); // melee attack recovery limit
    erase_code(0x42ec54, 7); // theft recovery limit
    hook_call(0x418437, display_melee_recovery_hook, 5);
    hook_call(0x48fd79, melee_damage_check_main_weapon_first, 6);
    patch_bytes(0x48fda6, melee_damage_weapon_loop_chunk, 8);
    hook_call(0x4b1bd9, bank_interest, 5);
    hook_call(0x4940b1, bank_interest_2, 5);
    hook_call(0x4b7de6, bank_withdraw, 6);
    hook_call(0x44ae8c, evt_set_bank_gold, 5);
    hook_call(0x4180ae, stat_hint_hook, 6);
    hook_jump(0x48ea13, new_stat_thresholds);
    hook_call(0x4506a5, rest_encounters, 13);
    // Upgrade Castle Harmondale (now Nighon) potion shop to item level 5.
    POTION_SHOP_STD[9] = POTION_SHOP_SPC[9] = 5;
    hook_call(0x41a810, color_broken_ac, 5);
    hook_call(0x4189be, color_broken_ac_2, 5);
    // Localization fix: separate hunter-as-npc and hunter-as-class strings.
    patch_pointer(0x452fa6, &new_strings[STR_HUNTER]);
    patch_pointer(0x48c310, &new_strings[STR_HUNTER]);
    // Same for monks.
    patch_pointer(0x47636d, &new_strings[STR_MONK]);
    hook_call(0x453543, monk_npc_name, 6); // can't just patch in place
    // And Merchant NPCs shared their name with the skill.
    patch_pointer(0x47620f, &new_strings[STR_MERCHANT]);
    hook_call(0x45336f, merchant_npc_name, 6); // again can't patch
    patch_pointer(0x4484f3, check_skill_hook);
    hook_call(0x44b360, evt_add_specitem, 5);
    hook_call(0x48dab0, pickpocket_specitem, 6);
    // Let mace paralysis be physical-elemental (was earth/poison).
    patch_byte(0x439cd3, PHYSICAL);
    hook_call(0x415745, print_version, 6);
    hook_jump(0x46901f, th_spear);
    // Expand on MM7Patch fix (replacing spear with a sword/dagger)
    // by allowing to replace it with a shield too.
    // Also allows the above hook to work properly.
    erase_code(0x469034, 46); // just nuke all the special spear code
    hook_call(0x4bc4c8, new_hireling_action, 5);
    hook_call(0x445f16, enable_new_hireling_action, 6);
    hook_call(0x44532e, new_hireling_action_text, 5);
    hook_jump(0x4bc4d1, (void *) 0x4bc81e); // skip old cook/chef statusline
    hook_call(0x4bc581, empty_extra_chest_hook, 6);
    erase_code(0x41f739, 54); // old porter etc. bonus
    hook_call(0x445f77, quartermaster_extra_dialog, 5);
    hook_call(0x445747, quartermaster_extra_dialog_text, 6);
    hook_call(0x4bc439, quartermaster_extra_action, 5);
    hook_call(0x42ee82, variable_wand_power, 5);
    hook_call(0x42f04e, variable_wand_power, 5);
    erase_code(0x491200, 2); // preserve pc pointer for the below hook
    erase_code(0x491207, 3); // ditto
    hook_call(0x49121b, personality_trading_bonus, 5);
    patch_byte(0x49124d, 0); // remove the old 7% merchant bonus
    hook_call(0x42aa85, recharge_spent_charges_sub_spell, 6);
    hook_call(0x42aa9a, recharge_spent_charges_add_spell, 6);
    hook_call(0x4169bf, recharge_spent_charges_sub_potion, 6);
    hook_call(0x4169d0, recharge_spent_charges_add_potion, 6);
    hook_jump(0x426dc7, monster_chooses_player);
    patch_bytes(0x4021ca, better_monster_hostility_chunk, 15);
    erase_code(0x4021d9, 23); // rest of old code
    hook_call(0x43420f, tavern_rest_buff, 5);
    hook_call(0x490d79, tavern_buff_on_rest, 5);
    hook_call(0x494142, dont_reset_cooks, 18);
    hook_call(0x445f0f, invert_cook_check, 5);
    hook_call(0x4bc56a, toggle_cook_reply, 6);
    hook_call(0x445523, print_cook_reply, 7);
    hook_call(0x4b4b93, reduce_training_time, 5);
    hook_call(0x4b474f, increase_training_price, 5);
    hook_call(0x4b8052, temple_heal_price, 5);
    hook_call(0x4bc3b3, increase_arena_reward, 5);
    hook_call(0x4b3c04, add_tax_reply, 7);
    hook_call(0x4b7bea, print_tax_reply, 6);
    hook_call(0x4b7901, tax_dialog, 5);
    hook_call(0x473c6e, restrict_flying_up, 5);
    hook_call(0x473d5e, restrict_flying_down, 8);
    hook_call(0x4742df, restrict_free_fall, 6);
    hook_call(0x473c57, disable_flight, 6); // flying up
    erase_code(0x473c39, 6); // old disable
    hook_call(0x473d52, disable_flight, 6); // flying down
    erase_code(0x473d34, 6); // old disable
    hook_call(0x439939, vampiric_cap, 10); // ranged
    hook_call(0x4399ca, vampiric_cap, 10); // melee
    hook_call(0x402277, berserk_no_run_away, 5);
    hook_call(0x406e84, berserk_no_run_away, 5);
    // Increase Luck effect on resistance rolls fourfold.
    patch_byte(0x48def9, 0x83); // conditions
    patch_byte(0x405482, 0x87); // dispel
    patch_byte(0x48d51c, 0x87); // damage (roll 1)
    patch_byte(0x48d544, 0x87); // damage (roll 2)
    patch_byte(0x48d567, 0x87); // damage (roll 3)
    patch_byte(0x48d58a, 0x87); // damage (roll 4)
    // Remove multiloot.
    erase_code(0x426da3, 22);
    // Do not lower max charges to 0 on recharge (at least 0/1 charges).
    patch_dword(0x42aaaa, 0x11941c6); // mov byte ptr [ecx+25], 1
    hook_call(0x47f28a, charge_zero_wands, 7);
    // Fix some forbidden bounty monsters.
    patch_word(0x4bd122, 232); // harmondale: forbid all peasants (a typo)
    patch_word(0x4bd128, 249); // and allow trolls (still the same typo)
    patch_word(0x4bcead, 1); // celeste: forbid angels (an omission)
    patch_word(0x4bceb3, 3); // second angel check
    patch_word(0x4bcea3, 186); // and restore the overwritten peasant check
    hook_call(0x418ac8, age_color, 5);
    hook_call(0x48c930, lich_physical_age, 7); // might
    hook_call(0x48c9b3, lich_mental_age, 9); // intellect
    hook_call(0x48ca30, lich_mental_age, 9); // personality
    hook_call(0x48caad, lich_physical_age, 7); // endurance
    hook_call(0x48cb2a, lich_physical_age, 7); // accuracy
    hook_call(0x48cba7, lich_physical_age, 7); // speed
    // and luck doesn't depend on age
    hook_call(0x44bb93, check_subtracted_qbit, 5);
    // Fix HP/SP regen during a 1 hour rest (increment time by 5, not 6, min).
    patch_byte(0x41f577, 5);
    patch_byte(0x41f584, 5);
    // Fix some buffs not disappearing on rest.
    patch_byte(0x490d25, 24);
    hook_call(0x445db5, reset_hireling_reply, 6);
    hook_call(0x49672a, short_id_skill_names, 5);
    // Fix floor gold piles not being nerfed by map treasure level.
    patch_dword(0x450084, 0x9090d889); // mov eax, ebx; nop; nop
    hook_call(0x490ef3, check_for_negative_discount, 5);
    // Only show the dismiss hireling reply when actually dismissing them.
    patch_bytes(0x4455a4, hireling_dismiss_reply_fix_stack_chunk, 3);
    hook_jump(0x4455a7, (void *) 0x4456fa); // skip initial reply
    hook_call(0x44551a, delay_dismiss_hireling_reply, 7);
    // reply is shown in empty_extra_chest_hook()
    hook_call(0x41c9f7, add_chest_hotkey, 5);
    hook_call(0x434d0b, chest_hotkey_hook, 5);
    hook_call(0x4abf76, dont_restart_music, 5);
    hook_call(0x46305d, reset_current_track, 7);
    hook_jump(0x4b3c96, add_deposit_box_reply);
    patch_dword(0x4b7d63, 250); // shift balance text down
    hook_call(0x4b7d6d, print_deposit_box_reply, 5);
    hook_call(0x4bcc13, open_deposit_box, 6);
    hook_call(0x4bd7f2, buy_deposit_box, 5);
    // Prevent XP-boosting hirelings from giving the 9% XP bonus w/o Learning.
    patch_word(0x49132b, 0xdb85); // test ebx, ebx -- check for base skill
    // Don't impose 300 recovery when aiming a spell in realtime mode.
    // This also fixes wrong PC getting the result of Telekinesis.
    erase_code(0x433209, 5); // push 300
    erase_code(0x433215, 21); // rest of old code
    // Same, but for PC-targeting spells.
    erase_code(0x4332a3, 5); // push 300
    erase_code(0x4332ac, 21); // the rest
    // Do not reset the current PC on load (we restore saved value instead).
    erase_code(0x45f26f, 41);
    // Expand the audible sprites array.
#define SOUNDLEN 125 // more than 127 and it would get tricky
    static int sound_sprites[SOUNDLEN];
    patch_byte(0x460e2b, SOUNDLEN); // bounds check
    patch_byte(0x47f1a3, SOUNDLEN); // ditto
    patch_pointer(0x460e4f, sound_sprites); // writing
    patch_pointer(0x47f1c3, sound_sprites); // ditto
    patch_pointer(0x4ab49d, sound_sprites); // reading
    // Also decrease the sound radius slightly.
    patch_dword(0x4ab4e9, 2500); // start
    patch_dword(0x4ab671, 2500); // stop
    // Downgrade Scholars to +5 to ID Item.
    erase_code(0x49111f, 9); // old bonus
    hook_call(0x48f954, new_scholar_bonus, 5);
    // Increase Fallen Wizard buff duration to the stated 6 hours.
    patch_dword(0x4bb8fc, SKILL_GM + 5); // was Master 5
    // Add two more cauldrons.
    patch_byte(0x4509a8, 6); // was 4
    patch_byte(0x4509b8, 20); // shift trash heap event down to make space
    patch_byte(0x45099b, 21); // another one
    hook_call(0x44015f, the_largest_manticore, 6);
    // Enable manticores in town halls.
    erase_code(0x4bce3d, 12); // the pit
    erase_code(0x4bcf2b, 12); // celeste
    erase_code(0x4bcfe9, 12); // tularean
    erase_code(0x4bd0d2, 12); // erathia
    erase_code(0x4bd198, 10); // harmondale
    hook_jump(0x43a4e9, shield_stacking_hook);
    hook_call(0x446970, new_event_command, 5);
    hook_call(0x448d8b, summon_soldiers, 5);
    // Extend the parsed awards.txt array.  (Addresses taken from MMExt.)
    static struct { char *text; int32_t type; } awards[AWARD_COUNT+1];
    patch_pointer(0x41910b, awards);
    patch_pointer(0x41919d, &awards[0].type);
    patch_pointer(0x4191a4, &awards[0].type);
    patch_pointer(0x41a14a, awards);
    patch_pointer(0x41a1f7, &awards[0].type);
    patch_pointer(0x44a887, awards);
    patch_pointer(0x44b222, awards);
    patch_pointer(0x47642e, &awards[1]);
    patch_pointer(0x4956ec, awards);
    patch_byte(0x41913a, AWARD_COUNT + 1); // TODO: will overflow at 127+
    patch_pointer(0x4764b7, awards + AWARD_COUNT + 1);
    hook_call(0x4bbd54, special_arena_prize, 5);
    hook_call(0x445600, arena_prize_text, 5);
    hook_call(0x4613b7, fixed_street_npcs, 5);
    hook_call(0x461353, restore_random_seed, 5);
    hook_call(0x49440b, running_recovery, 7);
    hook_call(0x418b16, get_raw_level, 5); // width calc
    hook_call(0x418b2a, get_raw_level, 5); // display
    hook_call(0x4bfaa5, get_raw_level, 5); // also the final certificate
    hook_call(0x4502a5, fixed_chest_tlvl, 5);
    hook_call(0x450039, fixed_ground_tlvl, 5);
    hook_call(0x44412b, fountain_timers, 6);
    hook_call(0x490d06, fountain_timers_rest_hook, 5);
    hook_call(0x44a597, set_walking_speed_hook, 6);
    hook_call(0x472870, apply_walking_speed, 5); // indoors
    hook_call(0x4738a0, apply_walking_speed, 5); // outdoors
    // Increase hireling boni to Luck.
    patch_dword(0x48cc35, 20); // fool
    patch_byte(0x48cc49, 40); // chimney sweep
    patch_byte(0x48cc5a, 30); // psychic
    // Also boost some other professions.
    patch_byte(0x48fad7, 3); // arms masters
    // weapons masters are in warhorse_armsmaster_bonus() below
    // squires are in champion_leadership() below
    patch_byte(0x48fa18, 4); // monks
    patch_byte(0x48fb1c, 4); // also monks
    // Let Accuracy (now Agility) increase AC instead of Speed.
    hook_call(0x48e652, get_accuracy, 5); // base ac
    hook_call(0x48e68b, get_accuracy, 5); // total ac
    // Bug fix: indoor refill count wasn't incremented.
    patch_byte(0x49a5c3, 0);
    // Bug (?) fix: summoned monsters could be looted for random items.
    patch_byte(0x44fe63, 0x35); // zero item chance instead of type
}

// Instead of special duration, make sure we (initially) target the first PC.
static void __declspec(naked) cure_weakness_chunk(void)
{
    asm
      {
        mov word ptr [ebx+4], si
        nop
      }
}

// Allow GM Cure Weakness to affect entire party.
static void __declspec(naked) mass_cure_weakness(void)
{
    asm
      {
        lea ecx, [PARTY_ADDR+edi] ; replaced code
        call dword ptr ds:timed_cure_condition ; replaced code
        cmp dword ptr [ebp-24], GM
        jne quit
        cmp word ptr [ebx+4], 3
        jae quit
        inc word ptr [ebx+4]
        push 0x42cb17 ; loop for all PCs
        ret
        quit:
        push 0x42deaa ; spell cast successfully
        ret
      }
}

// Make Remove Fear party-wide at GM as well.  Unfortunately, there's
// no ready code to check for GM Mind, so let's write our own.
// Called in aim_potions_type() above.
static void __declspec(naked) aim_remove_fear(void)
{
    asm
      {
        mov ecx, dword ptr [esp+32] ; skill override
        test ecx, ecx
        jnz override
        movzx ecx, word ptr [eax+SKILL_MIND*2].s_player.skills
        override:
        push 0x427807 ; test-if-GM hammerhands code
        ret 4
      }
}

// Basically the same as mass_cure_weakness() above, but with a different jump.
static void __declspec(naked) mass_remove_fear(void)
{
    asm
      {
        lea ecx, [PARTY_ADDR+edi] ; replaced code
        call dword ptr ds:timed_cure_condition ; replaced code
        cmp dword ptr [ebp-24], GM
        jne quit
        cmp word ptr [ebx+4], 3
        jae quit
        inc word ptr [ebx+4]
        push 0x42c262 ; loop for all PCs
        ret
        quit:
        push 0x42deaa ; post-cast code
        ret
      }
}

// Code for new GM Stone to Flesh, with 1 day/skill cure duration.
static void __declspec(naked) stone_to_flesh_chunk(void)
{
    asm
      {
        imul edi, edi, 60 * 60 * 24 ; one day (M duration)
        _emit 0xeb ; jmp
        _emit 0xc1 ; to 0x42b5dd
      }
}

// Code for new GM effect of most other cure condition spells.
// Falls through to Master case.
static void __declspec(naked) gm_cure_chunk(void)
{
    asm
      {
        imul edi, edi, 24 ; will be multiplied further after fallthrough
        nop
        nop
      }
}

// Bug fix: cure unconsciousness, set HP to 1, and inflict weakness
// only if Raise Dead succeeds in removing the dead condition.
static void __declspec(naked) raise_dead_chunk(void)
{
    asm
      {
        test al, al
        _emit 0x75 ; jnz
        _emit 0x8c ; to modified GM code
        push 0x42deaa ; post-cast code
        ret
      }
}

// Let Resurrection restore some HP.
static void __declspec(naked) resurrection_chunk(void)
{
    asm
      {
        add edi, 2
        lea edi, [edi*4+edi]
        lea edi, [edi*2+edi]
        lea ecx, [PARTY_ADDR+eax]
        call dword ptr ds:get_full_hp
        cmp edi, eax
        jbe fits
        mov edi, eax
        fits:
        nop
        nop
      }
}

// Allow Elixir of Life to work if low on HP or appropriately ill.
static void __declspec(naked) elixir_of_life_applicable(void)
{
    asm
      {
        lea ecx, [PARTY_ADDR+edi]
        call dword ptr ds:get_full_hp
        cmp eax, dword ptr [PARTY_ADDR+edi].s_player.hp
        jg ok
        mov eax, dword ptr [PARTY_ADDR+edi+COND_DRUNK*8]
        or eax, dword ptr [PARTY_ADDR+edi+COND_DRUNK*8+4]
        or eax, dword ptr [PARTY_ADDR+edi+COND_ZOMBIE*8]
        or eax, dword ptr [PARTY_ADDR+edi+COND_ZOMBIE*8+4]
        or eax, dword ptr [PARTY_ADDR+edi+COND_DISEASED_GREEN*8] ; replaced
        ok:
        ret
      }
}

// Also cure drunk and zombie with EoL.
static void __declspec(naked) elixir_of_life_new_cures(void)
{
    asm
      {
        push edx
        push eax
        push edx
        push eax
        push COND_DRUNK
        call dword ptr ds:timed_cure_condition
        push COND_ZOMBIE
        lea ecx, [PARTY_ADDR+edi]
        call dword ptr ds:timed_cure_condition
        test al, al
        jz not_zombie
        mov eax, dword ptr [PARTY_ADDR+edi].s_player.old_voice
        mov dword ptr [PARTY_ADDR+edi].s_player.voice, eax
        mov edx, dword ptr [PARTY_ADDR+edi].s_player.old_face
        mov byte ptr [PARTY_ADDR+edi].s_player.face, dl
        movzx ecx, word ptr [ebx+4] ; pc number
        call dword ptr ds:update_face
        not_zombie:
        lea ecx, [PARTY_ADDR+edi] ; restore
        jmp dword ptr ds:timed_cure_condition ; replaced call
      }
}

// Also heal some HP.
static void __declspec(naked) elixir_of_life_heal_hp(void)
{
    asm
      {
        call dword ptr ds:timed_cure_condition ; replaced call
        cmp word ptr [ebx], SPL_ELIXIR_OF_LIFE ; other spells arrive here
        jne skip
        mov eax, dword ptr [ebp-56] ; spell skill
        lea eax, [eax+eax*2]
        lea eax, [eax*4+25]
        lea ecx, [PARTY_ADDR+edi]
        push eax
        call dword ptr ds:heal_hp
        skip:
        mov eax, 0x42deaa ; post-cast
        jmp eax
      }
}

// Allow reviving monsters with Spirit magic (they're not made friendly).
static void __declspec(naked) revive_monster(void)
{
    asm
      {
        push dword ptr [esp+4]
        call dword ptr ds:spend_sp ; replaced call
        test eax, eax
        jz quit
        mov ecx, dword ptr [ebx].s_spell_queue_item.target_object
        test ecx, ecx
        jz quit ; to vanilla pc code
        sar ecx, 3
        imul edi, ecx, SIZE_MONSTER
        add edi, MAP_MONSTERS_ADDR
        cmp word ptr [edi].s_map_monster.hp, si ; == 0
        jg fail
        mov ax, word ptr [edi].s_map_monster.ai_state
        cmp ax, AI_DYING
        je ok
        cmp ax, AI_DEAD
        je ok
        fail:
        mov dword ptr [esp], 0x4290c1 ; fail spell code
        quit:
        ret 4
        ok:
        call dword ptr ds:resurrect_monster
        mov dword ptr [edi].s_map_monster.experience, esi ; prevent farming
        xor eax, eax
        inc eax ; for raise dead
        cmp word ptr [ebx], SPL_RESURRECTION
        jne skip
        mov eax, dword ptr [ebp-56] ; spell power
        lea eax, [eax+eax*2]
        lea eax, [eax+eax*4+30] ; 15 * skill + 30 HP
        mov ecx, dword ptr [edi].s_map_monster.max_hp
        cmp eax, ecx
        cmova eax, ecx
        skip:
        mov word ptr [edi].s_map_monster.hp, ax
        inc dword ptr [ebp-40] ; success flag
        xor eax, eax ; skip vanilla code
        ret 4
      }
}

// Rehaul the condition cure spells.  Generally, GM no longer
// removes time limit, with most spells' mastery effects shifted.
static inline void cure_spells(void)
{
    // Allow GM Cure Weakness to target entire party, but remove untimed cure.
    patch_byte(0x427c9f + SPL_CURE_WEAKNESS - 2, 8); // same as hammerhands
    patch_bytes(0x42caee, cure_weakness_chunk, 5);
    erase_code(0x42cb3c, 27); // remove some obsolete checks
    hook_jump(0x42cb7a, mass_cure_weakness);
    // Same for Remove Fear.  We can reuse the same chunk here.
    patch_bytes(0x42c239, cure_weakness_chunk, 5);
    erase_code(0x42c287, 27); // remove similar obsolete checks
    hook_jump(0x42c2c5, mass_remove_fear);
    // Just remove the untimed cure for GM Awaken.  10 days is plenty enough.
    erase_code(0x42a64f, 5);
    erase_code(0x42a680, 22);
    // Shift the max cure delay multipliers: Stone to Flesh.
    patch_dword(0x42b5d9, 60*3); // E -> N
    patch_dword(0x42b620, 60*60); // M -> E
    patch_bytes(0x42b614, stone_to_flesh_chunk, 8); // GM -> M (new code)
    patch_byte(0x42b5d6, 61); // and a jump to it
    erase_code(0x42b60e, 4); // remove old GM check
    // Shift the max cure delay multipliers: Remove Curse.
    patch_bytes(0x42ba07, gm_cure_chunk, 5); // GM -> M
    patch_dword(0x42ba0e, 60*60); // M -> E
    patch_dword(0x42ba16, 60*3); // E -> N
    erase_code(0x42ba4b, 16); // remove old GM code
    // Shift the max cure delay multipliers: Cure Paralysis.
    // The code changes are basically the same as with Remove Curse.
    patch_bytes(0x42c196, gm_cure_chunk, 5); // GM -> M
    patch_dword(0x42c19d, 60*60); // M -> E
    patch_dword(0x42c1a5, 60*3); // E -> N
    erase_code(0x42c1f5, 10); // remove old GM check
    // Shift the max cure delay multipliers: Cure Insanity.
    // Again, we can use the same code chunk here.
    patch_bytes(0x42c850, gm_cure_chunk, 5); // GM -> M
    patch_dword(0x42c857, 60*60); // M -> E
    erase_code(0x42c8c4, 30); // remove old GM code
    // Shift the max cure delay multipliers: Cure Poison.
    // Similar code, similar patches.
    patch_bytes(0x42cc56, gm_cure_chunk, 5); // GM -> M
    patch_dword(0x42cc5d, 60*60); // M -> E
    patch_dword(0x42cc65, 60*3); // E -> N
    erase_code(0x42ccd2, 67); // remove old GM code
    // Shift the max cure delay multipliers: Cure Disease.
    // There sure is a lot of copy-pasted code in the game.
    patch_bytes(0x42cfd0, gm_cure_chunk, 5); // GM -> M
    patch_dword(0x42cfd7, 60*60); // M -> E
    erase_code(0x42d044, 67); // remove old GM code
    // Shift the max cure delay multipliers: Raise Dead.
    // This should be the last one.
    patch_bytes(0x42bda5, gm_cure_chunk, 5); // GM -> M
    patch_dword(0x42bdac, 60*60); // M -> E
    // A bit intricate: we want all the side-effects of Raise Dead
    // (unconsc. cure, HP set to 1, and weakness) to only trigger
    // if the main effect succeeds.  Unconsc. cure also must be untimed,
    // as it plausibly may be present longer than death.
    // Thankfully, the old GM code more or less does just that.
    patch_bytes(0x42be19, (void *) 0x42be03, 10); // move HP = 1 past the check
    erase_code(0x42be23, 17); // remove (the rest of) untimed death cure
    erase_code(0x42bdff, 16); // remove old GM check
    patch_byte(0x42be00, 65); // extend jmp to over all old GM code
    patch_bytes(0x42be7f, raise_dead_chunk, 10);
    // Resurrection is overhauled: no time limit, no weakness,
    // and it restores HP a bit.  This means a lot of cut code.
    erase_code(0x42bfe6, 12); // old mastery checks
    patch_bytes(0x42c04d, resurrection_chunk, 28); // calculate HP
    erase_code(0x42c069, 6); // old GM check
    erase_code(0x42c13e, 22); // old weakness code
    erase_code(0x42c17f, 5); // fall through to set edi code
    // Rebrand Cure Disease as Elixir of Life, with extra abilities.
    hook_call(0x42d016, elixir_of_life_applicable, 6);
    hook_call(0x42d0b4, elixir_of_life_new_cures, 5);
    hook_jump(0x42d0ff, elixir_of_life_heal_hp);
    // Allow casting Raise Dead and Resurrection on monsters.
    patch_byte(0x427c9f + SPL_RAISE_DEAD - 2, 5); // aim at pc or monster
    patch_byte(0x427c9f + SPL_RESURRECTION - 2, 5); // ditto
    hook_call(0x42bdb9, revive_monster, 5); // raise dead
    hook_call(0x42c016, revive_monster, 5); // resurrection
}

// Bonus for mod-triggered debuffs.
static int debuff_penetration = 0;

// Our wrapper for the debuff resist function.
static int __stdcall debuff_monster(void *monster, int element, int bonus)
{
    debuff_penetration = bonus;
    int result = monster_resists_condition(monster, element);
    debuff_penetration = 0;
    return result;
}

// Let the magic (or some other) skill affect the chance of debuffs working.
// Shrinking Ray requires special handling here.
// Also handles Cursed monsters and GM ID Monster bonus.
static void __declspec(naked) pierce_debuff_resistance(void)
{
    asm
      {
        mov eax, dword ptr [debuff_penetration]
        test eax, eax
        jnz not_spell
        cmp dword ptr [ebp+4], 0x439c54 ; weapon / spell stun
        jne not_stun
        mov eax, dword ptr [ebp] ; old ebp
        mov eax, dword ptr [eax-32] ; stun power + 1
        dec eax
        jle weapon
        jmp not_spell
        not_stun:
        cmp dword ptr [ebp+4], 0x439cdf ; mace paralysis
        je weapon
        cmp edx, 0x439cdf ; same, but patch-hooked (GM axe)
        jne not_weapon
        weapon:
        mov ecx, dword ptr [ebp-8] ; stored edi
        ; vanilla debuffs only happen from main hand
        mov edx, dword ptr [ecx+SLOT_MAIN_HAND*4].s_player.equipment
        test edx, edx
        jz not_spell
        lea edx, [edx+edx*8]
        test byte ptr [ecx+edx*4+S_PL_ITEM0].s_item.flags, IFLAGS_BROKEN
        jnz not_spell
        not_broken:
        mov eax, dword ptr [ecx+edx*4-SIZE_ITEM].s_player.items
        lea eax, [eax+eax*2]
        shl eax, 4
        movzx eax, byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.skill
        push eax
        call dword ptr ds:get_skill
        and eax, SKILL_MASK
        jmp not_spell
        not_weapon:
        cmp dword ptr [ebp+4], 0x46bf98 ; gm shrinking ray code
        jne not_gm_ray
        mov eax, dword ptr [ebp-8] ; stored edi
        jmp shrinking_ray
        not_gm_ray:
        cmp dword ptr [ebp+4], 0x46ca24 ; projectile impact code
        jne not_projectile
        mov eax, dword ptr [ebp-4] ; stored esi
        shrinking_ray:
        mov eax, dword ptr [eax].s_map_object.spell_power
        jmp not_spell
        not_projectile:
        cmp dword ptr [ebp+4], 0x427db8 ; start of cast spell function
        jb not_spell
        cmp dword ptr [ebp+4], 0x42e968 ; end of cast spell function
        ja not_spell
        mov eax, dword ptr [ebp] ; stored ebp
        mov eax, dword ptr [eax-56] ; spell skill
        not_spell:
        shl eax, 1 ; double the skill to make the effect noticeable
        mov edx, dword ptr [edi+MBUFF_CURSED*SIZE_BUFF] \
                           .s_map_monster.spell_buffs
        or edx, dword ptr [edi+MBUFF_CURSED*SIZE_BUFF+4] \
                          .s_map_monster.spell_buffs
        jz not_cursed
        add eax, 10 ; effectively lowers res by 25% before skill bonus
        not_cursed:
        cmp byte ptr [edi].s_map_monster.id_level, GM
        jb no_id_bonus
        add eax, 5 ; less than curse, but still something
        no_id_bonus:
        add esi, eax
        lea ebp, [eax+30] ; standard difficulty check
        jmp dword ptr ds:random ; replaced call
      }
}

// Make sure to compare the roll with the new difficulty check.
static void __declspec(naked) debuff_resist_chunk(void)
{
    asm
      {
        cmp edx, ebp
        nop
      }
}

// Give Basic Slow a fixed duration of 5 minutes.
static void __declspec(naked) slow_5min_chunk(void)
{
    asm
      {
        mov eax, 60 * 5
        nop
      }
}

// Give Expert+ Slow a fixed duration of 20 minutes.
static void __declspec(naked) slow_20min_chunk(void)
{
    asm
      {
        mov eax, 60 * 20
        nop
      }
}

// The duration patched above actually wasn't used at all;
// instead it was fixed 3 min/skill, which is likely a bug.
static void __declspec(naked) slow_multiply_duration_chunk(void)
{
    asm
      {
        mov edi, dword ptr [ebp-16]
        shl edi, 7
      }
}

// Make Turn Undead duration dependent only on mastery and not skill.
static void __declspec(naked) turn_undead_duration_chunk(void)
{
    asm
      {
        ; edx == 3
        gm:
        shl edx, 1 ; gm 1 hour
        master:
        shl edx, 1 ; master 30 min
        jmp expert
        nop
        nop
        nop
        nop
        nop
        nop
        normal:
        sub edx, 2 ; normal 5 min
        expert:
        imul eax, edx, 60 * 5 ; expert 15 min
      }
}

// Standardized Expert debuff duration of 15 minutes.
// Used in Charm, Berserk, Master Mass Fear, and Control Undead.
static void __declspec(naked) duration_15min_chunk(void)
{
    asm
      {
        mov eax, 60 * 15
        nop
      }
}

// Standardized Master debuff duration of 30 minutes.
// Used in Berserk, GM Mass Fear, and Control Undead.
static void __declspec(naked) duration_30min_chunk(void)
{
    asm
      {
        mov eax, 60 * 30
        nop
      }
}

// Standardized GM debuff duration of 1 hour.
// Used in Berserk and Enslave.
static void __declspec(naked) duration_1hour_chunk(void)
{
    asm
      {
        mov eax, 60 * 60
        nop
      }
}

// Give Paralyze a fixed duration of 5/10/20/30 min on N/E/M/G.
static void __declspec(naked) paralyze_duration(void)
{
    asm
      {
        mov edx, dword ptr [ebp-24] ; skill mastery
        xor eax, eax
        dec edx ; 0/1/2/3
        setz al ; 1/0/0/0
        lea edi, [eax+edx*2] ; 1/2/4/6
        imul edi, edi, 60 * 5 ; x 5 min
        shl edi, 7 ; seconds to ticks
        ret
      }
}

// Give Shrinking Ray a fixed duration of 20 minutes.
static void __declspec(naked) shrinking_ray_duration_chunk(void)
{
    asm
      {
        mov eax, 128 * 60 * 20 ; in ticks
        push 0 ; replaced code
        nop
      }
}

// Rework most debuff spells: the duration now only depends on mastery,
// and the skill increases success chance.
// TODO: rework mace paralysis as well?  see 0x439cfe
static inline void debuff_spells(void)
{
    hook_call(0x427695, pierce_debuff_resistance, 5);
    erase_code(0x428fc8, 6); // do not multiply shrinking ray's skill by 300
    patch_bytes(0x4276aa, debuff_resist_chunk, 3);
    patch_bytes(0x428d6b, slow_5min_chunk, 6);
    patch_bytes(0x428d73, slow_20min_chunk, 6);
    patch_bytes(0x428d8b, slow_20min_chunk, 6);
    patch_bytes(0x428d95, slow_20min_chunk, 6);
    patch_bytes(0x428df5, slow_multiply_duration_chunk, 6);
    // Make Turn Undead duration fixed, for symmetry with other debuffs.
    patch_bytes(0x42bbed, turn_undead_duration_chunk, 21);
    patch_byte(0x42bbe9, 5); // master jump
    patch_byte(0x42bbec, 12); // normal jump
    patch_bytes(0x428e86, duration_15min_chunk, 6); // Charm
    // Berserk
    patch_bytes(0x42c4ac, duration_15min_chunk, 6); // E
    patch_bytes(0x42c4a4, duration_30min_chunk, 6); // M
    patch_bytes(0x42c49c, duration_1hour_chunk, 6); // GM
    // Mass Fear
    patch_bytes(0x42c696, duration_15min_chunk, 6); // M
    patch_bytes(0x42c68e, duration_30min_chunk, 6); // GM
    patch_bytes(0x42c5a6, duration_1hour_chunk, 6); // Enslave
    hook_call(0x428cf5, paralyze_duration, 6);
    // Control Undead
    patch_bytes(0x42e07c, duration_15min_chunk, 6); // E
    patch_bytes(0x42e072, duration_30min_chunk, 6); // M
    patch_bytes(0x46ca44, shrinking_ray_duration_chunk, 7); // N/E/M
    patch_bytes(0x46bf9c, shrinking_ray_duration_chunk, 8); // GM
}

// Provide the new buffer address to the parsing function.
static void __declspec(naked) spcitems_address_chunk(void)
{
    asm
      {
        mov eax, offset spcitems
        nop
      }
}

// Now provide the address for the generation probabilities specifically.
static void __declspec(naked) spcitems_probability_address_chunk(void)
{
    asm
      {
        mov edx, offset spcitems + S_SPC_PROB
        nop
      }
}

// The item generator needs the enchantment level address.
static void __declspec(naked) spcitems_level_address_chunk(void)
{
    asm
      {
        mov ecx, offset spcitems + S_SPC_LEVEL
        nop
      }
}

// Calculate probability address from level address provided earlier.
// The [ebp-8] is calculated in spc_ench_group() below.
static void __declspec(naked) spcitems_probability_from_level_chunk(void)
{
    asm
      {
        mov eax, dword ptr [ebp-8]
        movzx eax, byte ptr [ecx-S_SPC_LEVEL+eax].s_spcitem.probability
      }
}

// Address for probabilities again, but into a different register.
static void __declspec(naked) spcitems_probability_address_chunk_2(void)
{
    asm
      {
        mov ebx, offset spcitems + S_SPC_PROB
        nop
      }
}

// We will need a new spcitems buffer to store new enchantments.
static inline void spcitems_buffer(void)
{
    // spcitems.txt parsing function
    patch_bytes(0x457023, spcitems_address_chunk, 6);
    patch_dword(0x457032, SPC_COUNT); // loop count
    patch_bytes(0x45713d, spcitems_probability_address_chunk, 6);
    patch_byte(0x45714b, SPC_COUNT); // stored for later
    // items.txt parser
    patch_bytes(0x4578c0, spcitems_address_chunk, 6);
    patch_byte(0x4578e4, SPC_COUNT);
    // random item generator
    patch_bytes(0x456be9, spcitems_level_address_chunk, 6);
    patch_bytes(0x456c2a, spcitems_probability_from_level_chunk, 9);
    erase_code(0x456c32, 14);
    patch_bytes(0x456c7e, spcitems_probability_address_chunk_2, 6);
    patch_bytes(0x456cbd, spcitems_probability_address_chunk_2, 5);
    // item name
    patch_pointer(0x456616, spcitems - 1);
    // the other reference is handled in prefix_gender() above
    // item description handled in two_handed_bonus_desc() above
    patch_pointer(0x4564ae, &(spcitems-1)->value); // item value
    // enchant item spell (some of these are unused, but whatever)
    patch_pointer(0x42ad56, spcitems->probability);
    patch_pointer(0x42ada0, spcitems->probability);
    patch_pointer(0x42add5, spcitems->probability);
    patch_pointer(0x42afe6, spcitems->probability);
    patch_pointer(0x42b030, spcitems->probability);
    patch_pointer(0x42b069, spcitems->probability);
    patch_pointer(0x42b251, spcitems->probability);
    patch_pointer(0x42b29b, spcitems->probability);
    patch_pointer(0x42b2d0, spcitems->probability);
    patch_pointer(0x42ad37, &spcitems->level);
    patch_pointer(0x42afc7, &spcitems->level);
    patch_pointer(0x42b232, &spcitems->level);
}

// For remembering the prefix spcitems column (no more space in the struct).
static char spc_prefixes[SPC_COUNT];

// Externalize the prefix/suffix enchantment distinction into spcitems.txt.
static void __declspec(naked) parse_prefix_flag(void)
{
    asm
      {
        cmp eax, 2
        je prefix
        cmp eax, 18 ; replaced code, but with our field number
        ret
        prefix:
        mov ecx, dword ptr [ebp-24]
        neg ecx
        mov byte ptr [spc_prefixes+SPC_COUNT+ecx], 0
        cmp byte ptr [esi], 'y'
        je yes
        cmp byte ptr [esi], 'Y'
        jne no
        yes:
        mov byte ptr [spc_prefixes+SPC_COUNT+ecx], dl ; == 1
        no:
        test edx, edx ; set flags
        ret
      }
}

// And now query that parsed field when necessary.
static void __declspec(naked) read_prefix_flag(void)
{
    asm
      {
        cmp byte ptr [spc_prefixes+eax-1], 1
        ret ; jz follows shortly
      }
}

// Display the Cursed monster debuff.  It's the same color as Fate.
// We overwrite a switch table overflow check here,
// but the overflow cannot happen anyway, so it's okay.
static void __declspec(naked) display_cursed_debuff(void)
{
    asm
      {
        mov ecx, dword ptr [ebp-52] ; current buff
        dec ecx
        js cursed
        ret
        cursed:
        mov ecx, dword ptr [GLOBAL_TXT_ADDR+52*4]
        push 0x41ecd8 ; fate code
        ret 4
      }
}

// Cursed monsters also miss 50% of attacks against other monsters.
static void __declspec(naked) cursed_monster_hits_monster(void)
{
    asm
      {
        mov ecx, dword ptr [esp+12] ; attacker
        mov edx, dword ptr [ecx+MBUFF_CURSED*SIZE_BUFF] \
                           .s_map_monster.spell_buffs
        or edx, dword ptr [ecx+MBUFF_CURSED*SIZE_BUFF+4] \
                          .s_map_monster.spell_buffs
        jz success
        call dword ptr ds:random
        and eax, 1
        jnz success
        add esp, 8
        ret 16 ; force a miss (eax == 0)
        success:
        lea ebp, [esp+4] ; replaced code (modified)
        mov ecx, dword ptr [ebp+12] ; replaced code
        ret
      }
}

// In addition, resistances of a cursed monster are considered 25% lower
// (10 resistance penetration).  Also here: GM ID Monster adds 5 more,
// and (unrelated) all damage to monsters is lowered on higher difficulties.
static void __declspec(naked) cursed_monster_resists_damage(void)
{
    asm
      {
        add eax, edx ; replaced code
        mov esi, 30
        mov ecx, dword ptr [ebp+8] ; monster
        mov edx, dword ptr [ecx+MBUFF_CURSED*SIZE_BUFF] \
                           .s_map_monster.spell_buffs
        or edx, dword ptr [ecx+MBUFF_CURSED*SIZE_BUFF+4] \
                          .s_map_monster.spell_buffs
        jz not_cursed
        add esi, 10
        not_cursed:
        cmp byte ptr [ecx].s_map_monster.id_level, GM
        jb no_bonus
        add esi, 5
        no_bonus:
        mov dword ptr [ebp+12], esi ; unused at this point
        add esi, eax
        cmp dword ptr [elemdata.difficulty], 0
        jz skip
        mov eax, dword ptr [ebp+16] ; damage
        sar eax, 1
        cmp dword ptr [elemdata.difficulty], 2
        jae lower
        sar eax, 1
        lower:
        sub dword ptr [ebp+16], eax
        skip:
        ret
      }
}

// Replace the roll difficulty of 30 with our modified value.
static void __declspec(naked) mon_res_roll_chunk(void)
{
    asm
      {
        cmp edx, dword ptr [ebp+12]
      }
}

// Let Terrifying helmets inflict Afraid.  Called in cursed_weapon() below.
static void __stdcall terrifying_helmet(struct player *player,
                                        struct map_monster *monster)
{
    // we want highest weapon skill here
    int skill = 0, mastery = 0;
    int mainhand = player->equipment[SLOT_MAIN_HAND];
    if (mainhand)
      {
        struct item *weapon = &player->items[mainhand-1];
        if (!(weapon->flags & IFLAGS_BROKEN))
          {
            skill = get_skill(player, ITEMS_TXT[weapon->id].skill);
            mastery = skill_mastery(skill);
            skill &= SKILL_MASK;
          }
      }
    int offhand = player->equipment[SLOT_OFFHAND];
    if (offhand)
      {
        struct item *weapon = &player->items[offhand-1];
        int offhand_skill = ITEMS_TXT[weapon->id].skill;
        if (!(weapon->flags & IFLAGS_BROKEN) && offhand_skill < SKILL_BLASTER)
          {
            int skill2 = get_skill(player, offhand_skill);
            int mastery2 = skill_mastery(skill2);
            skill2 &= SKILL_MASK;
            if (skill < skill2)
                skill = skill2;
            if (mastery < mastery2)
                mastery = mastery2;
          }
      }
    if (!mastery) // shouldn't remain zero if we have a weapon
      {
        skill = get_skill(player, SKILL_UNARMED);
        mastery = skill_mastery(skill);
        skill &= SKILL_MASK;
      }
    int minutes = mastery <= 1 ? 5 : 15 << (mastery - 2); // 5, 15, 30, an hour
    if (debuff_monster(monster, MIND, skill))
        add_buff(monster->spell_buffs + MBUFF_FEAR,
                 CURRENT_TIME + minutes * MINUTE, mastery, 0, 0, 0);
}

// Defined below.
static void __stdcall headache_berserk(struct player *, struct map_monster *);
static void __stdcall viper_slow(struct player *, struct map_monster *);
static void multihit_message_check(void);

// Implement cursed weapons; the debuff is inflicted with a 20% chance.
// Black Knights treat all melee weapons as cursed.
// Headache berserk and Viper slow effects are also triggered here.
// One of multihit message hooks is also here.
// Finally, Terrifying helmets (plus Amuck) are also implemented here.
// TODO: should it make a sound?
static void __declspec(naked) cursed_weapon(void)
{
    asm
      {
        test ebx, ebx
        jz melee
        cmp dword ptr [ebx].s_map_object.spell_type, SPL_ARROW
        je bow
        cmp dword ptr [ebx].s_map_object.spell_type, SPL_KNIFE
        jne fail
        bow:
        mov eax, dword ptr [edi+SLOT_MISSILE*4].s_player.equipment
        xor ecx, ecx
        jmp check
        melee:
        push SPC_TERRIFYING
        mov ecx, edi
        call dword ptr ds:has_enchanted_item
        test eax, eax
        jnz fear
        cmp byte ptr [edi].s_player.class, CLASS_BLACK_KNIGHT
        ja no_zombie
        test byte ptr [NPC_ADDR+HORSE_DEYJA*SIZE_NPC].s_npc.bits, NPC_HIRED
        jnz fear
        no_zombie:
        push SLOT_MAIN_HAND
        push AMUCK
        mov ecx, edi
        call dword ptr ds:has_item_in_slot
        test eax, eax
        jz no_fear
        fear:
        push esi
        push edi
        call terrifying_helmet
        no_fear:
        mov ecx, 2
        mov eax, dword ptr [edi+SLOT_MAIN_HAND*4].s_player.equipment
        check:
        test eax, eax
        jz offhand
        lea eax, [eax+eax*8]
        lea eax, [edi+eax*4-SIZE_ITEM].s_player.items
        test byte ptr [eax].s_item.flags, IFLAGS_BROKEN
        jnz offhand
        cmp dword ptr [eax], VIPER
        je viper
        cmp dword ptr [eax], HEADACHE
        jne not_headache
        push eax
        push ecx
        push esi
        push edi
        call headache_berserk
        jmp restore
        viper:
        push eax
        push ecx
        push esi
        push edi
        call viper_slow
        restore:
        pop ecx
        pop eax
        not_headache:
        cmp byte ptr [edi].s_player.class, CLASS_BLACK_KNIGHT
        jne not_knight
        test ecx, ecx
        jnz cursed
        not_knight:
        cmp dword ptr [eax].s_item.bonus2, SPC_CURSED
        je cursed
        cmp dword ptr [eax].s_item.bonus2, SPC_WRAITH
        je cursed
        offhand:
        dec ecx
        jle fail
        mov eax, dword ptr [edi+SLOT_OFFHAND*4].s_player.equipment
        jmp check
        cursed:
        push eax
        call dword ptr ds:random
        mov ecx, 5 ; 20%/40% chance
        xor edx, edx
        div ecx
        dec edx
        jge not_friend
        push SLOT_ANY
        push FENCERS_FRIEND
        mov ecx, edi
        call dword ptr ds:has_item_in_slot
        dec eax
        not_friend:
        pop eax
        jnz fail
        mov eax, dword ptr [eax]
        lea eax, [eax+eax*2]
        shl eax, 4
        movzx eax, byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.skill
        push eax
        mov ecx, edi
        call dword ptr ds:get_skill
        and eax, SKILL_MASK
        push eax
        push MAGIC
        push esi ; monster
        call debuff_monster
        test eax, eax
        jz fail
        xor ecx, ecx
        mov eax, 20 * MINUTE
        mov edx, dword ptr [CURRENT_TIME_ADDR+4]
        add eax, dword ptr [CURRENT_TIME_ADDR]
        adc edx, ecx
        push ecx
        push ecx
        push ecx
        push ecx
        push edx
        push eax
        lea ecx, [esi+MBUFF_CURSED*SIZE_BUFF].s_map_monster.spell_buffs
        call dword ptr ds:add_buff
        push 0
        push esi
        call dword ptr ds:magic_sparkles
        fail:
        cmp dword ptr [ebp-12], 0 ; total damage
        jnz multihit_message_check ; other hook at this address
        ret ; no message if just stun (unless shown by stun code)
      }
}

// We need this for damage_messages() below,
// as the murder code overwrites ebx which stored it.
static int stored_projectile;

//Defined below.
static void __stdcall kill_checks(struct player *, struct map_monster *,
                                  struct map_object *);

// Implement soul stealing weapons: when used to kill a monster,
// they add SP equal to monster's level.  Just like vampiric weapons,
// overheal is possible, and wielding two such weapons will double SP gain.
// The new Sacrificial Dagger and Ethric's Staff are also soul stealing.
// The latter also raises zombies.  Also here: store the damaging projectile
// for later use, and run skill-related on-kill checks.
static void __declspec(naked) soul_stealing_weapon(void)
{
    asm
      {
        mov dword ptr [stored_projectile], ebx
        push ebx
        push esi
        push edi
        call kill_checks
        test ebx, ebx
        jnz quit
        movzx eax, byte ptr [edi].s_player.class
        movzx ebx, byte ptr [0x4ed634+eax] ; sp multiplier
        mov eax, dword ptr [edi+SLOT_MAIN_HAND*4].s_player.equipment
        test eax, eax
        jz offhand
        lea eax, [eax+eax*8]
        lea eax, [edi+eax*4-SIZE_ITEM].s_player.items
        test byte ptr [eax].s_item.flags, IFLAGS_BROKEN
        jnz offhand
        cmp dword ptr [eax], ETHRICS_STAFF
        jne no_zombie
        push esi
        push edi
        call ethrics_staff_zombie
        test ebx, ebx
        jnz soul_mainhand
        no_zombie:
        test ebx, ebx
        jz quit
        cmp dword ptr [eax], SACRIFICIAL_DAGGER
        je soul_mainhand
        cmp dword ptr [eax].s_item.bonus2, SPC_SOUL_STEALING
        jne offhand
        soul_mainhand:
        movzx eax, byte ptr [esi].s_map_monster.level
        add dword ptr [edi].s_player.sp, eax ; overheal is OK here
        offhand:
        test ebx, ebx
        jz quit
        xor ebx, ebx ; restore
        mov eax, dword ptr [edi+SLOT_OFFHAND*4].s_player.equipment
        test eax, eax
        jz quit
        lea eax, [eax+eax*8]
        lea eax, [edi+eax*4-SIZE_ITEM].s_player.items
        test byte ptr [eax].s_item.flags, IFLAGS_BROKEN
        jnz quit
        cmp dword ptr [eax], SACRIFICIAL_DAGGER
        je soul_offhand
        cmp dword ptr [eax].s_item.bonus2, SPC_SOUL_STEALING
        jne quit
        soul_offhand:
        movzx eax, byte ptr [esi].s_map_monster.level
        add dword ptr [edi].s_player.sp, eax ; overheal is OK here
        quit:
        mov ecx, dword ptr [ebp-24] ; replaced code
        xor edx, edx ; replaced code
        ret
      }
}

// Used for weapon attacks.  0 if regular hit, 1 if critical, 2 if backstab.
static int critical_hit;

// Reset the above variable.
static void __declspec(naked) reset_critical_hit(void)
{
    asm
      {
        mov dword ptr [critical_hit], eax ; == 0
        mov dword ptr [ebp-32], eax ; replaced code
        cmp ebx, eax ; replaced code
        ret
      }
}

// If the monster can be backstabbed, set the backstab critical flag.
static void __declspec(naked) check_backstab(void)
{
    asm
      {
        cmp word ptr [ecx+SKILL_THIEVERY*2].s_player.skills, SKILL_GM
        jae backstab
        mov edx, dword ptr [PARTY_DIR]
        sub dx, word ptr [esi].s_map_monster.direction
        test dh, 6 ; we want no more than +/-512 mod 2048 difference
        jnp quit ; PF == 1 will match 0x000 and 0x110 only
        backstab:
        mov dword ptr [critical_hit], 2
        quit:
        mov dword ptr [ebp-8], 4 ; replaced code
        ret
      }
}

// Make afraid monsters face away from you in turn-based mode,
// for easier backstabbing.  Will only work on hostile monsters.
// If the monster fights someone else, it will face away from them.
static void __declspec(naked) turn_afraid_monster(void)
{
    asm
      {
        test byte ptr [ebx+2].s_map_monster.bits, 8 ; hostile bit
        jz skip
        mov edx, dword ptr [ebx+MBUFF_FEAR*SIZE_BUFF].s_map_monster.spell_buffs
        or edx, dword ptr [ebx+MBUFF_FEAR*SIZE_BUFF+4] \
                          .s_map_monster.spell_buffs
        jnz turn
        cmp byte ptr [ebx].s_map_monster.ai_type, 1
        jb skip ; suicidal
        je turn ; wimp
        test byte ptr [ebx+2].s_map_monster.bits, 2 ; no flee bit
        jnz skip
        mov edx, dword ptr [ebx+MBUFF_BERSERK*SIZE_BUFF] \
                           .s_map_monster.spell_buffs
        or edx, dword ptr [ebx+MBUFF_BERSERK*SIZE_BUFF+4] \
                          .s_map_monster.spell_buffs
        jnz skip
        movzx edx, word ptr [ebx].s_map_monster.hp
        lea edx, [edx+edx*4] ; 1/5th == 20%
        cmp byte ptr [ebx].s_map_monster.ai_type, 3 ; aggressive
        jne check_hp
        shl edx, 1 ; 1/10th == 10%
        check_hp:
        cmp edx, dword ptr [ebx].s_map_monster.max_hp
        ja skip
        turn:
        xor ax, 0x400 ; turn around
        skip:
        mov word ptr [ebx].s_map_monster.direction, ax ; replaced code
        ret
      }
}

// Implement the lightweight armor enchantment: it reduces the
// recovery penalty by 10 after any skill bonuses, but never below 0.
// Elven Chainmail and RDSM are also lightweight.
static void __declspec(naked) lightweight_armor(void)
{
    asm
      {
        call dword ptr ds:ftol ; replaced code
        mov ecx, dword ptr [esi+SLOT_BODY_ARMOR*4].s_player.equipment
        lea ecx, [ecx+ecx*8]
        cmp dword ptr [esi+S_PL_ITEM0+ecx*4], ELVEN_CHAINMAIL
        je lightweight
        cmp dword ptr [esi+S_PL_ITEM0+ecx*4], RED_DRAGON_SCALE_MAIL
        je lightweight
        cmp dword ptr [esi+S_PL_ITEM0+ecx*4].s_item.bonus2, SPC_LIGHTWEIGHT
        jne quit
        lightweight:
        sub eax, 10
        jge quit
        xor eax, eax
        quit:
        ret
      }
}

// Ditto, but for shields.  In practice, lightweight shields
// are only useful at Basic skill.
static void __declspec(naked) lightweight_shield(void)
{
    asm
      {
        call dword ptr ds:ftol ; replaced code
        mov ecx, dword ptr [esi+SLOT_OFFHAND*4].s_player.equipment
        lea ecx, [ecx+ecx*8]
        cmp dword ptr [esi+S_PL_ITEM0+ecx*4].s_item.bonus2, SPC_LIGHTWEIGHT
        jne quit
        sub eax, 10
        jge quit
        xor eax, eax
        quit:
        ret
      }
}

// In line with condition_resistances(), increase Int/Per dispel
// resistance effect fourfold: from (Int+Per)/2 to (Int+Per)*2.
static void __declspec(naked) dispel_chunk(void)
{
    asm
      {
        shl edi, 1
      }
}

// Let the items of Permanence (and Kelebrim) protect from enemy Dispel Magic.
// Also store which PCs resisted in ebx, for use later.
static void __declspec(naked) dispel_immunity(void)
{
    asm
      {
        shl ebx, 1 ; unaffected pcs bitbield
        inc ebx ; mark as resisted
        idiv edi ; replaced code
        cmp edx, 30 ; replaced code
        jge quit
        mov ecx, dword ptr [esi]
        push SPC_PERMANENCE
        call dword ptr ds:has_enchanted_item
        dec eax ; set flags
        jz immune
        mov ecx, dword ptr [esi]
        push SLOT_OFFHAND
        push KELEBRIM
        call dword ptr ds:has_item_in_slot
        dec eax ; set flags
        jz immune
        mov ecx, dword ptr [esi]
        push NORMAL ; does not matter
        push SPL_DISPEL_MAGIC
        call absorb_spell
        dec eax ; set flags
        immune:
        lea ebx, [ebx+eax] ; ebx-- if no immunity
        quit:
        ret ; next command is jge
      }
}

// Allow the party to resist global buff dispel.  Each buff is assigned
// to a random PC (unless it has a caster set), and if said PC resisted,
// the buff will not be dispelled.
static void __declspec(naked) dispel_party_buffs(void)
{
    asm
      {
        mov esi, PARTY_BUFF_ADDR
        check_buff:
        mov cl, byte ptr [esi].s_spell_buff.caster
        test cl, cl
        jnz has_caster
        call dword ptr ds:random
        mov cl, al
        and cl, 3
        inc cl
        has_caster:
        mov edx, 16
        shr edx, cl
        test edx, ebx
        jnz resisted
        mov ecx, esi
        call dword ptr ds:remove_buff
        resisted:
        add esi, SIZE_BUFF
        cmp esi, PARTY_ADDR
        jl check_buff
        xor ebx, ebx
        pop edx
        mov eax, dword ptr [ebp-4] ; replaced code
        push ebx ; replaced code
        push ebx ; replaced code
        jmp edx
      }
}

// Implement seven new enchantments that each boost one magic school slightly,
// plus a corresponding stat.  Intended mainly for lower-tlvl robes and staves.
// Also here: add various stat boni to condition immunity enchantments.
static void __declspec(naked) magic_school_affinity(void)
{
    asm
      {
        mov eax, dword ptr [eax+12].s_player.items ; replaced code
        cmp eax, SPC_BODY_AFFINITY
        ja quit
        cmp eax, SPC_FIRE_AFFINITY
        jae affinity
        cmp eax, SPC_PERMANENCE
        jne not_perm
        cmp esi, STAT_PERSONALITY
        je ten
        not_perm:
        cmp eax, SPC_IMMUNITY
        jb quit
        jne not_imm
        cmp esi, STAT_ENDURANCE
        je ten
        not_imm:
        cmp eax, SPC_MEDUSA
        ja quit
        jne not_med
        cmp esi, STAT_MAGIC_RES
        je fifteen
        not_med:
        cmp eax, SPC_SANITY
        jne not_san
        cmp esi, STAT_INTELLECT
        je ten
        not_san:
        cmp eax, SPC_ANTIDOTES
        jne not_ant
        cmp esi, STAT_POISON_RES
        je ten
        not_ant:
        cmp eax, SPC_ALARMS
        jne not_ala
        cmp esi, STAT_SPEED
        je five
        not_ala:
        cmp eax, SPC_FREEDOM
        jne quit
        cmp esi, STAT_MIND_RES
        jne quit
        fifteen:
        add edi, 15
        quit:
        ret
        affinity:
        sub ecx, eax ; ecx == stat + 1
        cmp ecx, STAT_FIRE_MAGIC + 1 - SPC_FIRE_AFFINITY
        jne not_magic
        cmp dword ptr [esp+24], 2 ; non-cumulative bonus
        jg quit
        mov dword ptr [esp+24], 2
        ret
        not_magic:
        cmp eax, SPC_EARTH_AFFINITY
        je earth
        ; next we have some math acrobatics...
        ; fire to water match the order of their resistances,
        ; and spirit to body match them in inverse
        ; so we check the difference or sum respectively
        ja ego
        cmp ecx, STAT_FIRE_RES + 1 - SPC_FIRE_AFFINITY
        je ten
        ret
        ego:
        lea ecx, [esi+eax]
        cmp ecx, STAT_POISON_RES + SPC_BODY_AFFINITY
        jne skip
        ten:
        add edi, 10
        ret
        earth:
        cmp esi, STAT_AC
        jne skip
        five:
        add edi, 5
        skip:
        ret
      }
}

// Now that's we have an alternative to the "of X magic" enchants,
// make sure that the latter don't cancel the former at low skill.
static void __declspec(naked) dont_lower_magic_bonus(void)
{
    asm
      {
        and eax, SKILL_MASK / 2 ; replaced code
        cmp dword ptr [esp+24], eax
        jg quit
        mov dword ptr [esp+24], eax ; replaced code
        quit:
        ret
      }
}

// Add +10/15 to-hit to wielded Blessed weapons.  This hook is for main hand.
// Also here: add +5 to-hit to Masterful clubs in lieu of skill bonus,
// and implement Sword of Light's extra +20 to-hit bonus.
static void __declspec(naked) blessed_rightnand_weapon(void)
{
    asm
      {
        cmp esi, STAT_MELEE_ATTACK
        mov ecx, dword ptr [ebx+S_PL_ITEM0+eax*4]
        jne skip
        lea edx, [ecx+ecx*2]
        shl edx, 4
        mov eax, dword ptr [ebx+S_PL_ITEM0+eax*4].s_item.bonus2
        cmp eax, SPC_BLESSED
        jne not_blessed
        add dword ptr [esp+20], 10 ; stat bonus
        cmp byte ptr [ITEMS_TXT_ADDR+edx].s_items_txt_item.equip_stat, \
            ITEM_TYPE_WEAPON2 - 1
        jne not_blessed
        cmp byte ptr [ITEMS_TXT_ADDR+edx].s_items_txt_item.skill, SKILL_SWORD
        je extra_blessed
        cmp byte ptr [ITEMS_TXT_ADDR+edx].s_items_txt_item.skill, SKILL_AXE
        jne not_blessed
        extra_blessed:
        add dword ptr [esp+20], 5
        not_blessed:
        cmp ecx, SWORD_OF_LIGHT
        jne not_sword
        add dword ptr [esp+20], 20
        not_sword:
        cmp eax, SPC_MASTERFUL
        jne skip
        cmp byte ptr [ITEMS_TXT_ADDR+edx].s_items_txt_item.skill, SKILL_NONE
        jne skip
        add dword ptr [esp+20], 5 ; club bonus
        skip:
        mov eax, ecx ; replaced code, effectively
        ret
      }
}

// Same, but for the offhand.  (Clubs or two-handers cannot occur here.)
static void __declspec(naked) blessed_offhand_weapon(void)
{
    asm
      {
        cmp esi, STAT_MELEE_ATTACK
        jne skip
        cmp dword ptr [ebx+S_PL_ITEM0+eax*4].s_item.bonus2, SPC_BLESSED
        jne not_blessed
        add dword ptr [esp+20], 10 ; stat bonus
        not_blessed:
        cmp dword ptr [ebx+S_PL_ITEM0+eax*4], SWORD_OF_LIGHT
        jne skip
        add dword ptr [esp+20], 20
        skip:
        mov ebx, dword ptr [ebx+S_PL_ITEM0+eax*4] ; replaced code
        ret
      }
}

// Same, but for the missile weapon.
static void __declspec(naked) blessed_missile_weapon(void)
{
    asm
      {
        cmp esi, STAT_RANGED_ATTACK
        jne skip
        cmp dword ptr [ebx+S_PL_ITEM0+eax*4].s_item.bonus2, SPC_BLESSED
        jne skip
        add dword ptr [esp+20], 10 ; stat bonus
        skip:
        mov ebx, dword ptr [ebx+S_PL_ITEM0+eax*4] ; replaced code
        ret
      }
}

// Implement a weapon enchantment that gives +5 to the weapon's skill.
// Called from champion_leadership() below.
static int __thiscall masterful_weapon(struct player *player, int skill)
{
    int bonus = 0;
    for (int slot = SLOT_OFFHAND; slot <= SLOT_MISSILE; slot++)
      {
        int equip = player->equipment[slot];
        if (!equip)
            continue;
        struct item *weapon = &player->items[equip-1];
        if (weapon->bonus2 != SPC_MASTERFUL || weapon->flags & IFLAGS_BROKEN)
            continue;
        if (ITEMS_TXT[weapon->id].skill == skill)
            bonus += 5;
      }
    return bonus;
}

// Make "of Doom" slightly more useful.
static void __declspec(naked) of_doom_bonus(void)
{
    asm
      {
        jg skip ; replaced jump
        add edi, 3 ; was 1
        skip:
        ret
      }
}

// Let's add some new item enchantments.
static inline void new_enchants(void)
{
    hook_call(0x4570a2, parse_prefix_flag, 5);
    hook_call(0x4565bd, read_prefix_flag, 8);
    erase_code(0x4565c7, 60); // old prefix code
    // Spectral weapons are handled in undead_slaying_element() above.
    // Implement the monster cursed condition.
    // start from debuff 0 (cursed)
    patch_dword(0x41ec01, offsetof(struct map_monster, spell_buffs));
    hook_call(0x41ec1e, display_cursed_debuff, 13);
    erase_code(0x41ede3, 1); // one more cycle
    // effect on spells handled in cast_new_spells() above
    // miss chance vs. player handled in train_armor() below
    hook_call(0x427373, cursed_monster_hits_monster, 5);
    hook_call(0x4275a0, cursed_monster_resists_damage, 5);
    patch_bytes(0x4275ad, mon_res_roll_chunk, 3);
    patch_bytes(0x4275bd, mon_res_roll_chunk, 3);
    patch_bytes(0x4275cd, mon_res_roll_chunk, 3);
    patch_bytes(0x4275dd, mon_res_roll_chunk, 3);
    // condition resistance is handled in pierce_debuff_resistance() above
    hook_call(0x439bb3, cursed_weapon, 7);
    // For symmetry, indirectly penalize cursed players' resistances
    // through reducing luck to 10% of base.
    byte(0x4ede62) = 10;
    hook_call(0x439b0b, soul_stealing_weapon, 5);
    hook_call(0x439536, reset_critical_hit, 5);
    hook_call(0x439863, check_backstab, 7);
    // backstab damage doubled in temp_bane_melee_2() above
    hook_call(0x402fe2, turn_afraid_monster, 7);
    hook_call(0x403ef9, turn_afraid_monster, 7);
    // Give the "assassins'" ench backstab as well, but remove disarm bonus.
    patch_dword(0x48f724, dword(0x48f700)); // skill bonus jumptable
    hook_call(0x48e376, lightweight_armor, 5);
    hook_call(0x48e3e7, lightweight_shield, 5);
    // leaping boots dealt with in feather_fall_jump() above
    // Let's tweak dispel mechanics while we're at it.
    patch_bytes(0x405471, dispel_chunk, 2);
    erase_code(0x405428, 23); // remove unconditional party buff dispel
    hook_call(0x40548a, dispel_immunity, 5);
    hook_call(0x4054d8, dispel_party_buffs, 5);
    hook_call(0x48f2df, magic_school_affinity, 6);
    // patch most x1.5 spell boni in the code
    // nb: we skip ethric's and taledon's as we don't need light/dark
    hook_call(0x48ef9c, dont_lower_magic_bonus, 7);
    hook_call(0x48efb8, dont_lower_magic_bonus, 7);
    hook_call(0x48efd0, dont_lower_magic_bonus, 7);
    hook_call(0x48f10a, dont_lower_magic_bonus, 7);
    hook_call(0x48f1c3, dont_lower_magic_bonus, 7);
    hook_call(0x48f1db, dont_lower_magic_bonus, 7);
    hook_call(0x48f1f4, dont_lower_magic_bonus, 7);
    patch_byte(0x48ed15, 3); // nerf "of power" ench bonus
    hook_call(0x48eca3, blessed_rightnand_weapon, 7);
    hook_call(0x48ecf1, blessed_offhand_weapon, 7);
    hook_call(0x48f5f6, blessed_missile_weapon, 7);
    // masterful clubs are in blessed_rightnand_weapon()
    // other masterful weapons are in champion_leadership() below
    hook_call(0x48f3f6, of_doom_bonus, 7);
    // Remove the old 2x slaying weapon damage (also deletes mm7patch hacks).
    erase_code(0x48d25c, 70); // missile
    erase_code(0x48ce7b, 95); // right hand
    erase_code(0x48cfa6, 95); // left hand
    // Improve the "+3 to two skills" boni to +5.
    patch_byte(0x48f4f0, 5); // monks' (check)
    patch_byte(0x48f4f4, 5); // monks' (bonus)
    patch_byte(0x48f502, 5); // thieves' (check)
    patch_byte(0x48f506, 5); // thieves' (bonus)
    patch_byte(0x48f514, 5); // of identifying (check)
    patch_byte(0x48f518, 5); // of identifying (bonus)
    patch_byte(0x48f521, 5); // all three (check)
    patch_byte(0x48f525, 5); // all three (bonus)
    // Also boost "of the Ocean".
    patch_byte(0x48f550, 10); // check
    patch_byte(0x48f554, 10); // bonus
}

// Let the Elven Chainmail also improve bow skill.
static void __declspec(naked) elven_chainmail_bow_bonus(void)
{
    asm
      {
        jne not_speed ; replaced jump
        add edi, 15 ; replaced code
        ret
        not_speed:
        cmp esi, 44 ; bow skill
        jne quit
        add dword ptr [esp+20], 5 ; bonus
        quit:
        ret
      }
}

// Implement the Sacrificial Dagger SP bonus.
// Also here: Headache's mental penalty, Ellinger's Robe magic boost,
// Sword of Light, Clover, Clanker's Amulet, Gardener's Gloves, Shadow's Mask,
// Sniper's Quiver and Fencer's Friend's boni.
static void __declspec(naked) artifact_stat_bonus(void)
{
    asm
      {
        cmp eax, SACRIFICIAL_DAGGER
        jne not_dagger
        cmp esi, STAT_SP
        jne quit
        add edi, 20
        ret
        not_dagger:
        cmp eax, HEADACHE
        jne not_headache
        cmp esi, STAT_INTELLECT
        je penalty
        cmp esi, STAT_PERSONALITY
        je penalty
        cmp esi, STAT_MIND_RES
        jne quit
        penalty:
        sub edi, 30
        ret
        not_headache:
        cmp eax, ELLINGERS_ROBE
        jne not_robe
        cmp esi, STAT_FIRE_MAGIC
        jb quit
        cmp esi, STAT_DARK_MAGIC
        ja quit
        add edi, 2
        ret
        not_robe:
        cmp eax, SWORD_OF_LIGHT
        jne not_sword
        cmp esi, STAT_LIGHT_MAGIC
        jne quit
        add edi, 5
        ret
        not_sword:
        cmp eax, CLOVER
        jne not_clover
        cmp esi, STAT_LUCK
        jne quit
        add edi, 50
        ret
        not_clover:
        cmp eax, CLANKERS_AMULET
        jne not_clanker
        cmp esi, STAT_ALCHEMY
        jne quit
        add dword ptr [esp+20], 10
        ret
        not_clanker:
        cmp eax, GARDENERS_GLOVES
        jne not_gloves
        push 0x48f387 ; earth magic bonus
        ret 4
        not_gloves:
        cmp eax, SHADOWS_MASK
        jne not_mask
        cmp esi, STAT_THIEVERY
        je bonus
        cmp esi, STAT_DISARM
        jne quit
        bonus:
        add dword ptr [esp+20], 3
        ret
        not_mask:
        cmp eax, SNIPERS_QUIVER
        jne not_quiver
        cmp esi, STAT_BOW
        jne quit
        add dword ptr [esp+20], 8
        ret
        not_quiver:
        cmp eax, FENCERS_FRIEND
        jne not_friend
        cmp esi, STAT_AC
        jne quit
        add edi, 10
        not_friend:
        sub eax, PUCK ; replaced code
        quit:
        ret
      }
}

// Restrict the Sacrificial Dagger to goblins in the same way as Elfbane.
// Also here: restrict Sword of Light to Good PCs, like Justice.
static void __declspec(naked) sacrificial_dagger_goblin_only(void)
{
    asm
      {
        mov edx, MINDS_EYE ; replaced code
        cmp eax, SACRIFICIAL_DAGGER
        jne not_dagger
        mov eax, ELFBANE
        not_dagger:
        cmp eax, SWORD_OF_LIGHT
        jne not_sword
        mov eax, JUSTICE
        not_sword:
        ret
      }
}

// RDSM and robe worn image templates and coordinates.
static char rdsm_body[] = "itemrdsmv0";
static char rdsm_arm1[] = "itemrdsmv0a1";
static char rdsm_arm2[] = "itemrdsmv0a2";
static const int rdsm_body_xy[] = { 491, 101, 496, 107, 488, 137, 497, 140, };
static const int rdsm_arm1_xy[] = { 582, 104, 580, 106, 577, 135, 593, 144, };
static const int rdsm_arm2_xy[] = { 530, 105, 541, 108, 529, 137, 533, 143, };
static char robp_body[] = "itemrobpv0";
static char robp_arm1[] = "itemrobpv0a1";
static char robp_arm2[] = "itemrobpv0a2";
static const int robp_body_xy[] = { 494, 103, 496, 107, 489, 139, 496, 140, };
static const int robp_arm1_xy[] = { 592, 104, 581, 107, 590, 139, 595, 141, };
static const int robp_arm2_xy[] = { 531, 103, 538, 107, 531, 139, 532, 140, };
static char robm_body[] = "itemrobmv0";
static char robm_arm1[] = "itemrobmv0a1";
static char robm_arm2[] = "itemrobmv0a2";
static const int robm_body_xy[] = { 494, 100, 496, 102, 489, 136, 497, 141, };
static const int robm_arm1_xy[] = { 590, 104, 581, 106, 594, 138, 596, 143, };
static const int robm_arm2_xy[] = { 531,  99, 538, 107, 530, 138, 537, 141, };
static char robw_body[] = "itemrobwv0";
static char robw_arm1[] = "itemrobwv0a1";
static char robw_arm2[] = "itemrobwv0a2";
static const int robw_body_xy[] = { 494, 100, 497, 106, 488, 137, 495, 140, };
static const int robw_arm1_xy[] = { 593, 103, 581, 107, 590, 137, 595, 141, };
static const int robw_arm2_xy[] = { 530, 100, 538, 107, 528, 137, 531, 140, };
// the next two are recolors and so use the same xy
static char robe_body[] = "itemrobev0";
static char robe_arm1[] = "itemrobev0a1";
static char robe_arm2[] = "itemrobev0a2";
static char roba_body[] = "itemrobav0";
static char roba_arm1[] = "itemrobav0a1";
static char roba_arm2[] = "itemrobav0a2";

// Substitute our graphics and coordinates for worn RDSM/robe (w/o right arm).
static void __declspec(naked) display_worn_rdsm_body(void)
{
    asm
      {
        cmp ecx, RED_DRAGON_SCALE_MAIL
        je rdsm
        cmp ecx, PILGRIMS_ROBE
        je robp
        cmp ecx, MARTIAL_ROBE
        je robm
        cmp ecx, WIZARDS_ROBE
        je robw
        cmp ecx, ELLINGERS_ROBE
        je robe
        cmp ecx, ROBE_OF_THE_ARCHMAGISTER
        je roba
        sub eax, GOVERNORS_ARMOR ; replaced code
        ret
        rdsm:
        mov ecx, offset rdsm_body
        mov edi, offset rdsm_body_xy
        jmp coords
        robp:
        mov ecx, offset robp_body
        mov edi, offset robp_body_xy
        jmp coords
        robm:
        mov ecx, offset robm_body
        mov edi, offset robm_body_xy
        jmp coords
        robw:
        mov ecx, offset robw_body
        jmp robw_xy
        robe:
        mov ecx, offset robe_body
        jmp robw_xy
        roba:
        mov ecx, offset roba_body
        robw_xy:
        mov edi, offset robw_body_xy
        coords:
        mov ebx, dword ptr [edx].s_item.flags ; preserve
        mov eax, dword ptr [esp+40] ; body type
        mov edx, dword ptr [edi+eax*8]
        mov edi, dword ptr [edi+eax*8+4]
        mov dword ptr [esp+24], edx
        mov dword ptr [esp+20], edi
        add eax, '1'
        mov byte ptr [ecx+9], al
        push 2
        push ecx
        mov ecx, ICONS_LOD_ADDR
        call dword ptr ds:load_bitmap
        xchg eax, ebx
        push 0x43d4a1 ; code after setting coords
        ret 4
      }
}

// For the left arm code.  The vanilla armors are 0 to 17.
#define RDSM_INDEX 18
#define ROBP_INDEX 19
#define ROBM_INDEX 20
#define ROBW_INDEX 21
#define ROBE_INDEX 22
#define ROBA_INDEX 23

// Pass the check for displaying armor left arm.
static void __declspec(naked) display_worn_rdsm_arm(void)
{
    asm
      {
        cmp ecx, RED_DRAGON_SCALE_MAIL
        je rdsm
        cmp ecx, PILGRIMS_ROBE
        je robp
        cmp ecx, MARTIAL_ROBE
        je robm
        cmp ecx, WIZARDS_ROBE
        je robw
        cmp ecx, ELLINGERS_ROBE
        je robe
        cmp ecx, ROBE_OF_THE_ARCHMAGISTER
        je roba
        sub eax, GOVERNORS_ARMOR ; replaced code
        ret
        rdsm:
        mov edi, RDSM_INDEX
        jmp quit
        robp:
        mov edi, ROBP_INDEX
        jmp quit
        robm:
        mov edi, ROBM_INDEX
        jmp quit
        robw:
        mov edi, ROBW_INDEX
        jmp quit
        robe:
        mov edi, ROBE_INDEX
        jmp quit
        roba:
        mov edi, ROBA_INDEX
        quit:
        push 0x43db65 ; code after choosing index
        ret 4
      }
}

// Supply graphics info and coordinates for RDSM/robe left arm
// when the PC is holding a two-handed weapon.
// There's a check for whether the gfx are present which we skip.
static void __declspec(naked) display_worn_rdsm_arm_2h(void)
{
    asm
      {
        cmp edi, RDSM_INDEX
        je rdsm
        cmp edi, ROBP_INDEX
        je robp
        cmp edi, ROBM_INDEX
        je robm
        cmp edi, ROBW_INDEX
        je robw
        cmp edi, ROBE_INDEX
        je robe
        cmp edi, ROBA_INDEX
        je roba
        imul eax, eax, 17 ; replaced code
        add edi, eax ; replaced code
        ret
        rdsm:
        mov edx, offset rdsm_arm2
        mov ebx, offset rdsm_arm2_xy
        jmp coords
        robp:
        mov edx, offset robp_arm2 ; currently no arm2
        mov ebx, offset robp_arm2_xy
        jmp coords
        robm:
        mov edx, offset robm_arm2
        mov ebx, offset robm_arm2_xy
        jmp coords
        robw:
        mov edx, offset robw_arm2
        jmp robw_xy
        robe:
        mov edx, offset robe_arm2
        jmp robw_xy
        roba:
        mov edx, offset roba_arm2
        robw_xy:
        mov ebx, offset robw_arm2_xy
        coords:
        mov ecx, dword ptr [ebx+eax*8]
        test ecx, ecx
        jz skip
        mov ebx, dword ptr [ebx+eax*8+4]
        mov dword ptr [esp+28], ecx
        add eax, '1'
        mov byte ptr [edx+9], al
        push 2
        push edx
        mov ecx, ICONS_LOD_ADDR
        call dword ptr ds:load_bitmap
        xchg eax, ebx
        push 0x43dc10 ; code after setting coords
        ret 8
        skip:
        push 0x43deb6 ; skip the arm code
        ret 8
      }
}

// Ditto, but for left arm in its default position.
static void __declspec(naked) display_worn_rdsm_arm_idle(void)
{
    asm
      {
        cmp edi, RDSM_INDEX
        je rdsm
        cmp edi, ROBP_INDEX
        je robp
        cmp edi, ROBM_INDEX
        je robm
        cmp edi, ROBW_INDEX
        je robw
        cmp edi, ROBE_INDEX
        je robe
        cmp edi, ROBA_INDEX
        je roba
        imul eax, eax, 17 ; replaced code
        add edi, eax ; replaced code
        ret
        rdsm:
        mov edx, offset rdsm_arm1
        mov ecx, offset rdsm_arm1_xy
        jmp coords
        robp:
        mov edx, offset robp_arm1
        mov ecx, offset robp_arm1_xy
        jmp coords
        robm:
        mov edx, offset robm_arm1
        mov ecx, offset robm_arm1_xy
        jmp coords
        robw:
        mov edx, offset robw_arm1
        jmp robw_xy
        robe:
        mov edx, offset robe_arm1
        jmp robw_xy
        roba:
        mov edx, offset roba_arm1
        robw_xy:
        mov ecx, offset robw_arm1_xy
        coords:
        mov ebx, dword ptr [ecx+eax*8]
        test ebx, ebx
        jz skip
        mov edi, dword ptr [ecx+eax*8+4]
        add eax, '1'
        mov byte ptr [edx+9], al
        push 2
        push edx
        mov ecx, ICONS_LOD_ADDR
        call dword ptr ds:load_bitmap
        xchg eax, ebx
        mov ecx, edi
        mov edx, dword ptr [esp+52] ; worn item
        mov edx, dword ptr [edx+S_PL_ITEM0].s_item.flags
        push 0x43dd7d ; code after setting coords
        ret 8
        skip:
        push 0x43deb6 ; skip the arm code
        ret 8
      }
}

// TODO: maybe unhardcode the constant (it's in items.txt)
#define MAX_DRAGON_CHARGES 17

// Set the max and current charges for Dragon's Wrath to fixed 17.
// Also initialise the recharge timer (uses temp ench timer field).
static void __declspec(naked) set_dragon_charges(void)
{
    asm
      {
        cmp eax, DRAGONS_WRATH
        jne not_it
        cmp byte ptr [edx].s_item.max_charges, MAX_DRAGON_CHARGES
        je not_it ; make sure it`s not inited
        mov dword ptr [edx].s_item.charges, MAX_DRAGON_CHARGES
        mov byte ptr [edx].s_item.max_charges, MAX_DRAGON_CHARGES
        mov eax, dword ptr [CURRENT_TIME_ADDR]
        mov dword ptr [edx].s_item.temp_ench_time, eax
        mov eax, dword ptr [CURRENT_TIME_ADDR+4]
        mov dword ptr [edx+4].s_item.temp_ench_time, eax
        mov eax, dword ptr [edx] ; restore
        not_it:
        lea eax, [eax+eax*2] ; replaced code
        shl eax, 4 ; replaced code
        ret
      }
}

// Consider Dragon's Wrath a wand for status screen purposes.
static void __declspec(naked) check_dragon_wand(void)
{
    asm
      {
        cmp esi, DRAGONS_WRATH
        je quit
        cmp esi, LAST_WAND ; replaced code
        quit:
        ret
      }
}

// 30 minutes in game ticks, used as a division constant.
static const int half_hour = 30 * MINUTE;

// Defined below.
static void regen_living_knives(void);

// Restore Dragon's Wrath charges at the rate of 2/hour.
// Also here: regen the +3 throwing knives in a similar way.
static void __declspec(naked) regen_dragon_charges(void)
{
    asm
      {
        cmp dword ptr [ecx], DRAGONS_WRATH
        je dragon
        cmp dword ptr [ecx], LIVING_WOOD_KNIVES
        jne skip
        call regen_living_knives
        skip:
        mov eax, dword ptr [ecx].s_item.flags ; replaced code
        test al, 8 ; replaced code
        ret
        dragon:
        mov eax, dword ptr [CURRENT_TIME_ADDR]
        mov edx, dword ptr [CURRENT_TIME_ADDR+4]
        sub eax, dword ptr [ecx].s_item.temp_ench_time
        sbb edx, dword ptr [ecx+4].s_item.temp_ench_time
        idiv dword ptr [half_hour]
        cmp eax, 0
        jle quit
        cmp dword ptr [ecx].s_item.charges, MAX_DRAGON_CHARGES
        jae full
        add dword ptr [ecx].s_item.charges, eax
        cmp dword ptr [ecx].s_item.charges, MAX_DRAGON_CHARGES
        jbe full
        mov dword ptr [ecx].s_item.charges, MAX_DRAGON_CHARGES
        full:
        mov eax, dword ptr [CURRENT_TIME_ADDR]
        sub eax, edx ; set last charge regen time to remainder
        mov edx, dword ptr [CURRENT_TIME_ADDR+4]
        sbb edx, 0 ; (full half-hours are spent now)
        mov dword ptr [ecx].s_item.temp_ench_time, eax
        mov dword ptr [ecx+4].s_item.temp_ench_time, edx
        quit:
        xor eax, eax ; set zf
        ret
      }
}

// Check if some charges have regenerated before trying to shoot.
static void __declspec(naked) regen_dragon_shooting(void)
{
    asm
      {
        lea ecx, [eax-SIZE_ITEM].s_player.items
        call regen_dragon_charges ; works here too
        cmp dword ptr [ecx].s_item.charges, edi ; replaced code, basically
        mov ecx, dword ptr [ecx] ; just in case
        ret
      }
}

// Disallow casting Recharge Item on Dragon's Wrath.
static void __declspec(naked) cannot_recharge_dragon(void)
{
    asm
      {
        cmp dword ptr [ecx], DRAGONS_WRATH
        je cant
        cmp byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.equip_stat, \
            ITEM_TYPE_WAND - 1 ; replaced code
        ret
        cant:
        cmp ecx, esi ; unset zf
        ret
      }
}

// Get a random artifact ID, minding the gap between the new and old ones.
// Also here: don't count guaranteed artifacts towards the artifact limit.
static void __declspec(naked) random_artifact(void)
{
    asm
      {
        and dword ptr [ebp+12], 0x7f ; art counter
        xor edx, edx
        mov ecx, LAST_OLD_ARTIFACT - FIRST_ARTIFACT + 1
        add ecx, LAST_ARTIFACT - FIRST_NEW_ARTIFACT + 1
        div ecx
        cmp edx, LAST_OLD_ARTIFACT - FIRST_ARTIFACT
        jbe quit
        add edx, FIRST_NEW_ARTIFACT - LAST_OLD_ARTIFACT - 1
        quit:
        ret
      }
}

// Don't iterate over non-randomly-generated specitems
// when searching for an artifact to create.
// NB: this breaks MM7Patch's FixUnmarkedArtifactsMax,
// but we'll want to replace it anyway
static void __declspec(naked) jump_over_specitems(void)
{
    asm
      {
        cmp eax, LAST_OLD_ARTIFACT + 1 ; replaced code
        jl quit
        jg new
        mov eax, FIRST_NEW_ARTIFACT
        new:
        cmp eax, LAST_ARTIFACT + 1
        quit:
        ret
      }
}

// Let Headache deal extra Mind damage on hit.  Also here: Storm Trident has
// the same bonus damage as Iron Feather, and Viper deals 15 poison damage.
// Items "of The Jester" also do bonus Mind damage, and Fire Aura-specific
// nerfed "of Infernos" enchantment does the same 3d6 Fire as the regular one.
// Finally, Fencer's Friend has the Vampiric property.
static void __declspec(naked) headache_mind_damage(void)
{
    asm
      {
        cmp eax, HEADACHE
        je headache
        cmp eax, VIPER
        je viper
        cmp eax, STORM_TRIDENT
        je skip
        cmp eax, FENCERS_FRIEND
        je friend
        cmp dword ptr [ebx].s_item.bonus2, SPC_JESTER
        je jester
        cmp dword ptr [ebx].s_item.bonus2, SPC_INFERNOS_2
        je infernos
        sub eax, IRON_FEATHER ; replaced code
        skip:
        ret
        headache:
        call dword ptr ds:random
        xor edx, edx
        mov ecx, 6
        div ecx
        lea eax, [edx+10]
        jmp mind
        jester:
        call dword ptr ds:random
        xor edx, edx
        mov ecx, 5
        div ecx
        lea eax, [edx+6]
        mind:
        mov dword ptr [edi], MIND
        jmp quit
        viper:
        mov dword ptr [edi], POISON
        mov eax, 15
        quit:
        push 0x439fe8 ; return from calling func
        ret 4
        infernos:
        mov ecx, 3
        mov edx, 6
        mov dword ptr [esp], 0x439eb9 ; roll dice code
        ret
        friend:
        mov dword ptr [esp], 0x439f58 ; vampiric code
        ret
      }
}

// Headache also has a 20% (40% with FF) chance to cause Berserk.
// Called from cursed_weapon() above.
static void __stdcall headache_berserk(struct player *player,
                                       struct map_monster *monster)
{
    int skill = get_skill(player, SKILL_AXE);
    if (random() % 5 > has_item_in_slot(player, FENCERS_FRIEND, SLOT_ANY)
        || !debuff_monster(monster, MIND, skill & SKILL_MASK))
        return;
    remove_buff(monster->spell_buffs + MBUFF_CHARM);
    remove_buff(monster->spell_buffs + MBUFF_ENSLAVE);
    int mastery = skill_mastery(skill);
    if (mastery < EXPERT)
        mastery = EXPERT;
    add_buff(monster->spell_buffs + MBUFF_BERSERK,
             CURRENT_TIME + (15 << (mastery - 2)) * MINUTE,
             mastery, 0, 0, 0);
    struct map_object anim = { OBJ_BERSERK,
                               find_objlist_item(OBJLIST_THIS, OBJ_BERSERK),
                               monster->x, monster->y,
                               monster->z + monster->height };
    launch_object(&anim, 0, 0, 0, 0);
    make_sound(SOUND_THIS, word(SPELL_SOUNDS + SPL_BERSERK * 2),
               0, 0, -1, 0, 0, 0, 0);
}

// Use Lightning Bolt graphics in the spellbook if PC has the Storm Trident.
static void __declspec(naked) check_lightning_image(void)
{
    asm
      {
        mov eax, dword ptr [ebp-8] ; replaced code
        cmp byte ptr [eax+edi], 0 ; replaced code
        jnz quit
        cmp esi, 1 ; air
        jne nope
        cmp edi, 7 ; lightning bolt
        jne nope
        mov ecx, dword ptr [CURRENT_PLAYER]
        mov ecx, dword ptr [PC_POINTERS+ecx*4-4]
        push SLOT_MAIN_HAND
        push STORM_TRIDENT
        call dword ptr ds:has_item_in_slot
        test eax, eax
        ret
        nope:
        xor eax, eax ; set zf
        quit:
        ret
      }
}

// Also make the Lighning Bolt icon clickable.
static void __declspec(naked) check_lightning_button(void)
{
    asm
      {
        mov eax, dword ptr [esp+24] ; replaced code
        cmp byte ptr [eax+ebp], bl ; replaced code
        jnz quit
        cmp ebp, 6 ; lightning bolt
        jne nope
        cmp byte ptr [edi+0x1a4e], 1 ; air
        jne nope
        mov ecx, edi
        push SLOT_MAIN_HAND
        push STORM_TRIDENT
        call dword ptr ds:has_item_in_slot
        test eax, eax
        ret
        nope:
        xor eax, eax ; set zf
        quit:
        ret
      }
}

// Check for Trident-enabled LB on graphics redraw.
static void __declspec(naked) check_lightning_redraw(void)
{
    asm
      {
        lea eax, [ebx+ebp-1].s_player.spells_known ; replaced code
        cmp byte ptr [eax+esi], 0 ; replaced code
        jnz quit
        cmp ebp, 11 ; air
        jne nope
        cmp esi, 7 ; lightning bolt
        jne nope
        mov ecx, ebx
        push SLOT_MAIN_HAND
        push STORM_TRIDENT
        call dword ptr ds:has_item_in_slot
        test eax, eax
        ret
        nope:
        xor eax, eax ; set zf
        quit:
        ret
      }
}

// The spellbook mouseover spell check.
static void __declspec(naked) check_lightning_mouseover(void)
{
    asm
      {
        cmp byte ptr [ecx+eax].s_player.spells_known, bl ; replaced code
        jnz quit
        cmp eax, 6 ; lightning bolt
        jne nope
        mov ecx, dword ptr [esp+36] ; player
        cmp byte ptr [ecx].s_player.spellbook_page, 1 ; air
        jne nope
        push SLOT_MAIN_HAND
        push STORM_TRIDENT
        call dword ptr ds:has_item_in_slot
        test eax, eax
        ret
        nope:
        xor eax, eax ; set zf
        quit:
        ret
      }
}

// Click-on-spell-icon action.
static void __declspec(naked) check_lightning_click(void)
{
    asm
      {
        cmp byte ptr [ecx+eax].s_player.spells_known, bl ; replaced code
        jnz quit
        cmp eax, 6 ; lightning bolt
        jne nope
        mov ecx, dword ptr [esp+36] ; player
        cmp byte ptr [ecx].s_player.spellbook_page, 1 ; air
        jne nope
        push SLOT_MAIN_HAND
        push STORM_TRIDENT
        call dword ptr ds:has_item_in_slot
        test eax, eax
        mov eax, dword ptr [esp+24] ; restore
        ret
        nope:
        xor ebx, ebx ; set zf
        quit:
        ret
      }
}

// Enable the Air spellbook tab if Storm Trident is equipped.
static void __declspec(naked) check_air_button(void)
{
    asm
      {
        cmp word ptr [edi+SKILL_AIR*2].s_player.skills, bx ; replaced code
        jnz quit
        mov ecx, edi
        push SLOT_MAIN_HAND
        push STORM_TRIDENT
        call dword ptr ds:has_item_in_slot
        test eax, eax
        quit:
        ret
      }
}

// Actually draw the Air tab under the same conditions.
static void __declspec(naked) check_air_redraw(void)
{
    asm
      {
        mov eax, dword ptr [esp+28] ; replaced code
        cmp word ptr [eax], 0 ; replaced code
        jnz quit
        cmp ecx, 1 ; air
        jne nope
        mov ecx, ebx
        push SLOT_MAIN_HAND
        push STORM_TRIDENT
        call dword ptr ds:has_item_in_slot
        mov ecx, dword ptr [esp+20] ; restore
        test eax, eax
        ret
        nope:
        xor eax, eax ; set zf
        quit:
        ret
      }
}

// Cast Storm Trident's LB as a quick spell even with no SP.
// Also here: increase effective SP cost at higher difficulties.
static void __declspec(naked) free_quick_lightning(void)
{
    asm
      {
        cmp dword ptr [elemdata.difficulty], edi ; == 0
        jz easy
        mov ebx, eax
        shr ebx, 1
        cmp dword ptr [elemdata.difficulty], 2
        jae raise
        shr ebx, 1
        raise:
        add eax, ebx
        easy:
        cmp eax, dword ptr [esi].s_player.sp ; replaced code
        jle quit
        cmp ecx, SPL_LIGHTNING_BOLT
        jne nope
        mov ecx, esi
        push SLOT_MAIN_HAND
        push STORM_TRIDENT
        call dword ptr ds:has_item_in_slot
        test eax, eax
        jz nope
        xor eax, eax ; set zf
        ret
        nope:
        cmp esi, 0 ; set flags
        quit:
        ret
      }
}

// Use Spear skill instead of Air for Storm Trident's LB.
// Also fail if the spell is unknown and trident isn't equipped.
static void __declspec(naked) lightning_spear_skill(void)
{
    asm
      {
        cmp word ptr [ebx+10], si ; not zero if scroll/wand
        jnz pass
        mov ecx, dword ptr [ebp-32] ; PC
        test byte ptr [ebx+9], 4 ; flag means 'cast from trident' here
        jnz trident
        cmp byte ptr [ecx+SPL_LIGHTNING_BOLT-1].s_player.spells_known, 0
        jnz pass
        mov eax, 0x4290c1 ; fail spell
        jmp eax
        trident:
        push SKILL_SPEAR
        call dword ptr ds:get_skill
        mov edi, eax
        and edi, SKILL_MASK
        mov ecx, eax
        call dword ptr ds:skill_mastery
        mov dword ptr [ebp-24], eax
        movzx eax, word ptr [SPELL_INFO_ADDR+SPL_LIGHTNING_BOLT*SIZE_SPL_INFO \
                             +eax*2-2].s_spell_info.delay_normal
        mov dword ptr [ebp-180], eax ; recovery
        pass:
        mov eax, 0x4289b3 ; attack spells
        jmp eax
      }
}

// Finally, let the Trident grant water walking.
static void __declspec(naked) storm_trident_water_walking(void)
{
    asm
      {
        push SLOT_MAIN_HAND
        push STORM_TRIDENT
        call dword ptr ds:has_item_in_slot
        test eax, eax
        jz nope
        ret 4
        nope:
        jmp dword ptr ds:has_enchanted_item ; replaced call
      }
}

// Let Ellinger's Robe bestow the effects of Preservation buff.
static void __declspec(naked) ellingers_robe_preservation(void)
{
    asm
      {
        push SLOT_BODY_ARMOR
        push ELLINGERS_ROBE
        mov ecx, esi
        call dword ptr ds:has_item_in_slot
        test eax, eax
        jg quit
        cmp dword ptr [esi+PBUFF_PRESERVATION*SIZE_BUFF+4] \
                      .s_player.spell_buffs, 0 ; replaced code
        quit:
        ret
      }
}

// Viper has a 20% chance to inflict Slow.  Called from cursed_weapon() above.
static void __stdcall viper_slow(struct player *player,
                                 struct map_monster *monster)
{
    int skill = get_skill(player, SKILL_STAFF);
    if (random() % 5 || !debuff_monster(monster, MAGIC, skill & SKILL_MASK))
        return;
    int mastery = skill_mastery(skill);
    add_buff(monster->spell_buffs + MBUFF_SLOW,
             CURRENT_TIME + (mastery <= 1 ? 5 : 20) * MINUTE, mastery,
             (mastery <= 2 ? 2 : mastery == 3 ? 4 : 8), 0, 0);
    magic_sparkles(monster, 0);
    make_sound(SOUND_THIS, word(SPELL_SOUNDS + SPL_SLOW * 2),
               0, 0, -1, 0, 0, 0, 0);
}

// Save the party position when using Temple in a Bottle.
static void save_temple_beacon(void)
{
    elemdata.bottle = (struct beacon) {
        dword(PARTY_X), dword(PARTY_Y), dword(PARTY_Z), dword(PARTY_DIR),
        dword(PARTY_LOOK_ANGLE), dword(CURRENT_MAP_ID) - 1,
    };
    change_bit(QBITS, QBIT_TEMPLE_UNDERWATER,
               !uncased_strcmp(CUR_MAP_FILENAME, MAP_SHOALS));
}

// Hook for the above.
static void __declspec(naked) save_temple_beacon_hook(void)
{
    asm
      {
        call save_temple_beacon
        xor esi, esi ; replaced code
        xor edx, edx ; ditto
        mov ecx, edi ; and this too
        ret
      }
}

// Disallow using TiaB in Arena, as this would reset it anyway.
static void __declspec(naked) bottle_in_arena(void)
{
    asm
      {
        push dword ptr [esp+8] ; map filename
        push MAP_ARENA_ADDR
        call dword ptr ds:uncased_strcmp
        test eax, eax
        jz forbid
        mov dword ptr [esp], edi ; bottle temple filename
        call dword ptr ds:uncased_strcmp
        test eax, eax
        jz forbid
        add esp, 8
        ret
        forbid:
        add esp, 8
        push eax
        push eax
        push eax
        push eax
        push -1
        push eax
        push eax
        push SOUND_BUZZ
        mov ecx, SOUND_THIS_ADDR
        call dword ptr ds:make_sound
        xor eax, eax
        ret
      }
}

// Pseudo-map marker for MoveToMap event that is used in temple's exit door.
static const char leavetiab[] = "leavetiab";
static int tiab_strcmp; // so as not to compare twice

// Provide stored coords when leaving temple in a bottle.
static void __declspec(naked) movemap_leavetiab(void)
{
    asm
      {
        mov dword ptr [esp+60], eax ; replaced code
        lea eax, [esi+31]
        push eax
#ifdef __clang__
        mov eax, offset leavetiab
        push eax
#else
        push offset leavetiab
#endif
        call dword ptr ds:uncased_strcmp
        add esp, 8
        mov dword ptr [tiab_strcmp], eax ; for later
        test eax, eax
        jnz quit
        mov eax, dword ptr [elemdata.bottle.x]
        mov dword ptr [esp+64], eax
        mov eax, dword ptr [elemdata.bottle.y]
        mov dword ptr [esp+52], eax
        mov eax, dword ptr [elemdata.bottle.z]
        mov dword ptr [esp+32], eax
        movsx eax, word ptr [elemdata.bottle.direction]
        mov dword ptr [esp+40], eax
        movsx ebp, word ptr [elemdata.bottle.look_angle]
        quit:
        mov eax, dword ptr [esp+60] ; restore
        mov ecx, dword ptr [esp+64] ; same
        cmp byte ptr [esi+29], bl ; replaced code
        ret
      }
}

// Provide stored map name; immediate teleport branch.
static void __declspec(naked) movemap_immediate(void)
{
    asm
      {
        mov dword ptr [0x576cbc], eax ; replaced code
        cmp dword ptr [tiab_strcmp], ebx
        jnz quit
        mov eax, SIZE_MAPSTAT
        mul dword ptr [elemdata.bottle.map_index]
        mov ecx, dword ptr [MAPSTATS_ADDR+eax].s_mapstats_item.file_name
        quit:
        ret
      }
}

// Provide stored map name; exit dialogue branch.
static void __declspec(naked) movemap_dialog(void)
{
    asm
      {
        add edi, eax ; replaced code
        cmp dword ptr [tiab_strcmp], ebx
        jz tiab
        lea eax, [edi+31] ; replaced code
        ret
        tiab:
        mov eax, SIZE_MAPSTAT
        mul dword ptr [elemdata.bottle.map_index]
        mov eax, dword ptr [MAPSTATS_ADDR+eax].s_mapstats_item.file_name
        ret
      }
}

// Because neutral reputation would prevent ordinary blessings, add
// a rep-independent Pain Reflection for temple in a bottle instead.
static void __declspec(naked) bottle_temple_blessing(void)
{
    asm
      {
        movzx eax, byte ptr [0xf8b06f+ecx] ; replaced code
        cmp eax, edx ; replaced code
        jne quit
        mov eax, dword ptr [DIALOG2]
        mov eax, dword ptr [eax+28] ; temple id
        cmp eax, 87 ; temple in a bottle
        jne skip
        push ebx
        push 48
        lea edx, [SKILL_GM+20+edx+1] ; we know the temple power
        push edx
        lea edx, [ecx-1]
        mov ecx, SPL_PAIN_REFLECTION
        call dword ptr ds:aim_spell
        mov ecx, dword ptr [CURRENT_PLAYER]
        cmp ecx, ebx ; clear zf
        ret
        skip:
        xor eax, eax ; set zf
        quit:
        ret
      }
}

// Consider the temple in a bottle as "dark" (raises zombies).
static void __declspec(naked) dark_bottle_temple(void)
{
    asm
      {
        mov eax, dword ptr [eax+28] ; replaced code (temple id)
        cmp eax, 78 ; replaced code (deyja temple)
        jz quit
        cmp eax, 87 ; temple in a bottle
        quit:
        ret
      }
}

// Allow using Oghma Infinium and the bag of holding, by dragging the item
// to the character's portrait.  Both new arts cannot be used unidentified.
// Golden apples are also handled here (no ID check for them), and so are
// wine bottles (ordinary and magical both) and the Arena hourglass reward.
// Finally, there's Clanker's Journal which does require identification.
static void __declspec(naked) new_consumable_items(void)
{
    asm
      {
        cmp eax, MAGIC_WINE
        je magic
        cmp eax, WINE_BOTTLE
        je wine
        cmp eax, HOURGLASS_OF_IMPATIENCE
        je hourglass
        cmp eax, GOLDEN_APPLE
        jne not_apple
        mov ecx, dword ptr [ebp+8] ; player id
        dec ecx
        push ecx
        push SPL_REGENERATION
        mov eax, 5 * ONE_HOUR
        mov edx, dword ptr [CURRENT_TIME_ADDR+4]
        add eax, dword ptr [CURRENT_TIME_ADDR]
        adc edx, ebx ; ebx == 0
        push ebx
        push ebx
        push 10 ; regen power
        push GM
        push edx
        push eax
        push ebx
        push ebx
        push ebx
        push GM
        push edx
        push eax
        imul ecx, ecx, NBUFF_COUNT * SIZE_BUFF
        lea ecx, [elemdata.new_pc_buffs+ecx+NBUFF_FIRE_IMM*SIZE_BUFF]
        call dword ptr ds:add_buff
        lea ecx, [esi+PBUFF_REGENERATION*SIZE_BUFF].s_player.spell_buffs
        call dword ptr ds:add_buff
        mov ecx, dword ptr [CGAME]
        mov ecx, dword ptr [ecx+0xe50]
        call dword ptr ds:spell_face_anim
        mov eax, RED_APPLE ; also ordinary apple effects
        not_apple:
        test byte ptr [MOUSE_ITEM].s_item.flags, IFLAGS_ID
        jz not_it
        cmp eax, OGHMA_INFINIUM
        je oghma
        cmp eax, BAG_OF_HOLDING
        je bag
        cmp eax, CLANKERS_JOURNAL
        je journal
        not_it:
        sub eax, 616 ; replaced code
        ret
        oghma:
        add dword ptr [esi].s_player.skill_points, 80
        sub dword ptr [esi].s_player.birth_year, 20
        add word ptr [esi].s_player.age_bonus, 20
        mov ecx, dword ptr [CGAME]
        mov ecx, dword ptr [ecx+0xe50]
        mov eax, dword ptr [ebp+8]
        dec eax
        push eax
        push SPL_FEATHER_FALL
        call dword ptr ds:spell_face_anim
        push ebx ; unused
        push ANIM_LEARN
        mov ecx, esi
        call dword ptr ds:show_face_animation
        jmp remove
        magic:
        mov ecx, 7
        stat_loop:
        cmp word ptr [esi+S_PL_STATS+ecx*4-4], NATURAL_STAT_LIMIT
        jge stat_limit
        inc word ptr [esi+S_PL_STATS+ecx*4-4]
        stat_limit:
        loop stat_loop
        mov ecx, 9
        res_loop:
        cmp ecx, 6 ; skip unused res
        jne ok_res
        dec ecx
        dec ecx
        ok_res:
        cmp word ptr [esi+S_PL_RES+ecx*2-2], NATURAL_STAT_LIMIT
        jge res_limit
        inc word ptr [esi+S_PL_RES+ecx*2-2]
        res_limit:
        loop res_loop
        mov ecx, dword ptr [CGAME]
        mov ecx, dword ptr [ecx+0xe50]
        mov eax, dword ptr [ebp+8]
        dec eax
        push eax
        push SPL_FEATHER_FALL
        call dword ptr ds:spell_face_anim
        ; also the ordinary wine effect
        wine:
        push ebx ; cannot resist
        push COND_DRUNK
        mov ecx, esi
        call inflict_condition
        jmp remove
        journal:
        xor eax, eax
        dec eax
        mov word ptr [AUTONOTES_ADDR+6], ax ; starting from 49
        mov dword ptr [AUTONOTES_ADDR+8], eax
        mov word ptr [AUTONOTES_ADDR+12], ax
        or byte ptr [AUTONOTES_ADDR+14], 0xc0 ; up to 114
        mov byte ptr [BLINK_AUTONOTES], 1
        mov dword ptr [AUTONOTES_PAGE], ebx ; potions page
        mov ecx, dword ptr [CGAME]
        mov ecx, dword ptr [ecx+0xe50]
        mov eax, dword ptr [ebp+8]
        dec eax
        push eax
        push SPL_INVISIBILITY
        call dword ptr ds:spell_face_anim
        push ebx ; unused
        push ANIM_LEARN
        mov ecx, esi
        call dword ptr ds:show_face_animation
        jmp remove
        hourglass:
        mov eax, dword ptr [CURRENT_MAP_ID]
        dec eax ; we use element 0 now
        imul eax, eax, SIZE_MAPSTAT
        mov eax, dword ptr [MAPSTATS_ADDR+eax].s_mapstats_item.refill_days
        cmp dword ptr [OUTDOORS], 2
        jne indoors
        shr eax, 1 ; may need to be used twice
        sub dword ptr [OUTDOOR_LAST_REFILL_DAY], eax
        jmp message
        indoors:
        sub dword ptr [INDOOR_LAST_REFILL_DAY], eax
        message:
        mov ecx, dword ptr [new_strings+STR_HOURGLASS_USED*4]
        mov edx, 2
        call dword ptr ds:show_status_text
        push ebx
        push ebx
        push ebx
        push ebx
        push -1
        push ebx
        push ebx
        push SOUND_HARM
        mov ecx, SOUND_THIS_ADDR
        call dword ptr ds:make_sound
        remove:
        mov dword ptr [esp], 0x468e7c ; remove the item
        ret
        bag:
        cmp dword ptr [CURRENT_SCREEN], 10 ; chest
        je fail
        cmp dword ptr [CURRENT_SCREEN], 13 ; dialog
        je fail
        cmp dword ptr [CURRENT_SCREEN], 15 ; inv + chest
        je fail
        cmp dword ptr [CURRENT_SCREEN], 0
        jz exited
        push 0
        push 0
        push ACTION_EXIT
        mov ecx, ACTION_THIS_ADDR
        call dword ptr ds:add_action
        exited:
        push 1 ; so it`ll be preserved on exit
        push BOH_CHEST_ID
        push ACTION_EXTRA_CHEST
        mov ecx, ACTION_THIS_ADDR
        call dword ptr ds:add_action
        push 0x468e87 ; exit function
        ret 4
        fail:
        push 0x468624 ; buzz sound
        ret 4
      }
}

// Used immediately below.
static const char nwc_dlv[] = "nwc.dlv";

// Protect the temple inside the bottle from respawning, just like the castle.
static void __declspec(naked) do_not_respawn_temple(void)
{
    asm
      {
        pop ebx
        call dword ptr ds:uncased_strcmp ; replaced call
        test eax, eax
        jz quit
        mov dword ptr [esp+4], offset nwc_dlv ; instead of the castle
        call dword ptr ds:uncased_strcmp
        quit:
        jmp ebx
      }
}

// Equipped SoL sprite.
static const char itemsole[] = "itemsole";

// Sword of Light has separate equipped and inventory graphics.
static void __declspec(naked) equipped_sword_of_light(void)
{
    asm
      {
        cmp eax, SWORD_OF_LIGHT * SIZE_ITEM_TXT
        jne not_it
        mov dword ptr [esp+4], offset itemsole
        not_it:
        jmp dword ptr ds:load_bitmap ; replaced call
      }
}

// Also show equipped sprite on a right-click (but only after ID).
static void __declspec(naked) sword_of_light_rmb(void)
{
    asm
      {
        cmp dword ptr [eax], SWORD_OF_LIGHT
        jne not_it
        test byte ptr [eax].s_item.flags, IFLAGS_ID
        jz not_it
        mov dword ptr [esp+4], offset itemsole
        not_it:
        jmp dword ptr ds:load_bitmap ; replaced call
      }
}

// Implement Grim Reaper's instadeath effect.
// Called from lich_vampiric_touch() below.
static int __stdcall grim_reaper(struct player *player,
                                 struct map_monster *monster)
{
    // has the same immune monsters as GM unarmed, except oozes
    // (medusae and blaster guys are implicitly immune instead)
    if (monster->holy_resistance < IMMUNE
        || monster->magic_resistance == IMMUNE)
        return 0;
    int id = monster->id;
    if (id >= 34 && id <= 48 || id >= 64 && id <= 66 || id >= 79 && id <= 81
        || id >= 190 && id <= 192 || id >= 253 && id <= 255)
        return 0;
    if (random() % 5)
        return 0;
    // drain sp/hp even if monster resisted
    int new_sp = player->sp - 15;
    if (new_sp < 0)
      {
        player->sp = 0;
        damage_player(player, -new_sp * 2, ENERGY);
      }
    else
      {
        player->sp = new_sp;
      }
    if (elemdata.difficulty <= random() % 4
        && debuff_monster(monster, MAGIC,
                          get_skill(player, SKILL_AXE) & SKILL_MASK))
      {
        monster->hp = 0;
        make_sound(SOUND_THIS, SOUND_DIE, 0, 0, -1, 0, 0, 0, 0);
        return 1;
      }
    return 0;
}

// Replace chest 0 with whatever we need (-1 to restore).
static void __thiscall replace_chest(int id)
{
    static struct map_chest backup;
    if (id == replaced_chest)
        return;
#define CHEST(id) ((id) == -1 ? &backup : elemdata.extra_chests + (id))
    memcpy(CHEST(replaced_chest), MAP_CHESTS, sizeof(struct map_chest));
    memcpy(MAP_CHESTS, CHEST(id), sizeof(struct map_chest));
    replaced_chest = id;
}

// If we're opening the actual chest 0, restore it beforehand.
// Also here: break invisibility on looting (regular) chests.
static void __declspec(naked) open_regular_chest(void)
{
    asm
      {
        cmp ecx, ebx ; ebx == 0
        jnz skip
        dec ecx
        call replace_chest
        xor ecx, ecx
        skip:
        call dword ptr ds:open_chest ; replaced call
        test eax, eax
        jz quit
        mov ecx, PARTY_BUFF_ADDR + BUFF_INVISIBILITY * SIZE_BUFF
        call dword ptr ds:remove_buff
        or eax, 1
        mov dword ptr [REFRESH_SCREEN], eax
        quit:
        ret
      }
}

// Defined below.
static void place_order(void);

// Remember what button to draw in the down state.
static int pressed_quick_spell = -1;

// Also defined below.
static char *__stdcall get_quick_spell_hint(int button);

// Make a new action that opens an extra chest.
// We need an action to safely trigger it from inventory etc.
// Also here: the action for ordering an item in a shop,
// and the action that triggers a gamescript event.
// Also also, an action for opening the new key config page is here too.
// Finally, there are the two actions for the new quick spell buttons.
static void __declspec(naked) action_open_extra_chest(void)
{
    asm
      {
        cmp ecx, ACTION_EXTRA_CHEST
        je chest
        cmp ecx, ACTION_PLACE_ORDER
        je order
        cmp ecx, ACTION_VARIABLE_EVENT
        je event
        cmp ecx, ACTION_THIRD_KEY_CONFIG_PAGE
        je page
        cmp ecx, ACTION_QUICK_SPELL_HINT
        je hint
        cmp ecx, ACTION_QUICK_SPELL_PRESS
        je spell
        movzx eax, byte ptr [0x4353a1+eax] ; replaced code
        ret
        chest:
        mov ecx, dword ptr [esp+24] ; action param 1
        call replace_chest
        xor ecx, ecx
        call dword ptr ds:open_chest
        jmp quit
        order:
        call place_order
        jmp quit
        event:
        xor ecx, ecx
        mov eax, dword ptr [esp+48] ; action param 2
        test eax, eax
        setns cl
        mov dword ptr [GLOBAL_EVENT_FLAG], ecx
        dec ecx
        xor eax, ecx ; absolute value
        mov dword ptr [evt_variable_id], eax
        xor edx, edx
        mov ecx, dword ptr [esp+24]
        push 1
        call dword ptr ds:process_event
        xor ecx, ecx
        mov dword ptr [GLOBAL_EVENT_FLAG], ecx ; restore
        mov dword ptr [evt_variable_id], ecx ; just in case
        jmp quit
        page:
        mov dword ptr [0x506d88], ebx ; set page index var to zero
        jmp quit
        hint:
        push dword ptr [esp+24]
        call get_quick_spell_hint
        mov ecx, eax
        call dword ptr ds:set_hint
        jmp quit
        spell:
        mov eax, dword ptr [esp+24]
        mov dword ptr [pressed_quick_spell], eax
        mov ecx, dword ptr [CURRENT_PLAYER]
        dec ecx
        jl quit ; just in case
        lea ebx, [eax+ecx*4]
        mov edx, dword ptr [SELECTED_SPELL]
        test edx, edx
        jz set
        mov eax, dword ptr [elemdata.quick_spells+ebx*4]
        mov ecx, dword ptr [PC_POINTERS+ecx*4]
        movzx ecx, byte ptr [ecx].s_player.spellbook_page
        sub edx, ecx
        lea ecx, [ecx+ecx*2]
        lea edx, [edx+ecx*4]
        cmp eax, edx
        jne set
        xor edx, edx ; remove spell
        set:
        mov dword ptr [elemdata.quick_spells+ebx*4], edx
        jz unset
        push 0
        push ANIM_QUICK_SPELL
        mov ecx, dword ptr [CURRENT_PLAYER]
        mov ecx, dword ptr [PC_POINTERS+ecx*4-4]
        call dword ptr ds:show_face_animation
        jmp restore
        unset:
        push edx
        push edx
        push edx
        push edx
        push -1
        push edx
        push edx
        push SOUND_FIZZLE
        mov ecx, SOUND_THIS_ADDR
        call dword ptr ds:make_sound
        restore:
        xor ebx, ebx
        quit:
        mov eax, 118 ; no action
        ret
      }
}

// Disallow putting BoH into itself.
static void __declspec(naked) no_boh_recursion(void)
{
    asm
      {
        cmp dword ptr [edx], BAG_OF_HOLDING
        jne quit
        cmp dword ptr [ebp+8], 0
        jnz quit
        cmp dword ptr [replaced_chest], BOH_CHEST_ID
        jz fail
        quit:
        mov edx, dword ptr [0x4e2bec+eax] ; replaced code
        ret
        fail:
        push 0x41ffce ; no space face anim
        ret 4
      }
}

// Make Titan's Belt more relevant by giving it more direct effects.
static void __declspec(naked) titan_belt_recovery_penalty(void)
{
    asm
      {
        push SLOT_BELT
        push TITANS_BELT
        call dword ptr ds:has_item_in_slot
        test eax, eax
        jz quit
        add dword ptr [ebp-12], 10 ; penalty
        quit:
        mov ecx, esi ; restore
        jmp dword ptr ds:get_speed ; replaced call
      }
}

// And the other one, too.  This patches the magic effects function,
// as item bonus to damage is not always checked by the game.
// Also here: boots of kicking increase damage as well.
static void __declspec(naked) titan_belt_damage_bonus(void)
{
    asm
      {
        push ecx
        push SLOT_BELT
        push TITANS_BELT
        call dword ptr ds:has_item_in_slot
        pop ecx
        test eax, eax
        movzx eax, word ptr [ecx+PBUFF_HEROISM*SIZE_BUFF+S_SB_POWER] \
                            .s_player.spell_buffs ; replaced code
        jz no_belt
        add eax, 12 ; belt bonus
        no_belt:
        push eax
        push SPC_KICKING
        call dword ptr ds:has_enchanted_item
        test eax, eax
        pop eax
        jz quit
        add eax, 5 ; boot bonus
        quit:
        ret
      }
}

// Lower Flattener's speed when it's wielded in one hand.  If sword is in
// the left hand, this actually lowers the sword's speed, but it's okay.
static void __declspec(naked) flattener_penalty(void)
{
    asm
      {
        cmp dword ptr [ebp+8], ebx ; ranged flag
        jnz quit
        push SLOT_MAIN_HAND
        push FLATTENER
        call dword ptr ds:has_item_in_slot
        mov ecx, esi ; restore
        test eax, eax
        jz quit
        add dword ptr [ebp-20], 20 ; penalty
        quit:
        push 0x48d612 ; replaced call
        ret
      }
}

// Draw Flattener as a 2H weapon when appropriate.
static void __declspec(naked) flattener_2h(void)
{
    asm
      {
        mov eax, [ecx+SLOT_MAIN_HAND*4].s_player.equipment
        lea eax, [eax+eax*8]
        cmp dword ptr [ecx+eax*4-SIZE_ITEM].s_player.items, FLATTENER
        jne skip
        mov eax, 4 ; pass the check
        ret 4
        skip:
        jmp dword ptr ds:equipped_item_skill ; replaced call
      }
}

// Ditto, but this code draws the arm itself.
static void __declspec(naked) flattener_2h_body(void)
{
    asm
      {
        cmp edx, FLATTENER * SIZE_ITEM_TXT
        je quit
        ; replaced code next line:
        cmp byte ptr [ITEMS_TXT_ADDR+edx].s_items_txt_item.skill, SKILL_SPEAR
        quit:
        ret
      }
}

// Same check, different register.
static void __declspec(naked) flattener_2h_body_eax(void)
{
    asm
      {
        cmp eax, FLATTENER * SIZE_ITEM_TXT
        je quit
        ; replaced code next line:
        cmp byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.skill, SKILL_SPEAR
        quit:
        ret
      }
}

// The chief Flattener's effect (spectral-elemental mass distortion).
// Called from lich_vampiric_touch() below.
static int __stdcall flattener(struct player *player,
                               struct map_monster *monster)
{
    if (random() % 5 > has_item_in_slot(player, FENCERS_FRIEND, SLOT_ANY))
        return 0; // 20% or 40% chance
    int mres = monster->magic_resistance;
    if (monster->spell_buffs[MBUFF_DAY_OF_PROTECTION].expire_time)
        mres += monster->spell_buffs[MBUFF_DAY_OF_PROTECTION].power;
    int element = mres > monster->physical_resistance ? PHYSICAL : MAGIC;
    int skill = get_skill(player, SKILL_MACE) & SKILL_MASK;
    int damage = monster_resists(monster, element,
                                 monster->hp * (25 + skill * 2) / 100);
    if (damage)
        add_buff(monster->spell_buffs + MBUFF_MASS_DISTORTION,
                 dword(ANIM_TIMER) + 128, 0, 0, 0, 0);
    return damage;
}

// Let Eloquence Talisman boost Merchant, mostly for flavor.
static void __declspec(naked) eloquence_merchant_bonus(void)
{
    asm
      {
        jz no_merchant_npc ; replaced jump
        add esi, 6 ; replaced code
        no_merchant_npc:
        mov ecx, dword ptr [ebp-4] ; PC
        push SLOT_AMULET
        push ELOQUENCE_TALISMAN
        call dword ptr ds:has_item_in_slot
        lea eax, [eax+eax*4]
        add esi, eax
        ret
      }
}

// Massively increase Ethric's Staff's HP drain (x5), but disable when resting.
// TODO: should we make an exception for liches?
static void __declspec(naked) higher_ethric_drain(void)
{
    asm
      {
        cmp dword ptr [0x506d94], 2 ; resting flag
        je quit
        sub dword ptr [esi].s_player.hp, 5
        quit:
        ret
      }
}

// Worn Gadgeteer's Belt data.
static const int gadgeteers_belt_xy[] = { 530, 185, 533, 171,
                                          532, 214, 535, 210, };
static char gadgeteers_belt_gfx[] = "itemgadgv0";
// Same for Sniper's Quiver.
static const int snipers_quiver_xy[] = { 539, 169, 538, 164,
                                         537, 198, 542, 195, };
static char snipers_quiver_gfx[] = "snipquivv0";
// Also for Hero's Belt (used a MM6 image here).
static const int heros_belt_xy[] = { 540, 180, 536, 169,
                                     540, 213, 539, 207, };
static const char heros_belt_gfx[] = "heroblte"; // male only

// Draw the new belt on the paperdoll.
static void __declspec(naked) display_new_belt(void)
{
    asm
      {
        cmp ecx, GADGETEERS_BELT
        je belt
        cmp ecx, SNIPERS_QUIVER
        je quiver
        cmp ecx, HEROS_BELT
        je hero
        sub ecx, TITANS_BELT ; replaced code
        ret
        belt:
        mov ecx, offset gadgeteers_belt_xy
        mov edx, offset gadgeteers_belt_gfx
        jmp gfx
        quiver:
        mov ecx, offset snipers_quiver_xy
        mov edx, offset snipers_quiver_gfx
        jmp gfx
        hero:
        mov ecx, offset heros_belt_xy
        mov edx, offset heros_belt_gfx
        test edx, edx ; unset zf
        gfx:
        mov eax, dword ptr [esp+40] ; body type
        lea ecx, [ecx+eax*8]
        jnz got_gfx ; fixed for hero
        and eax, 1 ; no special dwarf gfx
        add eax, '1'
        mov byte ptr [edx+9], al
        got_gfx:
        mov eax, dword ptr [ecx]
        mov ecx, dword ptr [ecx+4]
        mov dword ptr [esp+24], eax
        mov dword ptr [esp+20], ecx
        push 2
        push edx
        mov ecx, ICONS_LOD_ADDR
        call dword ptr ds:load_bitmap
        mov ebx, eax
        push 0x43d954 ; code after setting coords
        ret 4
      }
}

// Scrolls that act on inventory don't use the scroll cast action code,
// so we must provide the variable (possibly boosted) power separately.
static void __declspec(naked) gadgeteer_special_scroll_bonus(void)
{
    asm
      {
        pop edx
        push dword ptr [scroll_power]
        jmp edx
      }
}

// Let Gadgeteer's Belt enhance drunk potion power.
// This hook is for HP and SP potions.
// Also here: nerf Divine Power to restore 3x potion power in SP.
static void __declspec(naked) gadgeteer_cure_potions_bonus(void)
{
    asm
      {
        mov ecx, esi
        push SLOT_BELT
        push GADGETEERS_BELT
        call dword ptr ds:has_item_in_slot
        mov edx, dword ptr [MOUSE_ITEM].s_item.bonus ; power
        cmp dword ptr [MOUSE_ITEM], POTION_DIVINE_CURE
        jb simple
        ja magic
        lea edx, [edx+edx*4]
        jmp simple
        magic:
        lea edx, [edx+edx*2] ; nerf
        simple:
        test eax, eax
        jz skip
        mov eax, edx
        shr eax, 1
        mov cl, byte ptr [esi].s_player.class
        and cl, -4
        cmp cl, CLASS_THIEF
        je skip
        shr eax, 1
        skip:
        add eax, edx
        ret
      }
}

// And this is for the Recharge Item potion.
static void __declspec(naked) gadgeteer_recharge_potion_bonus(void)
{
    asm
      {
        fild dword ptr [MOUSE_ITEM].s_item.bonus ; replaced code
        mov ecx, dword ptr [CURRENT_PLAYER]
        mov ecx, dword ptr [PC_POINTERS+ecx*4-4]
        mov bl, byte ptr [ecx].s_player.class
        push SLOT_BELT
        push GADGETEERS_BELT
        call dword ptr ds:has_item_in_slot
        test eax, eax
        jz quit
        and bl, -4
        cmp bl, CLASS_THIEF
        je thief
        fmul dword ptr [f1_25]
        jmp quit
        thief:
        fmul dword ptr [f1_5]
        quit:
        xor ebx, ebx ; restore
        ret
      }
}

// Gardener's Gloves ability: flag monster for a possible reagent drop.
// Does not work in light and dark proving grounds.
// TODO: maybe disable both this and natural reagents in arena as well?
static void __declspec(naked) plant_seed(void)
{
    asm
      {
        jnz hit ; replaced jump
        cmp dword ptr [ebp-32], eax ; replaced code
        jnz hit
        ret
        hit:
        mov ecx, edi
        push SLOT_GAUNTLETS
        push GARDENERS_GLOVES
        call dword ptr ds:has_item_in_slot
        test eax, eax
        jz skip
        push CUR_MAP_FILENAME_ADDR
        push MAP_BREEDING_ZONE_ADDR
        call dword ptr ds:uncased_strcmp
        test eax, eax
        jz restore
        mov dword ptr [esp], MAP_WALLS_OF_MIST_ADDR
        call dword ptr ds:uncased_strcmp
        test eax, eax
        restore:
        pop eax
        pop eax
        jz skip
        or byte ptr [esi].s_map_monster.mod_flags, MMF_EXTRA_REAGENT
        mov al, byte ptr [edi].s_player.class
        and al, -4
        cmp al, CLASS_RANGER
        je bonus
        cmp al, CLASS_DRUID
        jne skip
        bonus:
        or byte ptr [esi].s_map_monster.mod_flags, MMF_REAGENT_MORE_LIKELY
        skip:
        mov cx, word ptr [esi+40] ; restore
        inc eax ; clear zf
        ret
      }
}

// Whether to do autonote animations.  Filled in check_bounty_kill() below.
static int bounty_completed = 0;

// Possibly drop the reagent on death.  This uses the vanilla code
// that drops reagents from some monsters with a 20% chance.
// These monsters are NOT affected by the Gloves' ability.
// Eradicated and zombified monsters never drop any reagents (even vanilla).
// Also here: blink journal etc. on bounty completion.
static void __declspec(naked) harvest_seed(void)
{
    asm
      {
        cmp dword ptr [bounty_completed], 0
        jz no_bounty
        mov edi, 4
        loop:
        mov ecx, dword ptr [PC_POINTERS+edi*4-4]
        push 0 ; unused
        push ANIM_AWARD
        call dword ptr ds:show_face_animation
        lea edx, [edi-1]
        push edx
        push SPAN_EVT_SET
        mov ecx, dword ptr [CGAME]
        mov ecx, dword ptr [ecx+0xe50]
        call dword ptr ds:spell_face_anim
        dec edi
        jnz loop
        push edi
        push edi
        push edi
        push edi
        push -1
        push edi
        push edi
        push SOUND_QUEST
        mov ecx, SOUND_THIS_ADDR
        call dword ptr ds:make_sound
        mov byte ptr [BLINK_AUTONOTES], 1
        mov dword ptr [AUTONOTES_PAGE], 4 ; traders page
        mov dword ptr [bounty_completed], edi
        no_bounty:
        mov edi, 20 ; drop chance
        test byte ptr [esi].s_map_monster.mod_flags, \
             MMF_ERADICATED + MMF_ZOMBIE
        jnz skip
        cmp dword ptr [ebp-40], 0 ; vanilla reagent
        jnz quit
        movzx edi, byte ptr [esi].s_map_monster.mod_flags
        and edi, MMF_EXTRA_REAGENT + MMF_REAGENT_MORE_LIKELY
        jz skip
        shr edi, 3 ; flags also double as drop chance
        lea edi, [edi+edi*4]
        mov dword ptr [ebp-40], FIRST_REAGENT
        call dword ptr ds:random
        and eax, 3
        lea eax, [eax+eax*4]
        add dword ptr [ebp-40], eax
        movzx eax, byte ptr [esi].s_map_monster.level
        xor edx, edx
        add eax, 10
        mov ecx, 20
        div ecx
        cmp eax, 4
        jbe ok
        mov eax, 4
        ok:
        add dword ptr [ebp-40], eax
        quit:
        jmp dword ptr ds:random ; replaced call
        skip:
        mov eax, 99 ; no drop
        ret
      }
}

// Instead of a fixed 20% chance, use edi we set above.
static void __declspec(naked) reagent_chance_chunk(void)
{
    asm
      {
        cmp edx, edi
        nop
      }
}

// Mark guaranteed (tlvl 7) artifacts as generated, but in a special way.
// When counting artifacts towards the limit, these will be ignored.
static void __declspec(naked) mark_guaranteed_artifacts(void)
{
    asm
      {
        mov byte ptr [elemdata.artifacts_found-FIRST_ARTIFACT+eax], 0x80
        cmp dword ptr [ebp+4], 0x45051a ; if called from chest generator
        jne not_chest
        or byte ptr [edi+1].s_item.flags, 5 ; flag for mm7patch art refund
        not_chest:
        jmp dword ptr ds:set_specitem_bonus ; replaced call
      }
}

// Mark all static artifacts added by the mod as refundable.
// If a chest would have an artifact that's already generated,
// replace it with a random one.
static void __declspec(naked) fix_static_chest_items(void)
{
    asm
      {
        jl quit ; replaced jump
        mov ecx, dword ptr [esp+32]
        test byte ptr [ecx].s_map_chest.bits, 0x40 ; true if already checked
        jnz skip
        test byte ptr [ebx+1].s_item.flags, 5 ; set by mm7patch for tlvl6 arts
        jz not_random
        jp skip ; can appear in this loop, but aren`t preplaced
        not_random:
        mov eax, dword ptr [ebx]
        cmp eax, FIRST_ARTIFACT
        jb skip
        cmp eax, LAST_OLD_ARTIFACT
        jbe artifact
        cmp eax, FIRST_NEW_ARTIFACT
        jb skip
        cmp eax, LAST_ARTIFACT
        ja skip
        artifact:
        cmp byte ptr [elemdata.artifacts_found-FIRST_ARTIFACT+eax], 0
        jnz replace
        mov byte ptr [elemdata.artifacts_found-FIRST_ARTIFACT+eax], 0x80
        or byte ptr [ebx+1].s_item.flags, 5 ; flag for mm7patch art refund
        skip:
        mov dword ptr [esp], 0x45051e ; replaced jump adress
        quit:
        ret
        replace:
        mov dword ptr [esp], 0x450513 ; random artifact code
        ret
      }
}

// Prevent running the above code on every map reload by marking fixed chests.
static void __declspec(naked) mark_chest_checked(void)
{
    asm
      {
        or byte ptr [ebx].s_map_chest.bits, 0x40 ; the mark
        add ebx, SIZE_CHEST ; replaced code
        ret
      }
}

// Read just below, written in patch_compatibility().  Stores default chance.
static int normal_axe_chance;
// This one just remembers the result of FF equip check, as either 100 or 50.
static int current_mace_chance;

// Fencer's Friend's main ability: double the chance of special weapon effects.
// This hook is for MM7Patch axe perk and partly for vanilla mace perks.
static void __declspec(naked) double_axe_mace_chance(void)
{
    asm
      {
        push ecx
        push SLOT_ANY
        push FENCERS_FRIEND
        mov ecx, edi
        call dword ptr ds:has_item_in_slot
        mov ecx, eax
        mov eax, 100 ; normal skill% chance
        shr eax, cl ; possibly change to skill/50
        mov dword ptr [current_mace_chance], eax ; remember
        mov eax, dword ptr [normal_axe_chance]
        shr eax, cl ; from skill/60 to skill/30
        setz cl ; just in case
        add eax, ecx
        mov ecx, dword ptr [patch_options]
        mov dword ptr [ecx].s_patch_options.axe_gm_perk_chance, eax
        pop ecx ; restore
        jmp dword ptr ds:skill_mastery ; replaced call
      }
}

// Use the stored chance value.  Called for both M and GM perks.
static void __declspec(naked) provide_mace_chance(void)
{
    asm
      {
        xor edx, edx
        div dword ptr [current_mace_chance] ; was just 100
        ret
      }
}

// The new equipped Mind's Eye image (from MM6).
static const char minds_eye_gfx[] = "mindeyee"; // no variation

// Draw the new Mind's Eye graphics.
static void __declspec(naked) display_new_helm(void)
{
    asm
      {
        cmp eax, MINDS_EYE
        je mind
        sub eax, TALEDONS_HELM ; replaced code
        ret
        mind:
        mov cl, byte ptr [esp+40] ; body type
        and ecx, 1
        lea ecx, [ecx+ecx*2+530]
        mov dword ptr [esp+24], ecx ; x
        mov dword ptr [esp+20], 38 ; y
        push 2
#ifdef __clang__
        mov eax, offset minds_eye_gfx
        push eax
#else
        push offset minds_eye_gfx
#endif
        mov ecx, ICONS_LOD_ADDR
        call dword ptr ds:load_bitmap
        mov ebx, eax
        mov dword ptr [esp], 0x43e1c0 ; code after setting coords
        ret
      }
}

// Used just below.
static const char elven_chain_gfx[] = "elchv2a0";

// Provide new equipped sprite names for the Elven Chainmail.
static void __declspec(naked) elven_chainmail_gfx(void)
{
    asm
      {
        cmp edx, ELVEN_CHAINMAIL
        je elven
        lea eax, [edx-GOVERNORS_ARMOR] ; replaced code
        cmp eax, 46 ; ditto
        ret
        elven:
#ifdef __clang__
        mov eax, offset elven_chain_gfx
        push eax
#else
        push offset elven_chain_gfx
#endif
        push ecx ; buffer
        call dword ptr ds:strcpy_ptr
        add esp, 8
        mov ecx, dword ptr [ebp+8] ; body type
        mov edx, dword ptr [ebp+12] ; sprite type
        and ecx, 1 ; no dwarves
        sub byte ptr [eax+5], cl
        add byte ptr [eax+7], dl
        ret ; ja should trigger now
      }
}


// Let Ghoulbane act as GM Torch Light while equipped.
// This code is reused for four slightly different hooks.
static void __declspec(naked) ghoulbane_torch_common(void)
{
    asm
      {
        push ecx
        push edx
        push 4
        loop:
        mov ecx, dword ptr [esp]
        push SLOT_MAIN_HAND
        push GHOULSBANE
        mov ecx, dword ptr [PC_POINTERS+ecx*4-4]
        call dword ptr ds:has_item_in_slot
        test eax, eax
        jnz light
        dec dword ptr [esp]
        jnz loop
        light:
        pop eax
        pop edx
        pop ecx
        pop eax
        jz skip
        add dword ptr [esp], eax ; jump to torch power code
        mov al, 5 ; as gm torch
        skip:
        cmp dword ptr [PARTY_BUFF_ADDR+BUFF_TORCH_LIGHT*SIZE_BUFF+4], 0 ; repl.
        ret
      }
}

// First hook for the above.
static void __declspec(naked) ghoulbane_torch_1(void)
{
    asm
      {
        push 20
        jmp ghoulbane_torch_common
      }
}

// Second hook.
static void __declspec(naked) ghoulbane_torch_2(void)
{
    asm
      {
        push 25
        jmp ghoulbane_torch_common
      }
}

// Another hook; the code here is a bit different.
static void __declspec(naked) ghoulbane_torch_3(void)
{
    asm
      {
        ; replaced code below:
        mov esi, dword ptr [PARTY_BUFF_ADDR+BUFF_TORCH_LIGHT*SIZE_BUFF+4]
        push 34
        jmp ghoulbane_torch_common
      }
}

// The last hook.
static void __declspec(naked) ghoulbane_torch_4(void)
{
    asm
      {
        push 27
        jmp ghoulbane_torch_common
      }
}

// Instead of the now self-contradictory Agility bonus, give Ania AC reduction.
static void __declspec(naked) ania_selving_ac_penetration(void)
{
    asm
      {
        cmp dword ptr [ebx].s_map_object.item, ANIA_SELVING
        jne skip
        add dword ptr [ebp-40], 25 ; ac penetration
        skip:
        mov eax, 0x48d1e4 ; replaced call
        jmp eax
      }
}

// Add the new properties to some old artifacts,
// and code some brand new artifacts and relics.
static inline void new_artifacts(void)
{
    // remove old (and nonfunctional) elven chainmail recovery bonus
    erase_code(0x48ea64, 12);
    // elven chainmail is lightweight now
    hook_call(0x48f24e, elven_chainmail_bow_bonus, 5);
    hook_call(0x48eee0, artifact_stat_bonus, 5);
    hook_call(0x492c4a, sacrificial_dagger_goblin_only, 5);
    // corsair and old nick can backstab now
    // old nick poison damage increased in elemental_weapons() above
    patch_byte(0x48f086, 13); // old nick disarm bonus
    // kelebrim protects from dispel
    // hermes' sandals grant leaping
    // rdsm is lightweight
    hook_call(0x43d42f, display_worn_rdsm_body, 5);
    hook_call(0x43db2b, display_worn_rdsm_arm, 5);
    hook_call(0x43dba8, display_worn_rdsm_arm_2h, 5);
    hook_call(0x43dd38, display_worn_rdsm_arm_idle, 5);
    hook_call(0x456d57, set_dragon_charges, 6);
    hook_call(0x48d425, check_dragon_wand, 6);
    hook_call(0x458299, regen_dragon_charges, 5);
    hook_call(0x42ed3f, regen_dragon_shooting, 6);
    // also regenerates in red_empty_wands() below
    hook_call(0x42aa15, cannot_recharge_dragon, 7);
    // Let's replace the generated artifacts array with a bigger one.
    patch_pointer(0x4568f7, elemdata.artifacts_found);
    patch_byte(0x456901, LAST_ARTIFACT - FIRST_ARTIFACT + 1);
    hook_call(0x456909, random_artifact, 6);
    patch_pointer(0x456929, elemdata.artifacts_found);
    patch_pointer(0x45061e, elemdata.artifacts_found - FIRST_ARTIFACT);
    hook_call(0x45062e, jump_over_specitems, 5);
    // make space on the stack for all possible arts
    const int art_count = LAST_OLD_ARTIFACT - FIRST_ARTIFACT + 1
                        + LAST_ARTIFACT - FIRST_NEW_ARTIFACT + 1;
    patch_dword(0x4505fd, art_count * 4);
    patch_dword(0x450628, art_count * -4);
    patch_dword(0x450651, art_count * -4);
    hook_call(0x439e41, headache_mind_damage, 5);
    // stat penalty is in artifact_stat_bonus()
    // The below hooks deal with Storm Trident's free Lightning Bolt spell.
    hook_call(0x41136e, check_lightning_image, 7);
    hook_call(0x41166a, check_lightning_button, 7);
    hook_call(0x412bc6, check_lightning_redraw, 11);
    hook_call(0x43439c, check_lightning_mouseover, 7);
    hook_call(0x434648, check_lightning_click, 7);
    hook_call(0x411734, check_air_button, 7);
    hook_call(0x412d50, check_air_redraw, 8);
    // zero cost is in switch_off_spells_for_free() above
    hook_call(0x43010e, free_quick_lightning, 6);
    patch_pointer(0x42e9ad, lightning_spear_skill);
    // shock damage is in headache_mind_damage()
    hook_call(0x4942d5, storm_trident_water_walking, 5);
    hook_call(0x493e33, ellingers_robe_preservation, 6);
    hook_call(0x48dc59, ellingers_robe_preservation, 6);
    hook_call(0x494494, ellingers_robe_preservation, 6);
    // weakness immunity is in inflict_condition() above
    // magic bonus is in artifact_stat_bonus()
    // Viper swiftness is in temp_swiftness() above
    // poison damage is also in headache_mind_damage()
    hook_call(0x44c2d5, save_temple_beacon_hook, 6);
    hook_call(0x44c2c7, bottle_in_arena, 5);
    hook_call(0x447f80, movemap_leavetiab, 7);
    hook_call(0x44800a, movemap_immediate, 5);
    hook_call(0x4483f7, movemap_dialog, 5);
    hook_call(0x4b738c, bottle_temple_blessing, 9);
    hook_call(0x4b6f64, dark_bottle_temple, 6);
    hook_call(0x4b7574, dark_bottle_temple, 6);
    hook_call(0x46816f, new_consumable_items, 5);
    hook_call(0x49a55c, do_not_respawn_temple, 5);
    hook_call(0x43e380, equipped_sword_of_light, 5);
    hook_call(0x43e590, equipped_sword_of_light, 5);
    hook_call(0x41d8ea, sword_of_light_rmb, 5);
    // energy attack is in undead_slaying_element() above
    // light magic bonus is too in artifact_stat_bonus()
    // alignment restriction is in sacrificial_dagger_goblin_only()
    // also has dagger-like doubled to-hit bonus
    // oghma infinium effect is in new_consumable_items()
    // grim reaper sp drain is in sp_burnout() above
    // witchbane magic immunity is in is_immune() above
    // and its sp penalty is in get_new_full_sp() below
    hook_call(0x447ea4, open_regular_chest, 5);
    hook_call(0x430598, action_open_extra_chest, 7);
    hook_call(0x41ff6d, no_boh_recursion, 6);
    // clover double crit chance is in get_critical_chance() above
    // and luck bonus is in artifact_stat_bonus()
    hook_call(0x48e3f1, titan_belt_recovery_penalty, 5);
    hook_call(0x48f840, titan_belt_damage_bonus, 7);
    patch_dword(0x48f6a8, 0x48f556); // remove old effects
    // flattener is spectral
    hook_call(0x48e38d, flattener_penalty, 5);
    hook_call(0x43db84, flattener_2h, 5);
    hook_call(0x43d878, flattener_2h_body, 7);
    hook_call(0x43daba, flattener_2h_body_eax, 7);
    hook_call(0x43e79c, flattener_2h_body_eax, 7);
    hook_call(0x48f9db, eloquence_merchant_bonus, 5);
    // spell recovery bonus is in switch_off_spells_for_free() above
    // sp drain is in sp_burnout() above
    hook_call(0x493de7, higher_ethric_drain, 6);
    // ethric's staff is now soul stealing
    // also it raises zombies on kill
    hook_call(0x43d8d5, display_new_belt, 6);
    // wand bonus is in variable_wand_power() above
    // scroll bonus is in throw_potions_power() above
    hook_call(0x468762, gadgeteer_special_scroll_bonus, 5);
    hook_call(0x468798, gadgeteer_cure_potions_bonus, 5); // red
    hook_call(0x4687b7, gadgeteer_cure_potions_bonus, 5); // blue
    hook_call(0x468afc, gadgeteer_cure_potions_bonus, 8); // divine cure
    hook_call(0x468b09, gadgeteer_cure_potions_bonus, 8); // divine power
    // buff potions boosted in buff_potions_power() above
    // weapon-enchanting potions are in weapon_potions() above
    hook_call(0x416992, gadgeteer_recharge_potion_bonus, 6);
    // clanker's amulet alchemy bonus is in artifact_stat_bonus()
    // enchant item bonus is in enchant_item_noon_check() above
    hook_call(0x439a32, plant_seed, 5);
    erase_code(0x402e94, 6); // don't skip reagent code if no vanilla reagent
    hook_call(0x402e9a, harvest_seed, 5);
    patch_bytes(0x402ea5, reagent_chance_chunk, 3);
    // earth magic bonus is in artifact_stat_bonus()
    hook_call(0x450657, mark_guaranteed_artifacts, 5);
    hook_call(0x45028f, fix_static_chest_items, 6);
    hook_call(0x45052f, mark_chest_checked, 6);
    patch_byte(0x456935, 10); // reduce max randomly generated artifacts
    // lady escort and sniper quiver shielding are in shield_stacking() above
    hook_call(0x4397bb, double_axe_mace_chance, 5);
    hook_call(0x4397ec, provide_mace_chance, 6); // stun
    hook_call(0x439818, provide_mace_chance, 6); // paralysis
    hook_jump(0x48f27c, (void *) 0x48f23d); // remove of prot. from hero's belt
    hook_call(0x43e12f, display_new_helm, 5);
    hook_call(0x43c952, elven_chainmail_gfx, 9);
    // Set equip coords.
    dword(0x4e4e00 + 16 * 8) = 29; // male body x
    dword(0x4e5020 + 16 * 8) = 94; // male arm 1 x
    dword(0x4e5240 + 16 * 8) = 92; // male arm 2 x
    dword(0x4e5240 + 16 * 8 + 4) = 106; // male arm 2 y
    dword(0x4e4e00 + 17 * 8 + 16 * 8) = 27; // female body x
    dword(0x4e4e00 + 17 * 8 + 16 * 8 + 4) = 103; // female body y
    dword(0x4e5020 + 17 * 8 + 16 * 8) = 92; // female arm 1 x
    dword(0x4e5020 + 17 * 8 + 16 * 8 + 4) = 108; // female arm 1 y
    dword(0x4e5240 + 17 * 8 + 16 * 8) = 88; // female arm 2 x
    dword(0x4e5240 + 17 * 8 + 16 * 8 + 4) = 108; // female arm 2 y
    hook_call(0x43f45c, ghoulbane_torch_1, 6);
    hook_call(0x47bcb2, ghoulbane_torch_2, 6);
    hook_call(0x47bf31, ghoulbane_torch_3, 8);
    hook_call(0x47c564, ghoulbane_torch_4, 6);
    patch_dword(0x48f6b0, 0x48f19b); // remove 150 accuracy from ania selving
    hook_call(0x439663, ania_selving_ac_penetration, 5);
}

// When calculating missile damage, take note of the weapon's skill.
static void __declspec(naked) check_missile_skill(void)
{
    asm
      {
        movzx eax, byte ptr [ITEMS_TXT_ADDR+esi].s_items_txt_item.skill
        mov dword ptr [ebp-8], eax ; unused var
        movzx eax, byte ptr [ITEMS_TXT_ADDR+esi].s_items_txt_item.mod2 ; repl.
        ret
      }
}

// Do not add GM Bow damage if we're using blasters.
// For throwing knives, add GM Dagger bonus and half Might.
static void __declspec(naked) check_missile_skill_2(void)
{
    asm
      {
        cmp dword ptr [ebp-8], SKILL_DAGGER
        je dagger
        cmp dword ptr [ebp-8], SKILL_BOW
        jne skip
        mov ax, word ptr [edi] ; replaced code
        test ax, ax ; replaced code
        ret
        dagger:
        mov ecx, eax
        push SKILL_DAGGER
        call dword ptr ds:get_skill
        cmp eax, SKILL_GM
        jbe no_skill
        and eax, SKILL_MASK
        add esi, eax
        no_skill:
        lea ecx, [edi-0x112] ; PC
        call dword ptr ds:get_might
        push eax
        call dword ptr ds:get_effective_stat
        sar eax, 1
        add esi, eax
        skip:
        xor eax, eax ; set zf
        ret
      }
}

// Use ranged recovery time when shooting blasters.
static void __declspec(naked) blaster_ranged_recovery(void)
{
    asm
      {
        inc dword ptr [esp+4] ; melee -> ranged
        jmp dword ptr ds:get_attack_delay ; replaced call
      }
}

// Use a ranged weapon in melee if 0.  Strictly speaking, we should have
// an array of 40 here (one for each action), but it seems to work fine.
static int use_melee_attack;

// Allow shooting blasters (and bows) in melee
// by pressing quick cast with no spell set (or no SP).
static void __declspec(naked) missile_on_quick_cast(void)
{
    asm
      {
        mov dword ptr [0x50ca54+eax*4], 23 ; replaced code
        cmp dword ptr [esp+20], 7 ; check if quick spell
        setne al
        mov dword ptr [use_melee_attack], eax
        ret
      }
}

// Similarly, allow shooting in melee by shift-clicking with no quick spell.
// TODO: could also check SP for symmetry
static void __declspec(naked) missile_on_shift_click(void)
{
    asm
      {
        movzx ecx, byte ptr [eax].s_player.quick_spell ; replaced code
        test ecx, ecx
        jz no_spell
        ret
        no_spell:
        mov dword ptr [use_melee_attack], ecx ; == 0
        mov eax, dword ptr [ACTION_THIS_ADDR] ; actions count
        push 0x42255e ; weapon attack code
        ret 4
      }
}

// We'll need to remove zero from the melee flag on each normal click.
static void __declspec(naked) melee_on_normal_click(void)
{
    asm
      {
        or dword ptr [use_melee_attack], 1
        mov dword ptr [0x50ca54+eax*4], 23 ; replaced code
      }
}

// If in melee range and use melee flag set, disable blasters and wands.
static void __declspec(naked) allow_melee_with_blasters(void)
{
    asm
      {
        xor ecx, ecx ; replaced code
        cmp dword ptr [use_melee_attack], ecx
        jz check_blaster
        cmp dword ptr [ebp-4], 407 ; melee range
        jg check_blaster
        and dword ptr [ebp-12], ecx ; disable wand and set zf
        ret
        check_blaster:
        cmp dword ptr [ebp-8], ecx ; replaced code (blaster check)
        ret
      }
}

// As denoted above, allow bows in melee if use melee flag unset.
static void __declspec(naked) allow_bows_in_melee(void)
{
    asm
      {
        cmp dword ptr [use_melee_attack], ecx
        jz quit
        fnstsw ax ; replaced code
        test ah, 0x41 ; replaced code
        quit:
        ret
      }
}

// 0 if no blaster, 1 to draw later, 2 if drawing now.
static int draw_blaster;

// Do not draw equipped small blaster or throwing knives behind the body.
static void __declspec(naked) postpone_drawing_blaster(void)
{
    asm
      {
        and dword ptr [draw_blaster], 0
        mov eax, dword ptr [ebx+SLOT_MISSILE*4].s_player.equipment ; replaced
        test eax, eax ; replaced code
        jz quit
        lea edx, [eax+eax*8]
        mov edx, dword ptr [ebx+edx*4-SIZE_ITEM].s_player.items
        cmp edx, BLASTER
        je skip
        lea edx, [edx+edx*2]
        shl edx, 4
        cmp byte ptr [ITEMS_TXT_ADDR+edx].s_items_txt_item.skill, SKILL_DAGGER
        jne quit
        skip:
        mov byte ptr [draw_blaster], 1
        ; we will skip drawing it now because zf == 1
        quit:
        ret
      }
}

// Instead, draw them between body and a belt.
static void __declspec(naked) draw_blaster_behind_belt(void)
{
    asm
      {
        cmp dword ptr [draw_blaster], 1
        je blaster
        mov eax, dword ptr [ebx+SLOT_BELT*4].s_player.equipment ; replaced code
        ret
        blaster:
        mov eax, dword ptr [ebx+SLOT_MISSILE*4].s_player.equipment
        add dword ptr [draw_blaster], 1 ; now it == 2
        push 0x43d043 ; missile draw code
        ret 4
      }
}

// After drawing the blaster/knives out of order, return to the belt code.
static void __declspec(naked) return_from_drawing_blaster(void)
{
    asm
      {
        cmp dword ptr [draw_blaster], 2
        je belt
        mov eax, dword ptr [eax+SLOT_CLOAK*4].s_player.equipment ; replaced
        ret
        belt:
        mov ebx, eax
        mov eax, dword ptr [ebx+SLOT_BELT*4].s_player.equipment
        and dword ptr [draw_blaster], 0
        push 0x43d8b7 ; belt draw code
        ret 4
      }
}

// Female dolls require adjusting blaster location.
static void __declspec(naked) adjust_female_blaster(void)
{
    asm
      {
        cmp dword ptr [draw_blaster], 2
        jne quit
        mov eax, dword ptr [esp+36] ; player
        cmp byte ptr [eax].s_player.gender, 1
        jne quit
        sub ebx, 15
        sub ecx, 10
        quit:
        ret
      }
}

// Allow equipping a blaster in the missile slot with a wetsuit on.
static void __declspec(naked) missile_wetsuit_blaster(void)
{
    asm
      {
        mov eax, dword ptr [MOUSE_ITEM]
        cmp eax, BLASTER
        je quit
        cmp eax, BLASTER_RIFLE
        je quit
        cmp edi, 3 ; replaced code
        jne quit ; replaced jump
        cmp byte ptr [UNDERWATER], 0 ; replaced code
        quit:
        ret
      }
}

// Override items.txt blaster equip offsets when in a wetsuit.
static void __declspec(naked) adjust_wetsuit_blaster(void)
{
    asm
      {
        cmp ecx, BLASTER
        jne rifle
        add edi, 2
        sub edx, 12
        ret
        rifle:
        sub edi, 20
        sub edx, 42
        ret
      }
}

// When equipping a wand into a missile slot, preload its spell sound.
static void __declspec(naked) preload_equipped_wand_sound(void)
{
    asm
      {
        cmp dword ptr [MOUSE_ITEM], 604 ; replaced code (wetsuit)
        je quit
        cmp edi, ITEM_TYPE_WAND - 1
        jne quit
        wand:
        mov eax, dword ptr [ebx+SLOT_MISSILE*4].s_player.equipment
        test eax, eax ; just in case
        jz skip
        lea eax, [eax+eax*8]
        mov eax, dword ptr [ebx+eax*4-SIZE_ITEM].s_player.items
        push 0x469528 ; sound code
        ret 4
        skip:
        test ebx, ebx ; clear zf
        quit:
        ret
      }
}

// Print "always" in the to-hit field with a wand equipped.
// It's not strictly true with blades or debuffs, but it's good enough.
// Also prints "N/A" when no ranged weapon present.
// Also prints "always" for Snipers with a bow equipped.
// TODO: check charges here and in print damage function
static void __declspec(naked) print_wand_to_hit(void)
{
    asm
      {
        mov ecx, edi
        mov eax, dword ptr [ecx+SLOT_MISSILE*4].s_player.equipment
        test eax, eax
        jnz have_missile
        no_missile:
        push dword ptr [0x48d3cc] ; localized by the patch
        jmp print
        have_missile:
        lea eax, [eax+eax*8]
        test byte ptr [ecx+S_PL_ITEM0+eax*4].s_item.flags, IFLAGS_BROKEN
        jnz no_missile
        mov eax, dword ptr [ecx+eax*4-SIZE_ITEM].s_player.items
        lea eax, [eax+eax*2]
        shl eax, 4
        cmp byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.equip_stat, \
            ITEM_TYPE_WAND - 1
        je always
        cmp byte ptr [ecx].s_player.class, CLASS_SNIPER
        jne not_always
        cmp byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.skill, SKILL_BOW
        jne not_always
        always:
        push dword ptr [new_strings+STR_ALWAYS*4]
        print:
        push dword ptr [GLOBAL_TXT_ADDR+203*4]
        push 0x4e2e18 ; "%s %s" format string
        push esi
        call dword ptr ds:sprintf
        add esp, 16
        not_always:
        mov edx, dword ptr [ARRUS_FNT] ; replaced code
        ret
      }
}

// Ditto, but in the quick reference screen.
static void __declspec(naked) print_wand_to_hit_ref(void)
{
    asm
      {
        mov ecx, ebp
        mov eax, dword ptr [ecx+SLOT_MISSILE*4].s_player.equipment
        test eax, eax
        jnz have_missile
        no_missile:
        push dword ptr [0x48d3cc] ; localized by the patch
        jmp print
        have_missile:
        lea eax, [eax+eax*8]
        test byte ptr [ecx+S_PL_ITEM0+eax*4].s_item.flags, IFLAGS_BROKEN
        jnz no_missile
        mov eax, dword ptr [ecx+eax*4-SIZE_ITEM].s_player.items
        lea eax, [eax+eax*2]
        shl eax, 4
        cmp byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.equip_stat, \
            ITEM_TYPE_WAND - 1
        je always
        cmp byte ptr [ecx].s_player.class, CLASS_SNIPER
        jne not_always
        cmp byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.skill, SKILL_BOW
        jne not_always
        always:
        push dword ptr [new_strings+STR_ALWAYS*4]
        print:
        push esi
        call dword ptr ds:strcpy_ptr
        add esp, 8
        not_always:
        mov edx, dword ptr [ARRUS_FNT] ; replaced code
        ret
      }
}

// Wands, books and scrolls have a spell number written in the mod1 field,
// prefixed by S.  It was ignored, but no harm in actually parsing the number.
static void __declspec(naked) parse_sxx_items_txt_chunk(void)
{
    asm
      {
        jne quit
        inc ebx
        nop
        nop
        nop
        quit:
      }
}

// Instead of using a compiled-in table, let's read wand spells from items.txt.
static void __declspec(naked) get_parsed_wand_spell(void)
{
    asm
      {
        lea eax, [eax+eax*2]
        shl eax, 4
        movzx ecx, byte ptr [ITEMS_TXT_ADDR+eax] \
                            .s_items_txt_item.mod1_dice_count
        ret
      }
}

// Ditto, but in different code (specifically, it preloads the wand sound).
static void __declspec(naked) get_parsed_wand_spell_sound(void)
{
    asm
      {
        pop edx
        lea eax, [eax+eax*2]
        shl eax, 4
        movzx eax, byte ptr [ITEMS_TXT_ADDR+eax] \
                            .s_items_txt_item.mod1_dice_count
        push eax
        jmp edx
      }
}

// Put blasters and wands in the missile weapon slot.
// TODO: fix wand recovery being displayed incorrectly
static inline void ranged_blasters(void)
{
#define OFFSET_MISSILE (offsetof(struct player, equipment) \
                        + SLOT_MISSILE * sizeof(uint32_t))
    // actual shooting
    patch_dword(0x42ed08, OFFSET_MISSILE); // check slot for wands and blasters
    erase_code(0x439633, 4); // extraneous blaster damage function params
    patch_dword(0x439641, 0x48d1e4 - 0x439645); // melee -> ranged damage
    hook_call(0x48d24d, check_missile_skill, 7);
    hook_call(0x48d2ab, check_missile_skill_2, 6);
    hook_call(0x4282e6, blaster_ranged_recovery, 5);
    patch_dword(0x4283ac, OFFSET_MISSILE); // attached weapon to blaster proj
    // displaying the damage range
    patch_dword(0x48d382, OFFSET_MISSILE); // check missile slot for blasters
    patch_byte(0x48d39d, 31); // ranged damage min stat
    patch_byte(0x48d3a6, 32); // ranged damage max stat
    // missiles in melee
    hook_call(0x4301a8, missile_on_quick_cast, 11);
    hook_call(0x42241a, missile_on_shift_click, 7);
    hook_call(0x42256a, melee_on_normal_click, 11);
    erase_code(0x42ee31, 2); // unnecessary jump
    hook_call(0x42ee33, allow_melee_with_blasters, 5);
    hook_call(0x42eee9, allow_bows_in_melee, 5);
    // drawing small blasters
    hook_call(0x43d035, postpone_drawing_blaster, 8);
    hook_call(0x43d8b1, draw_blaster_behind_belt, 6);
    hook_call(0x43d1f7, return_from_drawing_blaster, 6);
    hook_call(0x43d090, adjust_female_blaster, 6);
    // blasters and wetsuits
    hook_call(0x4690d1, missile_wetsuit_blaster, 16);
    patch_dword(0x43ce6c, OFFSET_MISSILE); // draw missile weapon in a wetsuit
    hook_call(0x43cea9, adjust_wetsuit_blaster, 7);
    erase_code(0x43ceb0, 9);
    erase_code(0x43cebf, 2);
    // use wands from missile slot
    patch_dword(0x42ee6d, dword(0x42ee6d) + 4); // main hand -> missile slot
    patch_dword(0x42ee89, OFFSET_MISSILE);
    patch_dword(0x42ee9b, OFFSET_MISSILE);
    patch_dword(0x42f02f, OFFSET_MISSILE);
    patch_dword(0x42f055, OFFSET_MISSILE);
    patch_dword(0x42f067, OFFSET_MISSILE);
    patch_byte(0x469863, 2); // equip wands in missile slot
    byte(0x4e8354) = SLOT_MISSILE; // ditto
    patch_byte(0x45f2ed, 2); // fix no sound (preload wand sound on game load)
    hook_call(0x4690ee, preload_equipped_wand_sound, 10);
    // status screen
    patch_dword(0x48d40b, OFFSET_MISSILE); // check for wand in missile slot
    hook_call(0x418cc3, print_wand_to_hit, 6);
    hook_call(0x41a910, print_wand_to_hit_ref, 6);
    // replace some wand spells
    patch_bytes(0x457772, parse_sxx_items_txt_chunk, 6);
    hook_call(0x42ee7b, get_parsed_wand_spell, 7);
    hook_call(0x42f047, get_parsed_wand_spell, 7);
    hook_call(0x45f2f9, get_parsed_wand_spell_sound, 7);
    hook_call(0x46953f, get_parsed_wand_spell_sound, 7);
}

// Make sure to disable ranged attack with an empty wand equipped.
static void __declspec(naked) empty_wand_chunk(void)
{
    asm
      {
        mov dword ptr [ebp-16], edi ; unset bow var
      }
}

// Color equipped empty wands and low-tier knives red, as if broken.
// Make sure to check if the regenerating ones have regained some charges.
static void __declspec(naked) red_empty_wands(void)
{
    asm
      {
        and ecx, 0xf0 ; replaced code
        jnz quit
        cmp dword ptr [edi], LIVING_WOOD_KNIVES
        je regen
        cmp dword ptr [edi], DRAGONS_WRATH
        jne not_dragon
        regen:
        mov ecx, edi
        push eax
        call regen_dragon_charges ; still usable
        pop eax ; restore
        xor ecx, ecx
        jmp charged
        not_dragon:
        cmp dword ptr [edi], THROWING_KNIVES
        je charged
        cmp dword ptr [edi], FIRST_WAND
        jb not_it
        cmp dword ptr [edi], LAST_WAND
        ja not_it
        charged:
        cmp dword ptr [edi].s_item.charges, ecx ; == 0
        jnz not_it
        or al, IFLAGS_BROKEN ; for display only
        not_it:
        test ecx, ecx ; zf = 1
        quit:
        ret
      }
}

// Display current and max wand charges, even if it's empty.
static void __declspec(naked) display_wand_charges(void)
{
    asm
      {
        cmp byte ptr [edi].s_items_txt_item.equip_stat, ITEM_TYPE_WAND - 1
        je wand
        xor eax, eax ; set zf
        ret
        wand:
        pop edx
        movzx eax, byte ptr [ecx].s_item.max_charges
        push eax
        mov eax, dword ptr [ecx].s_item.charges ; replaced code
        test eax, eax
        jnz quit
        push dword ptr [GLOBAL_TXT_ADDR+464*4]
        push dword ptr [colors+CLR_RED*4]
        mov eax, offset zero_charges
        push eax
        add edx, 14 ; skip over pushes
        quit:
        jmp edx
      }
}

// Make the wand price depend both on current and maximum charges.
// Called from potion_price() above.
static void __declspec(naked) wand_price(void)
{
    asm
      {
        movzx ecx, byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.mod2
        shl ecx, 1
        movzx eax, byte ptr [esi].s_item.max_charges
        add eax, dword ptr [esi].s_item.charges
        add eax, 2 ; even totally spent wands cost something
        mul edi
        div ecx
        mov edi, eax
        test ecx, ecx ; clear zf
        ret
      }
}

// Create wands with some charges spent already.
static void __declspec(naked) preused_wands(void)
{
    asm
      {
        mov ebx, dword ptr [esi].s_item.charges
        mov byte ptr [esi].s_item.max_charges, bl
        shr ebx, 1 ; up to 50%
        jz quit
        call dword ptr ds:random
        xor edx, edx
        div ebx
        inc edx
        sub dword ptr [esi].s_item.charges, edx
        quit:
        ret
      }
}

// Same, but in the "add item" inventory command.
// We can reuse the above code here.
static void __declspec(naked) preused_wands_2(void)
{
    asm
      {
        lea esi, [ebp-44]
        jmp preused_wands
      }
}

// Same, but for stolen wands.  Also fixes a bug wherein
// stolen wands had rubbish values for max charges.
static void __declspec(naked) preused_wands_3(void)
{
    asm
      {
        lea eax, [eax+edx+1] ; replaced code
        mov dword ptr [ebp-52].s_item.charges, eax ; replaced code
        push esi
        push ebx
        lea esi, [ebp-52]
        call preused_wands
        pop ebx
        pop esi
        ret
      }
}

// More wand init code, not sure when it's called though.
static void __declspec(naked) preused_wands_4(void)
{
    asm
      {
        push ebx
        lea esi, [esp+24]
        call preused_wands
        pop ebx
        ret
      }
}

// This wand init code governs looting monsters with preset wands,
// notably Mr. Malwick (and possibly no-one else).
static void __declspec(naked) preused_wands_5(void)
{
    asm
      {
        push esi
        push ebx
        lea esi, [ebp-44]
        call preused_wands
        pop ebx
        pop esi
        ret
      }
}

// Shops are the exception: wands are always fully charged there.
// Same for throwing knives.
static void __declspec(naked) charge_shop_wands_common(void)
{
    asm
      {
        mov dword ptr [ecx].s_item.flags, 1 ; replaced code
        cmp dword ptr [ecx], THROWING_KNIVES
        je recharge
        cmp dword ptr [ecx], FIRST_WAND
        jb quit
        cmp dword ptr [ecx], LAST_WAND
        ja quit
        recharge:
        movzx edx, byte ptr [ecx].s_item.max_charges
        mov dword ptr [ecx].s_item.charges, edx
        quit:
        ret
      }
}

// Standard shop items hook.
static void __declspec(naked) charge_shop_wands_standard(void)
{
    asm
      {
        lea ecx, [SHOP_STANDARD_ITEMS+ecx*4]
        jmp charge_shop_wands_common
      }
}

// Special shop items hook.
static void __declspec(naked) charge_shop_wands_special(void)
{
    asm
      {
        lea ecx, [SHOP_SPECIAL_ITEMS+eax*4]
        jmp charge_shop_wands_common
      }
}

static char recharge_buffer[100], name_buffer[100];
static const float shop_recharge_multiplier = 0.2; // from 30% to 80%
// Defined below.
static void knife_repair_dialog(void);

// Wand recharge dialog: print cost and resulting number of charges.
// Also here: jump into the knife repair hook if in the black market.
static void __declspec(naked) shop_recharge_dialog(void)
{
    asm
      {
        lea esi, [edi+eax*4-SIZE_ITEM].s_player.items ; replaced code
        cmp dword ptr [esi], FIRST_WAND
        jb not_wand
        cmp dword ptr [esi], LAST_WAND
        jbe wand
        not_wand:
        mov edx, dword ptr [DIALOG2]
        mov edx, dword ptr [edx+28] ; shop id
        cmp edx, BLACK_MARKET_1
        je black
        cmp edx, BLACK_MARKET_2
        jne not_black
        black:
        jmp knife_repair_dialog ; same as for weapon shops
        not_black:
        test byte ptr [esi].s_item.flags, IFLAGS_BROKEN ; replaced code
        ret
        wand:
        movzx eax, byte ptr [esi].s_item.max_charges
        sub eax, dword ptr [esi].s_item.charges
        ja rechargeable
        xor ebx, ebx ; set zf
        ret
        rechargeable:
        mov edx, dword ptr [DIALOG2]
        imul edx, dword ptr [edx+28], SIZE_EVENT2D
        fld dword ptr [0x5912d8+edx] ; store price multiplier
        fld st(0)
        fmul dword ptr [shop_recharge_multiplier]
        push eax
        fimul dword ptr [esp]
        fisttp dword ptr [esp]
        pop ebx ; == restored charges
        cmp ebx, 0
        jbe cannot
        add ebx, dword ptr [esi].s_item.charges
        push 4
        fimul dword ptr [esp]
        fstp dword ptr [esp]
        mov ecx, edi
        call dword ptr ds:identify_price
        push eax
        push ebx
        cannot:
        mov ecx, esi
        call dword ptr ds:item_name
        mov ecx, offset name_buffer
        push ecx ; for the second sprintf
        push eax
        push dword ptr [colors+CLR_ITEM*4]
        push COLOR_FORMAT_ADDR
        push ecx
        call dword ptr ds:sprintf
        add esp, 16
        cmp ebx, 0
        cmova eax, dword ptr [new_strings+STR_RECHARGE*4]
        cmovbe eax, dword ptr [new_strings+STR_CANNOT_RECHARGE*4]
        push eax
        mov eax, offset recharge_buffer
        push eax
        call dword ptr ds:sprintf
        add esp, 20
        cmp ebx, 0
        ja no_adjust
        sub esp, 8
        fstp st(0)
        no_adjust:
        mov eax, offset recharge_buffer
        xor ebx, ebx
        push 0x4b5453
        ret 4
      }
}

// We need to store the number of charges after shop recharge for later.
static int new_charges;

// Actually clicking on the wand: check if we should recharge it,
// and calculate price and new charges if so.  Also here: repair knives.
static void __declspec(naked) prepare_shop_recharge(void)
{
    asm
      {
        cmp dword ptr [esi], FIRST_WAND
        jb not_wand
        cmp dword ptr [esi], LAST_WAND
        jbe wand
        not_wand:
        mov dword ptr [ebp-8], eax ; replaced code
        test byte ptr [esi].s_item.flags, IFLAGS_BROKEN ; replaced code
        jnz skip ; actual repair takes priority
        cmp dword ptr [esi], THROWING_KNIVES
        je knives
        cmp dword ptr [esi], LIVING_WOOD_KNIVES
        je knives
        xor eax, eax ; set zf
        skip:
        fstp st(0) ; discard store price multiplier
        ret
        knives:
        fld1 ; 20% bonus
        faddp
        jmp multiply
        wand:
        fld st(0)
        multiply:
        fmul dword ptr [shop_recharge_multiplier]
        movzx eax, byte ptr [esi].s_item.max_charges
        sub eax, dword ptr [esi].s_item.charges
        jbe cannot_recharge
        push eax
        fimul dword ptr [esp]
        fisttp dword ptr [esp]
        pop eax ; == restored charges
        cmp eax, 0
        ja recharge
        cannot_recharge:
        cmp dword ptr [esi], THROWING_KNIVES
        je quit
        cmp dword ptr [esi], LIVING_WOOD_KNIVES
        je quit
        fstp st(0) ; discard store price multiplier
        xor eax, eax ; set zf
        quit:
        ret
        recharge:
        add eax, dword ptr [esi].s_item.charges
        mov dword ptr [new_charges], eax
        cmp dword ptr [esi], THROWING_KNIVES
        je old_price
        cmp dword ptr [esi], LIVING_WOOD_KNIVES
        je old_price
        mov ecx, edi
        push 4
        fimul dword ptr [esp]
        fstp dword ptr [esp]
        call dword ptr ds:identify_price
        mov dword ptr [ebp-8], eax ; store the price
        old_price:
        test esi, esi ; clear zf
        ret
      }
}

// After passing all the checks, actually recharge the wand / repair knives.
static void __declspec(naked) perform_shop_recharge(void)
{
    asm
      {
        cmp dword ptr [esi], FIRST_WAND
        jb repair
        cmp dword ptr [esi], LAST_WAND
        jbe recharge
        test byte ptr [esi].s_item.flags, IFLAGS_BROKEN
        jnz repair ; actual repair first
        cmp dword ptr [esi], THROWING_KNIVES
        je recharge
        cmp dword ptr [esi], LIVING_WOOD_KNIVES
        jne repair
        recharge:
        mov eax, dword ptr [new_charges]
        mov dword ptr [esi].s_item.charges, eax
        mov byte ptr [esi].s_item.max_charges, al
        repair:
        mov eax, dword ptr [esi].s_item.flags ; replaced code
        mov ecx, edi ; replaced code
        ret
      }
}

// Make wands break instead of disappear when they run out of charges;
// also, let magical shops recharge wands for a price.
static inline void wand_charges(void)
{
    patch_bytes(0x42ed4f, empty_wand_chunk, 3);
    // Remove the code that destroys empty wands.
    erase_code(0x42ed52, 5); // when wand was already empty
    erase_code(0x42eeae, 14); // shooting at a monster
    erase_code(0x42f07d, 12); // shooting at nothing
    hook_call(0x43d0aa, red_empty_wands, 6);
    hook_call(0x41de08, display_wand_charges, 5);
    patch_pointer(0x41de17, nonzero_charges); // new format
    patch_byte(0x41de29, 20); // call fixup
    hook_call(0x456a78, preused_wands, 6);
    hook_call(0x44b357, preused_wands_2, 6);
    hook_call(0x48da1a, preused_wands_3, 7); // this overwrites mm7patch
    hook_call(0x415c93, preused_wands_4, 8);
    hook_call(0x426b36, preused_wands_5, 6);
    hook_call(0x4b8ebd, charge_shop_wands_standard, 11);
    hook_call(0x4b9038, charge_shop_wands_special, 11);
    hook_call(0x4b540c, shop_recharge_dialog, 11);
    patch_byte(0x4bdbc1, 0x14); // fstp -> fst (preserve store pricing)
    hook_call(0x4bdbd0, prepare_shop_recharge, 7);
    hook_call(0x4bdc0c, perform_shop_recharge, 5);
    // Related bug (?) fix: repairing an item also identified it for free.
    erase_code(0x4bdc15, 2);
}

// Print the damage in the stun message,
// and don't show it at all if the monster is dead.
static void __declspec(naked) stun_message(void)
{
    asm
      {
        cmp word ptr [esi].s_map_monster.hp, bx ; == 0
        jg message
        push 0x439cba ; skip over message code
        ret 8
        message:
        pop ecx
        push dword ptr [ebp-12] ; damage
        lea eax, [edi].s_player.name ; replaced code
        jmp ecx
      }
}

// Same, but for paralysis and MM7Patch's halved armor.
static void __declspec(naked) paralysis_message(void)
{
    asm
      {
        cmp word ptr [esi].s_map_monster.hp, 0
        jg message
        push 0x439d6e ; skip over message code
        ret 12
        message:
        pop eax
        pop ecx ; player name
        push dword ptr [ebp-12] ; damage
        push ecx
        cmp dword ptr [ebp-52], 2 ; check if halved armor
        jne okay
        mov ecx, dword ptr [0x439d57] ; mm7patch`s format string
        mov edx, dword ptr [new_strings+STR_HALVE_ARMOR*4] ; new message
        mov dword ptr [ecx], edx
        okay:
        mov edi, 0x5c5c30 ; replaced code
        jmp eax
      }
}

// Also: last_hit_player defined above.
// If both of those remain the same, combine the damage messages.
static int last_hit_spell;
// Accumulated damage to the monster(s).
static int total_damage;
// If only one monster is damaged, points to it, otherwise zero.
static void *only_target;
// Whether said monster was killed.
static char killed_only_target;

// Display the message for damaging several monsters with the same attack.
static char *__stdcall multihit_message(struct player *player, void *monster,
                                        int damage, int kill)
{
    static void *hit_monsters[100];
    static int hit_count, dead_count;

    if (only_target)
      {
        hit_count = 1;
        dead_count = killed_only_target;
        hit_monsters[0] = only_target;
        only_target = 0;
      }
    for (int i = 0; i <= hit_count && i < 100; i++)
        if (i == hit_count)
          {
            hit_monsters[i] = monster;
            hit_count++;
            break;
          }
        else if (hit_monsters[i] == monster)
            break;
    dead_count += kill;
    total_damage += damage;

    static char buffer[100];
    if (dead_count)
        sprintf(buffer, new_strings[STR_KILL_MANY], player->name, total_damage,
                hit_count, dead_count);
    else
        sprintf(buffer, new_strings[STR_DAMAGE_MANY], player->name,
                total_damage, hit_count);
    return buffer;
}

// Check if we should display the combined message.
static void __declspec(naked) multihit_message_check(void)
{
    asm
      {
        cmp dword ptr [0x6be1f8], 0 ; replaced code
        jnz message
        ret
        message:
        mov eax, dword ptr [ebp-12] ; damage
        mov dword ptr [ebp-16], eax ; unused at this point
        mov ecx, ebx
        cmp dword ptr [esp], 0x439b5b ; if called from kill message code
        cmove ecx, dword ptr [stored_projectile] ; then restore proj
        sete dl ; and set the kill flag
        test ecx, ecx
        jnz have_proj
        mov dword ptr [last_hit_player], ecx ; don`t stack melee messages
        inc ecx ; clear zf
        jmp record_hit ; will only be used for splitter`s fireball
        have_proj:
        mov eax, dword ptr [ecx].s_map_object.owner
        cmp eax, dword ptr [last_hit_player]
        je check_spell
        mov dword ptr [last_hit_player], eax
        mov eax, dword ptr [ecx].s_map_object.spell_type
        reset_spell:
        mov dword ptr [last_hit_spell], eax
        record_hit:
        mov eax, dword ptr [ebp-12] ; damage
        mov dword ptr [total_damage], eax
        mov dword ptr [only_target], esi
        mov byte ptr [killed_only_target], dl
        ret ; zf == 0 here
        check_spell:
        mov eax, dword ptr [ecx].s_map_object.spell_type
        cmp eax, dword ptr [last_hit_spell]
        jne reset_spell
        cmp dword ptr [only_target], esi
        jne multihit
        mov eax, dword ptr [ebp-12] ; damage
        add eax, dword ptr [total_damage]
        mov dword ptr [total_damage], eax
        mov dword ptr [ebp-16], eax
        mov byte ptr [killed_only_target], dl
        ret ; zf should be unset now
        multihit:
        movzx edx, dl ; kill flag
        push edx
        push dword ptr [ebp-12] ; damage
        push esi ; monster
        push edi ; player
        call multihit_message
        mov ecx, eax ; message
        push 0x439bf7 ; show status text
        ret 4
      }
}

// Also combine Splitter's hit message with message from
// the following fireball.  This will suppresss
// the halved armor message, but nothing is perfect.
static void __declspec(naked) splitter_fireball_message(void)
{
    asm
      {
        lea eax, [ebx*8-8+TGT_PARTY]
        mov dword ptr [last_hit_player], eax
        mov dword ptr [last_hit_spell], SPL_FIREBALL
        movsx eax, word ptr [edi].s_map_monster.height ; replaced code
        ret
      }
}

// Print "critically hits" / "backstabs" / "critically shoots"
// instead of "hits" / "shoots" as appropriate.
static void __declspec(naked) hit_qualifier(void)
{
    asm
      {
        pop edx
        mov ecx, dword ptr [critical_hit]
        cmovz eax, dword ptr [new_strings+STR_HITS*4+ecx*4]
        cmovnz eax, dword ptr [new_strings+STR_SHOOTS*4+ecx*4]
        push eax
        lea eax, dword ptr [edi].s_player.name ; replaced code
        jmp edx
      }
}

// As Immolation does not use the cast spell routine,
// its cumulative messages weren't reset.
static void __declspec(naked) reset_immolation_message(void)
{
    asm
      {
        mov dword ptr [last_hit_player], edi ; == 0
        jmp dword ptr ds:init_item ; replaced call
      }
}

// Supply the current PC as the caster for Immolation pedestal.
// Relevant for damage messages.  See also switch_off_immolation() above.
static void __declspec(naked) evt_immolation_caster(void)
{
    asm
      {
        mov dword ptr [ebp+8], esi ; replaced code
        fild dword ptr [ebp+8] ; replaced code
        mov eax, dword ptr [CURRENT_PLAYER]
        dec eax
        jl quit
        mov dword ptr [esp+12], eax ; pushed caster
        quit:
        ret
      }
}

// Condense consecutive damage messages for AOE spells and the like
// into a single message for each cast, plus handle crits and backstabs.
static inline void damage_messages(void)
{
    hook_call(0x439c93, stun_message, 6);
    patch_byte(0x439cac, 20); // call fixup
    hook_call(0x439d50, paralysis_message, 5);
    patch_byte(0x439d63, 20); // call fixup
    hook_call(0x439b56, multihit_message_check, 6);
    patch_byte(0x439b77, -16); // total damage  == [ebp-16]
    // also called from cursed_weapon() above
    patch_byte(0x439bc5, -16); // total damage  == [ebp-16]
    hook_call(0x42ef8a, splitter_fireball_message, 7);
    hook_call(0x439bce, hit_qualifier, 6);
    patch_byte(0x439bf1, 24); // stack fixup
    hook_call(0x493a68, reset_immolation_message, 5);
    hook_call(0x44962c, evt_immolation_caster, 6);
}

// Provide the address of the above buffer to the parsing function.
static void __declspec(naked) write_new_npc_text(void)
{
    asm
      {
        cmp dword ptr [esp+28], offset new_npc_text
        jae new
        add dword ptr [esp+28], 8 ; replaced code
        cmp dword ptr [esp+28], 0x722d94 ; also replaced code
        jl quit
        mov dword ptr [esp+28], offset new_npc_text
        cmp ebx, esp ; set flags
        quit:
        ret
        new:
        add dword ptr [esp+28], 4
        cmp dword ptr [esp+28], offset new_npc_text + NEW_TEXT_COUNT * 4
        ret
      }
}

// Provide the new entries when needed.
static void __declspec(naked) display_new_npc_text(void)
{
    asm
      {
        cmp eax, 789 ; old buffer size
        ja new
        mov eax, dword ptr [NPC_TOPIC_TEXT_ADDR+eax*8-4] ; replaced code
        ret
        new:
        mov eax, dword ptr [new_npc_text+eax*4-790*4]
        ret
      }
}

// Same, but in different register.
static void __declspec(naked) display_new_npc_text_2(void)
{
    asm
      {
        call display_new_npc_text
        mov ecx, eax
        ret
      }
}

// I want to add a couple new greetings, and the array has to be expanded.
// Also here: parse more NPC topics.  (This doesn't need new memory.)
// Finally, I also expand the NPC text (replies) array here.
static inline void npc_dialog(void)
{
    static void *npc_greet[2+GREET_COUNT*2];
    patch_word(0x476e38, 0xb890); // nop; mov eax
    patch_pointer(0x476e3a, npc_greet + 2); // 0th greeting is skipped
    patch_dword(0x476e45, GREET_COUNT);
    patch_pointer(0x4455dc, npc_greet);
    patch_pointer(0x4b2ba4, npc_greet);
    patch_dword(0x476b17, NPC_TOPIC_TEXT_ADDR + TOPIC_COUNT * 8); // add topics
    hook_call(0x476a43, write_new_npc_text, 13);
    hook_call(0x447bee, display_new_npc_text, 7);
    hook_call(0x447c0d, display_new_npc_text_2, 7);
    hook_call(0x447c65, display_new_npc_text, 7);
}

// Our implementation of stat-changing routines for the new game screen.
// Normally all stats are internally adjusted by 1, but if it results
// in no change to the visible value, we need to skip an extra point.
static void new_game_adjust_stat(struct player *player, int stat, int step)
{
    uint16_t *value;
    switch (stat)
      {
// I know what I'm doing!
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
        case STAT_MIGHT:
            value = &player->might_base;
            break;
        case STAT_INTELLECT:
            value = &player->intellect_base;
            break;
        case STAT_PERSONALITY:
            value = &player->personality_base;
            break;
        case STAT_ENDURANCE:
            value = &player->endurance_base;
            break;
        case STAT_ACCURACY:
            value = &player->accuracy_base;
            break;
        case STAT_SPEED:
            value = &player->speed_base;
            break;
        case STAT_LUCK:
            value = &player->luck_base;
            break;
        default:
            return;
#pragma GCC diagnostic pop
      }
    int race = get_race(player);
    int mul = RACE_STATS[race][stat][3], div = RACE_STATS[race][stat][2];
    int new = *value + step;
    if (mul < div)
      {
        while (new * mul / div == (new - 1) * mul / div)
            new += step;
      }
    if (step > 0 && new <= RACE_STATS[race][stat][1]
                 && new - *value <= new_game_get_bonus()
        || step < 0 && new >= RACE_STATS[race][stat][0] - 2)
        *value = new;
}

// Hook for the minus (decrease) button.
static void __thiscall new_game_decrease_stat(struct player *player, int stat)
{
    new_game_adjust_stat(player, stat, -1);
}

// Ditto, but for the plus (increase) button.
static void __thiscall new_game_increase_stat(struct player *player, int stat)
{
    new_game_adjust_stat(player, stat, 1);
}

// Apply the racial modifiers to PC's stats.
static void __declspec(naked) racial_stat(void)
{
    asm
      {
        push eax
        mov ecx, esi
        call dword ptr ds:get_race
        mov edx, dword ptr [esp+8]
        imul eax, eax, 7
        add eax, edx
        movzx ecx, byte ptr [RACE_STATS_ADDR+eax*4+2] ; denominator
        movzx eax, byte ptr [RACE_STATS_ADDR+eax*4+3] ; multiplier
        cmp edx, 4
        jb no_swap
        ; player stats are slightly out of order
        xor edx, 1 ; 5 -> 4, 4 -> 5, 6 -> 7
        cmp edx, 6
        adc edx, -1 ; 7 -> 6
        no_swap:
        movzx edx, word ptr [esi+S_PL_STATS+edx*4]
        imul edx
        idiv ecx
        pop ecx
        ret 4
      }
}

// Also account for race when checking a base stat in gamescript.
static void __declspec(naked) evt_cmp_base_stat(void)
{
    asm
      {
        cmp eax, 32
        jge base_stat
        ret
        base_stat:
        sub eax, 32
        push eax
        call racial_stat
        mov edi, eax
        push 0x44a3de ; the compare code
        ret 4
      }
}

// New values for RACE_STATS.
static const uint8_t race_stat_values[4][7][4] = {
    11, 25,  1, 1, 11, 25,  1, 1, 11, 25,  1, 1,  9, 25,  1, 1,
    11, 25,  1, 1, 11, 25,  1, 1, 10, 21,  5, 6, // human
    10, 22, 10, 7, 10, 22,  5, 7, 11, 25,  1, 1, 10, 22, 10, 7,
    10, 22,  5, 7, 11, 25,  1, 1,  9, 20,  1, 1, // elf
    10, 22,  5, 7, 10, 22, 10, 7, 10, 22, 10, 7, 11, 25,  1, 1,
    11, 25,  1, 1, 10, 22,  5, 7,  9, 20,  1, 1, // goblin
    10, 22,  5, 7, 11, 25,  1, 1, 11, 25,  1, 1, 10, 22,  5, 7,
    10, 22, 10, 7, 10, 22, 10, 7,  9, 20,  1, 1, // dwarf
};

// Handmade to appear as close as possible to the vanilla party,
// while utilizing exactly 50 bonus points.
static const int default_party_stats[4][7] = {
      { 22, 8,  8, 13, 10, 13,  7 },
      { 13, 9,  9, 13, 13, 13, 10 },
      { 8,  9, 20, 16, 19, 10,  7 },
      { 8, 22,  9, 19, 13,  9,  7 }
};

// Initialize the default Zoltan/Roderick/etc. party with adjusted stats.
static void default_party(void)
{
    for (int p = 0; p < 4; p++)
        for (int s = 0; s < 7; s++)
            PARTY[p].stats[s][0] = default_party_stats[p][s];
}

// Hook for the above.
static void __declspec(naked) default_party_hook(void)
{
    asm
      {
        mov edi, 220 ; replaced code
        jmp default_party
      }
}

// Our rewrite of get_full_hp().  Now Endurance and Bodybuilding
// increase HP by 5% per point of effect, provided the level
// is high enough.  Also, race affects HP factor.
// Also here: scale current HP with total after temp changes to endurance.
static int __thiscall get_new_full_hp(struct player *player)
{
    int level = get_level(player);
    int bonus = get_bodybuilding_bonus(player);
    int base = CLASS_HP_FACTORS[player->class];
    int race = get_race(player);
    if (race == RACE_ELF)
        base--;
    else if (race != RACE_HUMAN)
        base++;
    int add = CLASS_STARTING_HP[player->class>>2];
    add += get_stat_bonus_from_items(player, STAT_HP, 0);
    add += player->hp_bonus;
    int endurance = get_base_endurance(player);
    int temp = get_endurance(player) - endurance;
    static int temps[4];
    int id = player - PARTY;
    int change = temp != temps[id] && !(reset_hp_temp & 1 << id);
    int total[2];
    for (int i = !change; i < 2; i++)
      {
        if (i) temps[id] = temp;
        int full_bonus = bonus + get_effective_stat(endurance + temps[id]);
        if (level <= 20)
            total[i] = base * (level + full_bonus) + add;
        else
            total[i] = base * level * (full_bonus + 20) / 20 + add;
        if (total[i] < 1)
            total[i] = 1;
      }
    if (change && player->hp > 0)
      {
        player->hp = player->hp * total[1] / total[0];
        if (player->hp <= 0) player->hp = 1;
      }
    reset_hp_temp &= ~(1 << id);
    return total[1];
}

// Ditto, but for get_full_sp(), spellcasting stats, and Meditation.
// NB: goblins get one less SP per 2 levels, so we operate in half-points.
// Same is true for DP Thieves and LP monks (they trade 1 HP for 1/2 SP).
// Also here: scale current SP with total after temp stat changes, as above.
static int __thiscall get_new_full_sp(struct player *player)
{
    int id = player - PARTY;
    int stat = CLASS_SP_STATS[player->class];
    if (player->class < 5 || stat == 3)
        return 0;
    if (has_item_in_slot(player, WITCHBANE, SLOT_AMULET))
      {
        // no current sp changes!
        reset_sp_temp |= 1 << id;
        return 0;
      }
    int level = get_level(player);
    int bonus = get_meditation_bonus(player);
    int base = CLASS_SP_FACTORS[player->class] * 2;
    if (player->class == CLASS_ASSASSIN || player->class == CLASS_MASTER)
        base--;
    int race = get_race(player);
    if (race == RACE_ELF)
        base += 2;
    else if (race == RACE_GOBLIN)
        base--;
    int add = CLASS_STARTING_SP[player->class>>2];
    add += get_stat_bonus_from_items(player, STAT_SP, 0);
    add += player->sp_bonus;
    static int average = 0;
    if (!average) for (int i = 0; i < MAX_STATRATE_COUNT; i++)
        if (statrates[i].bonus == 0)
          {
            average = statrates[i].value;
            break;
          }
    int personality = average, intellect = average;
    int temp_per = 0, temp_int = 0;
    if (stat != 0)
      {
        personality = get_base_personality(player);
        temp_per = get_personality(player) - personality;
      }
    if (stat != 1)
      {
        intellect = get_base_intellect(player);
        temp_int = get_intellect(player) - intellect;
      }
    static int temps[4][2];
    int change = (temp_per != temps[id][0] || temp_int != temps[id][1])
               && !(reset_sp_temp & 1 << id);
    int total[2];
    for (int i = !change; i < 2; i++)
      {
        if (i)
          {
            temps[id][0] = temp_per;
            temps[id][1] = temp_int;
          }
        int full_bonus = bonus + get_effective_stat(personality + temps[id][0])
                               + get_effective_stat(intellect + temps[id][1]);
        total[i] = (base * level + 1) / 2; // round up for goblins
        if (level <= 20)
            total[i] += base * full_bonus >> 1; // but round down here
        else
            total[i] = total[i] * (full_bonus + 20) / 20;
        total[i] += add;
        if (total[i] <= 0)
            total[i] = 0;
      }
    if (change)
      {
        if (total[0])
            player->sp = player->sp * total[1] / total[0];
        else if (player->sp < total[1])
            player->sp = total[1];
      }
    reset_sp_temp &= ~(1 << id);
    return total[1];
}

// For a div in the below function.
static const int two_forty = 240;
// For the level-up message.
static int added_skill_points;

// Starting from level 20, grant ever more skill points on level up.
// Humans get additional points as their racial bonus.
// Also here: every 10th level, reset +2 stat wells.
static void __declspec(naked) human_skill_point(void)
{
    asm
      {
        test edx, edx ; edx == new_level % 10
        jnz no_reset
        and dword ptr [ebx].s_player.bits, ~0x24c360 ; reset the wells
        no_reset:
        cmp eax, 7 ; level 20+
        jae extra
        mov edx, eax
        jmp human
        extra:
        movzx eax, word ptr [ebx].s_player.level_base
        lea ecx, [eax-1]
        mul eax
        mul ecx
        cmp ecx, 40
        ja high
        cmp ecx, 35
        jbe low
        mov edx, 20 ; manually glue together high and low levels
        jmp human
        low:
        add eax, 900 ; bonus at levels 20-36 to preserve sp total
        high:
        div dword ptr [two_forty]
        push eax
        lea eax, [ecx-1]
        mul ecx
        mul ecx
        div dword ptr [two_forty]
        pop edx
        sub edx, eax
        human:
        mov ecx, ebx
        call dword ptr ds:get_race
        cmp eax, RACE_HUMAN
        jne not_human
        lea eax, [edx+7]
        shr eax, 3
        add edx, eax
        not_human:
        add dword ptr [ebx].s_player.skill_points, edx ; replaced code, almost
        mov dword ptr [added_skill_points], edx ; for the statusline
        mov ecx, ebx ; restore
        ret
      }
}

// Replace the starting weapon skill with the racial skill
// when initializing a character.  Monks are exempt.
// Humans just get an extra Learning instead.
static void __declspec(naked) init_racial_skill(void)
{
    asm
      {
        mov dl, byte ptr [STARTING_SKILLS_ADDR+eax+edi] ; replaced, sorta
        mov ecx, esi
        call dword ptr ds:get_race
        cmp eax, RACE_HUMAN
        je human
        cmp edi, SKILL_BLASTER
        jae skip
        cmp byte ptr [esi].s_player.class, CLASS_MONK
        je skip
        cmp eax, RACE_ELF
        je elf
        cmp eax, RACE_GOBLIN
        je goblin
        cmp eax, RACE_DWARF
        je dwarf
        skip:
        cmp dl, 2
        ret
        elf:
        cmp edi, SKILL_BOW
        ret
        goblin:
        cmp edi, SKILL_SWORD
        ret
        dwarf:
        cmp edi, SKILL_AXE
        ret
        human:
        cmp edi, SKILL_LEARNING
        jne skip
        ret
      }
}

// Substitute the racial skill when determining
// the first two skills to display.
static void __declspec(naked) check_racial_skill(void)
{
    asm
      {
        cmp eax, SKILL_BLASTER
        jae skip
        cmp byte ptr [ecx].s_player.class, CLASS_MONK
        je skip
        push ecx
        push eax
        call dword ptr ds:get_race
        mov ecx, eax
        pop eax
        cmp ecx, RACE_ELF
        je elf
        cmp ecx, RACE_GOBLIN
        je goblin
        cmp ecx, RACE_DWARF
        je dwarf
        pop ecx
        skip:
        cmp byte ptr [STARTING_SKILLS_ADDR+ebx+eax], 2 ; replaced code
        ret
        elf:
        cmp eax, SKILL_BOW
        jmp quit
        goblin:
        cmp eax, SKILL_SWORD
        jmp quit
        dwarf:
        cmp eax, SKILL_AXE
        quit:
        pop ecx
        ret
      }
}

// Extra pick that replaces Learning for humans.
static const int added_picks[9] = { SKILL_NONE, SKILL_NONE, SKILL_NONE,
                                    SKILL_NONE, SKILL_CHAIN, SKILL_NONE,
                                    SKILL_STAFF, SKILL_AIR, SKILL_NONE };

// Substitute the racial skill with the default weapon skill
// when displaying picked optional skills.  Also don't display Learning
// (twice) for humans, but do display the extra pick.
static void __declspec(naked) exclude_racial_skill(void)
{
    asm
      {
        push edx
        push ecx
        push eax
        call dword ptr ds:get_race
        mov edx, eax
        pop eax
        pop ecx
        cmp edx, RACE_HUMAN
        jne nonhuman
        cmp eax, SKILL_LEARNING
        je invert ; this will clear zf
        movzx edx, byte ptr [ecx].s_player.class
        cmp eax, dword ptr [added_picks+edx]
        je quit
        skip:
        cmp byte ptr [STARTING_SKILLS_ADDR+ebx+eax], 1 ; replaced code, almost
        jmp quit
        nonhuman:
        cmp eax, SKILL_BLASTER
        jae skip
        cmp byte ptr [ecx].s_player.class, CLASS_MONK
        je monk
        cmp byte ptr [STARTING_SKILLS_ADDR+ebx+eax], 1 ; replaced code, again
        jae race
        jmp quit
        monk:
        cmp byte ptr [STARTING_SKILLS_ADDR+ebx+eax], 1 ; also replaced code
        jb race
        jmp quit
        race:
        cmp edx, RACE_GOBLIN
        je goblin
        cmp edx, RACE_DWARF
        je dwarf
        ; elf
        cmp eax, SKILL_BOW
        jmp racial
        goblin:
        cmp eax, SKILL_SWORD
        jmp racial
        dwarf:
        cmp eax, SKILL_AXE
        racial:
        setne dl
        cmp byte ptr [ecx].s_player.class, CLASS_MONK
        jne invert
        test edx, edx
        jmp quit
        invert:
        cmp edx, 1
        quit:
        pop edx
        ret
      }
}

// Store class ID and racial skill for the hook below.
static void __declspec(naked) preserve_racial_skill(void)
{
    asm
      {
        movzx esi, byte ptr [ecx].s_player.class ; replaced code, sort of
        call dword ptr ds:get_race
        mov ecx, esi
        cmp eax, RACE_ELF
        je elf
        cmp eax, RACE_GOBLIN
        je goblin
        cmp eax, RACE_DWARF
        je dwarf
        mov ebx, SKILL_LEARNING
        ret
        elf:
        mov ebx, SKILL_BOW
        ret
        goblin:
        mov ebx, SKILL_SWORD
        ret
        dwarf:
        mov ebx, SKILL_AXE
        ret
      }
}

// Which skill picks to replace with the class' default weapon.
static const int excluded_picks[9] = { SKILL_NONE, SKILL_PERCEPTION,
                                       SKILL_SWORD, SKILL_DAGGER, SKILL_NONE,
                                       SKILL_NONE, SKILL_REPAIR,
                                       SKILL_PERCEPTION, SKILL_MERCHANT };

// In the available skill picks, remove racial skill, add the default
// weapon skill if the former replaces it, and remove the least useful
// skill if there's not enough space.  For humans, possibly add an extra
// pick instead (if Learning is removed).
static void __declspec(naked) substitute_racial_skill(void)
{
    asm
      {
        cmp ebx, SKILL_LEARNING
        je human
        cmp esi, CLASS_MONK
        je monk
        cmp eax, ebx
        je not_it
        cmp eax, dword ptr [excluded_picks+esi]
        je substitute
        cmp eax, SKILL_BLASTER
        jae skip
        cmp byte ptr [ecx], 0
        ja show
        jmp not_it
        monk:
        cmp eax, ebx
        je show
        cmp eax, dword ptr [excluded_picks+esi]
        je not_it
        skip:
        cmp byte ptr [ecx], 1
        je show
        not_it:
        dec edx ; revert inc in the code below
        test ecx, ecx ; clear zf
        ret
        substitute:
        push ebx
        add ebx, ecx
        sub ebx, eax
        cmp byte ptr [ebx], 0
        pop ebx
        jz not_it
        show:
        cmp edx, edi ; replaced code
        ret
        human:
        cmp eax, ebx
        je not_it
        cmp eax, dword ptr [added_picks+esi]
        jne skip
        jmp show
      }
}

// Defined below.
static void __thiscall shift_human_buttons(int player);
static void __thiscall unshift_human_buttons(int player);

// To make init_racial_skill() work properly when resetting the party,
// we need to set the faces (and thus, races) before it's called.
static void __declspec(naked) reset_races(void)
{
    asm
      {
        mov byte ptr [PARTY_ADDR].s_player.face, 17
        mov byte ptr [PARTY_ADDR+SIZE_PLAYER].s_player.face, 3
        mov byte ptr [PARTY_ADDR+SIZE_PLAYER*2].s_player.face, 14
        mov byte ptr [PARTY_ADDR+SIZE_PLAYER*3].s_player.face, 10
        cmp dword ptr [0x507a4c], 0
        jz too_early
        xor ecx, ecx
        call unshift_human_buttons
        inc ecx
        call shift_human_buttons ; second one is human
        inc ecx
        call unshift_human_buttons
        inc ecx
        call unshift_human_buttons
        too_early:
        mov byte ptr [esi+0x708], 15 ; replaced code
        ret
      }
}

// When changing PC race, take care to add/remove racial skills as needed.
// Also remove the picks that become unavailable.
static void __declspec(naked) change_racial_skill(void)
{
    asm
      {
        mov ecx, edi
        call dword ptr ds:get_race
        mov byte ptr [edi].s_player.face, dl
        mov edx, eax
        mov ecx, edi
        call dword ptr ds:get_race
        cmp eax, edx
        je quit
        cmp edx, RACE_ELF
        je was_elf
        cmp edx, RACE_DWARF
        je was_dwarf
        cmp edx, RACE_GOBLIN
        je was_goblin
        mov word ptr [edi+SKILL_LEARNING*2].s_player.skills, 0
        mov ecx, dword ptr [esp+20] ; player id
        push eax
        call unshift_human_buttons
        pop eax
        movzx ecx, byte ptr [edi].s_player.class
        mov edx, dword ptr [added_picks+ecx]
        cmp edx, SKILL_NONE
        je no_extra
        mov word ptr [edi+edx*2].s_player.skills, 0
        no_extra:
        cmp byte ptr [edi].s_player.class, CLASS_MONK
        je new_race
        shr ecx, 2
        imul ecx, ecx, SKILL_COUNT
        or edx, -1
        was_human_loop:
        inc edx
        cmp byte ptr [STARTING_SKILLS_ADDR+ecx+edx], 2
        jne was_human_loop
        mov word ptr [edi+edx*2].s_player.skills, 0
        jmp new_race
        was_elf:
        mov word ptr [edi+SKILL_BOW*2].s_player.skills, 0
        jmp new_race
        was_goblin:
        cmp byte ptr [edi].s_player.class, CLASS_MONK ; monks know sword
        je new_race
        mov word ptr [edi+SKILL_SWORD*2].s_player.skills, 0
        jmp new_race
        was_dwarf:
        mov word ptr [edi+SKILL_AXE*2].s_player.skills, 0
        new_race:
        cmp eax, RACE_ELF
        je elf
        cmp eax, RACE_GOBLIN
        je goblin
        cmp eax, RACE_DWARF
        je dwarf
        mov word ptr [edi+SKILL_LEARNING*2].s_player.skills, 1
        mov ecx, dword ptr [esp+20] ; player id
        call shift_human_buttons
        cmp byte ptr [edi].s_player.class, CLASS_MONK
        je quit
        movzx ecx, byte ptr [edi].s_player.class
        shr ecx, 2
        imul ecx, ecx, SKILL_COUNT
        or edx, -1
        human_loop:
        inc edx
        cmp byte ptr [STARTING_SKILLS_ADDR+ecx+edx], 2
        jne human_loop
        mov word ptr [edi+edx*2].s_player.skills, 1
        jmp quit
        elf:
        mov edx, SKILL_BOW
        jmp got_skill
        goblin:
        mov edx, SKILL_SWORD
        jmp got_skill
        dwarf:
        mov edx, SKILL_AXE
        got_skill:
        movzx ecx, byte ptr [edi].s_player.class
        shr ecx, 2
        imul ecx, ecx, SKILL_COUNT
        cmp byte ptr [STARTING_SKILLS_ADDR+ecx+edx], 0
        jne not_removed
        movzx ecx, byte ptr [edi].s_player.class
        mov ecx, dword ptr [excluded_picks+ecx]
        mov word ptr [edi+ecx*2].s_player.skills, 0
        not_removed:
        cmp byte ptr [edi].s_player.class, CLASS_MONK
        je quit
        mov word ptr [edi+edx*2].s_player.skills, 1
        quit:
        movzx eax, byte ptr [edi].s_player.face
        ret
      }
}

// Ditto, but for the code that cycles portraits leftwards.
static void __declspec(naked) decrement_race(void)
{
    asm
      {
        mov dl, byte ptr [eax]
        mov edi, ebx
        dec dl
        jns skills
        mov dl, 19
        skills:
        jmp change_racial_skill
      }
}

// Shift a human PC's mandatory skills up to make place for Learning.
static void __declspec(naked) shift_human_skills_up(void)
{
    asm
      {
        push ecx
        mov ecx, edi
        call dword ptr ds:get_race
        pop ecx
        cmp eax, RACE_HUMAN
        jne not_human
        mov eax, ebp
        shr eax, 1
        sub eax, 3
        sub dword ptr [esp+8], eax
        not_human:
        jmp dword ptr ds:print_string
      }
}

// And likewise shift the optional skills down.
static void __declspec(naked) shift_human_skills_down(void)
{
    asm
      {
        push ecx
        mov ecx, edi
        call dword ptr ds:get_race
        pop ecx
        cmp eax, RACE_HUMAN
        jne not_human
        mov eax, ebp
        shr eax, 1
        add eax, 3
        add dword ptr [esp+8], eax
        not_human:
        jmp dword ptr ds:print_string
      }
}

// We need to restore the PC pointer for the last one.
static void __declspec(naked) shift_last_human_skill(void)
{
    asm
      {
        mov edi, [esp+56]
        sub edi, 168
        jmp shift_human_skills_down
      }
}

static char learning_buffer[100];

// Print the human racial skill, Learning, as the third mandatory skill.
static void __declspec(naked) print_human_racial_skill(void)
{
    asm
      {
        mov ecx, edi
        call dword ptr ds:get_race
        cmp eax, RACE_HUMAN
        jne quit
        mov edx, dword ptr [SKILL_NAMES_ADDR+SKILL_LEARNING*4]
        push edx
        push dword ptr [0x5c347c] ; font
        mov ecx, 150
        call dword ptr ds:get_text_width
        push eax
        push 0x4ee7a8 ; format string
        mov eax, offset learning_buffer
        push eax
        call dword ptr ds:sprintf
        add esp, 16
        push ebx
        push ebx
        push ebx
        mov eax, offset learning_buffer
        push eax
        push dword ptr [esp+56] ; white color
        lea eax, [ebp+ebp*2+311*2+6]
        shr eax, 1
        push eax
        mov eax, dword ptr [esp+60] ; x coord
        sub eax, 24
        push eax
        mov edx, dword ptr [0x5c347c] ; font
        mov ecx, dword ptr [0x507a4c] ; dialog
        call dword ptr ds:print_string
        quit:
        mov eax, dword ptr [esp+60] ; replaced code
        ret 16
      }
}

// Adjust the button areas of the picked human skills.
// This mostly affects mouse clicks.
static void __thiscall __declspec(naked) shift_human_buttons(int player)
{
    asm
      {
        mov edx, dword ptr [0x507a4c] ; dialog
        mov edx, dword ptr [edx+76]
        test edx, edx
        jz quit
        loop:
        cmp dword ptr [edx+32], 72
        jl next
        cmp dword ptr [edx+32], 75
        jg next
        cmp dword ptr [edx+36], ecx
        jne next
        cmp dword ptr [edx+40], 0
        jne next
        mov eax, dword ptr [edx+12]
        shr eax, 1
        cmp dword ptr [edx+32], 73
        jg down
        neg eax
        down:
        add eax, 3
        add dword ptr [edx+4], eax
        add dword ptr [edx+20], eax
        mov dword ptr [edx+40], 1
        next:
        mov edx, dword ptr [edx+52]
        test edx, edx
        jnz loop
        quit:
        ret
      }
}

// Same, but in reverse.
static void __thiscall __declspec(naked) unshift_human_buttons(int player)
{
    asm
      {
        mov edx, dword ptr [0x507a4c] ; dialog
        mov edx, dword ptr [edx+76]
        test edx, edx
        jz quit
        loop:
        cmp dword ptr [edx+32], 72
        jl next
        cmp dword ptr [edx+32], 75
        jg next
        cmp dword ptr [edx+36], ecx
        jne next
        cmp dword ptr [edx+40], 1
        jne next
        mov eax, dword ptr [edx+12]
        shr eax, 1
        cmp dword ptr [edx+32], 73
        jg down
        neg eax
        down:
        add eax, 3
        sub dword ptr [edx+4], eax
        sub dword ptr [edx+20], eax
        mov dword ptr [edx+40], 0
        next:
        mov edx, dword ptr [edx+52]
        test edx, edx
        jnz loop
        quit:
        ret
      }
}

// Hook to shift buttons as soon as they're created.
static void __declspec(naked) shift_created_human_buttons(void)
{
    asm
      {
        mov ecx, 1
        call shift_human_buttons
        lea eax, [ebx+ebx*2] ; replaced code
        ret 96
      }
}

// Provide skill hint for humans' bonus Learning.
static void __declspec(naked) human_skill_hint(void)
{
    asm
      {
        cmp ecx, dword ptr [esi+4] ; replaced code
        jl not_it
        cmp ecx, dword ptr [esi+20] ; replaced code
        jle quit
        cmp dword ptr [esi+32], 73
        jne not_it
        cmp dword ptr [esi+40], 1
        jne not_it
        mov eax, ecx
        sub eax, dword ptr [esi+12]
        cmp eax, dword ptr [esi+20]
        jg quit
        mov eax, SKILL_LEARNING
        push 0x4173a5 ; skill hint code
        ret 4
        not_it:
        cmp esi, 0 ; set greater
        quit:
        ret
      }
}

// Determine maximal currently possible skill rank, accounting for
// racial skills.  These are generally one rank higher, although
// higher ranks may remain promotion-locked.
static int __cdecl get_max_skill_level(int class, int race,
                                       int skill, int real)
{
    int level = CLASS_SKILLS[class][skill];
    if (real && class == CLASS_INITIATE && skill != SKILL_BODYBUILDING
        && level == MASTER) // can gm already, but only with a token
        level = CLASS_SKILLS[class+1][skill];
    if (level == GM)
        return GM;
    int racial_skill;
    switch (race)
      {
        case RACE_HUMAN:
            racial_skill = SKILL_LEARNING;
            break;
        case RACE_ELF:
            racial_skill = SKILL_BOW;
            break;
        case RACE_GOBLIN:
            racial_skill = SKILL_SWORD;
            break;
        case RACE_DWARF:
            racial_skill = SKILL_AXE;
            break;
      }
    if (skill != racial_skill)
        return level;
    int stage = class & 3;
    if (stage == 1 && CLASS_SKILLS[class+1][skill] == GM
                   && CLASS_SKILLS[class+2][skill] == GM)
        return GM;
    if (level == MASTER)
        return stage > 1 ? GM : MASTER;
    if (level == EXPERT)
        return stage ? MASTER : EXPERT;
    return level || stage ? EXPERT : NORMAL;
}

// Prefetch text color constants.  Called from spells_txt_tail() above.
// Also here: prefetch some map IDs.
static void set_colors(void)
{
    colors[CLR_WHITE] = rgb_color(255, 255, 255);
    colors[CLR_ITEM] = rgb_color(255, 255, 155);
    colors[CLR_RED] = rgb_color(255, 0, 0);
    colors[CLR_YELLOW] = rgb_color(255, 255, 0);
    colors[CLR_PALE_YELLOW] = rgb_color(255, 255, 100);
    colors[CLR_GREEN] = rgb_color(0, 255, 0);
    colors[CLR_BLUE] = rgb_color(0, 251, 251); // 252+ breaks in widescreen
    colors[CLR_PURPLE] = rgb_color(255, 0, 255);
    castle_id = get_map_index(MAPSTATS, "d29.blv") - 1;
    bottle_id = get_map_index(MAPSTATS, "nwc.blv") - 1;
    genie_id = get_map_index(MAPSTATS, map_altar_of_wishes);
}

// Colorize skill ranks more informatively (also respect racial skills).
static int __fastcall get_skill_color(struct player *player,
                                      int skill, int rank)
{
    int class = player->class;
    int race = get_race(player);
    if (get_max_skill_level(class, race, skill, FALSE) >= rank)
        return colors[CLR_WHITE];
    int stage = class & 3;
    if (!stage && get_max_skill_level(class + 1, race, skill, FALSE) >= rank)
        return colors[CLR_YELLOW];
    if (stage < 2)
      {
        int good = get_max_skill_level(class - stage + 2, race, skill, FALSE)
                   >= rank;
        int evil = get_max_skill_level(class - stage + 3, race, skill, FALSE)
                   >= rank;
        if (good && evil)
            return colors[CLR_GREEN];
        if (good)
            return colors[CLR_BLUE];
        if (evil)
            return colors[CLR_PURPLE];
      }
    return colors[CLR_RED];
}

// Replace the max skill table check with our race-inclusive function.
static void __declspec(naked) teacher_skill_check(void)
{
    asm
      {
        push ecx
        mov edx, eax
        mov ecx, esi
        call dword ptr ds:get_race
        push eax
        push edx
        call get_max_skill_level
        add esp, 8
        pop ecx
        ret
      }
}

// Another check, this time for all promotion levels of the class.
// TODO: maybe adjust "cannot learn" messages to mention race
static void __declspec(naked) teacher_skill_promotion_check(void)
{
    asm
      {
        push ecx
        mov ecx, esi
        call dword ptr ds:get_race
        push eax
        mov eax, ebx
        and eax, -4
        push eax
        call get_max_skill_level
        cmp eax, dword ptr [ebp-8]
        setge al
        mov dword ptr [ebp-32], eax
        inc dword ptr [esp]
        call get_max_skill_level
        cmp eax, dword ptr [ebp-8]
        setge al
        mov dword ptr [ebp-28], eax
        inc dword ptr [esp]
        call get_max_skill_level
        cmp eax, dword ptr [ebp-8]
        setge al
        mov dword ptr [ebp-24], eax
        inc dword ptr [esp]
        call get_max_skill_level
        cmp eax, dword ptr [ebp-8]
        setge al
        mov dword ptr [ebp-20], eax
        add esp, 12
        mov eax, ebx
        and eax, -4
        mov edi, 1
        ret
      }
}

// Display Axe skill for dwarven monks in weapon shops.
// This is the only situation wherein a racial skill is not given at start.
static void __declspec(naked) dwarf_monk_axe_show(void)
{
    asm
      {
        cmp byte ptr [CLASS_SKILLS_ADDR+ecx+eax], bl ; replaced code
        jnz quit
        cmp eax, SKILL_AXE
        jne skip
        mov ecx, dword ptr [ebp-16] ; player
        mov dl, byte ptr [ecx].s_player.class
        and edx, -4
        cmp dl, CLASS_MONK
        jne skip
        call dword ptr ds:get_race
        cmp eax, RACE_DWARF
        mov eax, SKILL_AXE ; restore
        je ok
        skip:
        xor edx, edx ; set zf
        ret
        ok:
        test edi, edi ; clear zf
        quit:
        ret
      }
}

// Also actually let them buy the skill.
static void __declspec(naked) dwarf_monk_axe_buy_1(void)
{
    asm
      {
        cmp byte ptr [CLASS_SKILLS_ADDR+eax+esi], 0 ; replaced code
        jnz quit
        cmp esi, SKILL_AXE
        jne skip
        mov dl, byte ptr [edi].s_player.class
        and edx, -4
        cmp dl, CLASS_MONK
        jne skip
        mov edx, ecx
        mov ecx, edi
        call dword ptr ds:get_race
        mov ecx, edx
        cmp eax, RACE_DWARF
        je ok
        skip:
        xor edx, edx ; set zf
        ret
        ok:
        test edi, edi ; clear zf
        quit:
        ret
      }
}

// Another location related to buying.
static void __declspec(naked) dwarf_monk_axe_buy_2(void)
{
    asm
      {
        cmp byte ptr [CLASS_SKILLS_ADDR+edx+eax-36], 0 ; replaced code
        jnz quit
        cmp eax, SKILL_AXE + 36
        jne skip
        mov dl, byte ptr [edi].s_player.class
        and edx, -4
        cmp dl, CLASS_MONK
        jne skip
        mov edx, ecx
        mov ecx, edi
        call dword ptr ds:get_race
        mov ecx, edx
        cmp eax, RACE_DWARF
        mov eax, SKILL_AXE + 36
        je ok
        skip:
        xor edx, edx ; set zf
        ret
        ok:
        test edi, edi ; clear zf
        quit:
        ret
      }
}

// Describe PC's chosen race as well as class.
static void __declspec(naked) race_hint(void)
{
    asm
      {
        imul eax, eax, SIZE_PLAYER ; replaced code
        mov edx, dword ptr [esi+8] ; PC area width
        shr edx, 1
        add edx, dword ptr [esi] ; PC area left
        cmp edx, dword ptr [ebp-8] ; mouse x
        jg race
        ret
        race:
        push ecx
        lea ecx, [ebx+eax]
        lea edi, [ecx].s_player.name
        call dword ptr ds:get_race
        mov eax, dword ptr [new_strings+STR_HUMANS*4+eax*4]
        pop ecx ; restore
        push 0x4174f0
        ret 4
      }
}

// Let the racial resistance bonus increase with level.
static void __declspec(naked) racial_resistances(void)
{
    asm
      {
        cmp dword ptr [esp+28], 0
        jz no_bonus
        movzx eax, word ptr [ecx].s_player.level_base
        cmp dword ptr [esp+28], 10
        jae big_bonus
        test ebp, 0xf ; parity odd for shock, poison, holy
        jp halve
        dec eax ; scatter per-two-level increases
        halve:
        shr eax, 1
        jmp add_bonus
        big_bonus:
        dec eax
        add_bonus:
        add dword ptr [esp+28], eax
        no_bonus:
        jmp dword ptr ds:get_stat_bonus_from_items ; replaced call
      }
}

// Ditto, but for base resistances.
static void __declspec(naked) base_racial_resistances(void)
{
    asm
      {
        test esi, esi
        jz no_bonus
        movzx eax, word ptr [ecx].s_player.level_base
        cmp esi, 10
        jae big_bonus
        test byte ptr [esp+4], 0xf ; parity odd for shock, poison, holy
        jp halve
        dec eax ; scatter per-two-level increases
        halve:
        shr eax, 1
        jmp add_bonus
        big_bonus:
        dec eax
        add_bonus:
        add esi, eax
        no_bonus:
        jmp dword ptr ds:get_stat_bonus_from_items ; replaced call
      }
}

// Provide the preserved race (face, actually) for liches (or zombies).
static void __declspec(naked) get_lich_race(void)
{
    asm
      {
        movsx eax, byte ptr [ecx].s_player.face ; replaced code, almost
        cmp eax, 19
        jle alive
        movsx eax, byte ptr [ecx].s_player.old_face
        alive:
        mov ecx, eax
        ret
      }
}

// There can be dwarf liches now, but liches still don't have a dwarf body.
// So we restore original behavior when race is checked for paperdolls.
static void __declspec(naked) get_lich_paperdoll(void)
{
    asm
      {
        movsx ecx, byte ptr [ecx].s_player.face
        push 0x490108
        ret
      }
}

// Let's make PC races more meaningful.
static inline void racial_traits(void)
{
    hook_call(0x435a36, new_game_decrease_stat, 5);
    hook_call(0x435a83, new_game_increase_stat, 5);
    erase_code(0x4909bc, 6); // make bonus ignore racial multipliers
    // hooks for all 14 stat functions; we need to push the stat for the hook
    patch_word(0x48c847, 0x006a); // 0x6a is push
    hook_call(0x48c849, racial_stat, 5);
    patch_word(0x48c85e, 0x016a);
    hook_call(0x48c860, racial_stat, 5);
    patch_word(0x48c875, 0x026a);
    hook_call(0x48c877, racial_stat, 5);
    patch_word(0x48c88c, 0x036a);
    hook_call(0x48c88e, racial_stat, 5);
    patch_word(0x48c8a3, 0x046a);
    hook_call(0x48c8a5, racial_stat, 5);
    patch_word(0x48c8ba, 0x056a);
    hook_call(0x48c8bc, racial_stat, 5);
    patch_word(0x48c8d1, 0x066a);
    hook_call(0x48c8d3, racial_stat, 5);
    // total might is special as we need to preserve ecx instead of eax
    patch_byte(0x48c978, 0xc1); // add ecx, eax -> add eax, ecx
    patch_word(0x48c979, 0x006a);
    hook_call(0x48c97b, racial_stat, 5);
    patch_word(0x48c9f8, 0x016a);
    hook_call(0x48c9fa, racial_stat, 5);
    patch_word(0x48ca75, 0x026a);
    hook_call(0x48ca77, racial_stat, 5);
    patch_word(0x48caf2, 0x036a);
    hook_call(0x48caf4, racial_stat, 5);
    patch_word(0x48cb6f, 0x046a);
    hook_call(0x48cb71, racial_stat, 5);
    patch_word(0x48cbec, 0x056a);
    hook_call(0x48cbee, racial_stat, 5);
    patch_word(0x48cca7, 0x066a);
    hook_call(0x48cca9, racial_stat, 5);
    hook_call(0x449c01, evt_cmp_base_stat, 6);
    memcpy(RACE_STATS, race_stat_values, sizeof(race_stat_values));
    hook_call(0x4915a4, default_party_hook, 7);
    hook_jump(0x48e4f0, get_new_full_hp);
    hook_jump(0x48e55d, get_new_full_sp);
    hook_call(0x4b4b5c, human_skill_point, 6);
    hook_call(0x490301, init_racial_skill, 8);
    hook_call(0x490465, check_racial_skill, 8);
    hook_call(0x49042f, exclude_racial_skill, 8);
    hook_call(0x4903e3, preserve_racial_skill, 7);
    hook_call(0x4903fd, substitute_racial_skill, 7);
    patch_dword(0x491506, 0x4152); // default party cleric axe skill
    patch_dword(0x491591, 0x5c92); // default party sorcerer bow skill
    hook_call(0x4917df, reset_races, 7);
    hook_call(0x435f38, change_racial_skill, 5);
    hook_call(0x435fd9, decrement_race, 10);
    hook_call(0x49628c, shift_human_skills_up, 5);
    hook_call(0x4962e6, shift_human_skills_up, 5);
    hook_call(0x49634f, shift_human_skills_down, 5);
    hook_call(0x4963b4, shift_last_human_skill, 5);
    hook_call(0x49631c, print_human_racial_skill, 7);
    hook_call(0x497096, shift_created_human_buttons, 6);
    hook_call(0x417279, human_skill_hint, 12);
    // For most calls, we can restore player from ebx.
    patch_word(0x417a7d, 0xd989); // mov ecx, ebx
    hook_jump(0x417a7f, get_skill_color);
    // But shortly before the last call ebx is overwritten,
    // so we need to set ecx in advance.
    patch_dword(0x417ee2, 0x3ebd989); // mov ecx, ebx; jmp $+3
    patch_dword(0x417ef4, dword(0x417ef4) + 2); // call address
    erase_code(0x4b253f, 3); // don't multiply class
    hook_call(0x4b254a, teacher_skill_check, 8);
    hook_call(0x4b2569, teacher_skill_promotion_check, 5);
    erase_code(0x4b256e, 55); // unused now
    hook_call(0x4b9638, dwarf_monk_axe_show, 7);
    hook_call(0x4b972b, dwarf_monk_axe_show, 7);
    hook_call(0x4be1bb, dwarf_monk_axe_buy_1, 8);
    hook_call(0x4bd485, dwarf_monk_axe_buy_2, 8);
    hook_call(0x417372, race_hint, 6);
    hook_call(0x48e8a3, racial_resistances, 5);
    patch_word(0x48e87f, 0x15eb); // dwarf poison res used different var
    hook_call(0x48e79d, base_racial_resistances, 5);
    hook_call(0x490101, get_lich_race, 7);
    hook_call(0x43bd5f, get_lich_paperdoll, 5);
    hook_call(0x43cccc, get_lich_paperdoll, 5);
    hook_call(0x43eda1, get_lich_paperdoll, 5);
    hook_call(0x43edeb, get_lich_paperdoll, 5);
    hook_call(0x43ef6e, get_lich_paperdoll, 5);
}

// Implement Champion special ability, Leadership: for each Champion
// in the party, everyone's weapon and armor skills get a +2 bonus.
// Also here: Masterful weapon bonus, and smith and armorer hireling perks.
static void __declspec(naked) champion_leadership(void)
{
    asm
      {
        mov esi, eax ; squire bonus (replaced)
        mov ecx, eax ; increase to +3
        cmp byte ptr [PARTY_ADDR].s_player.class, CLASS_CHAMPION
        setz al
        add esi, eax
        cmp byte ptr [PARTY_ADDR+SIZE_PLAYER].s_player.class, CLASS_CHAMPION
        setz al
        add esi, eax
        cmp byte ptr [PARTY_ADDR+SIZE_PLAYER*2].s_player.class, CLASS_CHAMPION
        setz al
        add esi, eax
        cmp byte ptr [PARTY_ADDR+SIZE_PLAYER*3].s_player.class, CLASS_CHAMPION
        setz al
        add esi, eax
        lea esi, [esi*2+ecx]
        cmp edi, SKILL_SHIELD
        mov ecx, NPC_ARMORER
        jae npc
        push edi ; skill
        mov ecx, dword ptr [ebp-4] ; checked pc
        call masterful_weapon
        add esi, eax
        mov ecx, NPC_SMITH
        npc:
        call dword ptr ds:have_npc_hired
        lea esi, [esi+eax*2]
        ret
      }
}

// Implement Sniper special ability: 100% chance to hit with a bow.
// Also here: double damage from backstabs and luck, and critical misses.
static void __declspec(naked) sniper_accuracy(void)
{
    asm
      {
        test ebx, ebx
        jz weapon
        cmp dword ptr [ebx].s_map_object.spell_type, SPL_ARROW
        jb quit ; blades spell etc.
        weapon:
        call dword ptr ds:random
        xor edx, edx
        mov ecx, 100
        div ecx
        push edx
        push ebx
        push esi
        mov ecx, edi
        call get_critical_chance
        pop edx
        cmp eax, edx
        jge crit
        add edx, eax
        jge hit
        jmp no_crit
        crit:
        mov dword ptr [critical_hit], 1
        hit:
        cmp dword ptr [critical_hit], 2
        jne check_crit
        mov ecx, edi
        call get_backstab_chance
        test eax, eax
        jz no_backstab
        push eax
        call dword ptr ds:random
        xor edx, edx
        mov ecx, 100
        div ecx
        pop ecx
        cmp edx, ecx
        jb check_crit
        no_backstab:
        and dword ptr [critical_hit], 0
        check_crit:
        xor edx, edx ; to distinguish from critical miss
        cmp dword ptr [critical_hit], edx
        jz no_crit
        shl dword ptr [ebp-12], 1 ; total damage
        no_crit:
        test ebx, ebx
        jz not_it
        cmp dword ptr [ebx].s_map_object.spell_type, SPL_ARROW
        jne not_it
        cmp byte ptr [edi].s_player.class, CLASS_SNIPER
        jne not_it
        mov eax, 1
        ret 16
        not_it:
        test edx, edx ; < 0 if critical miss
        jz quit
        xor eax, eax
        ret 16
        quit:
        push 0x4272ac ; replaced call
        ret
      }
}

// Let Warlock's familiar also boost Dark magic (and Light, but it's not used).
// Also here: moon priest hireling bonuses (and light for sun priests).
static void __declspec(naked) warlock_dark_bonus(void)
{
    asm
      {
        jle moon
        cmp edi, SKILL_DARK
        jg skip
        jl no_moon ; light
        moon:
        mov ecx, NPC_MOON_ACOLYTE
        call dword ptr ds:have_npc_hired
        lea esi, [esi+eax*2]
        mov ecx, NPC_MOON_INITIATE
        call dword ptr ds:have_npc_hired
        lea eax, [eax+eax*2]
        add esi, eax
        mov ecx, NPC_MOON_PRELATE
        call dword ptr ds:have_npc_hired
        lea esi, [esi+eax*4]
        cmp edi, SKILL_DARK
        je warlock
        no_moon:
        ret ; to vanilla acolyte etc. checks
        warlock:
        mov dword ptr [esp], 0x48f8f5 ; warlock check
        ret
        skip:
        mov dword ptr [esp], 0x48fb1e ; replaced jump
        ret
      }
}

// Defined below.
static int __stdcall maybe_instakill(struct player *, struct map_monster *);

// New Lich bonus: drain life with unarmed (or GM Staff) attacks.
// Also here: apply Hammerhands bonus to GM Staff attacks, check for the
// new GM Unarmed perk, and trigger Grim Reaper and Flattener's effects.
static void __declspec(naked) lich_vampiric_touch(void)
{
    asm
      {
        call dword ptr ds:is_bare_fisted ; replaced call
        test eax, eax
        jnz unarmed
        mov ecx, dword ptr [edi+SLOT_MAIN_HAND*4].s_player.equipment
        test ecx, ecx
        jz skip
        lea ecx, [ecx+ecx*8]
        mov ecx, dword ptr [edi+ecx*4-SIZE_ITEM].s_player.items ; id
        cmp ecx, GRIM_REAPER
        je grim
        cmp ecx, FLATTENER
        je flat
        lea ecx, [ecx+ecx*2]
        shl ecx, 4
        cmp byte ptr [ITEMS_TXT_ADDR+ecx].s_items_txt_item.skill, SKILL_STAFF
        jne skip
        push SKILL_STAFF
        mov ecx, edi
        call dword ptr ds:get_skill
        shr eax, 8 ; test for GM
        jz skip
        unarmed:
        push esi
        push edi
        call maybe_instakill
        or dword ptr [ebp-32], eax ; force a hit even if 0 damage
        cmp byte ptr [edi].s_player.class, CLASS_LICH
        jne not_lich
        mov eax, dword ptr [ebp-20] ; damage
        xor edx, edx
        mov ecx, 5
        div ecx
        add dword ptr [edi].s_player.hp, eax ; overheal is ok
        not_lich:
        mov eax, 1 ; hammerhands applies as well
        skip:
        ret
        grim:
        push esi
        push edi
        call grim_reaper
        or dword ptr [ebp-32], eax ; also force a hit
        jmp quit
        flat:
        push esi
        push edi
        call flattener
        add dword ptr [ebp-12], eax ; bonus dmg does not affect vampirism
        quit:
        xor eax, eax ; not unarmed
        ret
      }
}

// Defined below.
static void __stdcall blaster_eradicate(struct player *, struct map_monster *,
                                        struct map_object *);

// Part of Hammerhands fix.  Replaces a mov with add
// (to total damage, which now contains HH damage),
// and swaps it with a cmp, as the add would ruin its flags.
// Blaster GM effect is also checked here.
static void __declspec(naked) add_to_damage(void)
{
    asm
      {
        add dword ptr [ebp-12], eax
        push ebx
        push esi
        push edi
        call blaster_eradicate
        cmp dword ptr [ebp-28], 0
        ret
      }
}

// In vanilla the interface only changed color after the arbiter movie.
// As there are now other ways to choose a path, let's set it along with qbit.
// Also here: track quest items when their corresponding qbit is set.
static void __declspec(naked) set_light_dark_path(void)
{
    asm
      {
        xor ecx, ecx
        cmp esi, QBIT_LIGHT_PATH - 1
        je light
        cmp esi, QBIT_DARK_PATH - 1
        jne skip
        mov ecx, 2 ; dark
        light:
        mov dword ptr [0xacd6c0], ecx ; alignment
        mov edx, 1
        call dword ptr ds:reset_interface
        skip:
        mov ecx, LOST_QBIT_COUNT
        lea eax, [esi+1]
        loop:
        cmp ax, word ptr [LOST_QBITS+ecx*4-4]
        loopne loop
        cmove cx, word ptr [LOST_QBITS+ecx*4+2]
        test ecx, ecx
        jz quit
        cmp byte ptr [elemdata.lost_items+ecx-FIRST_LOST_ITEM], LOST_NOTRACK
        jne quit
        mov byte ptr [elemdata.lost_items+ecx-FIRST_LOST_ITEM], LOST_GONE
        quit:
        mov eax, esi ; replaced code
        mov ecx, 8 ; also replaced code
        ret
      }
}

// A rewritten check for whether aligned relics can be equipped.
// Now, for fully promoted PCs, alignment of the class is checked,
// rather than the overall path choice.  For unpromoted characters
// it's still the latter, except ones who already took an aligned
// promotion quest: it will prevent equipping relics cross-aligned
// to the upcoming promotion, but not allow coaligned relics by itself.
// The exception is to prevent the situation when a PC can no longer use
// an equipped item after a promotion (we could force-remove it, but...)
static int __fastcall equip_aligned_relic(struct player *player, int align)
{
    // Promotion quests sorted by alignment and class.
    static const int quests[2][9] = { {33, 19, 28, 24, 30, 39, 42, 54, 47},
                                      {35, 21, 29, 26, 32, 38, 44, 55, 48} };
    switch (player->class % 4)
      {
        case 3:
            return align == QBIT_DARK_PATH;
        case 2:
            return align == QBIT_LIGHT_PATH;
        case 1:
            if (check_bit(QBITS,
                          quests[align==QBIT_LIGHT_PATH][player->class/4]))
                return 0;
            /* else fallthrough */
        case 0:
        default:
            return check_bit(QBITS, align);
      }
}

// Parse clsskill.txt, which is just 'Class Skills.txt' table from MMExt.
// Yes, I'm lazy!  But not so lazy as to depend on MMExt for just one table.
// Called from spells_txt_tail() above.
static void parse_clsskill(void)
{
    char *file = load_from_lod(EVENTS_LOD, "clsskill.txt", TRUE);
    DWORD OldProtect;
    VirtualProtect((LPVOID) CLASS_SKILLS_ADDR, CLASS_COUNT * SKILL_COUNT,
                   PAGE_EXECUTE_READWRITE, &OldProtect);
    if (strtok(file, "\r\n")) // skip first line
        for (int i = 0; i < SKILL_COUNT; i++)
          {
            char *line = strtok(0, "\r\n");
            if (!line)
                break;
            for (int j = 0; j < CLASS_COUNT; j++)
              {
                line = strchr(line + 1, '\t');
                if (!line)
                    break;
                char level;
                switch (line[1])
                  {
                    case '-':
                    default:
                        level = 0;
                        break;
                    case 'b':
                    case 'B':
                    case 'n':
                    case 'N':
                        level = NORMAL;
                        break;
                    case 'e':
                    case 'E':
                        level = EXPERT;
                        break;
                    case 'm':
                    case 'M':
                        level = MASTER;
                        break;
                    case 'g':
                    case 'G':
                        level = GM;
                        break;
                  }
                CLASS_SKILLS[j][i] = level;
              }
          }
    VirtualProtect((LPVOID) CLASS_SKILLS_ADDR, CLASS_COUNT * SKILL_COUNT,
                   OldProtect, &OldProtect);
    mm7_free(file);
}

// Allow showing text on the statusline (as opposed to NPC messages)
// even in houses, if the script event is correspondingly marked.
static void __declspec(naked) force_status_text(void)
{
    asm
      {
        mov ecx, dword ptr [GLOBAL_EVENT_FLAG] ; replaced code
        cmp byte ptr [esi+9], bl ; our marker (ebx == 0)
        jnz skip
        cmp ecx, 1 ; check if global event
        jne skip
        inc ecx ; pretend it`s a barrel or somesuch
        skip:
        ret
      }
}

// Make light and dark promotions more distinct.
static inline void class_changes(void)
{
    // Black Knight ability is in cursed_weapon() above.
    hook_call(0x48f944, champion_leadership, 8);
    patch_dword(0x48f94d, dword(0x48f94d) + 3); // jump address
    hook_call(0x439885, sniper_accuracy, 5);
    // The to-hit display is in print_wand_to_hit() above.
    hook_call(0x48f8c3, warlock_dark_bonus, 6);
    erase_code(0x493e76, 34); // liches no longer regen SP
    hook_call(0x4398da, lich_vampiric_touch, 5);
    // While we're here, prevent Hammerhands from interacting with
    // Vampiric weapons (also see add_damage_half() above).
    patch_byte(0x43990c, -12); // add to total damage
    hook_call(0x439910, add_to_damage, 7);
    // Enable class hints on the stats screen.
    patch_dword(0x418088, dword(0x418088) + 8);
    hook_call(0x44a8c8, set_light_dark_path, 5);
    // Make Masters and Assassins a little bit more magic-capable.
    CLASS_HP_FACTORS[CLASS_ASSASSIN] = 7;
    CLASS_SP_FACTORS[CLASS_ASSASSIN] = 2; // actually 1.5
    CLASS_HP_FACTORS[CLASS_MASTER] = 7;
    CLASS_SP_FACTORS[CLASS_MASTER] = 2; // same here
    hook_call(0x492c8d, equip_aligned_relic, 10);
    // Replace starting Spirit with Mind for Druids.
    STARTING_SKILLS[CLASS_DRUID/4][SKILL_SPIRIT] = 0;
    STARTING_SKILLS[CLASS_DRUID/4][SKILL_MIND] = 1;
    // Allow Monks to start with Disarm instead of their nerfed Dagger.
    STARTING_SKILLS[CLASS_MONK/4][SKILL_DAGGER] = 0;
    STARTING_SKILLS[CLASS_MONK/4][SKILL_DISARM_TRAPS] = 1;
    hook_call(0x447bdf, force_status_text, 6);
    // Tweak HP and SP of some classes to balance them better.
    // make them better than dark, who have a much easier promotion
    CLASS_HP_FACTORS[CLASS_CHAMPION] = 10;
    // match other hybrids, also makes 1st promotion more rewarding
    CLASS_HP_FACTORS[CLASS_PALADIN] = 3;
    // make them more magical like sorcs, also reward tough 2nd promotions
    CLASS_HP_FACTORS[CLASS_MASTER_ARCHER] = CLASS_HP_FACTORS[CLASS_SNIPER] = 5;
    CLASS_SP_FACTORS[CLASS_MASTER_ARCHER] = CLASS_SP_FACTORS[CLASS_SNIPER] = 4;
    // 1st promo way too easy, nerf them a bit
    CLASS_SP_FACTORS[CLASS_HUNTER] = 1;
    // reward the hardest promotion in the game
    CLASS_SP_FACTORS[CLASS_WARLOCK] = 6;
}

// Let the Perception skill increase gold looted from monsters.
static void __declspec(naked) perception_bonus_gold(void)
{
    asm
      {
        mov ecx, dword ptr [CURRENT_PLAYER]
        dec ecx
        jl no_player
        mov ecx, dword ptr [PC_POINTERS+ecx*4]
        call dword ptr ds:get_perception_bonus
        mov edx, dword ptr [ebp-4] ; gold
        mov ecx, 50
        add eax, ecx
        mul edx
        div ecx
        mov dword ptr [ebp-4], eax
        no_player:
        mov ecx, dword ptr [ebp-4] ; replaced code
        xor edx, edx ; replaced code
        ret
      }
}

// Also let it increase item drop odds.
static void __declspec(naked) perception_extra_item(void)
{
    asm
      {
        xor edx, edx
        mov ecx, 5000
        div ecx
        mov esi, edx
        xor eax, eax
        mov ecx, dword ptr [CURRENT_PLAYER]
        dec ecx
        jl no_player
        mov ecx, dword ptr [PC_POINTERS+ecx*4]
        call dword ptr ds:get_perception_bonus
        no_player:
        movzx edx, byte ptr [ebx].s_map_monster.item_chance
        add eax, 50
        mul edx
        cmp esi, eax
        ret
      }
}

// For use below.
static int alchemy_result, botched_potion;

// Let potions be brewable even without the requisite Alchemy skill,
// but with a possibility of explosion (up to 83% for black).
// Additionally, such potions are 'botched' and have lowered power.
// This hook remembers the mix result before skill is checked.
static void __declspec(naked) lenient_alchemy_remember(void)
{
    asm
      {
        mov dword ptr [ebp-4], edx ; replaced code
        mov dword ptr [alchemy_result], edx ; store the mix
        cmp dword ptr [ebp-44], ebx ; replaced code
        ret
      }
}

// This one gives a chance for a brew to succeed without the skill.
static void __declspec(naked) lenient_alchemy_allow(void)
{
    asm
      {
        mov dword ptr [botched_potion], ebx ; == 0
        cmp dword ptr [ebp-4], 1
        jb skip
        cmp dword ptr [ebp-4], 4
        ja skip
        cmp dword ptr [alchemy_result], POTION_BOTTLE
        jbe skip
        call dword ptr ds:random
        xor edx, edx
        mov ecx, 6
        div ecx
        cmp edx, dword ptr [ebp-4]
        jbe skip
        mov eax, dword ptr [alchemy_result]
        mov dword ptr [ebp-4], eax
        mov dword ptr [botched_potion], edx ; not zero here
        skip:
        lea eax, [esi].s_player.inventory ; replaced code
        ret
      }
}

// This hook reduces the skill-less potion's power by 25%.
// Also here: reset the stolen flag on newly brewed potions.
static void __declspec(naked) botched_potion_power(void)
{
    asm
      {
        sub eax, edx ; replaced code
        sar eax, 1 ; replaced code
        mov dword ptr [ecx], eax ; replaced code
        cmp dword ptr [botched_potion], ebx ; == 0
        jz skip
        sar eax, 2
        sub dword ptr [ecx], eax
        or byte ptr [ecx-4+1].s_item.flags, 0x20 ; unused flag
        skip:
        and byte ptr [ecx-4+1].s_item.flags, ~IFLAGS_STOLEN >> 8
        ret
      }
}

// When mixing a botched potion with a catalyst, also apply the penalty.
// This hook is for when the botched potion is held in cursor.
static void __declspec(naked) botched_potion_catalyst_1(void)
{
    asm
      {
        mov dword ptr [eax].s_player.items, ecx ; replaced code
        test byte ptr [MOUSE_ITEM+1].s_item.flags, 0x20 ; our flag
        jz skip
        or byte ptr [eax+S_PL_ITEMS+1].s_item.flags, 0x20
        mov ecx, dword ptr [eax+S_PL_ITEMS].s_item.bonus
        shr ecx, 2
        sub dword ptr [eax+S_PL_ITEMS].s_item.bonus, ecx
        skip:
        ret
      }
}

// This one is for when the catalyst is in cursor.
static void __declspec(naked) botched_potion_catalyst_2(void)
{
    asm
      {
        mov dword ptr [eax+S_PL_ITEMS].s_item.bonus, ecx ; replaced code
        test byte ptr [eax+S_PL_ITEMS+1].s_item.flags, 0x20
        jz skip
        shr ecx, 2
        sub dword ptr [eax+S_PL_ITEMS].s_item.bonus, ecx
        skip:
        ret
      }
}

// Mark a botched potion in its description, like 'stolen' or 'hardened'.
static void __declspec(naked) display_botched_potion(void)
{
    asm
      {
        mov eax, dword ptr [eax].s_item.flags ; replaced code
        test ah, 0x20
        jnz display
        test ah, 1 ; replaced code
        ret
        display:
        pop eax
        push ebx
        push ebx
        push ebx
        push dword ptr [new_strings+STR_BOTCHED*4]
        add eax, 12 ; skip over stolen code
        jmp eax
      }
}

// Length of blaster eradication animation.
#define ERAD_TIME 48

// Let a GM blaster shot have a small chance to eradicate the target,
// killing it without leaving a corpse.  For testing purposes,
// blasters of Carnage (unobtainable) always trigger this effect.
// Also here: Incinerate effect (also instadeath, but less fancy).
// Called from add_to_damage() above.
static void __stdcall blaster_eradicate(struct player *player,
                                        struct map_monster *monster,
                                        struct map_object *projectile)
{
    if (!projectile)
        return;
    if (projectile->spell_type == SPL_INCINERATE)
      {
        int power = projectile->spell_power;
        if (power * 3 > random() % 100 && elemdata.difficulty <= random() % 4
            && debuff_monster(monster, FIRE, power))
            monster->hp = 0;
      }
    if (projectile->spell_type != SPL_BLASTER)
        return;
    int skill = get_skill(player, SKILL_BLASTER);
    if (skill > SKILL_GM && (skill & SKILL_MASK) > random() % 200
        && elemdata.difficulty <= random() % 4
        && debuff_monster(monster, MAGIC, skill & SKILL_MASK)
        || projectile->item.bonus2 == SPC_CARNAGE)
      {
        monster->spell_buffs[MBUFF_MASS_DISTORTION].expire_time
            = dword(ANIM_TIMER) + ERAD_TIME;
        monster->mod_flags |= MMF_ERADICATED;
        monster->hp = 0;
        struct map_object anim = { OBJ_BLASTER_ERADICATION,
                                   find_objlist_item(OBJLIST_THIS,
                                                     OBJ_BLASTER_ERADICATION),
                                   monster->x, monster->y,
                                   monster->z + monster->height / 2 };
        launch_object(&anim, 0, 0, 0, 0);
      }
}

// Debuffs are usually removed from a dying monster.  Prevent this
// for Mass Distortion, which is more of a visual effect, and which
// is reused by the mod for the eradication death animation.
static void __declspec(naked) preserve_mdist_on_death(void)
{
    asm
      {
        cmp ebx, 12 ; counter
        je skip
        jmp dword ptr ds:remove_buff ; replaced call
        skip:
        ret
      }
}

// Animate the blaster eradication by shrinking the monster into nothingness.
// It's probably the best SFX possible here without rewriting the engine.
static void __thiscall draw_eradication(struct map_monster *monster,
                                        uint32_t *sprite_params)
{
    double scale = (monster->spell_buffs[MBUFF_MASS_DISTORTION].expire_time
                    - dword(ANIM_TIMER)) / (double) ERAD_TIME;
    sprite_params[0] = sprite_params[0] * scale; // sprite width
    sprite_params[1] = sprite_params[1] * scale; // sprite height
}

// Hook for the above.
static void __declspec(naked) draw_erad_hook(void)
{
    asm
      {
        test byte ptr [ecx].s_map_monster.mod_flags, MMF_ERADICATED
        jnz draw
        cmp dword ptr [ecx+MBUFF_MASS_DISTORTION*SIZE_BUFF] \
                      .s_map_monster.spell_buffs, eax ; replaced code
        ret
        draw:
        push esi
        call draw_eradication
        xor eax, eax ; set zf
        ret
      }
}

// Same, but for ouside maps.
static void __declspec(naked) draw_erad_hook_out(void)
{
    asm
      {
        test byte ptr [edi-146].s_map_monster.mod_flags, MMF_ERADICATED
        jnz draw
        cmp dword ptr [edi-146+MBUFF_MASS_DISTORTION*SIZE_BUFF] \
                      .s_map_monster.spell_buffs, edx ; replaced code
        ret
        draw:
        push ecx ; preserve
        lea ecx, [edi-146]
        push esi
        call draw_eradication
        xor eax, eax ; set zf
        pop ecx
        ret
      }
}

// To have the monster appear to shink inwards, we also need to adjust
// its Z-coord for drawing purposes.  This is done a bit earlier.
// Also here: remove the corpse (has to be here, before the LOS check).
static int __thiscall get_erad_mon_z(struct map_monster *monster)
{
    if (monster->spell_buffs[MBUFF_MASS_DISTORTION].expire_time <= 0
        || !(monster->mod_flags & MMF_ERADICATED))
        return 0;
    int time = monster->spell_buffs[MBUFF_MASS_DISTORTION].expire_time
             - dword(ANIM_TIMER);
    if (time <= 0)
        monster->ai_state = AI_REMOVED; // no corpse
    return (1.0 - time / (double) ERAD_TIME) * 0.8 * monster->height;
}

// Hook for the above.
static void __declspec(naked) erad_z_hook(void)
{
    asm
      {
        lea ecx, [edi-36]
        call get_erad_mon_z
        add dword ptr [esp+12], eax
        push 0x43668c ; replaced call
        ret
      }
}

// Same, but for outside maps.
static void __declspec(naked) erad_z_hook_out(void)
{
    asm
      {
        lea ecx, [edi-146]
        push eax ; preserve
        call get_erad_mon_z
        add esi, eax
        pop eax
        cmp dword ptr [0x507b74], 0 ; replaced code
        ret
      }
}

// Prevent the monster from being affected by gravity etc.
// during the eradication animation.
static void __declspec(naked) erad_stop_moving(void)
{
    asm
      {
        test byte ptr [esi].s_map_monster.mod_flags, MMF_ERADICATED
        mov ax, AI_REMOVED ; we need zf == 1 if flag set
        cmovz ax, word ptr [esi].s_map_monster.ai_state ; replaced code, almost
        ret
      }
}

// Make enchanted items more difficult to ID and repair.
// Also here: register id/repair training.
// NB: the latter will not work right at GM, but we don't need it to!
static void __declspec(naked) raise_ench_item_difficulty(void)
{
    asm
      {
        xor eax, eax
        cmp byte ptr [esi].s_items_txt_item.type, al ; ordinary items only
        jnz no_ench
        mov ecx, dword ptr [esp+24] ; item
        mov edx, dword ptr [ecx].s_item.bonus
        test edx, edx
        jz no_std
        cmp edx, TEMP_ENCH_MARKER
        je no_std
        mov eax, dword ptr [ecx].s_item.bonus_strength
        add eax, eax
        mov ecx, 5
        cmp edx, STAT_HP + 1
        je doubled
        cmp edx, STAT_SP + 1
        je doubled
        cmp edx, STAT_THIEVERY + 1
        je doubled
        cmp edx, STAT_DISARM + 1
        je doubled
        cmp edx, STAT_ARMSMASTER + 1
        jb divide
        cmp edx, STAT_UNARMED + 1
        ja divide
        doubled:
        add eax, eax
        jmp divide
        no_std:
        mov edx, dword ptr [ecx].s_item.bonus2
        test edx, edx
        jz no_ench
        imul edx, edx, SIZE_SPCITEM
        mov eax, dword ptr [spcitems+edx-SIZE_SPCITEM].s_spcitem.value
        cmp eax, 10
        ja spc
        jb ok
        mov eax, 2 ; antique is a bit too difficult now
        ok:
        add eax, eax
        jmp no_ench
        spc:
        mov ecx, 250
        divide:
        xor edx, edx
        div ecx
        no_ench:
        movsx ecx, byte ptr [esi].s_items_txt_item.id_difficulty ; repl, almost
        mov edx, SKILL_IDENTIFY_ITEM
        cmp dword ptr [esp], CAN_REPAIR_ADDR
        jb id
        mov edx, SKILL_REPAIR
        test ecx, ecx ; negative difficulty means auto-id but not repair
        jns id
        neg ecx
        id:
        add eax, ecx
        cmp edi, eax ; replaced code
        jl quit
        mov ecx, dword ptr [CURRENT_PLAYER]
        dec ecx
        imul ecx, ecx, SKILL_COUNT
        add ecx, edx
        cmp edx, SKILL_REPAIR
        setne dl
        lea ebp, [edx-1] ; needed for npc_repair_chunk() below
        inc dword ptr [elemdata.training+ecx*4] ; should also set the flags
        quit:
        ret
      }
}

// Don't count enchantment cost when trying to sell an un-ID'd item.
// For wands and scrolls, cap the cost at base item cost.
// This will also ignore variable potion cost, but those are always ID'd.
static void __declspec(naked) unid_item_sell_price(void)
{
    asm
      {
        test byte ptr [ecx].s_item.flags, IFLAGS_ID
        jz unid
        call dword ptr ds:item_value
        ret
        unid:
        mov edx, dword ptr [ecx]
        lea eax, [edx+edx*2]
        shl eax, 4
        cmp byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.equip_stat, \
            ITEM_TYPE_SCROLL - 1
        mov eax, dword ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.value
        je cap
        cmp edx, FIRST_WAND
        jb quit
        cmp edx, LAST_WAND
        ja quit
        cap:
        push eax
        call dword ptr ds:item_value
        pop edx
        cmp eax, edx
        cmovg eax, edx
        quit:
        ret

      }
}

// Forbid reading an unidentified scroll.
static void __declspec(naked) read_unid_scroll(void)
{
    asm
      {
        test byte ptr [MOUSE_ITEM].s_item.flags, IFLAGS_ID
        jz unid
        mov eax, [MOUSE_ITEM] ; replaced code
        ret
        unid:
        mov ecx, dword ptr [new_strings+STR_ID_BEFORE_READ*4]
        mov edx, 2
        call dword ptr ds:show_status_text
        push 0
        push ANIM_ID_FAIL
        mov ecx, esi
        call dword ptr ds:show_face_animation
        push 0x468e87
        ret 4
      }
}

// Same, but for spellbooks.
static void __declspec(naked) read_unid_book(void)
{
    asm
      {
        test byte ptr [MOUSE_ITEM].s_item.flags, IFLAGS_ID
        jz unid
        lea edi, [edx-400] ; replaced code
        ret
        unid:
        mov ecx, dword ptr [new_strings+STR_ID_BEFORE_READ*4]
        mov edx, 2
        call dword ptr ds:show_status_text
        push 0
        push ANIM_ID_FAIL
        mov ecx, esi
        call dword ptr ds:show_face_animation
        push 0x468e87
        ret 4
      }
}

// Now that blasters have value, we need to explicitly forbid enchanting them.
// Also here: allow enchanting robes.
static void __declspec(naked) cant_enchant_blasters(void)
{
    asm
      {
        cmp eax, BLASTER_RIFLE
        jg ok
        cmp eax, BLASTER - 1
        ret
        ok:
        cmp eax, FIRST_ROBE
        jge new
        cmp eax, FIRST_WAND - 1 ; replaced code
        ret
        new:
        cmp eax, LAST_PREFIX
        ret
      }
}

// Prevent hired smiths from fixing blasters.  Too advanced for them!
static void __declspec(naked) npcs_cant_repair_blasters(void)
{
    asm
      {
        cmp eax, BLASTER
        jz skip
        cmp eax, BLASTER_RIFLE
        jz skip
        jmp dword ptr ds:have_npc_hired ; replaced call
        skip:
        xor eax, eax
        ret
      }
}

// Most shops (except for Celeste and Pit ones) also cannot fix blasters now.
static void __declspec(naked) shops_cant_repair_blasters(void)
{
    asm
      {
        cmp dword ptr [ecx], BLASTER
        je blaster
        cmp dword ptr [ecx], BLASTER_RIFLE
        jne ok
        blaster:
        cmp edx, 5 ; celeste shop
        je ok
        cmp edx, 6 ; pit shop
        je ok
        xor eax, eax
        ret
        ok:
        push 0x4bda12 ; replaced call
        ret
      }
}

// Also change the shk message.
static void __declspec(naked) shops_cant_repair_blasters_msg(void)
{
    asm
      {
        cmp dword ptr [ebx], BLASTER
        je blaster
        cmp dword ptr [ebx], BLASTER_RIFLE
        je blaster
        ok:
        cmp esi, 2 ; replaced code
        ret
        blaster:
        cmp dword ptr [ebp+16], 5 ; celeste shop
        je ok
        cmp dword ptr [ebp+16], 6 ; pit shop
        je ok
        cmp esi, -1 ; set flags
        ret
      }
}

// Let the GM Shield skill reduce physical damage by 25%.
// This function also reimplements M Plate and GM Chain.
// Both of them stack additively with Shield.
static int __thiscall resist_phys_damage(struct player *player, int damage)
{
    int factor = 12;
    int body = player->equipment[SLOT_BODY_ARMOR];
    if (body)
      {
        struct item *armor = &player->items[body-1];
        if (!(armor->flags & IFLAGS_BROKEN))
          {
            if (ITEMS_TXT[armor->id].skill == SKILL_PLATE
                && player->skills[SKILL_PLATE] >= SKILL_MASTER)
                factor = 6;
            else if (ITEMS_TXT[armor->id].skill == SKILL_CHAIN
                     && player->skills[SKILL_CHAIN] >= SKILL_GM)
                factor = 8;
          }
      }
    int offhand = player->equipment[SLOT_OFFHAND];
    if (offhand && player->skills[SKILL_SHIELD] >= SKILL_GM)
      {
        struct item *shield = &player->items[offhand-1];
        if (!(shield->flags & IFLAGS_BROKEN)
            && ITEMS_TXT[shield->id].skill == SKILL_SHIELD)
            factor -= 3;
      }
    return damage * factor / 12;
}

// Hook for the above.
static void __declspec(naked) resist_phys_damage_hook(void)
{
    asm
      {
        mov ecx, esi
        push dword ptr [ebp-4]
        call resist_phys_damage
        ret
      }
}

// New Master Leather perk: chance to absorb enemy spells, restoring SP.
// Only works if SP won't overflow the natural limit.
// Also here: robes of Absorption have a 10% chance of doing the same.
static int __thiscall absorb_spell(struct player *player, int spell, int rank)
{
    if (spell <= 0 || spell > LAST_REAL_SPELL)
        return FALSE; // don't absorb death explosions etc.
    if (spell == SPL_LIGHT_BOLT)
        return FALSE; // can't be blocked by anything
    if (!has_enchanted_item(player, SPC_ABSORPTION) || random() % 10)
      {
        int body = player->equipment[SLOT_BODY_ARMOR];
        if (!body)
            return FALSE;
        struct item *armor = &player->items[body-1];
        if (armor->flags & IFLAGS_BROKEN
            || ITEMS_TXT[armor->id].skill != SKILL_LEATHER)
            return FALSE;
        int skill = get_skill(player, SKILL_LEATHER);
        if (skill < SKILL_MASTER || (skill & SKILL_MASK) <= random() % 100)
            return FALSE;
      }
    int new_sp = player->sp + SPELL_INFO[spell].cost[rank-1];
    if (new_sp <= get_full_sp(player))
      {
        player->sp = new_sp;
        static char message[128];
        sprintf(message, new_strings[STR_ABSORB_SPELL], player->name);
        show_status_text(message, 2);
        return TRUE;
      }
    return FALSE;
}

// Hook for monster spells.  Also here: instadeath from monster Incinerate.
static void __declspec(naked) absorb_monster_spell(void)
{
    asm
      {
        jnz spell
        ret
        spell:
        mov ecx, dword ptr [ebx].s_map_object.spell_power
        call dword ptr ds:skill_mastery
        mov ecx, edi
        push eax
        push dword ptr [ebx].s_map_object.spell_type
        call absorb_spell
        test eax, eax
        jz hit
        mov dword ptr [esp], 0x43a99a ; skip hit code
        ret
        hit:
        cmp dword ptr [ebx].s_map_object.spell_type, SPL_INCINERATE
        jne skip
        call dword ptr ds:random
        xor edx, edx
        mov ecx, 100
        div ecx
        mov eax, dword ptr [ebx].s_map_object.spell_power
        and eax, SKILL_MASK
        lea eax, [eax+eax*2]
        cmp eax, edx
        jbe skip
        ; now we make a debuff resistance roll
        push STAT_FIRE_RES
        mov ecx, edi
        call dword ptr ds:get_resistance
        mov ebx, eax
        mov ecx, edi
        call dword ptr ds:get_luck
        push eax
        call dword ptr ds:get_effective_stat
        lea ebx, [ebx+eax*4+30]
        call dword ptr ds:random
        xor edx, edx
        div ebx
        cmp edx, 30
        jae skip
        push 1 ; can resist through preservation etc.
        push COND_INCINERATED
        mov ecx, edi
        call inflict_condition
        skip:
        mov dword ptr [esp], 0x43a5ac ; replaced jump
        ret
      }
}

// Hook for non-monster spells.
static void __declspec(naked) absorb_other_spell(void)
{
    asm
      {
        push dword ptr [ebx].s_map_object.spell_mastery
        push dword ptr [ebx].s_map_object.spell_type
        call absorb_spell
        test eax, eax
        jz hit
        push 0x43a99a ; skip hit code
        ret 4
        hit:
        mov ecx, dword ptr [ebp+12] ; restore
        jmp dword ptr ds:get_full_hp ; replaced call
      }
}

// Hook for Armageddon.
static void __declspec(naked) absorb_armageddon(void)
{
    asm
      {
        or eax, dword ptr [ecx+COND_ERADICATED*8+4] ; replaced code
        jnz quit
        push MASTER ; does not matter
        push SPL_ARMAGEDDON
        call absorb_spell
        mov ecx, dword ptr [esi] ; restore
        test eax, eax
        quit:
        ret
      }
}

// Move GM Dodging bonus (dodging in leather) to GM Leather.
static void __declspec(naked) leather_dodging(void)
{
    asm
      {
        push SKILL_LEATHER
        call dword ptr ds:get_skill
        mov ecx, eax
        call dword ptr ds:skill_mastery
        mov edx, eax
        mov ecx, esi
        call dword ptr ds:skill_mastery
        ret
      }
}

// Reimplement the Monk dodging logic.  As it's now a Dodging perk
// instead of Unarmed, check that no heavy armor or shield is worn.
// TODO: should we check for broken items?
static int __thiscall maybe_dodge(struct player *player)
{
    int dodging = get_skill(player, SKILL_DODGING);
    if (dodging <= SKILL_GM || (dodging & SKILL_MASK) <= random() % 100)
        return 0;
    int shield = player->equipment[SLOT_OFFHAND];
    if (shield && ITEMS_TXT[player->items[shield-1].id].skill == SKILL_SHIELD)
        return 0;
    int body = player->equipment[SLOT_BODY_ARMOR];
    if (!body)
        return 1;
    int skill = ITEMS_TXT[player->items[body-1].id].skill;
    return skill == SKILL_LEATHER && player->skills[SKILL_LEATHER] >= SKILL_GM
           || skill >= SKILL_NONE; // robes and wetsuits
}

// The new GM Spear and Sword perk, like above but only in melee.
// This code shows the statusline etc. by itself.
static int __thiscall maybe_parry(struct player *player)
{
    int friend = -1;
    for (int slot = SLOT_MAIN_HAND; slot >= SLOT_OFFHAND; slot--)
      {
        int equip = player->equipment[slot];
        if (!equip)
            continue;
        struct item *weapon = &player->items[equip-1];
        if (weapon->flags & IFLAGS_BROKEN)
            continue;
        int type = ITEMS_TXT[weapon->id].skill;
        if (type != SKILL_SWORD && type != SKILL_SPEAR)
            continue;
        int skill = get_skill(player, type);
        if (skill < SKILL_GM)
            continue;
        if (friend < 0)
            friend = has_item_in_slot(player, FENCERS_FRIEND, SLOT_ANY);
        if ((skill & SKILL_MASK) > random() % (friend ? 50 : 100))
          {
            char buffer[40];
            sprintf(buffer, new_strings[STR_PARRY], player->name);
            show_status_text(buffer, 2);
            make_sound(SOUND_THIS, SOUND_WOOD_METAL, 0, 0, -1, 0, 0, 0, 0);
            return TRUE;
          }
      }
    return FALSE;
}

// Defined below.
static int __stdcall train_armor(struct map_monster *, struct player *);

// Hook for the above.  Also checks parrying for melee.
static void __declspec(naked) maybe_dodge_hook(void)
{
    asm
      {
        mov ecx, dword ptr [esp+8] ; player
        call maybe_dodge
        test eax, eax
        jnz dodge
        cmp dword ptr [esp], 0x43a044 ; melee code
        jne ranged
        mov ecx, dword ptr [esp+8]
        call maybe_parry
        test eax, eax
        jnz parry
        ranged:
        jmp train_armor ; includes replaced call
        dodge:
        mov edi, dword ptr [esp+8] ; player
        push 0x43a630 ; dodge code
        ret 12
        parry:
        xor eax, eax ; skip the rest of caller
        ret 8
      }
}

// Implement the new Unarmed GM bonus: small chance to instakill on hit.
// Called from lich_vampiric_touch() above.
static int __stdcall maybe_instakill(struct player *player,
                                     struct map_monster *monster)
{
    // monsters this doesn't work on: undead, elementals,
    // golems, gargoyles, droids, trees, and implicitly oozes
    if (monster->holy_resistance < IMMUNE)
        return 0;
    int id = monster->id;
    if (id >= 34 && id <= 48 || id >= 64 && id <= 66 || id >= 79 && id <= 81
        || id >= 190 && id <= 192 || id >= 253 && id <= 255)
        return 0;
    int skill = get_skill(player, SKILL_UNARMED);
    if (skill > SKILL_GM && (skill & SKILL_MASK) > random() % 200
        && elemdata.difficulty <= random() % 4
        && debuff_monster(monster, PHYSICAL, skill & SKILL_MASK))
      {
        monster->hp = 0;
        make_sound(SOUND_THIS, SOUND_DIE, 0, 0, -1, 0, 0, 0, 0);
        return 1;
      }
    return 0;
}

// Buff axes slightly, increasing the skill recovery bonus by 50%.
// NB: this overwrites some nop's from MM7Patch.
// The value here is halved in multiplicative_recovery() below.
static void __declspec(naked) boost_axe_recovery(void)
{
    asm
      {
        and eax, SKILL_MASK ; replaced code
        cmp byte ptr [edi].s_items_txt_item.skill, SKILL_AXE
        je axe
        add eax, eax
        ret
        axe:
        lea eax, [eax+eax*2]
        ret
      }
}

// Show any monster data at any rank if the skill is high enough.
// Also check and update the stored identification level.
static void __declspec(naked) new_id_monster_check(void)
{
    asm
      {
        mov ecx, dword ptr [ebp-20] ; monster
        test eax, eax ; zero if no skill
        jz ok
        cmp eax, GM ; eax == mastery
        je ok ; always id all
        mul edi ; skill value
        movzx edi, byte ptr [ecx].s_map_monster.level
        add eax, 30
        sub eax, edi
        cdq
        mov di, 10
        idiv edi
        cmp eax, GM
        jle ok
        mov al, GM
        ok:
        movzx edx, byte ptr [ecx].s_map_monster.id_level
        cmp edx, eax
        jl new
        mov eax, edx
        mov dword ptr [ebp-24], ebx ; suppress the face anim
        new:
        mov byte ptr [ecx].s_map_monster.id_level, al
        xor edi, edi
        inc edi
        dec eax
        jz normal
        dec eax
        jz expert
        dec eax
        jz master
        dec eax
        jnz zero
        mov dword ptr [ebp-56], edi ; gm id
        master:
        mov dword ptr [ebp-36], edi
        expert:
        mov dword ptr [ebp-40], edi
        normal:
        mov dword ptr [ebp-28], edi
        zero:
        mov eax, 0x41eb1a ; past the old code
        jmp eax
      }
}

// Normal ID Monster bonus: +5 to armor penetration.
static void __declspec(naked) id_monster_normal(void)
{
    asm
      {
        cmp byte ptr [ecx].s_map_monster.id_level, bl
        jz no_id
        add dword ptr [ebp+20], 5
        no_id:
        cmp dword ptr [ecx+MBUFF_HALVED_ARMOR*SIZE_BUFF+4] \
                      .s_map_monster.spell_buffs, ebx ; replaced code
        ret
      }
}

// Expert ID Monster bonus: -5 to monster's attack bonus (like Fate).
static void __declspec(naked) id_monster_expert(void)
{
    asm
      {
        cmp byte ptr [esi].s_map_monster.id_level, EXPERT
        jb no_bonus
        sub edi, 5 ; bless/fate/hop bonus
        no_bonus:
        lea ecx, [esi+MBUFF_FATE*SIZE_BUFF].s_map_monster.spell_buffs ; repl.
        ret
      }
}

// Master ID Monster bonus: monster only deals 90% damage to party.
static void __declspec(naked) id_monster_master(void)
{
    asm
      {
        cmp byte ptr [esi].s_map_monster.id_level, MASTER
        jb no_bonus
        cmp dword ptr [esp+8], ENERGY ; energy damage is an exception
        jae no_bonus
        mov eax, 9
        mul dword ptr [esp+4] ; damage
        div dword ptr [const_ten] ; no free registers
        mov dword ptr [esp+4], eax
        no_bonus:
        jmp dword ptr ds:damage_player ; replaced call
      }
}

// Used just below.
static const char attack_format_fixed[] = "%s\f00000\t060%s %dd%d+%d\n";
static const char attack_format_no_fixed[] = "%s\f00000\t060%s %dd%d\n";
static int second_attack = 0;

// Combine monster attack(s) type and damage on the same line.
static void __declspec(naked) print_full_monster_attack(void)
{
    asm
      {
        mov ecx, dword ptr [ebp-20] ; the monster
        add ecx, dword ptr [second_attack] ; first or second
        movzx edx, byte ptr [ecx].s_map_monster.attack1_damage_add
        test edx, edx
        jz no_fixed
        push edx
        no_fixed:
        movzx eax, byte ptr [ecx].s_map_monster.attack1_damage_dice_sides
        push eax
        movzx eax, byte ptr [ecx].s_map_monster.attack1_damage_dice_count
        push eax
        push dword ptr [ebp-0x1f0] ; element
        cmp dword ptr [second_attack], ebx
        mov eax, dword ptr [GLOBAL_TXT_ADDR+18*4] ; "attack"
        lea ecx, [ebp-0x1f4] ; zero as empty string
        cmovnz eax, ecx
        push eax
        test edx, edx
        mov eax, offset attack_format_fixed
        mov ecx, offset attack_format_no_fixed
        cmovz eax, ecx
        push eax
        push esi
        call dword ptr ds:sprintf
        lea esp, [ebp-0x204] ; restore
        ret
      }
}

// Global.txt entries for attack boni.  Used just below.
static char **const monster_bonus_strings[24] = {
    GLOBAL_TXT + 153, // none
    new_strings + STR_CURSE,
    new_strings + STR_WEAKNESS,
    new_strings + STR_SLEEP,
    new_strings + STR_INEBRIATION,
    new_strings + STR_INSANITY,
    GLOBAL_TXT + 166, // poison green
    GLOBAL_TXT + 166, // poison yellow
    GLOBAL_TXT + 166, // poison red
    new_strings + STR_DISEASE, // green
    new_strings + STR_DISEASE, // yellow
    new_strings + STR_DISEASE, // red
    new_strings + STR_PARALYSIS,
    new_strings + STR_STUN, // unconscious
    new_strings + STR_DEATH,
    new_strings + STR_PETRIFACTION,
    new_strings + STR_ERADICATION,
    new_strings + STR_BREAK_ITEM,
    new_strings + STR_BREAK_ARMOR,
    new_strings + STR_BREAK_WEAPON,
    new_strings + STR_STEAL_ITEM,
    new_strings + STR_AGING,
    new_strings + STR_DRAIN_MAGIC,
    new_strings + STR_FEAR,
};

// Loop the above code twice if the monster has two attacks.
// Also print the inflicted condition or other attack bonus if present.
static void __declspec(naked) print_monster_special_bonus(void)
{
    asm
      {
        cmp byte ptr [eax].s_map_monster.attack2_chance, bl ; == 0
        jz bonus
        xor dword ptr [second_attack], 6 ; second attack offset
        jz bonus
        movzx eax, byte ptr [eax].s_map_monster.attack2_element
        mov edx, 0x41ef8f ; back to attack code
        jmp edx
        bonus:
        movzx ecx, byte ptr [eax].s_map_monster.attack_special
        mov edx, dword ptr [monster_bonus_strings+ecx*4]
        push dword ptr [edx]
        push ebx
        push dword ptr [GLOBAL_TXT_ADDR+210*4] ; "special"
        push 0x4e3308 ; the format string
        push esi
        call dword ptr ds:sprintf
        mov dword ptr [esp], 0x41f088 ; print line code
        ret 16
      }
}

// Set just below, later checked in learn_gm_skill().
static int gm_quest;

// Let GM teachers be more creative with their demands.
static char *__stdcall gm_teaching_conditions(struct player *player, int skill)
{
#define DEFAULT ((char *) 0)
#define REFUSE ((char *) -1)
#define ACCEPT ((char *) -2)
    gm_quest = 0;
    int train_req = 0;
    int item = -1;
    static char reply_buffer[200];
    switch (skill)
      {
        case SKILL_STAFF:
            train_req = 100;
            goto monk;
        case SKILL_SWORD:
        case SKILL_DAGGER:
        case SKILL_AXE:
        case SKILL_SPEAR:
        case SKILL_MACE:
            train_req = 100;
            break;
        case SKILL_BOW:
            if (check_bit(QBITS, QBIT_BOW_GM_QUEST))
                return DEFAULT;
            gm_quest = 593;
            break;
        case SKILL_BLASTER:
            if (check_bit(QBITS, QBIT_BLASTER_GM_QUEST))
                return DEFAULT;
            gm_quest = 595;
            break;
        case SKILL_SHIELD:
        case SKILL_CHAIN:
        case SKILL_PLATE:
            train_req = 200;
            break;
        case SKILL_LEATHER:
            train_req = 200;
            goto monk;
        case SKILL_FIRE:
        case SKILL_AIR:
        case SKILL_WATER:
        case SKILL_SPIRIT:
        case SKILL_MIND:
        case SKILL_BODY:
              {
                int stat, element;
                switch (skill)
                  {
                    case SKILL_FIRE:
                        stat = STAT_FIRE_RES;
                        element = FIRE;
                        break;
                    case SKILL_AIR:
                        stat = STAT_SHOCK_RES;
                        element = SHOCK;
                        break;
                    case SKILL_WATER:
                        stat = STAT_COLD_RES;
                        element = COLD;
                        break;
                    case SKILL_SPIRIT:
                        stat = STAT_MAGIC_RES;
                        element = MAGIC;
                        break;
                    case SKILL_MIND:
                        stat = STAT_MIND_RES;
                        element = MIND;
                        break;
                    case SKILL_BODY:
                        stat = STAT_POISON_RES;
                        element = POISON;
                        break;
                  }
                if (get_base_resistance(player, stat) < 40
                    && !(is_immune(player, element) & 1))
                    return REFUSE;
                if ((player->skills[skill] & SKILL_MASK) < 12)
                    return REFUSE;
                return DEFAULT;
              }
        case SKILL_EARTH:
            if (get_base_ac(player) < 120)
                return REFUSE;
            if ((player->skills[skill] & SKILL_MASK) < 12)
                return REFUSE;
            return DEFAULT;
        case SKILL_LIGHT:
        case SKILL_DARK:
            if ((player->skills[skill] & SKILL_MASK) < 12)
                return REFUSE;
            if (check_bit(QBITS, skill == SKILL_LIGHT ? QBIT_LIGHT_PATH
                                                      : QBIT_DARK_PATH))
              {
                dword(NEW_SKILL_COST) = 0;
                return ACCEPT;
              }
            return REFUSE;
        case SKILL_IDENTIFY_ITEM:
            train_req = 400;
            break;
        case SKILL_MERCHANT:
            leave_map_rep(); // update rep array
            for (int i = 2; i <= 11; i++) // don't check emerald island!
                if (i == 7) // also skip evenmorn (no temple)
                    continue;
                else if (elemdata.reputation[i] > -5)
                    return REFUSE;
            dword(NEW_SKILL_COST) = 20000;
            return ACCEPT;
        case SKILL_REPAIR:
            train_req = 40;
            break;
        case SKILL_BODYBUILDING:
            if (check_bit(QBITS, QBIT_BODYBUIDING_GM_QUEST))
                return DEFAULT;
            gm_quest = 597;
            break;
        case SKILL_MEDITATION:
            if (check_bit(QBITS, QBIT_MEDITATION_GM_QUEST))
                return DEFAULT;
            gm_quest = 599;
            break;
        case SKILL_PERCEPTION:
          {
            int obelisks = 0;
            for (int bit = QBIT_FIRST_OBELISK; bit <= QBIT_LAST_OBELISK; bit++)
                if (check_bit(QBITS, bit))
                    obelisks++;
            return obelisks >= 10 ? DEFAULT : REFUSE;
          }
        case SKILL_DISARM_TRAPS:
            train_req = 60;
            break;
        case SKILL_DODGING:
        case SKILL_UNARMED:
            if ((player->skills[SKILL_DODGING] & SKILL_MASK) < 10
                || (player->skills[SKILL_UNARMED] & SKILL_MASK) < 10)
                return DEFAULT; // we'd skip the check w/ token otherwise
        monk:
            for (int i = 0; i < 14 * 9; i++)
              {
                int j = player->inventory[i] - 1;
                if (j >= 0 && player->items[j].id == INITIATE_TOKEN)
                  {
                    item = i;
                    break;
                  }
              }
            if (item >= 0)
                break;
            if (player->class == CLASS_INITIATE) // can GM only with a token
                return new_strings[STR_NO_INITIATE_TOKEN];
            if (train_req) // leather or staff
                break;
            return DEFAULT;
        case SKILL_IDENTIFY_MONSTER:
            train_req = 1000;
            break;
        case SKILL_ARMSMASTER:
            for (int i = SKILL_STAFF; i <= SKILL_MACE; i++)
                if (i == SKILL_BOW)
                    continue;
                else if (player->skills[i] < SKILL_EXPERT)
                    return REFUSE;
            return DEFAULT;
        case SKILL_THIEVERY:
            for (int i = 0; i < 14 * 9; i++)
              {
                int j = player->inventory[i] - 1;
                if (j >= 0 && player->items[j].flags & IFLAGS_STOLEN
                    && item_value(&player->items[j]) >= 3000)
                  {
                    item = i;
                    break;
                  }
              }
            if (item >= 0)
                break;
            return REFUSE;
        case SKILL_ALCHEMY:
            if (check_bit(QBITS, QBIT_ALCHEMY_GM_QUEST))
              {
                dword(NEW_SKILL_COST) = 0;
                return ACCEPT;
              }
            gm_quest = 601;
            break;
        case SKILL_LEARNING:
            if (player->level_base < 30)
                return REFUSE;
            goto monk;
      }
    if (gm_quest)
      {
        dword(TOPIC_ACTION) = TRUE; // can't really learn, but allows clicking
        return NPC_TOPIC_TEXT[gm_quest].topic;
      }
    if (train_req)
      {
        char *reply;
        switch (elemdata.training[player-PARTY][skill] * 4 / train_req)
          {
            case 0:
                reply = new_strings[STR_PRACTICE_0];
                break;
            case 1:
                reply = new_strings[STR_PRACTICE_1];
                break;
            case 2:
                reply = new_strings[STR_PRACTICE_2];
                break;
            case 3:
                reply = new_strings[STR_PRACTICE_3];
                break;
            case 4:
            default:
                reply = NULL;
                break;
          }
        if (reply)
          {
            sprintf(reply_buffer, reply, SKILL_NAMES[skill]);
            return reply_buffer;
          }
      }
    if (item >= 0)
      {
        dword(NEW_SKILL_COST) = ~item;
        char name_buffer[100];
        sprintf(name_buffer, COLOR_FORMAT, colors[CLR_ITEM],
                item_name(&player->items[player->inventory[item]-1]));
        sprintf(reply_buffer, new_strings[STR_GM_FOR_ITEM],
                SKILL_NAMES[skill], name_buffer);
        dword(TOPIC_ACTION) = TRUE;
        return reply_buffer;
      }
    return DEFAULT;
}

// Hook for the above.
static void __declspec(naked) gm_teaching_conditions_hook(void)
{
    asm
      {
        push eax
        push esi
        call gm_teaching_conditions
        test eax, eax
        jg custom
        inc eax
        je refuse
        mov eax, dword ptr [0xf8b02c] ; restore new skill
        jl quit
        lea ecx, [eax-7] ; replaced code
        cmp ecx, SKILL_ALCHEMY - 7 ; replaced code
        quit:
        ret
        custom:
        push 0x4b28cd ; skip to quit (eax is set)
        ret 4
        refuse:
        push 0x4b27f5 ; refuse message
        ret 4
      }
}

// Kludge to keep the quest message when the GM dialogue terminates.
static int keep_text = 0, suppress_greet = 0;

// Execute some special actions (quest, item cost) when the learn option
// is actually clicked.  Also avoid the money sound at 0 cost.
static void __declspec(naked) learn_gm_skill(void)
{
    asm
      {
        cmp dword ptr [0xf8b030], GM ; new skill level
        jne ordinary
        cmp dword ptr [gm_quest], ebx ; ebx == 0
        jnz quest
        ordinary:
        cmp ecx, ebx
        jz no_money
        jg gold
        mov eax, dword ptr [CURRENT_PLAYER]
        test eax, eax
        jz quit
        not ecx
        push ecx
        mov ecx, dword ptr [PC_POINTERS+eax*4-4]
        call dword ptr ds:delete_backpack_item
        xor ecx, ecx ; no gold cost, but make a sound
        gold:
        call dword ptr ds:spend_gold
        no_money:
        mov eax, dword ptr [CURRENT_PLAYER]
        test eax, eax
        quit:
        ret
        quest:
        xor eax, eax
        inc eax
        mov dword ptr [keep_text], eax
        mov dword ptr [suppress_greet], eax
        mov dword ptr [GLOBAL_EVENT_FLAG], eax
        push eax
        xor edx, edx
        mov ecx, dword ptr [gm_quest]
        call dword ptr ds:process_event
        mov dword ptr [GLOBAL_EVENT_FLAG], ebx
        xor eax, eax ; set zf
        ret
      }
}

// Do not erase the last NPC message when exiting dialogue,
// as long as our flag is set.  (Used directly above.)
static void __declspec(naked) keep_text_on_exit(void)
{
    asm
      {
        mov ecx, dword ptr [keep_text]
        jecxz erase ; can`t alter the flags
        mov dword ptr [keep_text], edi ; reset the flag
        ret
        erase:
        mov dword ptr [CURRENT_TEXT_ADDR], edi
        ret
      }
}

// Also don't print a greeting, as it would be overlapped
// with the quest message otherwise.
static void __declspec(naked) suppress_greet_after_gm(void)
{
    asm
      {
        cmp dword ptr [suppress_greet], 1
        mov dword ptr [suppress_greet], ebx ; reset
        ret
      }
}

// Let the Master in magic schools require a skill of 8, not 7.
static void __declspec(naked) master_spell_skill(void)
{
    asm
      {
        jl quit ; replaced jump
        cmp dword ptr [0xf8b02c], SKILL_FIRE ; new skill
        jb not_magic
        cmp dword ptr [0xf8b02c], SKILL_DARK
        ja not_magic
        cmp ebx, 8
        ret
        not_magic:
        cmp ebx, 7 ; replaced code
        quit:
        ret
      }
}

// Called when killing a monster.  For bow, check for GM quest completion.
// For melee weapons (and throwing knives), advance kill counters.
static void __stdcall kill_checks(struct player *player,
                                  struct map_monster *monster,
                                  struct map_object *proj)
{
    if (proj)
      {
        if (proj->spell_type == SPL_ARROW)
          {
            int new_player = player - PARTY + 1;
            // these are the animtime counters for turn-based/normal mode
            int new_time = dword(dword(TURN_BASED) ? ANIM_TIMER : 0x50ba84)
                         - proj->age;
            if (new_player == bow_kill_player && new_time == bow_kill_time
                && check_bit(QBITS, QBIT_BOW_GM_QUEST_ACTIVE)
                && !check_bit(QBITS, QBIT_BOW_GM_QUEST))
              {
                evt_set(player, EVT_QBITS, QBIT_BOW_GM_QUEST);
                // make the quest book blink
                evt_set(player, EVT_QBITS, QBIT_DUMMY);
                evt_sub(player, EVT_QBITS, QBIT_DUMMY);
              }
            bow_kill_player = new_player;
            bow_kill_time = new_time;
          }
        else if (proj->spell_type == SPL_KNIFE)
            elemdata.training[player-PARTY][SKILL_DAGGER]++;
      }
    else
      {
        int slot = SLOT_OFFHAND;
        int skill = SKILL_NONE;
        for (int i = 0; i < 2; i++)
          {
            int weapon = player->equipment[slot];
            if (weapon)
              {
                struct item *item = &player->items[weapon-1];
                int new_skill = ITEMS_TXT[item->id].skill;
                if (new_skill < SKILL_BLASTER && new_skill != skill
                    && !(item->flags & IFLAGS_BROKEN))
                  {
                    skill = new_skill;
                    elemdata.training[player-PARTY][skill]++;
                  }
              }
            slot = SLOT_MAIN_HAND;
          }
      }
}

// Trigger the Bodybuilding GM quest completion when appropriate.
static void bb_quest(void)
{
    if (check_bit(QBITS, QBIT_BODYBUIDING_GM_QUEST_ACTIVE)
        && !check_bit(QBITS, QBIT_BODYBUIDING_GM_QUEST))
      {
        evt_set(PARTY, EVT_QBITS, QBIT_BODYBUIDING_GM_QUEST);
        // make the quest book blink, and also sparkles
        for (int i = 0; i < 4; i++)
          {
            evt_set(PARTY + i, EVT_QBITS, QBIT_DUMMY);
            evt_sub(PARTY + i, EVT_QBITS, QBIT_DUMMY);
          }
      }
}

// Hook for the above.
static void __declspec(naked) bb_quest_hook(void)
{
    asm
      {
        cmp byte ptr [0xacd59c], 3
        jbe quit
        call bb_quest
        cmp ebx, edi ; should be greater
        quit:
        ret
      }
}

// Meditation GM quest: check if we're resting on top of Mt. Nighon.
static void meditation_quest(void)
{
    if (check_bit(QBITS, QBIT_MEDITATION_GM_QUEST_ACTIVE)
        && !check_bit(QBITS, QBIT_MEDITATION_GM_QUEST)
        && !uncased_strcmp(CUR_MAP_FILENAME, MAP_MOUNT_NIGHON)
        && dword(PARTY_Z) >= 7999) // only the volcano is that high
      {
        evt_set(PARTY, EVT_QBITS, QBIT_MEDITATION_GM_QUEST);
        // make the quest book blink, and also sparkles
        for (int i = 0; i < 4; i++)
          {
            evt_set(PARTY + i, EVT_QBITS, QBIT_DUMMY);
            evt_sub(PARTY + i, EVT_QBITS, QBIT_DUMMY);
          }
      }
}

// Hook for the above.
static void __declspec(naked) meditation_quest_hook(void)
{
    asm
      {
        call meditation_quest
        mov dword ptr [0x506d98], 480 ; replaced code
        ret
      }
}

// Alchemy GM quest: brew a rejuvenation potion (ID checked in the hook).
static void __thiscall alchemy_quest(struct player *player)
{
    if (check_bit(QBITS, QBIT_ALCHEMY_GM_QUEST_ACTIVE)
        && !check_bit(QBITS, QBIT_ALCHEMY_GM_QUEST))
      {
        evt_set(player, EVT_QBITS, QBIT_ALCHEMY_GM_QUEST);
        // make the quest book blink
        evt_set(player, EVT_QBITS, QBIT_DUMMY);
        evt_sub(player, EVT_QBITS, QBIT_DUMMY);
      }
}

// Hook for the above.
static void __declspec(naked) alchemy_quest_hook(void)
{
    asm
      {
        cmp dword ptr [ebp-4], REJUVENATION
        jne skip
        mov ecx, esi
        call alchemy_quest
        skip:
        mov eax, dword ptr [ebp-8] ; replaced code
        mov ecx, dword ptr [ebp-4] ; replaced code
        ret
      }
}

// A wrapper for monster hit roll, registers armor/shield training
// on a successfull block.  Also here: handle cursed monster attacks.
static int __stdcall train_armor(struct map_monster *monster,
                                 struct player *player)
{
    if (monster->spell_buffs[MBUFF_CURSED].expire_time && random() & 1)
        return FALSE; // missed but technically not blocked
    int result = monster_hits_player(monster, player);
    if (!result)
      {
        int body = player->equipment[SLOT_BODY_ARMOR];
        if (body)
          {
            struct item *armor = &player->items[body-1];
            int skill = ITEMS_TXT[armor->id].skill;
            if (!(armor->flags & IFLAGS_BROKEN)
                && skill >= SKILL_LEATHER && skill <= SKILL_PLATE)
                elemdata.training[player-PARTY][skill]++;
          }
        int offhand = player->equipment[SLOT_OFFHAND];
        if (offhand)
          {
            struct item *shield = &player->items[offhand-1];
            if (!(shield->flags & IFLAGS_BROKEN)
                && ITEMS_TXT[shield->id].skill == SKILL_SHIELD)
                elemdata.training[player-PARTY][SKILL_SHIELD]++;
          }
      }
    return result;
}

// Increment the training counter on a successful chest disarm.
static void __declspec(naked) train_disarm(void)
{
    asm
      {
        mov dword ptr [ebp-4], 1 ; replaced code
        mov ecx, dword ptr [CURRENT_PLAYER]
        dec ecx
        imul ecx, ecx, SKILL_COUNT
        add ecx, SKILL_DISARM_TRAPS
        inc dword ptr [elemdata.training+ecx*4]
        ret
      }
}

// Register a successful ID Monster use.
static void __declspec(naked) train_id_monster(void)
{
    asm
      {
        cmp dword ptr [ebp-24], ebx ; zero if monster is already id
        jz skip
        mov ecx, dword ptr [CURRENT_PLAYER]
        dec ecx
        imul ecx, ecx, SKILL_COUNT
        add ecx, SKILL_IDENTIFY_MONSTER
        inc dword ptr [elemdata.training+ecx*4]
        skip:
        cmp dword ptr [0x507a70], ebx ; replaced code
        ret
      }
}

// Let temporary levels boost skills slightly.
// NB: Learning doesn't scale bonus with mastery, so the effect is lower.
// Also here: penalize some skills based on difficulty.
static void __declspec(naked) level_skill_bonus(void)
{
    asm
      {
        movzx ebx, word ptr [eax+edi*2].s_player.skills ; replaced code, almost
        mov ecx, eax
        call dword ptr ds:get_level
        mov ecx, dword ptr [ebp-4] ; pc
        movzx ecx, word ptr [ecx].s_player.level_base
        sub eax, ecx
        jbe skip
        cmp ecx, 20
        ja ok
        mov ecx, 20 ; prevent abuse from purposefully staying at level 1
        ok:
        mov edx, ebx
        and edx, SKILL_MASK
        mul edx
        div ecx
        add esi, eax
        skip:
        mov eax, ebx
        cmp dword ptr [elemdata.difficulty], 0
        jz quit
        cmp edi, SKILL_IDENTIFY_ITEM
        jb quit
        cmp edi, SKILL_BODYBUILDING
        je quit
        cmp edi, SKILL_MEDITATION
        je quit
        cmp edi, SKILL_LEARNING
        je quit
        and eax, SKILL_MASK
        shr eax, 1
        cmp dword ptr [elemdata.difficulty], 2
        jae lower
        shr eax, 1
        lower:
        sub esi, eax
        mov eax, ebx
        quit:
        ret
      }
}

// To transfer data between the two hooks below.
static char weapon_mod2;

// When calculating skill bonus to AC, take note of weapon quality (mod2).
static void __declspec(naked) store_weapon_quality_bonus(void)
{
    asm
      {
        movzx edx, byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.skill ; repl.
        cmp edx, SKILL_BLASTER
        cmovbe ecx, dword ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.mod2
        mov byte ptr [weapon_mod2], cl
        xor ecx, ecx ; restore
        ret
      }
}

// Now add weapon quality to AC along with the skill (if applicable).
static void __declspec(naked) add_weapon_quality_bonus_to_ac(void)
{
    asm
      {
        and edi, SKILL_MASK ; replaced code
        xor ecx, ecx ; replaced code
        movzx edx, byte ptr [weapon_mod2] ; stored quality (or 0 for armor)
        add edi, edx ; to ac bonus
        ret
      }
}

// Add skill bonus to Thievery when stealing an item (bug fix).
static void __declspec(naked) stealing_skill_bonus(void)
{
    asm
      {
        push SKILL_THIEVERY
        call dword ptr ds:get_skill
        mov ecx, eax
        ret
      }
}

// Do not mark items shoplifted at GM as stolen.
static void __declspec(naked) flawless_theft(void)
{
    asm
      {
        mov ecx, dword ptr [ebp-20] ; current pc
        cmp word ptr [ecx+SKILL_THIEVERY*2].s_player.skills, SKILL_GM
        jae quit
        or word ptr [eax+S_PL_ITEM0].s_item.flags, IFLAGS_STOLEN ; almost repl
        quit:
        ret
      }
}

// Allow Learning to increase gamescript (quest etc.) XP.
static void __declspec(naked) learning_quest_xp(void)
{
    asm
      {
        mov ecx, esi
        call dword ptr ds:get_learning_bonus
        mov ecx, 100
        add eax, ecx
        mul dword ptr [ebp+12] ; base xp
        div ecx
        mov edx, 0x44b24d ; old code after xp read
        jmp edx
      }
}

// Let halved armor from GM Axe also halve physical resistance.
// This hook affects damage done to monsters.
// Note that while this would convert physical immunity to 100 resistance,
// it cannot happen because such monsters are also immune to halved armor.
static void __declspec(naked) halved_physical_damage_resistance(void)
{
    asm
      {
        cmp dword ptr [eax+MBUFF_HALVED_ARMOR*SIZE_BUFF] \
                      .s_map_monster.spell_buffs, edx
        jnz ok
        cmp dword ptr [eax+MBUFF_HALVED_ARMOR*SIZE_BUFF+4] \
                      .s_map_monster.spell_buffs, edx
        ok:
        movzx eax, byte ptr [eax].s_map_monster.physical_resistance ; old code
        jz quit
        shr eax, 1 ; halve
        quit:
        push 0x427595 ; replaced jump (roll resistance code)
        ret
      }
}

// This one affects resistance to physical conditions.
static void __declspec(naked) halved_physical_condition_resistance(void)
{
    asm
      {
        mov edi, dword ptr [ebp+8] ; replaced code (get monster)
        movzx esi, byte ptr [edi].s_map_monster.physical_resistance ; replaced
        mov edx, dword ptr [edi+MBUFF_HALVED_ARMOR*SIZE_BUFF] \
                           .s_map_monster.spell_buffs
        or edx, dword ptr [edi+MBUFF_HALVED_ARMOR*SIZE_BUFF+4] \
                          .s_map_monster.spell_buffs
        jz quit
        shr esi, 1 ; halve
        quit:
        ret
      }
}

// Used just below, to make sure we loop exactly twice.
static int double_shield_flag = 0;

// Double most shield boni at Master by looping through the item twice.
static void __declspec(naked) double_shield_bonus(void)
{
    asm
      {
        jl fail ; if weapon
        cmp eax, ITEM_TYPE_SHIELD - 1
        jne skip
        cmp word ptr [ebx+SKILL_SHIELD*2].s_player.skills, SKILL_MASTER
        jb skip
        not dword ptr [double_shield_flag] ; 0 <-> -1
        mov ecx, dword ptr [double_shield_flag]
        mov dword ptr [esp+40], ecx ; loop counter
        skip:
        cmp esi, STAT_AC ; we erased this check earlier
        jne fail
        cmp eax, ITEM_TYPE_AMULET - 1 ; replaced code
        ret
        fail:
        cmp ebx, esi ; always greater
        ret
      }
}

// Also double shield HP regeneration (which stacks in the mod).
static void __declspec(naked) double_shield_regen(void)
{
    asm
      {
        add edx, 4 ; replaced code
        cmp ecx, FIRST_SHIELD
        jb skip
        cmp ecx, LAST_SHIELD
        ja skip
        cmp word ptr [esi+SKILL_SHIELD*2].s_player.skills, SKILL_MASTER
        jb skip
        add ebx, ebx ; only shield regen here (offhand is 0th slot)
        skip:
        cmp edi, SLOT_COUNT ; also replaced
        ret
      }
}

// Return 2 if item is repaired by a hireling (won't take a turn).
// This code is also reached by skill-based repair,
// but raise_ench_item_difficulty() sets ebp to -1.
static void __declspec(naked) npc_repair_chunk(void)
{
    asm
      {
        add ebp, 2
      }
}

// Make odd Disarm skill values meaningful by imposing a 50% failure
// chance when the skill level and lock difficulty are exactly equal.
static void __declspec(naked) randomized_chest_disarm(void)
{
    asm
      {
        call dword ptr ds:get_disarm_bonus ; replaced call
        push eax
        call dword ptr ds:random
        shr eax, 1
        pop eax
        sbb eax, esi ; == 0
        ret
      }
}

// Make monster level actually matter when stealing from it.
static void __declspec(naked) steal_monster_level(void)
{
    asm
      {
        lea esi, [esi+esi*4] ; other factors (count x100%)
        add esi, eax ; monster level (now counts x20%)
        lea esi, [esi+esi*4]
        shl esi, 2
        ret
      }
}

// Tweak various skill effects.
static inline void skill_changes(void)
{
    // bodybuilding regen bonus is calculated in hp_burnout() above
    patch_word(0x493cdd, 0x9e01); // inc -> add ebx (= bonus)
    patch_byte(0x491087, 3); // remove previous GM bonus
    // meditation SP regen is in sp_burnout() above
    patch_byte(0x4910b2, 3); // remove old GM bonus
    hook_call(0x426a82, perception_bonus_gold, 5);
    hook_call(0x426c07, perception_extra_item, 12);
    erase_code(0x491276, 12); // remove 100% chance on GM
    hook_call(0x41641d, lenient_alchemy_remember, 6);
    hook_call(0x4164d9, lenient_alchemy_allow, 6);
    hook_call(0x416570, botched_potion_power, 6);
    hook_call(0x4165a5, botched_potion_catalyst_1, 6);
    hook_call(0x4165b3, botched_potion_catalyst_2, 6);
    hook_call(0x41e266, display_botched_potion, 6);
    hook_call(0x402e18, preserve_mdist_on_death, 5);
    hook_call(0x4401df, draw_erad_hook, 6);
    hook_call(0x47b9ee, draw_erad_hook_out, 6);
    hook_call(0x43ffe1, erad_z_hook, 5);
    hook_call(0x47b66d, erad_z_hook_out, 7);
    hook_call(0x470707, erad_stop_moving, 7); // outdoors
    hook_call(0x46f939, erad_stop_moving, 7); // indoors
    patch_byte(0x48fd08, 3); // remove old blaster GM bonus
    hook_call(0x491135, raise_ench_item_difficulty, 6);
    hook_call(0x4911d7, raise_ench_item_difficulty, 6);
    hook_call(0x490fea, unid_item_sell_price, 5);
    hook_call(0x491038, unid_item_sell_price, 5);
    hook_call(0x49581c, unid_item_sell_price, 5);
    hook_call(0x495869, unid_item_sell_price, 5);
    hook_call(0x4958c6, unid_item_sell_price, 5);
    hook_call(0x495911, unid_item_sell_price, 5);
    hook_call(0x4be266, unid_item_sell_price, 5);
    hook_call(0x468649, read_unid_scroll, 5);
    hook_call(0x4684ed, read_unid_book, 6);
    hook_call(0x42ab66, cant_enchant_blasters, 5); // GM
    hook_call(0x42adf6, cant_enchant_blasters, 5); // Master
    hook_call(0x42b096, cant_enchant_blasters, 5); // Expert (unused)
    hook_call(0x42b30b, cant_enchant_blasters, 5); // Normal (unused)
    hook_call(0x491191, npcs_cant_repair_blasters, 5);
    hook_call(0x4bdbe6, shops_cant_repair_blasters, 5);
    hook_call(0x490f91, shops_cant_repair_blasters_msg, 11);
    hook_call(0x48d5a3, resist_phys_damage_hook, 5);
    erase_code(0x48d5a8, 94); // old plate/chain code
    // old GM shield bonus jumped over in shield_stacking_hook() above
    hook_call(0x43a4cf, absorb_monster_spell, 6);
    // absorb_other_spell() called from damage_potions_player()
    hook_call(0x401bf2, absorb_armageddon, 6);
    // Also see cast_new_spells() and dispel_immunity() above.
    patch_byte(0x490021, -13); // remove old leather M bonus
    patch_dword(0x490097, 0xf08bce8b); // swap instructions
    hook_call(0x49009b, leather_dodging, 5);
    patch_byte(0x4900ab, 0xfa); // eax -> edx
    erase_code(0x48e7f9, 75); // old Leather GM bonus
    hook_call(0x43a03f, maybe_dodge_hook, 5); // melee
    hook_call(0x43a4dc, maybe_dodge_hook, 5); // ranged
    hook_call(0x48e43b, boost_axe_recovery, 5);
    hook_jump(0x41eaad, new_id_monster_check);
    patch_byte(0x41eaa0, 12); // don't skip the hook if zero skill
    hook_call(0x4272bc, id_monster_normal, 6);
    hook_call(0x4274a6, id_monster_expert, 6);
    hook_call(0x43a181, id_monster_master, 5);
    hook_call(0x43a69f, id_monster_master, 5);
    // gm bonus applied in pierce_debuff_resistance()
    // and cursed_monster_resists_damage() above
    hook_call(0x41efa3, print_full_monster_attack, 5);
    hook_jump(0x41efd5, print_monster_special_bonus);
    patch_pointer(0x41f073, GLOBAL_TXT + 210); // "special" for failed id
    hook_call(0x4b268f, gm_teaching_conditions_hook, 6);
    hook_call(0x4b218d, learn_gm_skill, 12);
    hook_call(0x4bd856, keep_text_on_exit, 6);
    hook_call(0x43260e, suppress_greet_after_gm, 6);
    hook_call(0x4b273c, master_spell_skill, 9);
    erase_code(0x46c1b4, 4); // preserve arrow age to determine shot timing
    // blaster quest completed in inflict_condition() above
    hook_call(0x4941d0, bb_quest_hook, 7);
    hook_call(0x4341f6, meditation_quest_hook, 10);
    hook_call(0x416544, alchemy_quest_hook, 6);
    // id item and repair training is in raise_ench_item_difficulty() above
    hook_call(0x42046d, train_disarm, 7);
    hook_call(0x41eb30, train_id_monster, 6);
    patch_byte(0x4912a1, 0xc6); // multiply perception bonus by mastery
    patch_byte(0x491307, 0xc6); // same with disarm
    patch_byte(0x491247, 0xce); // also merchant
    hook_call(0x48fbd5, level_skill_bonus, 8);
    hook_call(0x48ffdc, store_weapon_quality_bonus, 7);
    hook_call(0x49005b, add_weapon_quality_bonus_to_ac, 5);
    // new master dagger bonus is in sniper_accuracy() above
    patch_byte(0x48cee9, 0xeb); // remove old bonus (main hand)
    patch_byte(0x48d014, 0xeb); // offhand
    // thievery backstab is checked in check_backstab() above
    dword(0x4edd58) = 300; // remove 5x multiplier at GM
    hook_call(0x48d7ad, stealing_skill_bonus, 7); // steal from shop
    patch_word(0x48d8ee, 0xce8b); // mov ecx, esi
    hook_call(0x48d8f0, stealing_skill_bonus, 5); // steal from a monster
    hook_call(0x4be11b, flawless_theft, 7);
    patch_pointer(0x44b944, learning_quest_xp);
    // new sword/spear gm bonus is in maybe_parry() above
    erase_code(0x48ffea, 2); // erase old bonus
    erase_code(0x48ffef, 2); // ditto
    patch_pointer(0x4275fd, halved_physical_damage_resistance); // jumptable
    hook_call(0x427682, halved_physical_condition_resistance, 7);
    erase_code(0x48ee63, 5); // fall through to our hook for all stats
    hook_call(0x48ee71, double_shield_bonus, 5);
    hook_call(0x493c67, double_shield_regen, 6);
    // also double aggro in weighted_monster_preference() above
    patch_bytes(0x4911df, npc_repair_chunk, 3);
    hook_call(0x420451, randomized_chest_disarm, 5);
    hook_call(0x48d93d, steal_monster_level, 5);
}

// The mod's new hotkeys.
static int quick_heal_key = 0, quick_repair_key = 0;
static int quick_spell_keys[4] = { '7', '8', '9', '0' };
// Used in extra_key_config() below.
static int *hotkey_settings[] = {
    [6] = &quick_heal_key, &quick_repair_key, quick_spell_keys,
          quick_spell_keys + 1, quick_spell_keys + 2, quick_spell_keys + 3,
};
#define HOTKEY_COUNT (sizeof(hotkey_settings) / sizeof(int *))

// Switch off some of MM7Patch's features to ensure compatibility.
static inline void patch_compatibility(void)
{
    HMODULE patch = GetModuleHandle("MM7patch.dll");
    FARPROC get_options = GetProcAddress(patch, "GetOptions");
    patch_options = (void *) get_options();
    patch_options->fix_unimplemented_spells = FALSE; // conflicts with my hook
    patch_options->fix_unmarked_artifacts = FALSE; // I do it differently
    patch_options->fix_light_bolt = FALSE; // I don't want this!
    patch_options->armageddon_element = MAGIC; // can't read spells.txt yet
    patch_options->keep_empty_wands = FALSE; // my implementation is better
    patch_byte(0x42efc9, 10); // new melee recovery limit (for the hint)
    normal_axe_chance = patch_options->axe_gm_perk_chance; // we may change it
    hotkey_settings[0] = (int *) patch_options + 13419; // TODO: will break!
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
    hotkey_settings[1] = &patch_options->quick_load_key;
    hotkey_settings[2] = &patch_options->double_speed_key;
    hotkey_settings[3] = &patch_options->autorun_key;
    hotkey_settings[4] = &patch_options->inventory_key;
    hotkey_settings[5] = &patch_options->char_screen_key;
#pragma GCC diagnostic pop
}

// Let robes, crowns and hats have an increased chance to generate enchanted,
// to compensate for their low base utility (the % chance is rolled twice).
static void __declspec(naked) robe_crown_ench_chance(void)
{
    asm
      {
        mov eax, dword ptr [edi+0x116b4+eax*4] ; spc ench chance
        lea ecx, [eax+ebx]
        cmp edx, ecx
        jge fail
        skip:
        test eax, eax ; replaced comparison, basically
        ret
        fail:
        mov ecx, dword ptr [esi]
        lea ecx, [ecx+ecx*2]
        shl ecx, 4
        cmp byte ptr [edi+4+ecx].s_items_txt_item.mod1_dice_count, 1 ; base ac
        ja skip
        cmp byte ptr [edi+4+ecx].s_items_txt_item.equip_stat, \
            ITEM_TYPE_ARMOR - 1
        je reroll
        cmp byte ptr [edi+4+ecx].s_items_txt_item.equip_stat, \
            ITEM_TYPE_HELM - 1
        jne skip
        reroll:
        call dword ptr ds:random
        xor edx, edx
        mov ecx, 100
        div ecx
        test ecx, ecx ; clear zf
        ret
      }
}

// Same for staves (b/c they're magical and can get valuable enchantments).
static void __declspec(naked) staff_ench_chance(void)
{
    asm
      {
        mov ecx, 100 ; replaced code, kinda
        div ecx ; ditto
        cmp edx, dword ptr [ebx] ; this one is verbatim
        jl quit
        mov ecx, dword ptr [esi]
        lea ecx, [ecx+ecx*2]
        shl ecx, 4
        cmp byte ptr [edi+4+ecx].s_items_txt_item.skill, SKILL_STAFF
        jne skip
        call dword ptr ds:random
        xor edx, edx
        mov ecx, 100
        div ecx
        skip:
        cmp edx, dword ptr [ebx]
        quit:
        ret 4
      }
}

// Parse two more prob columns into empty (padding) fields.
static void __declspec(naked) spcitems_new_probability(void)
{
    asm
      {
        cmp edx, 15
        jb old
        add edx, 5 ; skip over other fields
        old:
        mov ecx, dword ptr [ebp-16] ; replaced code
        mov byte ptr [ecx+edx+5], al ; changed a bit
        ret
      }
}

// Treat robes and crowns/hats as their own item types for ench purposes.
static void __declspec(naked) std_ench_group(void)
{
    asm
      {
        cmp byte ptr [edi+4+ecx].s_items_txt_item.equip_stat, \
            ITEM_TYPE_ARMOR - 1
        jne not_robe
        cmp byte ptr [edi+4+ecx].s_items_txt_item.skill, SKILL_MISC
        je robe
        not_robe:
        cmp byte ptr [edi+4+ecx].s_items_txt_item.equip_stat, \
            ITEM_TYPE_HELM - 1
        jne not_crown
        cmp byte ptr [edi+4+ecx].s_items_txt_item.mod1_dice_count, 0
        je crown
        not_crown:
        movzx ecx, byte ptr [edi+4+ecx].s_items_txt_item.equip_stat ; replaced
        ret
        robe:
        mov ecx, 12
        ret
        crown:
        mov ecx, 13
        ret
      }
}

// Same, but for Enchant Item instead of natural generation.
static void __declspec(naked) std_ench_group_ei(void)
{
    asm
      {
        cmp byte ptr [ITEMS_TXT_ADDR+ecx].s_items_txt_item.equip_stat, \
            ITEM_TYPE_ARMOR - 1
        jne not_robe
        cmp byte ptr [ITEMS_TXT_ADDR+ecx].s_items_txt_item.skill, SKILL_MISC
        je robe
        not_robe:
        cmp byte ptr [ITEMS_TXT_ADDR+ecx].s_items_txt_item.equip_stat, \
            ITEM_TYPE_HELM - 1
        jne not_crown
        cmp byte ptr [ITEMS_TXT_ADDR+ecx].s_items_txt_item.mod1_dice_count, 0
        jz crown
        not_crown:
        ; replaced code next line:
        movzx ecx, byte ptr [ITEMS_TXT_ADDR+ecx].s_items_txt_item.equip_stat
        ret
        robe:
        mov ecx, 12
        ret
        crown:
        mov ecx, 13
        ret
      }
}

// This one is for special enchs, and it also special-cases staves.
static void __declspec(naked) spc_ench_group(void)
{
    asm
      {
        mov ecx, dword ptr [esi]
        lea ecx, [ecx+ecx*2]
        shl ecx, 4
        movzx edx, byte ptr [edi+4+ecx].s_items_txt_item.equip_stat
        cmp edx, ITEM_TYPE_WEAPON - 1
        je weapon
        cmp edx, ITEM_TYPE_WEAPON2 - 1
        je weapon
        cmp edx, ITEM_TYPE_ARMOR - 1
        je armor
        cmp edx, ITEM_TYPE_HELM - 1
        je helm
        cmp edx, ITEM_TYPE_GAUNTLETS - 1
        je gauntlets
        other:
        mov dword ptr [ebp-8], edx
        ret
        weapon:
        cmp byte ptr [edi+4+ecx].s_items_txt_item.skill, SKILL_STAFF
        je staff
        mov dword ptr [ebp-8], 0 ; any non-staff weapon
        ret
        staff:
        mov dword ptr [ebp-8], 1 ; staff
        ret
        armor:
        cmp byte ptr [edi+4+ecx].s_items_txt_item.skill, SKILL_MISC
        jne other
        mov dword ptr [ebp-8], 17 ; robe
        ret
        helm:
        cmp byte ptr [edi+4+ecx].s_items_txt_item.mod1_dice_count, 0
        jnz other
        mov dword ptr [ebp-8], 18 ; crown
        ret
        gauntlets:
        cmp byte ptr [edi+4+ecx].s_items_txt_item.skill, SKILL_UNARMED
        jne other
        mov dword ptr [ebp-8], 19 ; caestus
        ret
      }
}

// Provide the stored group as necessary.
static void __declspec(naked) spc_ench_group_chunk(void)
{
    asm
      {
        mov eax, dword ptr [ebp-8]
      }
}

// Same, but into ecx.
static void __declspec(naked) spc_ench_group_chunk_2(void)
{
    asm
      {
        mov ecx, dword ptr [ebp-8]
      }
}

// Also special enchs, but for Enchant Item.
static void __declspec(naked) spc_ench_group_ei(void)
{
    asm
      {
        mov esi, dword ptr [edi]
        lea esi, [esi+esi*2]
        shl esi, 4
        movzx eax, byte ptr [ITEMS_TXT_ADDR+esi].s_items_txt_item.equip_stat
        cmp eax, ITEM_TYPE_WEAPON - 1
        je weapon
        cmp eax, ITEM_TYPE_WEAPON2 - 1
        je weapon
        cmp eax, ITEM_TYPE_ARMOR - 1
        je armor
        cmp eax, ITEM_TYPE_HELM - 1
        je helm
        cmp eax, ITEM_TYPE_GAUNTLETS - 1
        je gauntlets
        quit:
        mov dword ptr [ebp-36], eax ; store in an unused var
        lea eax, [ebp-3696] ; replaced code
        ret
        weapon:
        cmp byte ptr [ITEMS_TXT_ADDR+esi].s_items_txt_item.skill, SKILL_STAFF
        je staff
        mov al, 0 ; any non-staff weapon
        jmp quit
        staff:
        mov al, 1 ; staff
        jmp quit
        armor:
        cmp byte ptr [ITEMS_TXT_ADDR+esi].s_items_txt_item.skill, SKILL_MISC
        jne quit
        mov al, 17 ; robe
        jmp quit
        helm:
        cmp byte ptr [ITEMS_TXT_ADDR+esi].s_items_txt_item.mod1_dice_count, 0
        jnz quit
        mov al, 18 ; crown
        jmp quit
        gauntlets:
        cmp byte ptr [ITEMS_TXT_ADDR+esi].s_items_txt_item.skill, SKILL_UNARMED
        jne quit
        mov al, 19 ; caestus
        jmp quit
      }
}

// Read the item group.
static void __declspec(naked) spc_ench_group_ei_chunk(void)
{
    asm
      {
        mov eax, dword ptr [ebp-36]
      }
}

// Now read in into ecx and keep it there.
static void __declspec(naked) spc_ench_group_ei_chunk_2(void)
{
    asm
      {
        mov eax, ecx
        mov ecx, dword ptr [ebp-36]
      }
}

// Expert code swaps edi and esi.
static void __declspec(naked) spc_ench_group_ei_expert(void)
{
    asm
      {
        mov edi, esi
        call spc_ench_group_ei
        mov esi, edi
        ret
      }
}

// Change the mechanics of robe, crown, hat, and staff enchantment.
static inline void new_enchant_item_types(void)
{
    hook_call(0x456aaa, robe_crown_ench_chance, 8);
    hook_call(0x456ba4, staff_ench_chance, 5);
    // robes are made player-enchantable in cant_enchant_blasters() above
    // Add more columns to stditems and spcitems.
    patch_byte(0x456eef, 13); // 2 more to stditems (+1 for craft item)
    patch_dword(0x456f25, 11); // and totals
    // NB: new totals occupy (unused) part of bonus range array
    patch_dword(0x456f73, dword(0x456f73) + 2); // don't parse lvl1 bonus range
    patch_byte(0x4570be, 18); // spcitems value column
    patch_byte(0x45710d, 20); // column count
    hook_call(0x4570b3, spcitems_new_probability, 7);
    // This will calculate (junk) sums of levels and value too, but it`s ok.
    patch_dword(0x457146, 20); // probabilities + fields we skip over
    hook_call(0x456ace, std_ench_group, 5);
    patch_byte(0x456aee, 0x39); // use our ecx
    erase_code(0x456afa, 2); // don`t recalculate ecx
    erase_code(0x456b04, 6); // more recalculation
    erase_code(0x456b0d, 5); // ditto
    hook_call(0x42acb4, std_ench_group_ei, 7); // GM
    patch_byte(0x42acd7, 0xb1); // same as above (keep ecx)
    erase_code(0x42acde, 2);
    erase_code(0x42ace3, 3);
    erase_code(0x42ace9, 10);
    hook_call(0x42af44, std_ench_group_ei, 7); // Master
    patch_byte(0x42af67, 0xb1);
    erase_code(0x42af6e, 2);
    erase_code(0x42af73, 3);
    erase_code(0x42af79, 10);
    hook_call(0x42b1a1, std_ench_group_ei, 7); // Expert (unused)
    patch_byte(0x42b1c4, 0xb9);
    erase_code(0x42b1cb, 2);
    erase_code(0x42b1d0, 3);
    erase_code(0x42b1d6, 10);
    hook_call(0x42b401, std_ench_group_ei, 7); // Normal (unused)
    patch_byte(0x42b424, 0xb1);
    erase_code(0x42b42b, 2);
    erase_code(0x42b430, 3);
    erase_code(0x42b436, 10);
    hook_call(0x456bdc, spc_ench_group, 10);
    patch_bytes(0x456c87, spc_ench_group_chunk, 3);
    erase_code(0x456c8a, 8); // rest of old group read
    patch_bytes(0x456cc5, spc_ench_group_chunk_2, 3);
    erase_code(0x456cc8, 5); // ditto
    hook_call(0x42ad2c, spc_ench_group_ei, 6); // GM
    patch_bytes(0x42ad43, spc_ench_group_ei_chunk, 3);
    erase_code(0x42ad46, 12); // rest of replaced code
    patch_bytes(0x42ad8f, spc_ench_group_ei_chunk_2, 5);
    erase_code(0x42ad94, 8); // same
    erase_code(0x42adbf, 2); // preserve ecx
    erase_code(0x42adc4, 13); // ditto
    hook_call(0x42afbc, spc_ench_group_ei, 6); // Master
    patch_bytes(0x42afd3, spc_ench_group_ei_chunk, 3);
    erase_code(0x42afd6, 12);
    patch_bytes(0x42b01f, spc_ench_group_ei_chunk_2, 5);
    erase_code(0x42b024, 8);
    erase_code(0x42b053, 2);
    erase_code(0x42b058, 13);
    hook_call(0x42b227, spc_ench_group_ei_expert, 6); // actually unused
    patch_bytes(0x42b23e, spc_ench_group_ei_chunk, 3);
    erase_code(0x42b241, 12);
    patch_bytes(0x42b28a, spc_ench_group_ei_chunk_2, 5);
    erase_code(0x42b28f, 8);
    erase_code(0x42b2ba, 2);
    erase_code(0x42b2bf, 13);
    // Allow HP/SP regen to work on robes.
    patch_dword(0x493bf8, LAST_PREFIX);
}

// For the sprite filename.
static char knife_buffer[10];
static const char knife_equipped_suffix[] = "e";

// Knives have a separate paperdoll sprite.
static void __declspec(naked) equipped_knife_sprite(void)
{
    asm
      {
        cmp dword ptr [edi], BOOMERANG_KNIFE ; an exception
        je skip
        cmp byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.skill, SKILL_DAGGER
        je knife
        skip:
        pop edx
        push dword ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.bitmap ; replaced
        jmp edx
        knife:
        push eax ; preserve
        push ecx ; ditto
        push dword ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.bitmap
#ifdef __clang__
        mov eax, offset knife_buffer
        push eax
#else
        push offset knife_buffer
#endif
        call dword ptr ds:strcpy_ptr
#ifdef __clang__
        mov edx, offset knife_equipped_suffix
        mov eax, offset knife_buffer
        push edx
        push eax
#else
        push offset knife_equipped_suffix
        push offset knife_buffer
#endif
        call dword ptr ds:strcat_ptr
        add esp, 16
        pop ecx ; restore
        pop eax ; this too
#ifdef __clang__
        mov edx, offset knife_buffer
        xchg edx, dword ptr [esp]
#else
        pop edx
        push offset knife_buffer
#endif
        jmp edx
      }
}

// Let the Dagger skill affect throwing knife to-hit.
static void __declspec(naked) knife_skill_accuracy(void)
{
    asm
      {
        cmp edi, SKILL_DAGGER
        jne skip
        cmp dword ptr [ebp-4], SLOT_MISSILE
        je quit ; same as bow
        skip:
        sub edi, SKILL_BOW ; replaced code
        quit:
        ret
      }
}

// Let GM Dagger and Might increase throwing knife damage.
// This hook is for damage display purposes.
static void __declspec(naked) knife_displayed_damage(void)
{
    asm
      {
        mov eax, dword ptr [esi+SLOT_MISSILE*4].s_player.equipment
        test eax, eax
        jz quit
        lea eax, [eax+eax*8]
        test byte ptr [esi+S_PL_ITEM0+eax*4].s_item.flags, IFLAGS_BROKEN
        jnz skip
        mov eax, dword ptr [esi+eax*4-SIZE_ITEM].s_player.items
        lea eax, [eax+eax*2]
        shl eax, 4
        cmp byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.skill, SKILL_DAGGER
        je dagger
        cmp byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.skill, SKILL_BOW
        jne skip
        mov ax, word ptr [esi+SKILL_BOW*2].s_player.skills ; replaced code
        test ax, ax ; ditto
        quit:
        ret
        dagger:
        mov ecx, esi
        call dword ptr ds:get_might
        push eax
        call dword ptr ds:get_effective_stat
        sar eax, 1
        add edi, eax
        mov ecx, esi
        push SKILL_DAGGER
        call dword ptr ds:get_skill
        cmp eax, SKILL_GM
        jb skip
        and eax, SKILL_MASK
        add edi, eax
        skip:
        xor eax, eax ; set zf
        ret
      }
}

// Appropriate the unused spell 101 for throwing knives.
static void __declspec(naked) knife_spell(void)
{
    asm
      {
        cmp ecx, SPL_ARROW
        jne quit
        mov eax, dword ptr [esi+SLOT_MISSILE*4].s_player.equipment
        lea eax, [eax+eax*8]
        mov eax, dword ptr [esi+eax*4-SIZE_ITEM].s_player.items
        lea eax, [eax+eax*2]
        shl eax, 4
        cmp byte ptr [ITEMS_TXT_ADDR+eax].s_items_txt_item.skill, SKILL_DAGGER
        jne quit
        mov ecx, SPL_KNIFE
        mov dword ptr [ebp-20], 2 ; sound flag
        quit:
        jmp dword ptr ds:aim_spell ; replaced call
      }
}

// Give throwing knives the dagger swing sound.
// TODO: maybe something more appropriate?
static void __declspec(naked) knife_sound(void)
{
    asm
      {
        cmp dword ptr [ebp-20], 2 ; sound flag
        jae knife
        mov dword ptr [ebp-4], SKILL_BOW ; replaced code
        ret
        knife:
        mov dword ptr [ebp-4], SKILL_DAGGER ; skill for sound purposes
        ret
      }
}

// Avoid throwing two knives with Master Bow.
static void __declspec(naked) no_knife_double_shot(void)
{
    asm
      {
        xor ecx, ecx
        cmp eax, SPL_ARROW - 1
        cmove cx, word ptr [esi+SKILL_BOW*2].s_player.skills ; replaced movzx
        ret
      }
}

// Like thrown potions, throwing knife velocity depends on Might.
// TODO: the multiplier could be tweaked later
static void __declspec(naked) knife_velocity(void)
{
    asm
      {
        movzx eax, word ptr [eax+ecx+48] ; replaced code
        cmp word ptr [ebx], SPL_KNIFE
        jne arrow
        push eax
        push edx
        mov ecx, dword ptr [ebp-32]
        call dword ptr ds:get_might
        push eax
        call dword ptr ds:get_effective_stat
        imul eax, 150
        pop edx
        pop ecx
        add eax, ecx
        arrow:
        ret
      }
}

// The +0 and +3 knives start with 50-100 and 40-80 max charges
// respectively; like wands, +0 knives will be pre-used.
// For the +3 knives we instead set knife regeneration time.
// Called from evt_add_specitem(), pickpocket_specitem()
// and random_scroll_power() above, plus from just below.
static void __declspec(naked) init_knife_charges(void)
{
    asm
      {
        mov eax, dword ptr [esi] ; replaced code
        mov ebx, 51
        cmp eax, THROWING_KNIVES
        je charges
        mov ebx, 41
        cmp eax, LIVING_WOOD_KNIVES
        jne quit
        mov eax, dword ptr [CURRENT_TIME_ADDR]
        mov dword ptr [esi].s_item.temp_ench_time, eax
        mov eax, dword ptr [CURRENT_TIME_ADDR+4]
        mov dword ptr [esi+4].s_item.temp_ench_time, eax
        charges:
        call dword ptr ds:random
        xor edx, edx
        div ebx
        add ebx, edx
        dec ebx
        mov byte ptr [esi].s_item.max_charges, bl
        mov dword ptr [esi].s_item.charges, ebx
        cmp dword ptr [esi], LIVING_WOOD_KNIVES
        je full
        shr ebx, 1
        call dword ptr ds:random
        xor edx, edx
        div ebx
        sub dword ptr [esi].s_item.charges, edx
        full:
        mov eax, dword ptr [esi] ; restore
        quit:
        lea eax, [eax+eax*2] ; replaced code
        ret
      }
}

// Call the above code from some other item-generating function.
static void __declspec(naked) also_init_knife_charges(void)
{
    asm
      {
        mov esi, eax
        call init_knife_charges
        mov eax, esi ; restore
        mov ebx, DRAW_IMAGE_THIS_ADDR ; ditto
        mov ecx, PARTY_BIN_ADDR ; replaced code
        ret
      }
}

// Ditto, for the corpse-looting code.
static void __declspec(naked) init_looted_knife_charges(void)
{
    asm
      {
        push ebx
        mov esi, eax
        call init_knife_charges
        mov eax, esi ; restore
        pop ebx ; ditto
        mov esi, PARTY_BIN_ADDR ; replaced code
        ret
      }
}

// Spend one charge when throwing a knife; do not fire at 0 charges.
static void __declspec(naked) use_knife_charge(void)
{
    asm
      {
        lea ecx, [esi+eax*4-SIZE_ITEM].s_player.items ; missile weapon
        test byte ptr [ecx].s_item.flags, IFLAGS_BROKEN ; replaced code, almost
        jnz quit
        cmp dword ptr [ecx], THROWING_KNIVES
        je knives
        cmp dword ptr [ecx], LIVING_WOOD_KNIVES
        jne skip
        call regen_living_knives ; update charges
        knives:
        cmp dword ptr [ecx].s_item.charges, 0
        jz fail
        dec dword ptr [ecx].s_item.charges
        skip:
        xor eax, eax ; set zf
        ret
        fail:
        test esi, esi ; clear zf
        quit:
        ret
      }
}

// Repair (some) knives on a Ctrl-click.  Called from autobrew() above.
static void __thiscall repair_knives(struct player *player, struct item *knife)
{
    int spent = knife->max_charges - knife->charges;
    if (!spent)
        return;
    int skill = get_skill(player, SKILL_REPAIR);
    int percent = skill & SKILL_MASK;
    // same % as recharge item, but with shifted mastery
    if (skill >= SKILL_GM)
        percent = 100;
    else if (skill >= SKILL_MASTER)
        percent += 80;
    else if (skill >= SKILL_EXPERT)
        percent += 70;
    else if (skill > 0)
        percent += 50;
    if (percent < 80 && have_npc_hired(NPC_SMITH))
        percent = 80;
    int repaired = spent * percent / 100;
    if (!repaired)
      {
        show_face_animation(player, ANIM_REPAIR_FAIL, 0);
        return;
      }
    if (percent >= 100)
        knife->charges = knife->max_charges;
    else
      {
        knife->charges += repaired;
        knife->max_charges = knife->charges;
      }
    show_face_animation(player, ANIM_REPAIR, 0);
}

// 5 minutes in game ticks, used as a division constant.
static const int five_minutes = 5 * MINUTE;

// Restore one +3 knife every 5 minutes if no temp enchant present.
// Called from use_knife_charge() and also regen_dragon_charges() above.
// TODO: this will cut charges to max if above -- is this ok?
static void __declspec(naked) regen_living_knives(void)
{
    asm
      {
        mov eax, dword ptr [CURRENT_TIME_ADDR]
        mov edx, dword ptr [CURRENT_TIME_ADDR+4]
        sub eax, dword ptr [ecx].s_item.temp_ench_time
        sbb edx, dword ptr [ecx+4].s_item.temp_ench_time
        jb quit
        div dword ptr [five_minutes]
        test eax, eax
        jz quit
        add dword ptr [ecx].s_item.charges, eax
        movzx eax, byte ptr [ecx].s_item.max_charges
        cmp dword ptr [ecx].s_item.charges, eax
        jbe ok
        mov dword ptr [ecx].s_item.charges, eax
        ok:
        mov eax, dword ptr [CURRENT_TIME_ADDR]
        sub eax, edx ; set timer to remainder
        mov edx, dword ptr [CURRENT_TIME_ADDR+4]
        sbb edx, 0
        mov dword ptr [ecx].s_item.temp_ench_time, eax
        mov dword ptr [ecx+4].s_item.temp_ench_time, edx
        quit:
        ret
      }
}

// Similar to wand recharge, weapon shops offer throwing knife repair.
static void __declspec(naked) knife_repair_dialog(void)
{
    asm
      {
        lea esi, [edi+eax*4-SIZE_ITEM].s_player.items ; replaced code
        test byte ptr [esi].s_item.flags, IFLAGS_BROKEN ; replaced code
        jnz quit ; broken status takes priority
        cmp dword ptr [esi], THROWING_KNIVES
        je knives
        cmp dword ptr [esi], LIVING_WOOD_KNIVES
        je knives
        skip:
        xor ebx, ebx ; set zf
        quit:
        ret
        knives:
        movzx eax, byte ptr [esi].s_item.max_charges
        sub eax, dword ptr [esi].s_item.charges
        jbe skip
        mov edx, dword ptr [DIALOG2]
        imul edx, dword ptr [edx+28], SIZE_EVENT2D
        fld dword ptr [0x5912d8+edx] ; store price multiplier
        fld1 ; 20% bonus
        fadd st(0), st(1)
        fmul dword ptr [shop_recharge_multiplier]
        push eax
        fimul dword ptr [esp]
        fisttp dword ptr [esp]
        pop ebx ; == restored charges
        cmp ebx, 0
        jbe cannot
        add ebx, dword ptr [esi].s_item.charges
        sub esp, 4
        fstp dword ptr [esp]
        mov ecx, esi
        call dword ptr ds:item_value
        push eax
        mov ecx, edi
        call dword ptr ds:repair_price
        push eax
        push ebx
        cannot:
        mov ecx, esi
        call dword ptr ds:item_name
        mov ecx, offset name_buffer
        push ecx ; for the second sprintf
        push eax
        push dword ptr [colors+CLR_ITEM*4]
        push COLOR_FORMAT_ADDR
        push ecx
        call dword ptr ds:sprintf
        add esp, 16
        cmp ebx, 0
        cmova eax, dword ptr [new_strings+STR_REPAIR_KNIVES*4]
        cmovbe eax, dword ptr [new_strings+STR_CANNOT_KNIVES*4]
        push eax
        mov eax, offset recharge_buffer
        push eax
        call dword ptr ds:sprintf
        add esp, 20
        cmp ebx, 0
        ja no_adjust
        sub esp, 8
        fstp st(0)
        no_adjust:
        mov eax, offset recharge_buffer
        xor ebx, ebx
        push 0x4b5453
        ret 4
      }
}

// Make knife price depend on charges.  Called from potion_price() above.
static void __declspec(naked) knife_price(void)
{
    asm
      {
        mov ecx, 150 ; +0 knives min + max
        cmp dword ptr [esi], LIVING_WOOD_KNIVES
        jne multiply
        mov ecx, 120 ; +3 knives min + max
        multiply:
        movzx eax, byte ptr [esi].s_item.max_charges
        add eax, dword ptr [esi].s_item.charges
        mul edi
        div ecx
        test eax, eax
        jz zero
        mov edi, eax
        xor eax, eax ; set zf
        ret
        zero:
        mov edi, 1 ; disallow 0 price just in case
        ret
      }
}

// Give a set of knives for starting with dagger skill.
static void __declspec(naked) start_with_knives(void)
{
    asm
      {
        push ebx
        push esi
        lea esi, [ebp-116]
        mov ecx, esi
        call dword ptr ds:init_item
        mov dword ptr [esi], THROWING_KNIVES
        call init_knife_charges
        mov eax, esi
        pop esi ; restore
        pop ebx
        push eax
        push edi ; == -1
        mov ecx, esi
        call dword ptr ds:put_item_in_backpack
        mov eax, 0x497753 ; old pointer here
        jmp eax ; (will also give a dagger)
      }
}

// Implement a dagger-skill alternative to bows.
static inline void throwing_knives(void)
{
    // knives drawn under belt in postpone_drawing_blaster() above
    hook_call(0x43d07b, equipped_knife_sprite, 6);
    hook_call(0x48fcd6, knife_skill_accuracy, 8);
    hook_call(0x48d138, knife_displayed_damage, 10); // min damage
    hook_call(0x48d1a5, knife_displayed_damage, 10); // max damage
    // actual damage is in check_missile_skill_2() above
    hook_call(0x42ef0b, knife_spell, 5);
    hook_call(0x42f017, knife_spell, 5);
    hook_call(0x42eecf, knife_sound, 7);
    hook_call(0x4280de, no_knife_double_shot, 7);
    dword(SPELL_OBJ_IDS + SPL_KNIFE * 4 - 4) = OBJ_KNIFE; // projectile id
    hook_call(0x428264, knife_velocity, 5);
    // knives treated as arrows in explode_potions_jump() above
    hook_jump(0x4396aa, (void *) 0x439652); // treat knives as arrows when hit
    // knife count in temp_enchant_height() and display_temp_enchant() above
    hook_call(0x415cce, also_init_knife_charges, 5);
    hook_call(0x426b72, init_looted_knife_charges, 5);
    // full charge in shops in charge_shop_wands_common() above
    hook_call(0x42ecf9, use_knife_charge, 8);
    hook_call(0x4b954b, knife_repair_dialog, 11);
    // actually repaired in prepare_shop_recharge() and perform_shop_recharge()
    patch_pointer(0x4978e5, start_with_knives);
}

// Draw the right options difficulty button in the settings screen.
static void __declspec(naked) get_difficulty_button(void)
{
    asm
      {
        mov ecx, dword ptr [elemdata.difficulty]
        neg ecx
        add ecx, 2
        shl ecx, 6
        ret
      }
}

// On pressing a button, update the difficulty (unless in combat).
static void __declspec(naked) change_difficulty(void)
{
    asm
      {
        test byte ptr [STATE_BITS], 0x30 ; if enemies are near
        jnz forbid
        shr ecx, 6
        neg ecx
        add ecx, 2
        mov dword ptr [elemdata.difficulty], ecx
        ret
        forbid:
        push ebx
        push ebx
        push ebx
        push ebx
        push -1
        push ebx
        push ebx
        push SOUND_BUZZ
        mov ecx, SOUND_THIS_ADDR
        call dword ptr ds:make_sound
        mov ecx, dword ptr [GLOBAL_TXT_ADDR+638*4] ; "hostiles nearby"
        mov edx, 2
        call dword ptr ds:show_status_text
        ret
      }
}

// Adjust monster recovery based on difficulty.
static void __declspec(naked) difficult_monster_recovery(void)
{
    asm
      {
        mov eax, dword ptr [MONSTERS_TXT+eax-44].s_map_monster.recovery ; repl.
        cmp dword ptr [elemdata.difficulty], ebx
        jz skip
        mov ecx, eax
        shr ecx, 1
        cmp dword ptr [elemdata.difficulty], 2
        jae lower
        shr ecx, 1
        lower:
        sub eax, ecx
        skip:
        ret
      }
}

// Ditto, but using different registers.
static void __declspec(naked) difficult_monster_recovery_esi(void)
{
    asm
      {
        mov esi, dword ptr [MONSTERS_TXT+esi-44].s_map_monster.recovery ; repl.
        cmp dword ptr [elemdata.difficulty], ecx
        jz skip
        mov ebx, esi
        shr ebx, 1
        cmp dword ptr [elemdata.difficulty], 2
        jae lower
        shr ebx, 1
        lower:
        sub esi, ebx
        skip:
        ret
      }
}

// Same, but in a different place.
static void __declspec(naked) difficult_monster_recovery_after(void)
{
    asm
      {
        cmp dword ptr [elemdata.difficulty], esi
        jz skip
        shr eax, 1
        cmp dword ptr [elemdata.difficulty], 2
        jae lower
        shr eax, 1
        lower:
        sub dword ptr [ebp+8], eax
        skip:
        cmp dword ptr [TURN_BASED], 1 ; replaced code
        ret
      }
}

// Amount of XP to get the first point of reputation via bard NPC bonus.
// After that it rises triangularly.  The numbers are chosen such that
// clearing the entire region will grant roughly 10 reputation in total.
static const int bard_rep_cost[12] = {    -1,  300,  1000, 2000, 2000, 6000,
                                       10000, 1000, 15000, 4000, 3500, 7000, };

// Add bonus experience for killing monsters on higher difficulties.
// Also here: handle bard NPC reputation bonus (unaffected by difficulty).
// TODO: the code will grant at most 1 rep per monster -- is this ok?
static void __declspec(naked) difficult_monster_experience(void)
{
    asm
      {
        mov ebx, eax
        add ecx, NPC_BARD
        call dword ptr ds:have_npc_hired
        test eax, eax
        jz no_bard
        mov ecx, dword ptr [reputation_index]
        mov ecx, dword ptr [reputation_group+ecx*4]
        test ecx, ecx
        jz no_bard
        mov eax, dword ptr [elemdata.bard_bonus+ecx*4]
        add dword ptr [elemdata.bard_xp+ecx*4], ebx
        inc eax
        mul dword ptr [bard_rep_cost+ecx*4]
        cmp eax, dword ptr [elemdata.bard_xp+ecx*4]
        ja no_bard
        sub dword ptr [elemdata.bard_xp+ecx*4], eax
        inc dword ptr [elemdata.bard_bonus+ecx*4]
        cmp dword ptr [OUTDOORS], 2
        je outdoors
        dec dword ptr [0x6be514] ; indoor rep
        jmp no_bard
        outdoors:
        dec dword ptr [0x6a1140] ; outdoor rep
        no_bard:
        mov eax, ebx
        xor ecx, ecx ; restore
        cmp dword ptr [elemdata.difficulty], ecx
        jz skip
        shr ebx, 1
        cmp dword ptr [elemdata.difficulty], 2
        jae raise
        shr ebx, 1
        raise:
        add eax, ebx
        skip:
        mov edx, PARTY_ADDR + 112 ; replaced code
        ret
      }
}

// Reduce gold earned on higher difficulties.
static void __declspec(naked) difficult_gold_gain(void)
{
    asm
      {
        xor edi, edi ; replaced code
        xor ebp, ebp ; ditto
        cmp dword ptr [elemdata.difficulty], edi
        jz skip
        mov eax, ecx
        shr eax, 1
        cmp dword ptr [elemdata.difficulty], 2
        jae lower
        shr eax, 1
        lower:
        sub ecx, eax
        skip:
        mov eax, edx ; replaced code
        ret
      }
}

// Also reduce the profit from selling items.
static void __declspec(naked) difficult_barter(void)
{
    asm
      {
        cmp esi, eax ; replaced code
        jl skip ; replaced jump
        mov eax, esi ; replaced code
        cmp dword ptr [elemdata.difficulty], 0
        jz skip
        shr esi, 1
        cmp dword ptr [elemdata.difficulty], 2
        jae lower
        shr esi, 1
        lower:
        sub eax, esi
        skip:
        ret
      }
}

// Used for shop orders (verify_item() etc.) way below.
static struct item order_gold;

// Visually reduce the value of gold piles on higher difficulties.
static void __declspec(naked) difficult_gold_pile(void)
{
    asm
      {
        mov eax, dword ptr [ecx].s_item.bonus2 ; replaced code
        cmp ecx, offset order_gold ; this is not a real item
        je skip
        cmp dword ptr [elemdata.difficulty], ebx
        jz skip
        shr eax, 1
        cmp dword ptr [elemdata.difficulty], 2
        jae lower
        shr eax, 1
        lower:
        neg eax
        add eax, dword ptr [ecx].s_item.bonus2
        skip:
        mov dword ptr [ebp-120], eax ; replaced code
        ret
      }
}

// Also reduce bank gold quest rewards.
static void __declspec(naked) difficult_bank_gold(void)
{
    asm
      {
        add dword ptr [BANK_GOLD], eax ; replaced code
        cmp dword ptr [elemdata.difficulty], 0
        jz skip
        shr eax, 1
        cmp dword ptr [elemdata.difficulty], 2
        jae lower
        shr eax, 1
        lower:
        sub dword ptr [BANK_GOLD], eax
        skip:
        ret
      }
}

// Fix the statusline message for looting gold and an item.
static void __declspec(naked) difficult_looted_gold(void)
{
    asm
      {
        cmp dword ptr [elemdata.difficulty], 0
        jz skip
        mov eax, dword ptr [esp+12] ; gold value for display
        shr eax, 1
        cmp dword ptr [elemdata.difficulty], 2
        jae lower
        shr eax, 1
        lower:
        sub dword ptr [esp+12], eax
        skip:
        jmp dword ptr ds:sprintf ; replaced call
      }
}

// I need to exempt box traders from difficulty gold penalties,
// as the profit margin is their entire point, so I'll use
// evt.Sub("Gold", -sell_price) for them, and make it give irreducible gold.
// Update: no box traders anymore, but this is still used elsewhere.
static void __declspec(naked) subtract_negative_gold(void)
{
    asm
      {
        cmp ecx, 0
        jl give
        cmp ecx, dword ptr [PARTY_GOLD] ; replaced code
        ret
        give:
        neg ecx
        add ecx, dword ptr [PARTY_GOLD]
        add dword ptr [esp], 12 ; skip over old code
        jmp dword ptr ds:set_gold
      }
}

// Allow monsters to attack again before finishing the current animation.
// Important for when monster recovery is lowered below the anim speed.
static void __declspec(naked) faster_monster_swing(void)
{
    asm
      {
        cmp dword ptr [ebx].s_map_monster.action_time, eax ; replaced code
        jge quit ; if finished already
        xor eax, eax
        inc eax
        cmp dword ptr [ebx].s_map_monster.recovery, eax
        jge skip
        mov cx, word ptr [ebx].s_map_monster.ai_state
        shl eax, cl
        test eax, 0x4300c ; attack states
        jnz quit
        skip:
        neg eax ; set flags
        quit:
        ret
      }
}

// Also increase displayed SP cost in a spellbook (actual cost is elsewhere).
static void __declspec(naked) difficult_spell_cost(void)
{
    asm
      {
        ; replaced code next line:
        movzx eax, word ptr [SPELL_INFO_ADDR+eax*2+SIZE_SPL_INFO+S_SI_COST]
        cmp dword ptr [elemdata.difficulty], ebx ; == 0
        jz easy
        mov edx, eax
        shr edx, 1
        cmp dword ptr [elemdata.difficulty], 2
        jae costly
        shr edx, 1
        costly:
        add eax, edx
        easy:
        ret
      }
}

// Break some chest items when triggering a trap on Medium/Hard difficulty.
static void __thiscall break_chest(struct map_chest *chest)
{
    if (!elemdata.difficulty) return; // not on easy
    for (int i = 0; i < CHEST_MAX_ITEMS; i++)
      {
        struct item *item = &chest->items[i];
        if ((signed) item->id <= 0 || item->id > LAST_PREFIX
            || item->id >= FIRST_WAND && item->id <= LAST_WAND)
            continue;
        if (random() % 4 < elemdata.difficulty)
            item->flags |= IFLAGS_BROKEN;
      }
}

// Hook for the above.
static void __declspec(naked) break_chest_hook(void)
{
    asm
      {
        mov ecx, dword ptr [ebp-44] ; chest bits address
        sub ecx, 2 ; point to struct start
        call break_chest
        lea ecx, [ebp-176] ; replaced code
        ret
      }
}

// Add nasty effects to chest traps on higher difficulties.
static int __thiscall chest_damage(struct player *player, int damage,
                                   int element)
{
    if (elemdata.difficulty) switch (element)
      {
        case FIRE:
        case COLD:
            for (int i = random() % (elemdata.difficulty + 1); i > 0; i--)
              {
                int count = 0, slot;
                for (int j = 0; j < 14*9; j++)
                  {
                    int num = player->inventory[j];
                    if (num > 0)
                      {
                        int type = ITEMS_TXT[player->items[num-1].id]
                                   .equip_stat + 1;
                        if (element == FIRE ? type == ITEM_TYPE_SCROLL
                                              || type == ITEM_TYPE_BOOK
                                            : type == ITEM_TYPE_REAGENT
                                              || type == ITEM_TYPE_POTION)
                            if (random() % ++count == 0)
                                slot = j;
                      }
                  }
                if (!count) break;
                delete_backpack_item(player, slot);
                show_face_animation(player, ANIM_DISMAY, 0);
                spell_face_anim(SPELL_ANIM_THIS, SPAN_DEBUFF, player - PARTY);
              }
            break;
        case SHOCK:
            if (!is_immune(player, SHOCK)
                && random() % 8 < elemdata.difficulty)
                inflict_condition(player, COND_PARALYZED, TRUE);
            break;
        case POISON:
            if (random() % 4 < elemdata.difficulty)
                inflict_condition(player,
                                  COND_POISONED_GREEN + random() % 3 * 2,
                                  TRUE);
            break;
      }
    return damage_player(player, damage, element);
}

// Use a semi-fixed random seed to restrict mob loot to just several
// options on higher difficulties.  Overwrites a randomize_item() call.
static void __declspec(naked) fixed_corpse_loot(void)
{
    asm
      {
        xor eax, eax
        cmp dword ptr [elemdata.difficulty], 1
        jae ok
        jmp dword ptr ds:randomize_item
        ok:
        sete al
        lea esi, [eax*8+7]
        shl esi, 3
        call dword ptr ds:random
        and esi, eax
        add esi, ebx ; monster pointer
        sub esi, MAP_MONSTERS_ADDR ; just the offset
        mov ecx, dword ptr [CURRENT_MAP_ID]
        add esi, dword ptr [elemdata.monster_loot_seed+ecx*4-4]
        call dword ptr ds:get_thread_context
        push esi
        mov esi, dword ptr [eax+20] ; random seed
        call dword ptr ds:srandom
        pop ecx
        push dword ptr [esp+12]
        push dword ptr [esp+12]
        push dword ptr [esp+12]
        mov ecx, ITEMS_TXT_ADDR - 4
        call dword ptr ds:randomize_item
        push esi
        call dword ptr ds:srandom ; restore
        pop ecx
        ret 12
      }
}

// Allow some monsters to ignore Invisibility on Medium/Hard.
static void __declspec(naked) see_through_invisibility(void)
{
    asm
      {
        cmp dword ptr [elemdata.difficulty], ebx ; == 0
        jz ok
        cmp byte ptr [esi].s_map_monster.magic_resistance, IMMUNE
        jb ok
        cmp ebx, esi ; set less
        ret
        ok:
        ; replaced code below:
        cmp dword ptr [PARTY_BUFF_ADDR+BUFF_INVISIBILITY*SIZE_BUFF+4], ebx
        ret
      }
}

// Used just below.
static char invis_buffer[500];

// Shared code used by the two below hooks.
static void __declspec(naked) invisibility_description_shared(void)
{
    asm
      {
        jne skip
        mov eax, dword ptr [elemdata.difficulty]
        push dword ptr [new_strings+STR_INVISIBILITY_EASY*4+eax*4]
        push dword ptr [esp+16] ; pushed description
#ifdef __clang__
        mov eax, offset invis_buffer
        push eax
#else
        push offset invis_buffer
#endif
        call dword ptr ds:sprintf
        add esp, 12
        mov dword ptr [esp+12], offset invis_buffer
        skip:
        jmp dword ptr ds:sprintf ; replaced call
      }
}

// Adjust Invisibility guild description according to its current function.
static void __declspec(naked) invisibility_description_guild(void)
{
    asm
      {
        cmp esi, SPL_INVISIBILITY
        jmp invisibility_description_shared
      }
}

// Same, but for PC spellbooks.
static void __declspec(naked) invisibility_description_spellbook(void)
{
    asm
      {
        cmp byte ptr [edi].s_player.spellbook_page, 1 ; air
        jne skip
        cmp dword ptr [ebp-20], 7 ; invis
        skip:
        jmp invisibility_description_shared
      }
}

// The distance from monster at which Invisibility is removed (on Hard).
#define INVISIBILITY_DISTANCE 700

// On Hard, dispel Invisibility when party is too close to a monster.
static void __declspec(naked) invisibility_hitbox_check(void)
{
    asm
      {
        cmp dword ptr [MONSTER_COUNT], 0 ; replaced code
        jle quit
        cmp dword ptr [elemdata.difficulty], 2
        jne skip
        cmp dword ptr [PARTY_BUFF_ADDR+BUFF_INVISIBILITY*SIZE_BUFF], 0
        jnz invis
        cmp dword ptr [PARTY_BUFF_ADDR+BUFF_INVISIBILITY*SIZE_BUFF+4], 0
        jz skip
        invis:
        sub dword ptr [CURRENT_HITBOX+156], INVISIBILITY_DISTANCE ; lower bound
        add dword ptr [CURRENT_HITBOX+160], INVISIBILITY_DISTANCE ; upper bound
        push dword ptr [CURRENT_HITBOX+120] ; preserve entity
        push dword ptr [CURRENT_HITBOX+124] ; preserve distance
        push dword ptr [MONSTER_COUNT]
        loop:
        dec dword ptr [esp]
        jl restore
        mov ecx, dword ptr [esp]
        mov edx, INVISIBILITY_DISTANCE
        call dword ptr ds:check_monster_in_hitbox
        test eax, eax
        jz loop
        mov ecx, PARTY_BUFF_ADDR + BUFF_INVISIBILITY * SIZE_BUFF
        call dword ptr ds:remove_buff
        mov dword ptr [REFRESH_SCREEN], 1
        restore:
        pop eax
        pop dword ptr [CURRENT_HITBOX+124]
        pop dword ptr [CURRENT_HITBOX+120]
        add dword ptr [CURRENT_HITBOX+156], INVISIBILITY_DISTANCE
        sub dword ptr [CURRENT_HITBOX+160], INVISIBILITY_DISTANCE
        skip:
        xor eax, eax
        inc eax ; set greater
        quit:
        ret
      }
}

// Note the party's current speed vector.
static void __declspec(naked) remember_movement_speed(void)
{
    asm
      {
        mov ecx, CURRENT_HITBOX ; replaced code
        mov edx, dword ptr [ecx+28]
        mov dword ptr [party_speed.x], edx
        mov edx, dword ptr [ecx+32]
        mov dword ptr [party_speed.y], edx
        mov edx, dword ptr [ecx+36]
        mov dword ptr [party_speed.z], edx
        cmp dword ptr [esp], 0x473897 ; outdoor code
        jb skip
        mov eax, dword ptr [ebp-72] ; new z
        sub eax, dword ptr [0xacd528] ; (old) stable z
        cdq
        shld edx, eax, 7
        shl eax, 7
        cmp dword ptr [0x50ba7c], 1 ; just in case
        jle small
        idiv dword ptr [0x50ba7c] ; ticks since last frame
        small:
        add dword ptr [party_speed.z], eax
        skip:
        ret
      }
}

// Improve monster accuracy by aiming at where party is moving towards.
// Called just below and also in cast_new_spells() above.
static void adjust_aim(int attacker, int speed, int *buffer)
{
    int old_x = dword(PARTY_X);
    int old_y = dword(PARTY_Y);
    int old_z = dword(PARTY_Z);
    struct map_monster *monster = MAP_MONSTERS + attacker;
    int dx = old_x - monster->x;
    int dy = old_y - monster->y;
    int dz = old_z - monster->z - monster->height * 3 / 4;
    double time = sqrt(dx * dx + dy * dy + dz * dz) / speed;
    dword(PARTY_X) = old_x + time * party_speed.x;
    dword(PARTY_Y) = old_y + time * party_speed.y;
    dword(PARTY_Z) = old_z + time * party_speed.z;
    aim_at_target(attacker * 8 + TGT_MONSTER, TGT_PARTY, buffer, FALSE);
    dword(PARTY_X) = old_x;
    dword(PARTY_Y) = old_y;
    dword(PARTY_Z) = old_z;
}

// Adjust monster aim when shooting non-spell projectiles.
static void __fastcall shoot_adjust_aim(int monster_id, void *vector,
                                        int missile, int attack)
{
    if (MON_TARGETS[monster_id] == TGT_PARTY && elemdata.difficulty)
      {
        // TODO: unhardcode this
        int speed = 4000; // most monster missiles
        if (missile == 4 || missile == 13) // air or ener/laser
            speed = 6000; // a bit faster
        adjust_aim(monster_id, speed, vector);
      }
    monster_shoots(monster_id, vector, missile, attack);
}

// Also increase party hitbox WRT projectiles on Hard.
static void __declspec(naked) shoot_adjust_hitbox(void)
{
    asm
      {
        mov eax, 0x46ef05 ; replaced call
        cmp dword ptr [elemdata.difficulty], 2
        je hard
        jmp eax
        hard:
        shl dword ptr [0xacce4c], 1 ; party radius
        call eax
        shr dword ptr [0xacce4c], 1 ; restore
        ret
      }
}

// Fix turn rate at smooth to prevent trouble from bad registry settings.
static void __declspec(naked) smooth_turn_chunk(void)
{
    asm
      {
        mov eax, 3
      }
}

// Allow optionally increasing game difficulty.
static inline void difficulty_level(void)
{
    hook_call(0x414fe1, get_difficulty_button, 6);
    hook_call(0x431d9f, change_difficulty, 5);
    erase_code(0x431da4, 21); // rest of the old button-press code
    patch_bytes(0x465ba3, smooth_turn_chunk, 5);
    hook_call(0x4064b5, difficult_monster_recovery, 6);
    hook_call(0x40657e, difficult_monster_recovery_esi, 6);
    hook_call(0x40363a, difficult_monster_recovery_after, 7);
    hook_call(0x403811, difficult_monster_recovery_after, 7);
    hook_call(0x4039da, difficult_monster_recovery_after, 7);
    hook_call(0x403be6, difficult_monster_recovery_after, 7);
    hook_call(0x403e1e, difficult_monster_recovery_after, 7);
    // damage lowered in cursed_monster_resists_damage() above
    // also a chance to resist instadeath in resp. code
    hook_call(0x42695b, difficult_monster_experience, 5);
    hook_call(0x420bb2, difficult_gold_gain, 6);
    hook_call(0x4b809a, difficult_barter, 6);
    hook_call(0x41d964, difficult_gold_pile, 6);
    hook_call(0x44b854, difficult_bank_gold, 6);
    hook_call(0x426ad7, difficult_looted_gold, 5);
    hook_call(0x44bbf6, subtract_negative_gold, 6);
    // skill penalty in level_skill_bonus() above
    patch_pointer(0x417d78, "%s: %+d"); // display penalty correctly
    hook_call(0x4020ef, faster_monster_swing, 6);
    // spell cost increase is in switch_off_spells_for_free() above
    // and another cost check in free_quick_lightning() above
    hook_call(0x410d5c, difficult_spell_cost, 8);
    hook_call(0x420867, break_chest_hook, 6);
    hook_call(0x438f69, chest_damage, 5);
    hook_call(0x426c36, fixed_corpse_loot, 5);
    hook_call(0x4013c8, see_through_invisibility, 6);
    hook_call(0x4b15cb, invisibility_description_guild, 5);
    hook_call(0x410c63, invisibility_description_spellbook, 5);
    hook_call(0x473182, invisibility_hitbox_check, 7); // indoors
    hook_call(0x4745fd, invisibility_hitbox_check, 6); // outdoors
    hook_call(0x47315c, remember_movement_speed, 5); // indoors
    hook_call(0x4745b4, remember_movement_speed, 5); // outdoors
    hook_call(0x402159, shoot_adjust_aim, 5); // realtime
    hook_call(0x4067ab, shoot_adjust_aim, 5); // turn-based
    hook_call(0x4716b9, shoot_adjust_hitbox, 5); // indoors
    hook_call(0x471ea2, shoot_adjust_hitbox, 5); // outdoors
}

// Holds an unused travel reply that can be replaced with ours.
static void *empty_reply;
static int empty_reply_index;

// Reset the above variable before cycling through replies.
static void __declspec(naked) reset_empty_reply(void)
{
    asm
      {
        and dword ptr [empty_reply], 0
        lea eax, [ebp-636] ; replaced code
        ret
      }
}

// Whenever a reply is skipped, note it down.
static void __declspec(naked) remember_empty_reply(void)
{
    asm
      {
        mov dword ptr [empty_reply], ebx
        mov edx, dword ptr [ebp-8] ; reply index + 1
        dec edx
        mov dword ptr [empty_reply_index], edx
        mov dword ptr [ebx+20], eax ; replaced code
        mov dword ptr [ebx+12], eax ; ditto
        ret
      }
}

// Used to hold the buy horse reply w/o formatting.
static char horse_buffer[100];
// Used below.
static const int horses_cost[9] = { 1000, 2000, 3000, 3000, 4000, 4000, 5000 };

// Replace the empty reply with ours, for buying a horse, if applicable.
static void __declspec(naked) add_horse_reply(void)
{
    asm
      {
        cmp dword ptr [empty_reply], 0
        jz skip
        mov ecx, QBITS_ADDR
        mov edx, QBIT_CAVALIER_HORSE
        call dword ptr ds:check_bit
        test eax, eax
        jz skip
        mov ecx, dword ptr [DIALOG2]
        mov eax, dword ptr [ecx+28] ; house id
        cmp eax, 63 ; first boat
        jae skip
        sub eax, 54 ; first stables
        jb skip ; just in case
        push dword ptr [horses_cost+eax*4]
        push dword ptr [new_strings+STR_BUY_HORSE*4]
#ifdef __clang__
        mov eax, offset horse_buffer
        push eax
#else
        push offset horse_buffer
#endif
        call dword ptr ds:sprintf
        mov ecx, dword ptr [DIALOG1]
        mov eax, dword ptr [empty_reply_index]
        cmp eax, dword ptr [ecx+44]
        cmove eax, dword ptr [colors+CLR_ITEM*4]
        cmovne eax, dword ptr [colors+CLR_WHITE*4]
        push eax
        push 0x4e2da8 ; color format string
        push dword ptr [ebp-12] ; reply buffer
        call dword ptr ds:sprintf
#ifdef __clang__
        mov eax, offset horse_buffer
        push eax
#else
        push offset horse_buffer
#endif
        push dword ptr [ebp-12]
        call dword ptr ds:strcat_ptr
        add esp, 32
        push 0
        push 0
        lea eax, [ebp-136]
        push eax
        mov edx, offset horse_buffer
        mov ecx, dword ptr [ARRUS_FNT]
        call dword ptr ds:get_text_height
        mov ecx, dword ptr [empty_reply]
        mov edx, dword ptr [ebp-16]
        mov dword ptr [ecx+12], eax
        mov dword ptr [ecx+4], edx
        add edx, eax
        dec edx
        mov dword ptr [ecx+36], 109 ; hitherto unused
        mov dword ptr [ecx+20], edx
        add eax, dword ptr [ebp-52]
        add dword ptr [ebp-16], eax
        ret ; zf is unset, so we skip the no routes message
        skip:
        mov eax, dword ptr [ebp-48] ; replaced code
        cmp dword ptr [ebp-16], eax ; this too
        ret
      }
}

// Actually buy the horse if clicked on the reply.
static void __declspec(naked) horse_buy_action(void)
{
    asm
      {
        jle skip
        cmp eax, 109 ; our reply (last one)
        je horse
        ret ; flags are set
        skip:
        cmp esi, ebx ; set flags
        ret
        horse:
        mov ecx, dword ptr [DIALOG2]
        mov edi, dword ptr [ecx+28] ; house id
        mov ecx, dword ptr [horses_cost+edi*4-54*4]
        cmp ecx, dword ptr [PARTY_GOLD]
        jbe buy
        mov dword ptr [esp], 0x4b6a32 ; not enough gold branch
        ret
        buy:
        call dword ptr ds:spend_gold
        imul edi, edi, 76
        or byte ptr [NPC_ADDR+edi-54*SIZE_NPC+HORSE_HARMONDALE*SIZE_NPC] \
                    .s_npc.bits, NPC_HIRED
        inc byte ptr [0xacd542] ; quest hireling count
        call set_walking_speed
        push QBIT_CAVALIER_HORSE
        push EVT_QBITS
        mov ecx, esi
        call dword ptr ds:evt_sub
        mov dword ptr [esp], 0x4b6a50 ; quit subdialog branch
        ret
      }
}

// Show a description of the horse NPC on a right-click.
static void __declspec(naked) horse_rmb(void)
{
    asm
      {
        mov eax, dword ptr [ebp-12] ; NPC id
        cmp eax, 57 ; dragon familiar (replaced)
        je quit
        cmp eax, HORSE_HARMONDALE ; first horse
        jb skip
        cmp eax, HORSE_AVLEE ; last horse
        ja skip
        mov eax, dword ptr [new_npc_text+57*4+eax*4-HORSE_HARMONDALE*4]
        add dword ptr [esp], 6 ; skip dragon code
        quit:
        ret
        skip:
        add dword ptr [esp], 8 ; to hireling code
        ret
      }
}

// Open bags or cast Fly when talking with the horse.
static void __declspec(naked) horse_topics(void)
{
    asm
      {
        cmp ecx, 605 ; first new topic
        jge horse
        skip:
        cmp ecx, 200 ; replaced code
        ret
        horse:
        cmp ecx, 608
        jg skip
        mov esi, ecx
        push 0
        push 0
        push ACTION_EXIT
        mov ecx, ACTION_THIS_ADDR
        call dword ptr ds:add_action
        cmp esi, 607
        jg fly
        push 1
        je right
        push 5
        jmp open
        right:
        push 6
        open:
        push ACTION_EXTRA_CHEST
        mov ecx, ACTION_THIS_ADDR
        call dword ptr ds:add_action
        jmp quit
        fly:
        mov ecx, NPC_WIND_MASTER
        call dword ptr ds:hireling_action
        push 1
        mov edx, QBIT_USED_PEGASUS
        mov ecx, QBITS_ADDR
        call dword ptr ds:change_bit
        quit:
        mov dword ptr [NPC_COMMAND], 78 ; fix null pointer reply
        mov dword ptr [esp], 0x4bc81e ; after action code
        ret
      }
}

// Reset pegasus flight at the beginning of a new day (3 AM).
static void __declspec(naked) reset_pegasus_wait(void)
{
    asm
      {
        push edx ; == 0
        mov edx, QBIT_USED_PEGASUS
        mov ecx, QBITS_ADDR
        call dword ptr ds:change_bit
        inc byte ptr [0xacd59c] ; replaced code
        ret
      }
}

// Also reset it after a timeskip (travel, train etc.)
static void __declspec(naked) reset_pegasus_timeskip(void)
{
    asm
      {
        adc dword ptr [CURRENT_TIME_ADDR+4], edx ; replaced code
        push 0
        mov edx, QBIT_USED_PEGASUS
        mov ecx, QBITS_ADDR
        call dword ptr ds:change_bit
        ret
      }
}

// Some horses also decrease foot travel time.
static void __declspec(naked) horse_foot_travel(void)
{
    asm
      {
        mov esi, dword ptr [0x6bcefc] ; replaced code
        dec esi
        test byte ptr [NPC_ADDR+HORSE_TULAREAN*SIZE_NPC].s_npc.bits, NPC_HIRED
        jnz reduce
        test byte ptr [NPC_ADDR+HORSE_BRACADA*SIZE_NPC].s_npc.bits, NPC_HIRED
        jnz reduce
        inc esi
        test byte ptr [NPC_ADDR+HORSE_ERATHIA*SIZE_NPC].s_npc.bits, NPC_HIRED
        jnz reduce
        test byte ptr [NPC_ADDR+HORSE_TATALIA*SIZE_NPC].s_npc.bits, NPC_HIRED
        jnz reduce
        test byte ptr [NPC_ADDR+HORSE_AVLEE*SIZE_NPC].s_npc.bits, NPC_HIRED
        jz skip
        reduce:
        dec esi
        dec esi
        skip:
        ret
      }
}

// Same for travelling via stables.
static void __declspec(naked) horse_stable_travel(void)
{
    asm
      {
        dec esi
        test byte ptr [NPC_ADDR+HORSE_TULAREAN*SIZE_NPC].s_npc.bits, NPC_HIRED
        jnz reduce
        inc esi
        test byte ptr [NPC_ADDR+HORSE_ERATHIA*SIZE_NPC].s_npc.bits, NPC_HIRED
        jnz reduce
        test byte ptr [NPC_ADDR+HORSE_TATALIA*SIZE_NPC].s_npc.bits, NPC_HIRED
        jnz reduce
        test byte ptr [NPC_ADDR+HORSE_AVLEE*SIZE_NPC].s_npc.bits, NPC_HIRED
        jz skip
        reduce:
        dec esi
        dec esi
        skip:
        mov dword ptr [ebp-16], 71 ; replaced code
        ret
      }
}

// We also need to adjust the stable dialog.
static void __declspec(naked) horse_stable_dialog(void)
{
    asm
      {
        cmp dword ptr [eax+28], 63 ; replaced code
        jge quit
        test byte ptr [NPC_ADDR+HORSE_TULAREAN*SIZE_NPC].s_npc.bits, NPC_HIRED
        jz no_three
        sub dword ptr [ebp-4], 3
        jmp skip
        no_three:
        test byte ptr [NPC_ADDR+HORSE_ERATHIA*SIZE_NPC].s_npc.bits, NPC_HIRED
        jnz reduce
        test byte ptr [NPC_ADDR+HORSE_TATALIA*SIZE_NPC].s_npc.bits, NPC_HIRED
        jnz reduce
        test byte ptr [NPC_ADDR+HORSE_AVLEE*SIZE_NPC].s_npc.bits, NPC_HIRED
        jz skip
        reduce:
        sub dword ptr [ebp-4], 2
        skip:
        cmp esp, ebp ; set flags
        quit:
        ret 12 ; we replaced a stack fixup
      }
}

// Tatalia warhorse improves Armsmaster for all Knights.
// Also boost the regular Weapons Master hireling.
static void __declspec(naked) warhorse_armsmaster_bonus(void)
{
    asm
      {
        jz skip ; replaced jump
        add esi, 5 ; the new npc skill bonus
        skip:
        test byte ptr [NPC_ADDR+HORSE_TATALIA*SIZE_NPC].s_npc.bits, NPC_HIRED
        jz quit
        mov ecx, dword ptr [ebp-4] ; PC
        cmp byte ptr [ecx].s_player.class, CLASS_BLACK_KNIGHT
        ja quit
        add esi, 3
        quit:
        ret
      }
}

// Cavaliers may purchase a steed that can grant a number of benefits.
static inline void horses(void)
{
    hook_call(0x4b6cad, reset_empty_reply, 6);
    hook_call(0x4b6e81, remember_empty_reply, 6);
    hook_call(0x4b6e9f, add_horse_reply, 6);
    hook_call(0x4b6979, horse_buy_action, 9);
    hook_call(0x416b79, horse_rmb, 6);
    hook_call(0x4bc79e, horse_topics, 6);
    hook_call(0x494169, reset_pegasus_wait, 6);
    hook_call(0x4b1b80, reset_pegasus_timeskip, 6);
    hook_call(0x444da4, horse_foot_travel, 6);
    hook_call(0x4b6b08, horse_stable_travel, 7);
    hook_call(0x4b6d73, horse_stable_dialog, 7);
    // zombie horse fear is in cursed_weapon() above
    hook_call(0x48fae3, warhorse_armsmaster_bonus, 5);
    // unicorn magic immunity is in is_immune() above
}

// The new XP requirements for level training, now cubical!
static int __thiscall get_level_up_xp(int level)
{
    if (level <= 0)
        return 0; // just in case
    int xp = level * (level + 1) * 25;
    if (level >= 20)
        return xp * (level + 1); // cubical growth
    return xp * 20; // old formula
}

// Let the recovery bonuses stack multiplicatively.
// Also enforces the new recovery limit of 10.
// NB: this overwrites MM7Patch code for the BlasterRecovery option.
static void __declspec(naked) multiplicative_recovery(void)
{
    asm
      {
        mov dword ptr [ebp-12], eax ; swift bonus, stack var unused here
        mov dword ptr [ebp-20], ecx ; base recovery with all penalties
        mov dword ptr [ebp-4], 100 ; also unused
        fld1
        fild dword ptr [ebp-4]
        fild dword ptr [ebp-12]
        fdiv st(0), st(1)
        fsubr st(0), st(2)
        fild dword ptr [ebp-16] ; armsmaster bonus
        fdiv st(0), st(2)
        fsubr st(0), st(3)
        fmulp
        fild dword ptr [ebp-28] ; haste bonus
        fdiv st(0), st(2)
        fsubr st(0), st(3)
        fmulp
        fild dword ptr [ebp-32] ; weapon skill bonus (doubled)
        fld st(2)
        fadd st(0), st(0)
        fdivp
        fsubr st(0), st(3)
        fmulp
        fild dword ptr [ebp-36] ; speed bonus
        fdiv st(0), st(2)
        fsubp st(3), st(0)
        fmulp st(2), st(0)
        fstp st(0)
        fimul dword ptr [ebp-20]
        fisttp dword ptr [ebp-4]
        mov eax, dword ptr [ebp-4]
        cmp eax, 10 ; new limit (hard to reach in practice)
        jg quit
        mov eax, 10
        quit:
        ret
      }
}

// Nerf dual daggers slightly by raising left-hand dagger recovery to 70.
static void __declspec(naked) offhand_dagger_recovery(void)
{
    asm
      {
        cmp eax, SKILL_DAGGER
        movzx eax, word ptr [0x4edd80+eax*2] ; replaced code (base recovery)
        jne quit
        add eax, 10 ; the penalty
        quit:
        ret
      }
}

// Address various balance issues introduced in 3.0.
static inline void balance_tweaks(void)
{
    hook_jump(0x4b465b, get_level_up_xp); // replace old function
    hook_call(0x4b46dd, get_level_up_xp, 5); // training hall
    erase_code(0x4b46e2, 14); // rest of old code (likely an inline)
    patch_dword(0x48d448, 0xd189ce89); // mov esi, ecx; mov ecx, edx
    hook_call(0x48d44c, get_level_up_xp, 5); // xp/level green/white color
    patch_word(0x48d451, 0xf189); // mov ecx, esi
    erase_code(0x48d453, 12); // rest of the inline
    // extra skill points are in human_skill_point() above
    // statusline: provide stored sp value instead of recalculating
    patch_word(0x4b4c06, 0xa190); // nop; mov eax, ...
    patch_pointer(0x4b4c08, &added_skill_points);
    erase_code(0x4b4c12, 2); // old code
    erase_code(0x4b4c19, 3); // ditto
    // training price adjusted in increase_training_price() above
    // Decrease training hall level limits according to the dilated levels.
    TRAIN_MAX_LEVELS[4] = TRAIN_MAX_LEVELS[5] = 100; // was 200
    TRAIN_MAX_LEVELS[7] = TRAIN_MAX_LEVELS[8] = 40; // was 50
    TRAIN_MAX_LEVELS[9] = 60; // was 100
    erase_code(0x48e4cf, 14); // old recovery bonuses
    hook_call(0x48e4e3, multiplicative_recovery, 6);
    word(0x4edd8a) = 90; // buff bow recovery
    // Let HP regen stack.
    erase_code(0x493c29, 2);
    erase_code(0x493c31, 2);
    hook_call(0x48e2b2, offhand_dagger_recovery, 8);
}

// Add a "buy scrolls" option to magic guild dialogs.
static void __declspec(naked) add_scroll_reply(void)
{
    asm
      {
        push edx ; preserve
        mov edx, CONV_BUY_SCROLLS
        call dword ptr ds:add_reply
        pop edx
        mov ecx, 2
        jmp dword ptr ds:add_reply ; replaced call
      }
}

// Same, but for the mirrored path guilds.
static void __declspec(naked) add_scroll_reply_ld(void)
{
    asm
      {
        mov ecx, 1
        mov edx, CONV_BUY_SCROLLS
        call dword ptr ds:add_reply
        mov eax, 0x4b3d26 ; three-reply branch
        jmp eax
      }
}

// Send a click on "buy scrolls" towards the buy books code.
static void __declspec(naked) click_scroll_reply(void)
{
    asm
      {
        mov eax, dword ptr [CURRENT_CONVERSATION] ; replaced code
        cmp eax, CONV_BUY_SCROLLS
        jne quit
        dec eax ; pretend we`re buying books
        quit:
        ret
      }
}

// Supply the "buy scrolls" text for the new reply.
static void __declspec(naked) print_scroll_reply(void)
{
    asm
      {
        mov eax, dword ptr [eax+36] ; replaced code
        cmp eax, CONV_BUY_SPELLS ; ditto
        jz books
        cmp eax, CONV_BUY_SCROLLS
        jnz not_scrolls
        mov edx, dword ptr [new_strings+STR_BUY_SCROLLS*4]
        not_scrolls:
        ret
        books:
        mov edx, dword ptr [GLOBAL_TXT_ADDR+400*4] ; "buy spells"
        ret
      }
}

// For the second use of the above, we need to switch registers.
static void __declspec(naked) mov_scroll_reply_chunk(void)
{
    asm
      {
        mov eax, edx
        nop dword ptr [eax]
      }
}

// Populate a magic guild with appropriate scrolls.
static void __thiscall restock_scrolls(int guild)
{
    int max_level = word(0x4f0db0 + guild * 2); // vanilla book lvl array
    int school = EVENTS2D[guild + FIRST_GUILD].type - 5;
#define SCHOOL(element) (school == SKILL_##element - SKILL_FIRE)
    int extra = SCHOOL(SPIRIT) || SCHOOL(MIND); // 12 spells
    if (SCHOOL(LIGHT) && max_level == 11
        && !check_bit(QBITS, QBIT_DIVINE_INTERVENTION))
        extra = -1; // 11th spell not found yet
    int image = dword(CURRENT_CONVERSATION) == CONV_BUY_SCROLLS;
    int rank = max_level > 10 ? SKILL_GM : max_level > 7 ? SKILL_MASTER
                                            : max_level > 4 ? SKILL_EXPERT : 0;
    for (int i = 0; i < 12; i++)
      {
        int roll = random() % (max_level + extra);
        int id = FIRST_SCROLL + school * 11 + roll;
        if (roll == max_level)
            id = SCHOOL(SPIRIT) ? SCROLL_FATE : SCROLL_TELEPATHY;
        struct item *scroll = &elemdata.guild_scrolls[guild][i];
        init_item(scroll);
        scroll->id = id;
        scroll->flags = IFLAGS_ID;
        scroll->charges = (max_level + 1) / 2 + random() % max_level + rank;
        int spell = ITEMS_TXT[id].mod1_dice_count;
        // these would have permanent effects on gm
        if ((spell == SPL_FIRE_AURA || spell == SPL_WIZARD_EYE
             || spell == SPL_SPECTRAL_WEAPON || spell == SPL_CHARM
             || spell == SPL_VAMPIRIC_WEAPON || spell == SPL_CONTROL_UNDEAD)
            && rank == SKILL_GM)
            scroll->charges += SKILL_MASTER - SKILL_GM;
        if (image)
          {
            int bitmap = load_bitmap(ICONS_LOD, ITEMS_TXT[id].bitmap, 2);
            pointer(SHOP_IMAGES + (i + 1) * 4) = LOADED_BITMAPS[bitmap];
          }
      }
}

// Hook for the above.
static void __declspec(naked) restock_scrolls_hook(void)
{
    asm
      {
        call dword ptr ds:restock_books ; replaced call
        mov ecx, dword ptr [DIALOG2]
        mov ecx, dword ptr [ecx+28] ; house id
        sub ecx, FIRST_GUILD
        jmp restock_scrolls
      }
}

// Vanilla array for guild books on sale.
#define BOOKS 0xadf894

// Substitute our scroll array for the usual guild wares when appropriate.
static void __declspec(naked) check_scroll_bought(void)
{
    asm
      {
        cmp dword ptr [CURRENT_CONVERSATION], CONV_BUY_SCROLLS
        je scroll
        cmp dword ptr [BOOKS+eax*4-FIRST_GUILD*12*36], ebx ; replaced code
        ret
        scroll:
        cmp dword ptr [elemdata.guild_scrolls+eax*4-FIRST_GUILD*12*36], ebx
        ret
      }
}

// Same, but for fetching the item bitmap.
static void __declspec(naked) check_scroll_bought_image(void)
{
    asm
      {
        cmp dword ptr [CURRENT_CONVERSATION], CONV_BUY_SCROLLS
        je scroll
        mov eax, dword ptr [BOOKS+eax*4-FIRST_GUILD*12*36] ; replaced code
        ret
        scroll:
        mov eax, dword ptr [elemdata.guild_scrolls+eax*4-FIRST_GUILD*12*36]
        ret
      }
}

// Also for checking if the shelves are empty.
static void __declspec(naked) check_scroll_bought_empty(void)
{
    asm
      {
        cmp dword ptr [CURRENT_CONVERSATION], CONV_BUY_SCROLLS
        je scroll
        add eax, BOOKS - FIRST_GUILD * 12 * 36 ; replaced code
        ret
        scroll:
        add eax, offset elemdata.guild_scrolls - FIRST_GUILD * 12 * 36
        ret
      }
}

// This one forms the merchant reply.  Also used for clicking to buy.
static void __declspec(naked) check_scroll_bought_reply(void)
{
    asm
      {
        cmp dword ptr [CURRENT_CONVERSATION], CONV_BUY_SCROLLS
        je scroll
        lea esi, dword ptr [BOOKS+ecx*4-FIRST_GUILD*12*36-36] ; replaced code
        ret
        scroll:
        lea esi, dword ptr [elemdata.guild_scrolls+ecx*4-FIRST_GUILD*12*36-36]
        ret
      }
}

// Treat buy scrolls window the same as buy spells for clicking purposes.
// Also here: support black market's armor screen in a similar way.
static void __declspec(naked) click_buy_scroll(void)
{
    asm
      {
        mov eax, dword ptr [CURRENT_CONVERSATION] ; replaced code
        cmp eax, CONV_BUY_ARMOR
        jne not_armor
        mov al, CONV_BUY_SPC
        not_armor:
        cmp eax, CONV_BUY_SCROLLS
        jne quit
        dec eax ; pretend it`s books
        quit:
        ret
      }
}

// Same, but for right clicks.
static void __declspec(naked) right_click_scroll(void)
{
    asm
      {
        cmp dword ptr [CURRENT_CONVERSATION], CONV_BUY_SPELLS ; replaced code
        je quit
        cmp dword ptr [CURRENT_CONVERSATION], CONV_BUY_SCROLLS
        quit:
        ret
      }
}

// And this is for right-clicking a sold scroll.
static void __declspec(naked) check_scroll_bought_hint(void)
{
    asm
      {
        cmp dword ptr [CURRENT_CONVERSATION], CONV_BUY_SCROLLS
        je scroll
        lea ecx, dword ptr [BOOKS+eax*4-FIRST_GUILD*12*36-36] ; replaced code
        ret
        scroll:
        lea ecx, dword ptr [elemdata.guild_scrolls+eax*4-FIRST_GUILD*12*36-36]
        mov dword ptr [esp], 0x4b1ab5 ; regular rmb window (not spell desc)
        ret
      }
}

#define GUILD_SCROLL_Y_ADJ 32

// Lower the sold scroll images so they wouldn't float in midair.
static void __declspec(naked) sold_scrolls_height(void)
{
    asm
      {
        cmp dword ptr [CURRENT_CONVERSATION], CONV_BUY_SCROLLS
        jne skip
        add dword ptr [esp+8], GUILD_SCROLL_Y_ADJ ; bitmap y
        skip:
        jmp dword ptr ds:draw_over_other ; replaced call
      }
}

// Same, but for the mouse click mask.
static void __declspec(naked) sold_scrolls_height_mask(void)
{
    asm
      {
        cmp dword ptr [CURRENT_CONVERSATION], CONV_BUY_SCROLLS
        jne skip
        add ecx, GUILD_SCROLL_Y_ADJ * 2560 ; seems to be x and y at once?
        skip:
        jmp dword ptr ds:set_image_mouseover ; replaced call
      }
}

// Get SP restore price, based on guild fanciness, PC level, and Merchant.
static int __thiscall guild_sp_price(struct player *player)
{
    static const int base_price = 50; // TODO: maybe tweak later
    // This value is 2.0, 3.0, 4.0 or 5.0, depending on guild tier.
    int val = EVENTS2D[dword(dword(DIALOG2) + 28)].multiplier;
    int merchant = get_merchant_bonus(player);
    int level = player->level_base;
    if (level <= 10)
        level = 100;
    else
        level *= level;
    if (merchant > 100 * 2 / 3) // at most 1/3 base price for services
        return base_price * val * level * 1 / (100 * 3);
    return base_price * val * level * (100 - merchant) / (100 * 100);
}

// Restore active PC's spell points, charge gold, return 0 if not enough.
// Also place a mana anchor (to discourage Lloyd's Beacon abuse).
static int guild_restore_sp(void)
{
    int current = dword(CURRENT_PLAYER) - 1;
    struct player *player = &PARTY[current];
    int max_sp = get_full_sp(player);
    if (player->sp >= max_sp)
        return TRUE; // do nothing
    int price = guild_sp_price(player);
    if (dword(PARTY_GOLD) < price)
        return FALSE;
    spend_gold(price);
    struct spell_buff *anchor
        = &elemdata.new_pc_buffs[current][NBUFF_ANCHORED_MANA];
    int new_power = anchor->power + max_sp - player->sp; // cumulative
    if (new_power >= 1 << 16) // guard from overflow
        new_power = (1 << 16) - 1;
    add_buff(anchor, CURRENT_TIME + 2 * ONE_HOUR, 0, new_power, 0, 0);
    player->sp = max_sp;
    return TRUE;
}

// Hook for the above.
static void __declspec(naked) guild_restore_sp_hook(void)
{
    asm
      {
        call guild_restore_sp
        test eax, eax
        jz no_gold
        mov eax, 0x4b5e73 ; exit
        jmp eax
        no_gold:
        mov eax, 0x4b5e1a ; say no gold code
        jmp eax
      }
}

// For storing the "restore SP" reply; also doubles as SP check cache.
static char restore_sp_buffer[100];

// Print the restore SP prompt when appropriate.
static void __declspec(naked) print_restore_sp(void)
{
    asm
      {
        cmp word ptr [ecx+eax*2-36*2].s_player.skills, bx ; replaced code
        jz quit
        cmp eax, SKILL_DARK + 36 ; no learning/meditation
        ja skip
        mov byte ptr [restore_sp_buffer], bl ; will remain 0 if no prompt
        call dword ptr ds:get_full_sp
        mov ecx, dword ptr [ebp-24] ; player
        cmp dword ptr [ecx].s_player.sp, eax
        jge skip
        call guild_sp_price
        push eax
        push dword ptr [new_strings+STR_RESTORE_SP*4]
#ifdef __clang__
        mov eax, offset restore_sp_buffer
        push eax
#else
        push offset restore_sp_buffer
#endif
        call dword ptr ds:sprintf
        add esp, 12
        lea eax, [ebp-120]
        push ebx
        push ebx
        push eax
        mov edx, offset restore_sp_buffer
        mov ecx, dword ptr [ARRUS_FNT]
        call dword ptr ds:get_text_height
        add dword ptr [ebp-8], eax ; total height
        inc dword ptr [ebp-12] ; active reply count
        skip:
        test edi, edi ; clear zf
        quit:
        ret
      }
}

// This one actually prints the composed reply.
static void __declspec(naked) print_restore_sp_display(void)
{
    asm
      {
        cmp word ptr [ecx+eax*2-36*2].s_player.skills, bx ; replaced code
        jz quit
        cmp eax, SKILL_DARK + 36 ; no learning/meditation
        ja skip
        cmp byte ptr [restore_sp_buffer], bl
        jz skip
        mov eax, offset restore_sp_buffer
        mov dword ptr [esp], 0x4b62c4 ; print code
        ret
        skip:
        test edi, edi ; clear zf
        quit:
        ret
      }
}

// Reimplement weapon, armor and magic shop replies with a fifth one added.
// Also here: remove the confirm order button when it's no longer needed.
static void __declspec(naked) add_order_reply(void)
{
    asm
      {
        xor ecx, ecx
        mov edx, CONV_BUY_STD
        call dword ptr ds:add_reply
        mov ecx, 1
        mov edx, CONV_BUY_SPC
        call dword ptr ds:add_reply
        mov ecx, 2
        mov edx, CONV_QUERY_ORDER ; the new one!
        call dword ptr ds:add_reply
        mov ecx, 3
        mov edx, CONV_INVENTORY
        call dword ptr ds:add_reply
        mov ecx, 4
        mov edx, CONV_LEARN
        call dword ptr ds:add_reply
        cmp dword ptr [CURRENT_CONVERSATION], CONV_CONFIRM_ORDER
        je ok
        mov eax, dword ptr [DIALOG2]
        cmp dword ptr [eax+32], 7 ; button count
        jne ok
        mov ecx, dword ptr [eax+80] ; the button
        mov edx, dword ptr [ecx+48] ; next button
        mov dword ptr [eax+80], edx
        and dword ptr [edx+52], 0 ; link to the removed button
        dec dword ptr [eax+32]
        push ecx
        mov ecx, REMOVE_BUTTON_THIS
        call dword ptr ds:remove_button
        ok:
        mov eax, 0x4b3c84 ; five-reply code
        jmp eax
      }
}

// The array for store main screen topic options.
#define SHOP_REPLIES 0xf8b038

// Print the text for the new reply.
static void __declspec(naked) print_order_reply(void)
{
    asm
      {
        mov ecx, dword ptr [new_strings+STR_PLACE_ORDER*4]
        mov dword ptr [SHOP_REPLIES+12], eax ; replaced code, but shifted down
        mov dword ptr [SHOP_REPLIES+8], ecx ; and we put new text in its place
        ret
      }
}

// Order items, filled below; order_gold was also declared earlier.
static struct item order_result, order_ore, order_gold, order_reagent;
static int order_ore_count, have_order_reagent, order_days;

// Return a mouseover hint for the confirm order screen.
static char *__thiscall get_order_text(int id)
{
    static char buffer[300];
    char hlname[100], reagent[100], reagname[100], orename[100];
    if (id > 1)
      {
        sprintf(buffer, new_npc_text[862-790], order_ore_count);
        return buffer;
      }
    sprintf(hlname, COLOR_FORMAT, colors[CLR_ITEM], item_name(&order_result));
    if (id)
      {
        sprintf(buffer, new_npc_text[861-790], hlname);
        return buffer;
      }
    if (have_order_reagent)
      {
        int id = order_reagent.id;
        char *specifier = NULL;
        switch (ITEMS_TXT[id].equip_stat + 1)
          {
            case ITEM_TYPE_REAGENT:
                specifier = new_npc_text[863-790]; // "reagent"
                break;
            case ITEM_TYPE_POTION:
                if (id != MAGIC_POTION && id != FLAMING_POTION
                    && id != FREEZING_POTION && id != NOXIOUS_POTION
                    && id != SHOCKING_POTION && id != SWIFT_POTION
                    && id != SLAYING_POTION) // these have "potion" in names
                    specifier = new_npc_text[864-790]; // "potion of"
                break;
            case ITEM_TYPE_SCROLL:
                specifier = new_npc_text[865-790]; // "scroll of"
                break;
            case ITEM_TYPE_BOOK:
                specifier = new_npc_text[866-790]; // "spellbook of"
                break;
            case ITEM_TYPE_GEM:
                specifier = new_npc_text[867-790]; // "gemstone"
                break;
          }
        sprintf(specifier ? reagname : reagent, COLOR_FORMAT,
                colors[CLR_ITEM], ITEMS_TXT[id].name);
        if (specifier)
            sprintf(reagent, specifier, reagname);
      }
    sprintf(orename, COLOR_FORMAT, colors[CLR_ITEM],
            ITEMS_TXT[order_ore.id].name);
    sprintf(buffer, new_npc_text[859+have_order_reagent-790], hlname,
            order_days, order_gold.bonus2, orename, reagent);
    return buffer;
}

// 0 for initial prompt, 1 for parse failure, 2 for wrong item/shop type.
static int order_message_type = 0;
// Used just below.
static char order_message_buffer[100];


// Do a prompt when the reply is clicked.
// Also here: draw the order's result and materials.
// Also also: check the current order ready status.
// EI shops do not take orders as the player is unlikely to stay that long.
static void __declspec(naked) query_order(void)
{
    asm
      {
        jz quit ; we replaced a jnz
        dec eax ; our reply is 1 higher
        jnz not_query
        cmp dword ptr [MESSAGE_DIALOG], 0 ; check if we`re in a prompt already
        jnz skip
        mov byte ptr [0x5b07b8], al ; reset any message override
        mov ecx, dword ptr [DIALOG2]
        mov ecx, dword ptr [ecx+28] ; house id
        cmp ecx, 1 ; ei weapon
        je emerald
        cmp ecx, 15 ; ei armor
        je emerald
        cmp ecx, 29 ; ei magic
        jne not_emerald
        emerald:
        mov eax, dword ptr [new_strings+STR_EI_NO_ORDER*4]
        mov dword ptr [CURRENT_TEXT_ADDR], eax
        jmp simple_message
        not_emerald:
        lea ecx, [elemdata.order_timers+ecx*8-8]
        cmp dword ptr [ecx], 0
        jnz have_order
        cmp dword ptr [ecx+4], 0
        jz new_order
        have_order:
        mov eax, dword ptr [ecx]
        mov edx, dword ptr [ecx+4]
        sub eax, dword ptr [CURRENT_TIME_ADDR]
        sbb edx, dword ptr [CURRENT_TIME_ADDR+4]
        jb ready
        mov ecx, ONE_DAY
        div ecx
        test eax, eax
        jz round_up
        add edx, edx
        cmp edx, ecx
        jbe round_down
        round_up:
        inc eax
        round_down:
        push eax
        push dword ptr [new_strings+STR_ORDER_NOT_READY*4]
#ifdef __clang__
        mov eax, offset order_message_buffer
        push eax
#else
        push offset order_message_buffer
#endif
        call dword ptr ds:sprintf
        add esp, 12
        mov dword ptr [CURRENT_TEXT_ADDR], offset order_message_buffer
        cmp dword ptr [SHOPKEEPER_MOOD], 0 ; skip if happy already
        jnz simple_message
        mov dword ptr [SHOPKEEPER_MOOD], 2 ; neutral
        jmp simple_message
        ready:
        and dword ptr [ecx], 0
        and dword ptr [ecx+4], 0
        mov dword ptr [SHOPKEEPER_MOOD], 1 ; happy
        mov eax, dword ptr [DIALOG2]
        mov eax, dword ptr [eax+28] ; house id
        lea eax, [eax+eax*8]
        lea eax, [elemdata.current_orders+eax*4-SIZE_ITEM]
        push eax
        mov ecx, PARTY_BIN_ADDR
        call dword ptr ds:add_mouse_item
        mov eax, dword ptr [new_strings+STR_ORDER_READY*4]
        mov dword ptr [CURRENT_TEXT_ADDR], eax
        simple_message:
        push MESSAGE_SIMPLE
        xor edx, edx
        inc edx
        jmp message
        new_order:
        cmp dword ptr [order_message_type], 1
        cmovb eax, dword ptr [new_strings+STR_PROMPT1*4]
        cmove eax, dword ptr [new_npc_text+857*4-790*4]
        cmova eax, dword ptr [new_npc_text+858*4-790*4]
        and dword ptr [order_message_type], 0 ; reset
        mov dword ptr [CURRENT_TEXT_ADDR], eax
        push dword ptr [new_strings+STR_PROMPT2*4]
        push STATUS_MESSAGE
        call dword ptr ds:strcpy_ptr
        add esp, 8
        push MESSAGE_QUESTION
        xor edx, edx
        message:
        mov ecx, MESSAGE_MARKER
        call dword ptr ds:message_dialog
        jmp skip
        not_query:
        dec eax
        jnz skip
        push dword ptr [SHOP_IMAGES]
        push 8
        push 8
        mov ecx, DRAW_IMAGE_THIS_ADDR
        call dword ptr ds:draw_background
        mov ecx, dword ptr [SHOP_IMAGES+4]
        movzx eax, word ptr [ecx+24] ; sprite width
        sub eax, 238 * 2
        neg eax
        shr eax, 1
        movzx edx, word ptr [ecx+26] ; sprite height
        sub edx, 153 * 2
        neg edx
        shr edx, 1
        lea ebx, [edx+edx*4]
        shl ebx, 9
        lea ebx, [ebx+eax*4]
        push ecx
        push edx
        push eax
        mov ecx, DRAW_IMAGE_THIS_ADDR
        call dword ptr ds:draw_over_other
        push 1
        mov edx, dword ptr [SHOP_IMAGES+4]
        mov ecx, dword ptr [MOUSEOVER_BUFFER]
        add ecx, ebx
        call dword ptr ds:set_mouse_mask
        mov ebx, dword ptr [order_ore_count]
        cmp ebx, 3
        jbe upper_row
        lower_row:
        lea eax, [ebx+ebx*8]
        lea eax, [40+eax*4-4*36]
        push eax
        push dword ptr [SHOP_IMAGES+8]
        push 260 + 36
        push eax
        mov ecx, DRAW_IMAGE_THIS_ADDR
        call dword ptr ds:draw_over_other
        pop ecx
        push 2
        mov edx, dword ptr [SHOP_IMAGES+8]
        lea ecx, [ecx*4+(260+36)*640*4]
        add ecx, dword ptr [MOUSEOVER_BUFFER]
        call dword ptr ds:set_mouse_mask
        dec ebx
        cmp ebx, 3
        ja lower_row
        upper_row:
        lea eax, [ebx+ebx*8]
        lea eax, [40+eax*4-36]
        push eax
        push dword ptr [SHOP_IMAGES+8]
        push 260
        push eax
        mov ecx, DRAW_IMAGE_THIS_ADDR
        call dword ptr ds:draw_over_other
        pop ecx
        push 2
        mov edx, dword ptr [SHOP_IMAGES+8]
        lea ecx, [ecx*4+260*640*4]
        add ecx, dword ptr [MOUSEOVER_BUFFER]
        call dword ptr ds:set_mouse_mask
        dec ebx
        ja upper_row
        mov ecx, dword ptr [SHOP_IMAGES+12]
        movzx eax, word ptr [ecx+24] ; sprite width
        sub eax, 239 * 2
        neg eax
        shr eax, 1
        movzx edx, word ptr [ecx+26] ; sprite height
        sub edx, 324 * 2
        neg edx
        shr edx, 1
        lea ebx, [edx+edx*4]
        shl ebx, 9
        lea ebx, [ebx+eax*4]
        push ecx
        push edx
        push eax
        mov ecx, DRAW_IMAGE_THIS_ADDR
        call dword ptr ds:draw_over_other
        push 3
        mov edx, dword ptr [SHOP_IMAGES+12]
        mov ecx, dword ptr [MOUSEOVER_BUFFER]
        add ecx, ebx
        call dword ptr ds:set_mouse_mask
        cmp dword ptr [have_order_reagent], 0
        jz no_reagent
        mov ecx, dword ptr [SHOP_IMAGES+16]
        movzx eax, word ptr [ecx+24] ; sprite width
        sub eax, 384 * 2
        neg eax
        shr eax, 1
        movzx edx, word ptr [ecx+26] ; sprite height
        sub edx, 294 * 2
        neg edx
        shr edx, 1
        lea ebx, [edx+edx*4]
        shl ebx, 9
        lea ebx, [ebx+eax*4]
        push ecx
        push edx
        push eax
        mov ecx, DRAW_IMAGE_THIS_ADDR
        call dword ptr ds:draw_over_other
        push 4
        mov edx, dword ptr [SHOP_IMAGES+16]
        mov ecx, dword ptr [MOUSEOVER_BUFFER]
        add ecx, ebx
        call dword ptr ds:set_mouse_mask
        no_reagent:
        push dword ptr [SHOP_IMAGES+20]
        push 410
        push 520
        mov ecx, DRAW_IMAGE_THIS_ADDR
        call dword ptr ds:draw_background
        xor ebx, ebx
        push ebx
        push ebx
        push esp
        mov ecx, dword ptr [MOUSE_THIS_PTR]
        call dword ptr ds:get_mouse_coords
        pop eax
        pop ecx
        add eax, dword ptr [SCANLINE_OFFSET+ecx*4]
        mov ecx, dword ptr [MOUSEOVER_BUFFER]
        mov ecx, dword ptr [ecx+eax*4]
        movzx ecx, cx
        call get_order_text
        cmp dword ptr [esp], 0x4badc3 + 5 ; if called from armor shop
        je armor
        mov dword ptr [esp], 0x4b91ed ; print msg (same code for weapon/magic)
        sub dword ptr [ebp-124], 14 ; widen text area
        add dword ptr [ebp-116], 28 ; ditto
        ret
        armor:
        xor edi, edi
        sub dword ptr [ebp-120], 14 ; widen text area
        add dword ptr [ebp-112], 28 ; ditto
        mov dword ptr [esp], 0x4bad96 ; armor shop msg (different code!)
        ret
        skip:
        mov dword ptr [esp], 0x4b9c24 ; replaced jump (end of function)
        quit:
        ret
      }
}

// Revert a MM7Patch change that enables Fly and WWalk icons
// in the message screen, but only if we're not in the main screen.
static void __declspec(naked) disable_prompt_spell_icons(void)
{
    asm
      {
        mov eax, dword ptr [CURRENT_SCREEN] ; replaced code
        cmp eax, 19
        jne skip
        mov eax, dword ptr [0x5067f8] ; old screen
        skip:
        ret
      }
}

// Make sure the prompt is not white-on-white for the light path.
static void __declspec(naked) prompt_text_color(void)
{
    asm
      {
        mov eax, dword ptr [0x50797c] ; current path-specific text color
        mov dword ptr [esp+12], eax ; prompt color
        jmp dword ptr ds:print_string ; replaced call
      }
}

// A hacky strncasecmp replacement that ignores case both for ASCII and CP1251.
// TODO: could parse E-dots in input
static int __declspec(naked) __stdcall mystrcmp(char *left, char *right, int n)
{
    asm
      {
        push esi
        push edi
        cld
        mov esi, dword ptr [esp+12] ; left
        mov edi, dword ptr [esp+16] ; right
        mov ecx, dword ptr [esp+20] ; n
        loop:
        test ecx, ecx
        jz equal
        repe cmpsb
        je equal
        mov al, byte ptr [esi-1]
        mov dl, byte ptr [edi-1]
        ja compare
        xchg al, dl ; for simplicity
        compare:
        sub dl, al
        cmp dl, 'A' - 'a'
        jne unequal
        test al, 0x60 ; all lowercase letters are here
        jz unequal
        jnp unequal ; we check for two bits
        test al, 0x80 ; CP1251 has all 32 letters there (we ignore E-dots)
        jnz loop
        cmp al, 'a'
        jb unequal
        cmp al, 'z'
        jbe loop
        unequal:
        xor eax, eax
        inc eax ; we do not return -1 for less (unnecessary)
        jmp quit
        equal:
        xor eax, eax
        quit:
        pop edi
        pop esi
        ret 12
      }
}

// Bitmask for the standard bonuses who get halved value and double price.
#define HALVED_STDS ((2 << STAT_HP) + (2 << STAT_SP) + (2 << STAT_THIEVERY) \
                     + (2 << STAT_DISARM) + (2 << STAT_ARMSMASTER) \
                     + (2 << STAT_DODGING) + (2 << STAT_UNARMED))

// Helper function for sorting each skill by item bonus.
static int skill_sort(const void *pleft, const void *pright)
{
    int left = *(int *) pleft, right = *(int *) pright;
    int result = ITEMS_TXT[left].mod2 - ITEMS_TXT[right].mod2;
    if (ITEMS_TXT[left].equip_stat + 1 >= ITEM_TYPE_ARMOR)
        result += ITEMS_TXT[left].mod1_dice_count
                - ITEMS_TXT[right].mod1_dice_count;
    if (result) return result;
    result = ITEMS_TXT[left].value - ITEMS_TXT[right].value;
    if (result) return result;
    return left - right;
}

// Get an (equippable, regular) item by its textual description.
static int __thiscall parse_item(const char *description)
{
    static int namelen[LAST_PREFIX], gnamelen[LAST_PREFIX];
    static int wandof[LAST_WAND-FIRST_WAND+1][2];
    static int skills[SKILL_PLATE+1][3];
    static int skill_sorted[LAST_SHIELD+1];
    static char samename[LAST_PREFIX];
    static int grouplen[LAST_PREFIX+1] = {0};
    static int stdlen[24], spclen[SPC_COUNT], spc2len[SPC_COUNT];
    static char stdof[24];
    static char *spc2[SPC_COUNT];
    static int init = FALSE;
    static const char space[] = " \f\n\r\t\v";
    if (!init)
      {
        int skill = SKILL_NONE;
        for (int i = 1, group_start = 1; i <= LAST_PREFIX; i++)
          {
            namelen[i-1] = strlen(ITEMS_TXT[i].name);
            gnamelen[i-1] = strlen(ITEMS_TXT[i].generic_name);
            samename[i-1] = !strcmp(ITEMS_TXT[i].name,
                                    ITEMS_TXT[i].generic_name);
            if (ITEMS_TXT[group_start].mod1_dice_count
                                 ? !ITEMS_TXT[i].mod2 || i == BLASTER
                                 : strcmp(ITEMS_TXT[i].generic_name,
                                          ITEMS_TXT[group_start].generic_name))
              {
                grouplen[group_start-1] = i - group_start;
                group_start = i;
              }
            if (i >= FIRST_WAND && i <= LAST_WAND)
              {
                char *after = strstr(ITEMS_TXT[i].name,
                                     ITEMS_TXT[FIRST_WAND].generic_name);
                if (after)
                  {
                    after += strlen(ITEMS_TXT[FIRST_WAND].generic_name);
                    wandof[i-FIRST_WAND][0] = after - ITEMS_TXT[i].name;
                    wandof[i-FIRST_WAND][1] = wandof[i-FIRST_WAND][0] + 1
                                            + !strncmp(after, " of", 3) * 3;
                  }
              }
            // we don't track knives here, since they barely count
            // as a "random dagger"; other new items are also a miss
            if (skill != SKILL_MISC)
              {
                int new_skill = ITEMS_TXT[i].skill;
                if (new_skill != skill)
                  {
                    if (skill < SKILL_NONE)
                        skills[skill][1] = i - skills[skill][0];
                    skill = new_skill;
                    if (skill < SKILL_NONE) skills[skill][0] = i;
                  }
              }
            if (i <= LAST_SHIELD) skill_sorted[i] = i;
            if (i == LAST_PREFIX)
                grouplen[group_start-1] = LAST_PREFIX + 1 - group_start;
          }
        grouplen[LAST_PREFIX] = -1; // guard from overflow
        for (int i = SKILL_STAFF; i <= SKILL_PLATE; i++)
          {
            skills[i][2] = strlen(SKILL_NAMES[i]);
            qsort(skill_sorted + skills[i][0], skills[i][1],
                  sizeof(int), skill_sort);
          }
        for (int i = 0; i < 24; i++)
          {
            stdlen[i] = strlen(STDITEMS[i].name);
            stdof[i] = !strncmp(STDITEMS[i].name, "of ", 3);
          }
        for (int i = 0; i < SPC_COUNT; i++)
          {
            char *name = spcitems[i].name;
            char *varpart = NULL;
            if (have_itemgend)
                varpart = strstr(name, "^R[");
            if (!varpart)
              {
                spclen[i] = strlen(name);
                spc2[i] = NULL;
                spc2len[i] = 0;
                continue;
              }
            char *second = strchr(varpart, ']') + 1;
            second += strspn(second, space);
            spclen[i] = varpart - name;
            spc2[i] = second;
            spc2len[i] = strlen(second);
          }
        init = TRUE;
      }
    if (!description)
        return FALSE;
    char *current;
    int number = strtol(description, &current, 10);
    current += strspn(current, space);
    int spc = 0;
    int maxlen = 0;
    for (int i = 0; i < SPC_COUNT; i++)
      {
        int len = spclen[i];
        if (len <= maxlen || !spc_prefixes[i])
            continue;
        if (!mystrcmp(current, spcitems[i].name, len))
          {
            if (spc2[i])
              {
                char *next = strpbrk(current, space);
                if (*spc2[i])
                  {
                    next += strspn(next, space);
                    if (mystrcmp(next, spc2[i], spc2len[i]))
                        continue;
                    next += spc2len[i];
                  }
                len = next - current;
              }
            spc = i + 1;
            maxlen = len;
          }
      }
    if (spc)
        current += maxlen;
    if (!number)
        number = strtol(current, &current, 10);
    current += strspn(current, space);
    int id = 0, gid = 0;
    maxlen = 0;
    for (int i = 1; i <= LAST_PREFIX; i++)
      {
        int gnlen = gnamelen[i-1];
        if (gnlen > maxlen && !mystrcmp(current, ITEMS_TXT[i].generic_name,
                                        gnlen))
          {
            maxlen = gnlen;
            id = gid = i;
          }
        int nlen = namelen[i-1];
        if (nlen > maxlen && !mystrcmp(current, ITEMS_TXT[i].name, nlen))
          {
            maxlen = nlen;
            id = i;
            gid = 0;
          }
        if (i >= FIRST_WAND && i <= LAST_WAND)
          {
            int wnlen = wandof[i-FIRST_WAND][0];
            if (wnlen > maxlen && !mystrcmp(current, ITEMS_TXT[i].name, wnlen))
              {
                maxlen = wnlen;
                id = i;
                gid = FIRST_WAND;
              }
          }
      }
    int by_skill = FALSE;
    // not clubs since their generic name already matches
    if (!id) for (int i = SKILL_STAFF; i <= SKILL_PLATE; i++)
        if (!mystrcmp(current, SKILL_NAMES[i], skills[i][2]))
          {
            id = skills[i][0];
            gid = skill_sorted[id];
            by_skill = TRUE;
            maxlen = skills[i][2];
            break;
          }
    if (!id || id == BLASTER || id == BLASTER_RIFLE)
        return FALSE;
    current += maxlen;
    if (gid == FIRST_WAND)
      {
        current += strspn(current, space);
        if (!mystrcmp(current, "of", 2))
            current += 2;
      }
    if (!number)
        number = strtol(current, &current, 10);
    current += strspn(current, space);
    int std = 0;
    maxlen = 0;
    if (gid == FIRST_WAND)
      {
        int ap = id / 5; // skip wrong wand appearances
        int by_ap = gid / 5 != ap; // basic wands have a generic name
        for (int i = FIRST_WAND; i <= LAST_WAND; i++)
          {
            if (by_ap && i / 5 != ap)
                continue;
            int of = wandof[i-FIRST_WAND][1];
            int len = namelen[i-1] - of;
            if (len > maxlen
                && !mystrcmp(current, ITEMS_TXT[i].name + of, len))
              {
                maxlen = len;
                id = i;
                gid = 0;
              }
          }
      }
    else if (!spc)
      {
        int of = FALSE;
        if (!number && !mystrcmp(current, "of", 2))
          {
            char *test = current + 2;
            number = strtol(test, &test, 10);
            if (number)
              {
                of = TRUE;
                current = test + strspn(test, space);
              }
          }
        for (int i = 1; i <= 24; i++)
          {
            int len = stdlen[i-1] - of * 3;
            if (len <= maxlen || of && !stdof[i-1])
                continue;
            if (!mystrcmp(current, STDITEMS[i-1].name + of * 3, len))
              {
                maxlen = len;
                std = i;
              }
          }
        if (of && !std)
            return FALSE;
        if (!of) for (int i = 0; i < SPC_COUNT; i++)
          {
            int len = spclen[i];
            if (len <= maxlen || spc_prefixes[i])
                continue;
            if (!mystrcmp(current, spcitems[i].name, len))
              {
                maxlen = len;
                spc = i + 1;
                std = 0;
              }
          }
      }
    current += maxlen;
    if (!number)
        number = strtol(current, &current, 10);
    current += strspn(current, space);
    if (*current)
        return FALSE;
    int adjust = FALSE;
    if (gid)
      {
        if (ITEMS_TXT[gid].equip_stat + 1 == ITEM_TYPE_WAND)
            adjust = TRUE; // will just be randomized
        else if (number && !std && ITEMS_TXT[gid].mod1_dice_count)
          {
            int armor = ITEMS_TXT[gid].equip_stat + 1 >= ITEM_TYPE_ARMOR;
            int quality = ITEMS_TXT[gid].mod2
                        + armor * ITEMS_TXT[gid].mod1_dice_count;
            int sign = (number > quality) - (number < quality);
            int eid, skill;
            if (by_skill) skill = ITEMS_TXT[gid].skill;
            if (sign) do
              {
                id += sign;
                eid = by_skill ? skill_sorted[id] : id;
                if (by_skill ? ITEMS_TXT[eid].skill != skill
                             : grouplen[id-(sign==1)])
                    return FALSE;
                quality = ITEMS_TXT[eid].mod2
                        + armor * ITEMS_TXT[eid].mod1_dice_count;
              }
            while (quality != number);
            if (by_skill) id = skill_sorted[id];
          }
        else if (grouplen[gid-1] || by_skill) // exclude (elven) saber
            adjust = TRUE;
      }
    int equip = ITEMS_TXT[id].equip_stat + 1;
    if (equip == ITEM_TYPE_WEAPON2 && ITEMS_TXT[id].skill != SKILL_STAFF)
        equip = ITEM_TYPE_WEAPON;
    int wand = equip == ITEM_TYPE_WAND;
    int robe = equip == ITEM_TYPE_ARMOR && ITEMS_TXT[id].skill == SKILL_MISC;
    int crown = equip == ITEM_TYPE_HELM && !ITEMS_TXT[id].mod1_dice_count;
    int caestus = equip == ITEM_TYPE_GAUNTLETS
                  && ITEMS_TXT[id].skill == SKILL_UNARMED;
    if ((equip <= ITEM_TYPE_MISSILE || caestus) && std)
        return FALSE;
    if (wand && (std || spc))
        return FALSE;
    init_item(&order_result);
    order_result.flags = IFLAGS_ID;
    int fanciness = 0; // up to 300
    if (spc)
      {
        int prob;
        if (robe)
            prob = spcitems[spc-1].robe_prob;
        else if (crown)
            prob = spcitems[spc-1].crown_prob;
        else if (caestus)
            prob = spcitems[spc-1].caestus_prob;
        else
            prob = spcitems[spc-1].probability[equip-1];
        if (!prob)
            return FALSE;
        order_result.bonus2 = spc;
        fanciness = (spcitems[spc-1].level + 1) * 60 + random() % 3 * 30;
      }
    if (std)
      {
        int column = robe ? 9 : crown ? 10 : equip - 4;
        if (!STDITEMS[std-1].probability[column])
            return FALSE;
        order_result.bonus = std;
        int max = 1 << std & HALVED_STDS ? 12 : 25;
        if (number < 0 || number > max)
            return FALSE;
        if (!number)
            number = 1 + random() % max;
        order_result.bonus_strength = number;
        fanciness = number * (1 << std & HALVED_STDS ? 25 : 12);
      }
    if (adjust && (fanciness || by_skill || !samename[gid-1]))
      {
        if (!fanciness)
            fanciness = random() % 300 + 1;
        int multiplier;
        if (wand && id != gid) // by appearance
            multiplier = 5;
        else if (by_skill)
            multiplier = skills[ITEMS_TXT[gid].skill][1];
        else multiplier = grouplen[gid-1];
        fanciness *= multiplier - 1;
        id += fanciness / 300 + (random() % 300 < fanciness % 300);
        if (by_skill) id = skill_sorted[id];
      }
    order_result.id = id;
    if (wand)
      {
        int max = ITEMS_TXT[id].mod2;
        if (number < 0 || number > max + 6)
            return FALSE;
        if (!number)
            number = max + random() % 7;
        order_result.charges = order_result.max_charges = number;
      }
    if (id == THROWING_KNIVES || id == LIVING_WOOD_KNIVES)
      {
        int max = 40 + (id == THROWING_KNIVES) * 10;
        if (!number || gid)
            number = max + random() % (max + 1);
        if (number < 0 || number > max * 2)
            return FALSE;
        order_result.charges = order_result.max_charges = number;
        if (id == LIVING_WOOD_KNIVES)
            order_result.temp_ench_time = CURRENT_TIME;
      }
    return TRUE;
}

// Filled below when parsing stditems.txt and spcitems.txt.
static int std_craft_items[24], spc_craft_items[SPC_COUNT];

// Check if the generated item is OK for the current shop, and compute price.
static int verify_item(void)
{
    int shop = dword(0xf8b018); // shop type (1-3)
    struct items_txt_item *type = &ITEMS_TXT[order_result.id];
    switch (type->equip_stat + 1)
      {
        case ITEM_TYPE_WEAPON:
        case ITEM_TYPE_WEAPON2:
        case ITEM_TYPE_MISSILE:
            if (shop != 1)
                return FALSE;
            break;
        case ITEM_TYPE_ARMOR:
        case ITEM_TYPE_SHIELD:
            if (shop != 2)
                return FALSE;
            break;
        case ITEM_TYPE_HELM:
        case ITEM_TYPE_BELT:
        case ITEM_TYPE_CLOAK:
        case ITEM_TYPE_GAUNTLETS:
        case ITEM_TYPE_BOOTS:
            if (shop == 2)
                break;
            // else fallthrough
        case ITEM_TYPE_RING:
        case ITEM_TYPE_AMULET:
        case ITEM_TYPE_WAND:
            if (shop != 3)
                return FALSE;
            break;
        default: // shouldn't happen!
            return FALSE;
      }
    int value = item_value(&order_result);
    int markup = 0; // increase price for rare bonuses
    have_order_reagent = order_result.bonus || order_result.bonus2;
    if (have_order_reagent)
      {
        init_item(&order_reagent);
        order_reagent.flags = IFLAGS_ID;
        int lmin, lmax;
        if (order_result.bonus)
          {
            order_reagent.id = std_craft_items[order_result.bonus-1];
            int amt = order_result.bonus_strength;
            if (1 << order_result.bonus & HALVED_STDS)
                amt += amt;
            markup = (amt >= 24) + (amt >= 25);
            //TODO: unhardcode this
            lmin = 2 + (amt > 5) + (amt > 8) + (amt > 12) + (amt > 17);
            if (1 << order_result.bonus & HALVED_STDS)
                amt++;
            lmax = 6 - (amt < 15) - (amt < 10) - (amt < 6) - (amt < 3);
          }
        else
          {
            order_reagent.id = spc_craft_items[order_result.bonus2-1];
            struct spcitem *spc = &spcitems[order_result.bonus2-1];
            int tier = spc->level + 'A';
            lmin = 3 + (tier > 'B') + (tier > 'C');
            lmax = 4 + (tier > 'A') + (tier > 'C');
            int equip = type->equip_stat + 1;
            int skill = type->skill;
            if (equip == ITEM_TYPE_WEAPON2 && skill != SKILL_STAFF)
                equip = ITEM_TYPE_WEAPON;
            int prob;
            if (equip == ITEM_TYPE_ARMOR && skill == SKILL_MISC)
                prob = spc->robe_prob;
            else if (equip == ITEM_TYPE_HELM && !type->mod1_dice_count)
                prob = spc->crown_prob;
            else if (equip == ITEM_TYPE_GAUNTLETS && skill == SKILL_UNARMED)
                prob = spc->caestus_prob;
            else prob = spc->probability[equip-1];
            markup = (prob < 5) + (prob < 10);
          }
        int max = 0;
        for (int level = lmin; level <= lmax; level++)
            if (max < type->chance[level-1])
                max = type->chance[level-1];
        markup += (max < 5) + (max < 10);
      }
    int tprob = 0, wprob = 0;
    for (int i = 0; i < 6; i++)
      {
        tprob += type->chance[i];
        wprob += type->chance[i] * i;
      }
    int ore = wprob / tprob + (wprob % tprob * 2 > tprob);
    if (markup && ore < 5) ore++;
    // Average random item price for tlvl 1-6.
    static const int avg_price[6] = { 100, 250, 500, 1000, 1500, 2500 };
    init_item(&order_ore);
    order_ore.id = FIRST_ORE + ore;
    order_ore.flags = IFLAGS_ID;
    order_ore_count = (value * 4 + avg_price[ore]) / (avg_price[ore] * 2);
    if (type->equip_stat + 1 == ITEM_TYPE_WAND)
        order_ore_count /= 2; // they're all too expensive!
    if (order_ore_count < 1)
        order_ore_count = 1;
    else if (order_ore_count > 6)
        order_ore_count = 6;
    value <<= markup / 2;
    if (markup & 1)
        value = value * 7 / 5;
    // Shop tier, from 1.5 to 4.0.
    float fancy = EVENTS2D[dword(dword(DIALOG2) + 28)].multiplier;
    order_days = value / fancy / 100;
    if (order_days < 1)
        order_days = 1;
    value *= fancy;
    int fin_value = value - item_value(&order_reagent);
    if (fin_value * 2 < value)
        fin_value = value / 2;
    init_item(&order_gold);
    order_gold.flags = IFLAGS_ID;
    order_gold.id = LARGE_GOLD_PILE - (fin_value < 1000) - (fin_value < 200);
    order_gold.bonus2 = fin_value;
    return TRUE;
}

// When the prompt is filled or otherwise exited, parse it.
// Also here: return to main conversation after order result message.
// Also also: gift a genie-wished item (reuses the prompt code).
static void __declspec(naked) complete_order_prompt(void)
{
    asm
      {
        mov eax, dword ptr [0x590f14] ; replaced code
        cmp dword ptr [0x5c3298], MESSAGE_MARKER
        jne quit
        cmp dword ptr [0x5c329c], 2 ; this is for genie wishes
        je genie
        pop ecx ; skip unpause code
        push 0
        push 0
        push ACTION_EXIT
        mov ecx, ACTION_THIS_ADDR
        call dword ptr ds:add_action
        cmp dword ptr [0x5c329c], 1 ; exit if just message
        je no_item
        mov ecx, STATUS_MESSAGE
        cmp byte ptr [ecx], 0
        jz no_item
        call parse_item
        test eax, eax
        push 1 ; keep action below after exit
        jz bad_parse
        call verify_item
        test eax, eax
        jz bad_type
        mov edx, 2
        mov ecx, dword ptr [new_strings+STR_CONFIRM_ORDER_HINT*4]
        call dword ptr ds:show_status_text
        push CONV_CONFIRM_ORDER
        reenter:
        push ACTION_CHANGE_CONVERSATION
        mov ecx, ACTION_THIS_ADDR
        call dword ptr ds:add_action
        no_item:
        and dword ptr [MESSAGE_DIALOG], 0 ; we skip over this
        quit:
        ret
        bad_type:
        inc eax
        bad_parse:
        inc eax
        mov dword ptr [order_message_type], eax
        push CONV_QUERY_ORDER
        jmp reenter
        refused_wish:
#ifdef __clang__
        mov eax, offset order_result
        push eax
#else
        push offset order_result
#endif
        push 0
        push 6
        mov ecx, ITEMS_TXT_ADDR - 4
        call dword ptr ds:randomize_item
        mov ecx, dword ptr [new_strings+STR_GENIE_ITEM_DEFAULT*4]
        jmp give_item
        genie:
        mov dword ptr [esp], 0x445321 ; skip event code
        mov ecx, STATUS_MESSAGE
        cmp byte ptr [ecx], 0
        jz refused_wish
        call parse_item
        test eax, eax
        jz bad_wish
        mov ecx, dword ptr [new_strings+STR_GENIE_ITEM_OK*4]
        give_item:
        mov edx, 2
        call dword ptr ds:show_status_text
        mov ecx, PARTY_BIN_ADDR
#ifdef __clang__
        mov eax, offset order_result
        push eax
#else
        push offset order_result
#endif
        call dword ptr ds:add_mouse_item
        jmp no_item
        bad_wish:
        dec dword ptr [genie_wish_attempts]
        jz refused_wish
        mov eax, dword ptr [new_npc_text+857*4-790*4]
        mov dword ptr [CURRENT_TEXT_ADDR], eax
        and byte ptr [0x5b07b8], 0 ; reset override
        push dword ptr [new_strings+STR_GENIE_ITEM_ASK*4]
        push STATUS_MESSAGE
        call dword ptr ds:strcpy_ptr
        add esp, 12 ; also skip unpause code
        and dword ptr [MESSAGE_DIALOG], 0 ; otherwise it won`t reinit
        push MESSAGE_QUESTION
        mov edx, 2
        mov ecx, MESSAGE_MARKER
        call dword ptr ds:message_dialog
        ret
      }
}

// The "blueprint" background for the confirm order screen.
static const char orderbg[] = "orderbg";
// The confirm order button icon.
static const char orderbtn[] = "orderbtn";

// Load the background and item graphics when visualising the order.
// Also here: add the confirm order button.
// Also also: switch shop backgrounds for the black market.
static void __declspec(naked) preload_order_images(void)
{
    asm
      {
        cmp eax, CONV_CONFIRM_ORDER
        jne skip
        mov dword ptr [esp+4], offset orderbg ; switch background
        push 2
        mov eax, dword ptr [order_result] ; item id
        lea eax, [eax+eax*2]
        shl eax, 4
        push dword ptr [ITEMS_TXT_ADDR+eax] ; item picture
        call dword ptr ds:load_bitmap
        lea eax, [eax+eax*8]
        lea eax, [LOADED_BITMAPS_ADDR+eax*8]
        mov dword ptr [SHOP_IMAGES+4], eax
        push 2
        mov eax, dword ptr [order_ore] ; item id
        lea eax, [eax+eax*2]
        shl eax, 4
        push dword ptr [ITEMS_TXT_ADDR+eax] ; item picture
        mov ecx, ebp ; icons.lod
        call dword ptr ds:load_bitmap
        lea eax, [eax+eax*8]
        lea eax, [LOADED_BITMAPS_ADDR+eax*8]
        mov dword ptr [SHOP_IMAGES+8], eax
        push 2
        mov eax, dword ptr [order_gold] ; item id
        lea eax, [eax+eax*2]
        shl eax, 4
        push dword ptr [ITEMS_TXT_ADDR+eax] ; item picture
        mov ecx, ebp ; icons.lod
        call dword ptr ds:load_bitmap
        lea eax, [eax+eax*8]
        lea eax, [LOADED_BITMAPS_ADDR+eax*8]
        mov dword ptr [SHOP_IMAGES+12], eax
        cmp dword ptr [have_order_reagent], edi ; == 0
        jz no_reagent
        push 2
        mov eax, dword ptr [order_reagent] ; item id
        lea eax, [eax+eax*2]
        shl eax, 4
        push dword ptr [ITEMS_TXT_ADDR+eax] ; item picture
        mov ecx, ebp ; icons.lod
        call dword ptr ds:load_bitmap
        lea eax, [eax+eax*8]
        lea eax, [LOADED_BITMAPS_ADDR+eax*8]
        mov dword ptr [SHOP_IMAGES+16], eax
        no_reagent:
        push 2
#ifdef __clang__
        mov eax, offset orderbtn
        push eax
#else
        push offset orderbtn
#endif
        mov ecx, ebp ; icons.lod
        call dword ptr ds:load_bitmap
        lea eax, [eax+eax*8]
        lea eax, [LOADED_BITMAPS_ADDR+eax*8]
        mov dword ptr [SHOP_IMAGES+20], eax
        push edi
        push dword ptr [new_strings+STR_CONFIRM_ORDER*4]
        push edi
        push edi
        push ACTION_PLACE_ORDER
        push edi
        push 1
        push 35
        push 169
        push 410
        push 471
        push dword ptr [DIALOG2]
        call dword ptr ds:add_button
        add esp, 48
        mov ecx, ebp ; restore
        skip:
        mov eax, dword ptr [DIALOG2]
        mov eax, dword ptr [eax+28] ; shop id
        cmp eax, BLACK_MARKET_1
        je black
        cmp eax, BLACK_MARKET_2
        jne quit
        black:
        mov eax, dword ptr [CURRENT_CONVERSATION]
        cmp eax, CONV_BUY_STD
        jne nonweap
        mov dword ptr [esp+4], 0x4f0e04 ; weapon bg
        nonweap:
        cmp eax, CONV_BUY_ARMOR
        jne quit
        mov dword ptr [esp+4], 0x4f0dfc ; armor bg
        quit:
        jmp dword ptr ds:load_bitmap ; replaced call
      }
}

// Enable hints on clicking the order blueprint items.
// Also here: hints for the black market armor screen.
static void __declspec(naked) right_click_order(void)
{
    asm
      {
        mov eax, dword ptr [CURRENT_CONVERSATION] ; replaced code
        cmp eax, CONV_CONFIRM_ORDER
        je skip
        cmp eax, CONV_BUY_ARMOR
        je skip
        cmp eax, CONV_BUY_STD ; also replaced code
        skip:
        ret
      }
}

// Actually provide an item struct for the hint.
// Also here: get the correct item for BM armor screen.
static void __declspec(naked) right_click_order_hint(void)
{
    asm
      {
        cmp dword ptr [CURRENT_CONVERSATION], CONV_CONFIRM_ORDER
        je order
        cmp dword ptr [CURRENT_CONVERSATION], CONV_BUY_ARMOR
        jne skip
        add eax, SIZE_ITEM * 3
        skip:
        lea ecx, [SHOP_SPECIAL_ITEMS+eax*4-SIZE_ITEM] ; replaced code
        ret
        order:
        mov eax, dword ptr [ebp-4] ; active item
        lea eax, [eax+eax*2]
        lea eax, [item_structs+eax*2-6]
        jmp eax
        item_structs:
        mov ecx, offset order_result
        ret
        mov ecx, offset order_ore
        ret
        mov ecx, offset order_gold
        ret
        mov ecx, offset order_reagent
        ret
      }
}

// Populate the std bonus craft item array when reading the bonus data.
static void __declspec(naked) read_std_craft_items(void)
{
    asm
      {
        cmp dword ptr [ebp-4], 13 ; new column
        jb old
        mov ecx, 24
        sub ecx, dword ptr [ebp-16] ; counter
        mov dword ptr [std_craft_items+ecx*4], eax
        ret
        old:
        mov ecx, dword ptr [ebp-24] ; replaced code
        mov byte ptr [ecx+edx+6], al ; ditto
        quit:
        ret
      }
}

// Same, but for spc boni.
static void __declspec(naked) read_spc_craft_items(void)
{
    asm
      {
        cmp eax, 20 ; new column
        jb quit
        ja skip
        push esi
        call dword ptr ds:atoi_ptr
        pop ecx
        mov ecx, SPC_COUNT
        sub ecx, dword ptr [ebp-24] ; counter
        mov dword ptr [spc_craft_items+ecx*4], eax
        skip:
        add dword ptr [esp], 29 ; replaced jump
        quit:
        ret
      }
}

// Remove the required gold and items and start the order timer.
static void place_order(void)
{
    int house = dword(dword(DIALOG2) + 28);
    if (dword(PARTY_GOLD) < order_gold.bonus2)
      {
        shop_voice(house, SHOP_VOICE_NO_GOLD);
        show_status_text(GLOBAL_TXT[155], 2); // not enough gold
        return;
      }
    struct player *owners[7];
    int items[7];
    int got_reagent = !have_order_reagent, got_ore = 0;
    for (struct player *player = PARTY; player < PARTY + 4; player++)
        for (int i = 0; i < 14*9; i++)
          {
            int item = player->inventory[i];
            if (item > 0)
              {
                int id = player->items[item-1].id;
                if (!got_reagent && id == order_reagent.id)
                  {
                    got_reagent = TRUE;
                    owners[0] = player;
                    items[0] = i;
                  }
                else if (got_ore < order_ore_count && id == order_ore.id)
                  {
                    got_ore++;
                    owners[got_ore] = player;
                    items[got_ore] = i;
                  }
              }
          }
    if (!got_reagent || got_ore < order_ore_count)
      {
        shop_voice(house, SHOP_VOICE_NO_GOLD);
        show_status_text(new_strings[STR_NOT_ENOUGH_REAGENTS], 2);
        return;
      }
    spend_gold(order_gold.bonus2);
    for (int i = !have_order_reagent; i <= got_ore; i++)
        delete_backpack_item(owners[i], items[i]);
    elemdata.current_orders[house-1] = order_result;
    elemdata.order_timers[house-1] = CURRENT_TIME + order_days * ONE_DAY;
    dword(SHOPKEEPER_MOOD) = 1; // happy
    add_action(ACTION_THIS, ACTION_EXIT, 0, 0);
}

// If the party is checking on an order and it's not ready yet,
// prevent the shopkeeper from badmouthing them afterwards.
static void __declspec(naked) leave_shop_no_response(void)
{
    asm
      {
        cmp dword ptr [SHOPKEEPER_MOOD], 2 ; our marker
        je silent
        cmp dword ptr [PARTY_GOLD], 10000 ; replaced code
        ret
        silent:
        mov dword ptr [SHOPKEEPER_MOOD], ebx ; reset to zero
        ret ; this will go towards 'too poor' code, so no curses
      }
}

// Make sure the game doesn't try to write at a negative offset
// to the mouseover buffer in case of very tall boots for sale.
static void __declspec(naked) clip_boots_to_screen(void)
{
    asm
      {
        cmp ebx, 4 ; top row is 0-3
        jae skip
        test edi, edi ; y offset
        jns skip
        lea eax, [edi+edi*4]
        shl eax, 9
        sub ecx, eax
        add word ptr [edx+26], di ; adjust image height
        push edx
        lea eax, [ebx+1]
        push eax
        call dword ptr ds:set_image_mouseover ; replaced call
        pop edx
        sub word ptr [edx+26], di ; restore
        ret 4
        skip:
        jmp dword ptr ds:set_image_mouseover
      }
}

// Restock empty bottles on every potion shop visit.
// Apparently some people never have enough of them!
static void __declspec(naked) always_restock_bottles(void)
{
    asm
      {
        mov eax, dword ptr [esi+28] ; replaced code (house id)
        xor edi, edi ; also replaced
        cmp eax, 42 ; first alchemist
        jb skip
        cmp eax, 53 ; last alchemist
        ja skip
        lea ecx, [eax+eax*2]
        lea ecx, [ecx+ecx*8]
        shl ecx, 4
        add ecx, SHOP_STANDARD_ITEMS
        add edi, 6
        loop:
        call dword ptr ds:init_item
        mov dword ptr [ecx], POTION_BOTTLE
        add ecx, 36
        dec edi
        jnz loop
        mov eax, dword ptr [esi+28] ; restore
        skip:
        ret
      }
}

// Provide a hint about taverns wherein the player is yet to win at Arcomage.
static char *arcomage_hint(void)
{
    static char buffer[200];
    int chance = 1, tavern;
    for (int i = 108; i <= 120; i++)
        if (!byte(0xacd571+i) && !(random() % chance++))
            tavern = i;
    static const int regions[13] = { 1, 2, 3, 4, 5, 6, 7,
                                     8, 9, 10, 12, 13, 38 };
    sprintf(buffer, new_npc_text[898-790], EVENTS2D[tavern].name,
            MAPSTATS[regions[tavern-108]].name);
    return buffer;
}

// Hook for the above.
static void __declspec(naked) arcomage_hint_hook(void)
{
    asm
      {
        cmp ecx, 627 ; the new topic
        je arcomage
        cmp ecx, 200 ; replaced code
        ret
        arcomage:
        call arcomage_hint
        mov dword ptr [CURRENT_TEXT_ADDR], eax
        add dword ptr [esp], 16 ; jump over vanilla code
        ret
      }
}

// Let shops and guilds restock faster if some items are bought.
// Also here: remove bought BM items from the stolen items array.
// Also also: decrease shop wariness for each bought item (except bottles).
static void __declspec(naked) faster_shop_restock(void)
{
    asm
      {
        and byte ptr [edi-SIZE_ITEM].s_item.owner, 0 ; bought swag marker
        mov eax, dword ptr [ebp-4] ; the item
        cmp dword ptr [eax], POTION_BOTTLE
        je skip ; these restock immediately
        mov edi, dword ptr [DIALOG2]
        mov edi, dword ptr [edi+28] ; shop id
        cmp dword ptr [elemdata.shop_wariness+edi*4-4], 0
        jle calm
        dec dword ptr [elemdata.shop_wariness+edi*4-4]
        jz calm
        dec dword ptr [elemdata.shop_wariness+edi*4-4]
        calm:
        imul esi, edi, SIZE_EVENT2D
        movzx eax, word ptr [EVENTS2D_ADDR+esi].s_event2d.restock
        mov bx, word ptr [EVENTS2D_ADDR+esi].s_event2d.type
        mov esi, 24 ; magic shop, guild
        cmp edi, BLACK_MARKET_1
        je black
        cmp edi, BLACK_MARKET_2
        je black
        dec ebx
        jz weapon
        dec ebx
        jz armor
        sub ebx, 2
        jnz restock
        add esi, 6 ; potion = 18
        weapon:
        sub esi, 4 ; weapon = 12
        armor:
        sub esi, 10 ; armor = 16
        black:
        add esi, 2 ; black market = 26
        restock:
        mov ebx, ONE_DAY
        mul ebx
        div esi
        cmp edi, FIRST_GUILD
        jb shop
        sub edi, FIRST_GUILD - 53 ; after last shop
        shop:
        lea edi, [0xaccec4+edi*8] ; refill time
        mov esi, dword ptr [edi]
        mov edx, dword ptr [edi+4]
        sub esi, dword ptr [CURRENT_TIME_ADDR]
        sbb edx, dword ptr [CURRENT_TIME_ADDR+4]
        jl ok
        jg reduce
        cmp esi, ebx
        jbe ok
        sub esi, eax
        cmp esi, ebx
        ja reduce
        mov esi, dword ptr [CURRENT_TIME_ADDR]
        mov edx, dword ptr [CURRENT_TIME_ADDR+4]
        add esi, ebx
        adc edx, 0
        mov dword ptr [edi], esi
        mov dword ptr [edi+4], edx
        jmp ok
        reduce:
        sub dword ptr [edi], eax
        sbb dword ptr [edi+4], 0
        ok:
        xor ebx, ebx
        inc ebx ; restore
        skip:
        call dword ptr ds:spend_gold ; replaced code
        mov eax, dword ptr [DIALOG2]
        mov eax, dword ptr [eax+28]
        cmp eax, BLACK_MARKET_1
        je swag
        cmp eax, BLACK_MARKET_2
        jne quit
        swag:
        mov ecx, dword ptr [ebp-4]
        movzx eax, byte ptr [ecx].s_item.owner
        dec eax
        jl quit
        lea ecx, [eax+eax*8]
        lea ecx, [elemdata.stolen_items+ecx*4]
        call dword ptr ds:init_item
        quit:
        ret
      }
}

// For the black market, have buy weapon/armor/misc options instead of std/spc.
static void __declspec(naked) black_market_replies(void)
{
    asm
      {
        mov ecx, dword ptr [DIALOG2]
        mov ecx, dword ptr [ecx+28] ; shop id
        cmp ecx, BLACK_MARKET_1
        je black
        cmp ecx, BLACK_MARKET_2
        jne add_order_reply ; old hook at this address
        black:
        xor ecx, ecx
        mov edx, CONV_BUY_STD ; weapons
        call dword ptr ds:add_reply
        mov ecx, 1
        mov edx, CONV_BUY_ARMOR
        call dword ptr ds:add_reply
        mov ecx, 2
        mov edx, CONV_BUY_SPC ; magic
        call dword ptr ds:add_reply
        mov ecx, 3
        mov edx, CONV_INVENTORY
        call dword ptr ds:add_reply
        mov ecx, 4
        mov edx, CONV_LEARN
        call dword ptr ds:add_reply
        mov eax, 0x4b3c84 ; five-reply code
        jmp eax
      }
}

// Depending on the current screen, reuse weapon/armor/magic shop code.
static void __declspec(naked) black_market_screens(void)
{
    asm
      {
        mov ecx, dword ptr [DIALOG2]
        mov ecx, dword ptr [ecx+28] ; shop id
        cmp ecx, BLACK_MARKET_1
        je black
        cmp ecx, BLACK_MARKET_2
        jne skip
        black:
        mov eax, dword ptr [CURRENT_CONVERSATION]
        cmp eax, CONV_BUY_STD
        je weapon
        cmp eax, CONV_BUY_ARMOR
        je armor
        skip:
        mov eax, 0x4b4f32 ; replaced call (magic shop)
        jmp eax
        weapon:
        mov eax, 0x4b9072 ; weapon shop
        jmp eax
        armor:
        mov eax, 0x4ba88b ; armor shop
        jmp eax
      }
}

// Pretend the black market armor screen is a "buy special" screen.
static void __declspec(naked) init_bm_armor_screen(void)
{
    asm
      {
        mov edx, dword ptr [esp+20] ; replaced code, basically
        cmp edx, CONV_BUY_ARMOR
        je skip
        cmp edx, CONV_BUY_SPC ; also replaced code
        skip:
        ret
      }
}

// Forbid stealing from the black market.  Cugel is just better than you!
static void __declspec(naked) disable_bm_theft(void)
{
    asm
      {
        cmp dword ptr [CURRENT_SCREEN], 0
        jz skip ; if stealing from monsters
        mov eax, dword ptr [DIALOG2]
        mov eax, dword ptr [eax+28] ; shop id
        cmp eax, BLACK_MARKET_1
        je black
        cmp eax, BLACK_MARKET_2
        jne skip
        black:
        xor eax, eax ; pretend we have no skill
        ret 4
        skip:
        jmp dword ptr ds:get_skill ; replaced call
      }
}

// Some help code for the below function, reused twice.
static int get_shelf(int item)
{
    int type = ITEMS_TXT[item].equip_stat + 1;
    if (type <= ITEM_TYPE_MISSILE)
        return 0;
    else if (type <= ITEM_TYPE_SHIELD)
        return 3;
    else if (type <= ITEM_TYPE_BOOTS && ITEMS_TXT[item].mod1_dice_count > 0)
        return 2;
    else return 1;
}

// Implement the special logic for black market wares generation.
static void __thiscall restock_black_market(int house)
{
    static const struct { struct item *wares; int level, num, extra, type[4]; }
        stock[] = {
          { (void *) SHOP_STANDARD_ITEMS, 5, 6, 6,
              { ITEM_TYPE_WEAPON, ITEM_TYPE_WEAPON,
                ITEM_TYPE_WEAPON2, ITEM_TYPE_MISSILE } },
          { (void *) SHOP_SPECIAL_ITEMS, 4, 12, 12,
              { ITEM_TYPE_MISC, ITEM_TYPE_MISC,
                ITEM_TYPE_MISC, ITEM_TYPE_MISC } },
          { (struct item *) SHOP_SPECIAL_ITEMS + 12, 5, 4, 8,
              { ITEM_TYPE_HELM, ITEM_TYPE_CLOAK,
                ITEM_TYPE_GAUNTLETS, ITEM_TYPE_BOOTS } },
          { (struct item *) SHOP_SPECIAL_ITEMS + 16, 5, 4, 0,
              { ITEM_TYPE_ARMOR, ITEM_TYPE_ARMOR,
                ITEM_TYPE_ARMOR, ITEM_TYPE_SHIELD } },
    };
    for (int i = 0, bonus; i < sizeof(stock) / sizeof(stock[0]); i++)
      {
        if (stock[i].extra)
            bonus = random() % stock[i].extra;
        for (int j = 0; j < stock[i].num; j++)
          {
            int extra = !bonus--;
            struct item *current = &stock[i].wares[house*12+j];
            randomize_item(ITEMS_TXT_ADDR - 4, stock[i].level + extra,
                           stock[i].type[random()&3], current);
            if (current->id >= FIRST_WAND && current->id <= LAST_WAND
                || current->id == THROWING_KNIVES)
                current->charges = current->max_charges;
            current->flags = IFLAGS_ID;
            if (extra || random() % 3 == 0)
                current->flags |= IFLAGS_STOLEN;
          }
      }
    // Offer lost quest items, if any.
    // NB: we assume that they get lost 1-2 at a time,
    // so the code just replaces a random item generated above.
    // With many lost items, they might start replacing each other,
    // which thankfully doesn't really break anything either.
    replace_chest(-1); // for the below call
    track_lost_items(FALSE);
    unsigned int day = CURRENT_TIME >> 13;
    day /= 256 * 60 * 24 >> 13; // avoid long division dependency
    for (int i = FIRST_LOST_ITEM; i <= LAST_LOST_ITEM; i++)
      {
        int lost = elemdata.lost_items[i-FIRST_LOST_ITEM];
        if (lost > 0)
          {
            int check = can_refill_map(lost - 1);
            if (!check || check > 0 && elemdata.next_refill_day[lost-1] > day)
                continue;
          }
        else if (lost != LOST_GONE) continue;
        int shelf = get_shelf(i);
        struct item *item = stock[shelf].wares + house * 12
                            + random() % stock[shelf].num;
        init_item(item);
        item->id = i;
        item->flags = IFLAGS_ID;
        set_specitem_bonus(ITEMS_TXT_ADDR - 4, item);
      }
    // Once per game, sell an artifact (will reappear on restock if unsold).
    if (!check_bit(QBITS, QBIT_BM_ARTIFACT))
      {
        unsigned int i = 0;
        for (struct player *p = PARTY; p < PARTY + 4; p++)
            if (p->class % 4 == 0) i = -1; // everyone must be promoted
        for (/* i */; i < MAX_STOLEN_ITEMS; i++)
            if (!elemdata.stolen_items[i].id) break;
        struct item *artifact = elemdata.stolen_items + i;
        if (i < MAX_STOLEN_ITEMS && generate_artifact(artifact))
          {
            change_bit(QBITS, QBIT_BM_ARTIFACT, TRUE);
            artifact->flags |= IFLAGS_STOLEN;
          }
      }
    // Sell items stolen from party, including the above.
    for (int i = 0; i < MAX_STOLEN_ITEMS; i++)
      {
        struct item *swag = elemdata.stolen_items + i;
        if (!swag->id) continue;
        int shelf = get_shelf(swag->id);
        struct item *sold = stock[shelf].wares + house * 12
                            + random() % stock[shelf].num;
        *sold = *swag;
        sold->flags |= IFLAGS_ID;
        sold->flags &= ~IFLAGS_BROKEN;
        sold->owner = i + 1; // unused in vanilla?
      }
}

// Hook for the above.
static void __declspec(naked) restock_black_market_hook(void)
{
    asm
      {
        mov ecx, dword ptr [DIALOG2]
        mov ecx, dword ptr [ecx+28] ; shop id
        cmp ecx, BLACK_MARKET_1
        je black
        cmp ecx, BLACK_MARKET_2
        jne skip
        black:
        add dword ptr [esp], 5 ; skip over restock spc, too
        jmp restock_black_market
        skip:
        mov eax, 0x4b8da0 ; replaced call (restock std)
        jmp eax
      }
}

// Enable the code that randomizes weapon positions for the black market.
static void __declspec(naked) black_market_weapon_spread(void)
{
    asm
      {
        je skip ; replaced jne
        mov eax, dword ptr [esi+28] ; shop id
        cmp eax, BLACK_MARKET_1
        je skip
        cmp eax, BLACK_MARKET_2
        je skip
        mov dword ptr [esp], 0x4bd810 ; replaced jump destination
        skip:
        ret
      }
}

// Print the text for black market replies.
static void __declspec(naked) print_bm_replies(void)
{
    asm
      {
        mov ecx, dword ptr [DIALOG2]
        mov ecx, dword ptr [ecx+28] ; shop id
        cmp ecx, BLACK_MARKET_1
        je black
        cmp ecx, BLACK_MARKET_2
        jne print_order_reply ; old hook here
        black:
        mov dword ptr [SHOP_REPLIES+12], eax ; replaced code, but shifted down
        mov eax, dword ptr [new_strings+STR_BUY_WEAPONS*4]
        mov dword ptr [SHOP_REPLIES], eax ; was buy std
        mov eax, dword ptr [new_strings+STR_BUY_ARMOR*4]
        mov dword ptr [SHOP_REPLIES+4], eax ; was buy spc
        mov eax, dword ptr [new_strings+STR_BUY_MAGIC*4]
        mov dword ptr [SHOP_REPLIES+8], eax ; inserted
        ret
      }
}

// Buy the proper item on BM armor screen.
static void __declspec(naked) buy_bm_armor(void)
{
    asm
      {
        cmp dword ptr [CURRENT_CONVERSATION], CONV_BUY_ARMOR
        jne skip
        add ecx, SIZE_ITEM * 3
        skip:
        lea ecx, [SHOP_SPECIAL_ITEMS+ecx*4] ; replaced code
        ret
      }
}

// Finally, load the proper item bitmap.
static void __declspec(naked) bmp_bm_armor(void)
{
    asm
      {
        cmp dword ptr [esp+20], CONV_BUY_ARMOR ; action param
        jne skip
        add eax, SIZE_ITEM * 3
        skip:
        mov eax, dword ptr [SHOP_SPECIAL_ITEMS+eax*4] ; replaced code
        ret
      }
}

// Fix overly tall boots crashing in the BM armor screen.
// This is the same as clip_boots_to_screen(), but with different registers.
static void __declspec(naked) clip_bm_boots_to_screen(void)
{
    asm
      {
        xchg ebx, edi ; the only difference
        push dword ptr [esp+4]
        call clip_boots_to_screen ; same hack as for std/spc
        xchg ebx, edi ; restore
        ret 4
      }
}

// Always show the restock timer in BM armor screen.
// This hook is more involved than the others because of different code order.
static void __declspec(naked) bm_armor_restock_msg(void)
{
    asm
      {
        jl skip ; replaced jump
        cmp word ptr [ebp-20], 0 ; mouseover item
        jnz ok
        mov dword ptr [esp], 0x4bb2a6 ; to restock message
        ok:
        ret
        skip:
        mov dword ptr [esp], 0x4bb600 ; replaced jump address
        ret
      }
}

// Allow selling any items (incl. stolen ones) to the black market.
static void __declspec(naked) bm_sell_stolen_items(void)
{
    asm
      {
        base:
        mov ebx, dword ptr [DIALOG2]
        mov ebx, dword ptr [ebx+28] ; shop id
        cmp ebx, BLACK_MARKET_1
        je black
        cmp ebx, BLACK_MARKET_2
        jne skip
        black:
        xor eax, eax
        inc eax ; allow
        add dword ptr [esp], 97 ; to function end
        skip:
        mov ebx, 740 ; restore
        ret
      }
}

// Give the black market an unique, thematic set of taught skills.
static void __declspec(naked) black_market_skills(void)
{
    asm
      {
        mov edx, dword ptr [DIALOG2]
        mov edx, dword ptr [edx+28] ; shop id
        cmp edx, BLACK_MARKET_1
        je black
        cmp edx, BLACK_MARKET_2
        jne skip
        black:
        mov dword ptr [ebp-4], 4 ; skill count
        mov dword ptr [ebp-28], SKILL_DAGGER + 36
        mov dword ptr [ebp-24], SKILL_LEATHER + 36
        mov dword ptr [ebp-20], SKILL_DISARM_TRAPS + 36
        mov dword ptr [ebp-16], SKILL_THIEVERY + 36
        ret
        skip:
        mov dword ptr [ebp-24], SKILL_REPAIR + 36 ; replaced code
        ret
      }
}

// Let Lasker teach skills for free if you have guild membership.
static void __declspec(naked) lasker_free_teaching(void)
{
    asm
      {
        mov ecx, dword ptr [DIALOG2]
        cmp dword ptr [ecx+28], MASTER_THIEF
        jne skip
        ; thieves guild membership award
        test byte ptr [esi+(109-1)/8].s_player.awards, 0x80 >> (109-1) % 8
        jz skip
        and dword ptr [NEW_SKILL_COST], 0
        skip:
        cmp dword ptr [NEW_SKILL_COST], 0 ; replaced code
        ret
      }
}

// Also use unique NPC text that reflects the lack of money cost.
static void __declspec(naked) lasker_teacher_text(void)
{
    asm
      {
        mov edx, dword ptr [DIALOG2]
        cmp dword ptr [edx+28], MASTER_THIEF
        jne skip
        mov edx, dword ptr [CURRENT_PLAYER]
        mov edx, dword ptr [PC_POINTERS+edx*4-4]
        ; thieves guild membership award
        test byte ptr [edx+(109-1)/8].s_player.awards, 0x80 >> (109-1) % 8
        jz skip
        xor eax, eax
        cmp ecx, 287 ; disarm
        setne al
        cmp ecx, 207 ; dagger
        sete dl
        add al, dl
        mov eax, dword ptr [new_npc_text+903*4-790*4+eax*4] ; new dialog
        skip:
        mov dword ptr [CURRENT_TEXT_ADDR], eax ; replaced code
        ret
      }
}

// If an enemy has no space for stolen items, migrate them to BM instead.
static void __declspec(naked) store_stolen_items(void)
{
    asm
      {
        add ecx, SIZE_ITEM ; replaced code, in spirit
        cmp dword ptr [ecx], edi ; also this
        jz quit
        mov ecx, offset elemdata.stolen_items
        mov edx, MAX_STOLEN_ITEMS - 1
        loop:
        cmp dword ptr [ecx], edi ; == 0
        jz quit
        add ecx, SIZE_ITEM
        dec edx
        jge loop
        quit:
        ret
      }
}

// Vanilla bug: the code that changes the Arena Master's 'enter combat'
// dialog topic into 'collect prize' also affected all hireling dialog.
static void __declspec(naked) arena_prize_topic(void)
{
    asm
      {
        xor cl, cl ; prepare to skip the prize code
        cmp eax, dword ptr [NPC_TOPIC_TEXT_ADDR-8+399*8] ; combat topic
        jne quit
        mov cl, byte ptr [ARENA_TOPIC] ; replaced code
        quit:
        ret
      }
}

// Semi-bug fix: display greetings for extra NPCs put in stores.
static void __declspec(naked) greetings_in_shops(void)
{
    asm
      {
        cmp dword ptr [0x591270], 1 ; only slot 1 is store owner
        jne skip
        cmp dword ptr [0x590f00], edi ; replaced code (owner pic check)
        ret
        skip:
        xor ecx, ecx ; set zf
        ret
      }
}

// Various changes to stores, guilds and other buildings.
static inline void shop_changes(void)
{
    hook_call(0x4b3b29, add_scroll_reply, 5); // elemental guilds
    hook_jump(0x4b3b30, (void *) 0x4b3cfc); // four-reply branch
    hook_call(0x4b3b61, add_scroll_reply, 5); // self guilds
    hook_jump(0x4b3b68, (void *) 0x4b3cfc); // ditto
    hook_jump(0x4b3b79, add_scroll_reply_ld); // light
    hook_jump(0x4b3b8a, add_scroll_reply_ld); // dark
    hook_call(0x4b5dcb, click_scroll_reply, 5);
    hook_call(0x4b6169, print_scroll_reply, 6); // planning code
    erase_code(0x4b61b4, 6); // remove unconditional "buy spells" text
    hook_call(0x4b6283, print_scroll_reply, 6); // printing code
    patch_bytes(0x4b62bf, mov_scroll_reply_chunk, 5);
    hook_call(0x4bd302, restock_scrolls_hook, 5);
    hook_call(0x4b5ef0, check_scroll_bought, 7); // top shelf
    hook_call(0x4b5f65, check_scroll_bought, 7); // bottom shelf
    patch_byte(0x4b6001, CONV_BUY_SPELLS); // fix statusline
    hook_call(0x4bd361, check_scroll_bought_image, 7);
    hook_call(0x4b5fdb, check_scroll_bought_empty, 5);
    hook_call(0x4b609d, check_scroll_bought_reply, 7); // reply
    hook_call(0x4bdaf0, click_buy_scroll, 5);
    hook_call(0x4bdec0, check_scroll_bought_reply, 7); // buy
    hook_call(0x4b19bf, right_click_scroll, 7);
    hook_call(0x4b1a21, check_scroll_bought_hint, 7);
    hook_call(0x4b5f0c, sold_scrolls_height, 5); // top shelf
    hook_call(0x4b5f84, sold_scrolls_height, 5); // bottom shelf
    hook_call(0x4b5f26, sold_scrolls_height_mask, 5); // top shelf
    hook_call(0x4b5f9e, sold_scrolls_height_mask, 5); // bottom shelf
    hook_jump(0x4b5e3a, guild_restore_sp_hook);
    hook_call(0x4b6187, print_restore_sp, 8);
    hook_call(0x4b62a1, print_restore_sp_display, 8);
    // Remove SP heal from temples.
    erase_code(0x4b6f8f, 15); // SP loss no longer qualifies for healing
    erase_code(0x4b7564, 11); // and is not in fact restored
    // The next three hooks are in a jumptable.
    patch_pointer(0x4b3d51, add_order_reply); // weapon shop
    patch_pointer(0x4b3d55, add_order_reply); // armor shop
    // magic shop called from black_market_replies() below
    hook_call(0x4b937c, print_order_reply, 5); // weapon shop
    hook_call(0x4bab8f, print_order_reply, 5); // armor shop
    // magic shop called from print_bm_replies() below
    // Shift the replies down.
    patch_dword(0x4b9389, dword(0x4b9389) + 4); // weapon, the last reply
    patch_dword(0x4b93ac, dword(0x4b93ac) + 4); // weapon, replies loop
    patch_dword(0x4bab9c, dword(0x4bab9c) + 4); // armor, the last reply
    patch_dword(0x4babbe, dword(0x4babbe) + 4); // armor, replies loop
    patch_dword(0x4b524a, dword(0x4b524a) + 4); // magic, the last reply
    patch_dword(0x4b526d, dword(0x4b526d) + 4); // magic, replies loop
    hook_call(0x4b95a3, query_order, 6); // weapon shop
    hook_call(0x4badc3, query_order, 6); // armor shop
    hook_call(0x4b5477, query_order, 6); // magic shop
    hook_call(0x4416e3, disable_prompt_spell_icons, 5);
    hook_call(0x44517e, prompt_text_color, 5);
    hook_call(0x4452e9, complete_order_prompt, 5);
    patch_byte(0x4326dd, byte(0x4326dd) + 11); // do not reset screen to 0
    patch_byte(0x41c486, 50); // allow longer prompts
    hook_call(0x4bcb97, preload_order_images, 5);
    hook_call(0x4b1a32, right_click_order, 8);
    hook_call(0x4b1aae, right_click_order_hint, 7);
    // Slightly lower shop text so it won't overwrite shk name in extremis.
    patch_dword(0x4b921e, dword(0x4b921e) + 14); // weapon
    patch_dword(0x4bb052, dword(0x4bb052) + 14); // armor
    patch_dword(0x4baa28, dword(0x4baa28) + 14); // also armor (consistency)
    patch_dword(0x4b5705, dword(0x4b5705) + 14); // magic (consistency)
    hook_call(0x456ed3, read_std_craft_items, 7);
    hook_call(0x4570e2, read_spc_craft_items, 5);
    hook_call(0x4b1d63, leave_shop_no_response, 10);
    // Adjust some shops' treasure levels.
    for (int i = 1; i <= 11; i++) // not ei
      {
        WEAPON_SHOP_STD[i][0]++;
        if (i == 10) // castle shops are already resp. 2/4 and 3/4
            continue;
        WEAPON_SHOP_SPC[i][0]++;
        ARMOR_SHOP_STD[i][1][0]++;
        ARMOR_SHOP_SPC[i][1][0]++;
      }
    // keep top shelf one tlvl lower
    ARMOR_SHOP_SPC[0][0][0]--;
    ARMOR_SHOP_STD[10][0][0]--;
    ARMOR_SHOP_SPC[10][0][0]--;
    // why were surface bracada/deyja magic shops better than celeste/pit?
    MAGIC_SHOP_STD[4] = MAGIC_SHOP_STD[5] = 3; // bra/dey
    MAGIC_SHOP_SPC[4] = MAGIC_SHOP_SPC[5] = 4;
    MAGIC_SHOP_STD[6] = MAGIC_SHOP_STD[7] = 4; // cel/pit
    MAGIC_SHOP_SPC[6] = MAGIC_SHOP_SPC[7] = 5;
    for (int i = 2; i <= 8; i++) // not level 1/2
        POTION_SHOP_STD[i]++; // reagents
    // Also tweak the sold item types.
    // allow EI shop to teach dagger and sell knives
    WEAPON_SHOP_STD[0][3] = ITEM_TYPE_MISSILE; // both bows and knives
    WEAPON_SHOP_STD[0][2] = ITEM_TYPE_AXE; // move here from spc
    WEAPON_SHOP_SPC[0][1] = ITEM_TYPE_BOW; // swap with above
    WEAPON_SHOP_SPC[0][2] = ITEM_TYPE_DAGGER; // teach the skill
    WEAPON_SHOP_SPC[0][3] = ITEM_TYPE_WEAPON2; // still sell 2h axes/swords
    // celeste & pit weapon shops tried to teach everything,
    // but there's a hardcoded limit of 5 skills per shop
    WEAPON_SHOP_STD[4][3] = ITEM_TYPE_WEAPON; // no axe in cel
    WEAPON_SHOP_STD[4][4] = ITEM_TYPE_WEAPON2; // no bow either
    WEAPON_SHOP_SPC[4][4] = ITEM_TYPE_MISSILE; // also here
    WEAPON_SHOP_STD[5][2] = ITEM_TYPE_SPEAR; // pit is inverse
    WEAPON_SHOP_STD[5][3] = ITEM_TYPE_MACE; // (compared to cel)
    WEAPON_SHOP_SPC[5][2] = ITEM_TYPE_STAFF; // those were std
    WEAPON_SHOP_SPC[5][3] = ITEM_TYPE_AXE; // still taught here
    WEAPON_SHOP_STD[5][1] = ITEM_TYPE_WEAPON2; // no dagger in pit
    WEAPON_SHOP_STD[5][4] = ITEM_TYPE_MISSILE; // still knives
    WEAPON_SHOP_SPC[5][1] = ITEM_TYPE_WEAPON; // also no sword
    // sell some more 2h weapons in nighon
    WEAPON_SHOP_STD[6][4] = WEAPON_SHOP_SPC[6][4] = ITEM_TYPE_WEAPON2;
    // tatalia main shop only sold 1h melee and taught nothing
    WEAPON_SHOP_STD[7][2] = WEAPON_SHOP_SPC[7][2] = ITEM_TYPE_WEAPON2;
    WEAPON_SHOP_SPC[7][3] = ITEM_TYPE_SWORD; // the shop is "blades
    WEAPON_SHOP_SPC[7][4] = ITEM_TYPE_BOW; // and bows", so own it
    WEAPON_SHOP_STD[7][3] = ITEM_TYPE_DAGGER; // also blades
    WEAPON_SHOP_STD[7][4] = ITEM_TYPE_STAFF; // staff is too rare
    // sell cloaks and boots at all armor shops
    for (int i = 0; i <= 11; i++)
      {
        ARMOR_SHOP_STD[i][0][2] = ARMOR_SHOP_SPC[i][0][2] = ITEM_TYPE_CLOAK;
        ARMOR_SHOP_STD[i][0][4] = ARMOR_SHOP_SPC[i][0][4] = ITEM_TYPE_BOOTS;
      }
    hook_call(0x4bb126, clip_boots_to_screen, 5); // standard
    hook_call(0x4bb1e7, clip_boots_to_screen, 5); // special
    hook_call(0x4bd5a3, always_restock_bottles, 5);
    hook_call(0x4b242f, arcomage_hint_hook, 6);
    // Always show the restock timer.
    patch_dword(0x4b9a7e, 0x4b9a0a - 0x4b9a82); // weapon
    patch_dword(0x4bb31a, 0x4bb2a6 - 0x4bb31e); // armor
    patch_dword(0x4b5b2c, 0x4b5ab8 - 0x4b5b30); // magic
    patch_dword(0x4ba6d8, 0x4ba664 - 0x4ba6dc); // potion
    patch_dword(0x4b6084, 0x4b6013 - 0x4b6088); // guild
    // Fix armor shops treated as empty even with with some items remaining.
    patch_byte(0x4bb237, 8); // std
    patch_byte(0x4bb25c, 8); // spc
    hook_call(0x4bdf26, faster_shop_restock, 5);
    // Add another ship route between Tatalia and Evenmorn.
    // make space by removing some duplicate routes
    TRANSPORT[56-54][2] = TRANSPORT[56-54][3] = 3; // same as 8
    TRANSPORT[57-54][1] = TRANSPORT[57-54][2] = TRANSPORT[57-54][3] = 1; // 10
    // pirate ship
    TRANSPORT[71-54][0] = TRANSPORT[71-54][1] = TRANSPORT[71-54][2]
                        = TRANSPORT[71-54][3] = 26; // was unused
    // the trip back
    TRANSPORT[67-54][0] = 8; // like vanilla tatalia, but disabled w/o map
    TRANSPORT[67-54][1] = 10; // to the pirate island, also starts disabled
    // the routes themselves
    TRAVEL_ROUTES[26] = (struct travel_route) {
        .map_index = TRAVEL_ROUTES[18].map_index, // evenmorn
        .weekdays = { 1, 0, 1, 0, 1, 0, 0 }, // MWF
        .time = 3,
        .x = TRAVEL_ROUTES[18].x,
        .y = TRAVEL_ROUTES[18].y,
        .z = TRAVEL_ROUTES[18].z,
        .direction = TRAVEL_ROUTES[18].direction,
        .qbit = QBIT_PIRATE_SHIP,
    };
    memcpy(TRAVEL_ROUTES + 8, TRAVEL_ROUTES + 22, sizeof(struct travel_route));
    TRAVEL_ROUTES[8].qbit = QBIT_EVENMORN_MAP;
    TRAVEL_ROUTES[10] = (struct travel_route) {
        .map_index = TRAVEL_ROUTES[22].map_index, // tatalia
        .weekdays = { 0, 1, 0, 1, 0, 0, 1 }, // when it doesn't sail elsewhere
        .time = 3, .x = -19000, .y = 5900, .z = 209, .direction = 0,
        .qbit = QBIT_PIRATE_SHIP,
    };
    // Bug fix: the direction of 0 isn't respected.
    for (int i = 0; i <= 34; i++)
        if (TRAVEL_ROUTES[i].direction == 0)
            TRAVEL_ROUTES[i].direction = 1; // close enough
    // Set up the new ship house.
    HOUSE_MOVIES[20].name = HOUSE_MOVIES[19].name; // boat video
    HOUSE_MOVIES[20].portrait = 803; // some guy with eyepatch
    HOUSE_MOVIES[20].voice = 37; // unused warlock boat sounds
    // Same, but for the fake boat before getting permission.
    HOUSE_MOVIES[185].name = HOUSE_MOVIES[19].name;
    HOUSE_MOVIES[185].voice = 37;
    // Setup the house animation for the black market.
    HOUSE_MOVIES[17].type = 3; // magic shop
    HOUSE_MOVIES[17].voice = 35; // warlock armor
    patch_pointer(0x4b3d59, black_market_replies); // overrides magic shop code
    hook_call(0x4b330d, black_market_screens, 5);
    // different bgs in preload_order_images() above
    // armor screen clicks in click_buy_scroll() and right_click_order() above
    hook_call(0x4bd3ba, init_bm_armor_screen, 7);
    hook_call(0x492c3a, disable_bm_theft, 5);
    hook_call(0x4bd54b, restock_black_market_hook, 5);
    hook_call(0x4bd62c, black_market_weapon_spread, 6);
    hook_call(0x4b523d, print_bm_replies, 5);
    // Use the next store's inventory for BM armor, to prevent overlap.
    patch_dword(0x4bb50a, SHOP_SPECIAL_ITEMS + SIZE_ITEM * 12); // check empty
    patch_dword(0x4bb59c, SHOP_SPECIAL_ITEMS + SIZE_ITEM * 12); // mouseover
    patch_dword(0x4bb614, SHOP_SPECIAL_ITEMS + SIZE_ITEM * 12); // draw
    hook_call(0x4bdffa, buy_bm_armor, 7);
    // right-click in right_click_order_hint() above
    hook_call(0x4bd6bd, bmp_bm_armor, 7);
    hook_call(0x4bb6a1, clip_bm_boots_to_screen, 5);
    erase_code(0x4bb57e, 3); // preserve mouseover item var
    hook_call(0x4bb6ae, bm_armor_restock_msg, 6);
    // replies for stolen items enabled in check_for_negative_discount() above
    hook_call(0x4bda4e, bm_sell_stolen_items, 5); // overwrites mm7patch nop's
    hook_call(0x4b371a, black_market_skills, 7);
    hook_call(0x4b26ca, lasker_free_teaching, 7);
    hook_call(0x4b3f5e, lasker_teacher_text, 5);
    patch_word(0x4f075e, 0); // don't return wetsuits for now
    erase_code(0x490f01, 2); // for black market quest item sell text hook
    hook_call(0x48e026, store_stolen_items, 8);
    patch_dword(0x48dea1, LAST_PREFIX); // allow stealing robes etc.
    // Revert an MM7Patch hook that forbade theft with mon inventory full.
    // This will cause the face animation to still show on failed theft,
    // but with space for 16 extra stolen items it's unlikely in practice.
    patch_dword(0x48df0c, 0x8d08458b); // mov eax, [ebp+8]; lea...
    patch_word(0x48df10, 0xff48); // ...ecx, [eax-1]
    erase_code(0x4b2076, 53); // don't remove the topic on joining a guild
    hook_call(0x44581d, arena_prize_topic, 6);
    hook_call(0x4b2b56, greetings_in_shops, 6);
}

// Allow non-bouncing projectiles to trigger facets in Altar of Wishes.
// Necessary for the room 1 tic-tac-toe puzzle.
static void __declspec(naked) genie_projectile_trigger(void)
{
    asm
      {
        mov eax, 0x46bffe ; replaced call (returns 0 if proj destroyed)
        call eax ; ditto
        test eax, eax ; the check after the hook
        jnz quit
        mov ecx, dword ptr [CURRENT_MAP_ID]
        cmp ecx, dword ptr [genie_id]
        sete al
        quit:
        ret
      }
}

// Add genie.dlv to the save file at game start.
static void new_game_genie(void)
{
    // this really oughta be unhardcoded, but ehh
#define GENIE_DLV_SIZE 146281
    static const struct file_header header = { "genie.dlv", GENIE_DLV_SIZE };
    void *file = find_in_lod(GAMES_LOD, header.name, 1);
    char buffer[GENIE_DLV_SIZE];
    fread(buffer, 1, GENIE_DLV_SIZE, file);
    append_to_lod(SAVEGAME_LOD, &header, buffer);
}

// Hook for the above.
static void __declspec(naked) new_game_genie_hook(void)
{
    asm
      {
        mov eax, 0x461780 ; replaced call
        call eax
        call new_game_genie
        ret
      }
}

// Get the proper map ID when setting a Lloyd's Beacon inside the genie map.
static void __declspec(naked) set_genie_beacon(void)
{
    asm
      {
        mov eax, dword ptr [genie_id]
        cmp eax, dword ptr [CURRENT_MAP_ID]
        je genie
        mov eax, dword ptr [0x6a0b0c] ; replaced code
        ret
        genie:
        mov word ptr [esp+20], ax ; the map index
        add dword ptr [esp], 75 ; jump to set id code
        ret
      }
}

// Since the new map is not in the base games.lod, skip searching in there.
static void __declspec(naked) genie_beacon_map_name(void)
{
    asm
      {
        shr ecx, 5 ; restore map id
        cmp ecx, dword ptr [genie_id]
        je genie
        jmp dword ptr ds:uncased_strcmp ; replaced call
        genie:
        mov ebp, ecx ; return value
        xor eax, eax ; skip the other code
        ret
      }
}

// Also fix the two recall beacon checks that try to pull map name from there.
static void __declspec(naked) genie_recall_beacon_map_name(void)
{
    asm
      {
        pop ecx
        mov eax, dword ptr [esp+32] ; beacon struct, maybe
        mov ax, word ptr [eax+26] ; map id
        cmp ax, word ptr [genie_id]
        jne skip
        mov dword ptr [esp], offset map_altar_of_wishes
        skip:
        push CUR_MAP_FILENAME_ADDR ; replaced code
        jmp ecx
      }
}

// Relocated visible facet buffer.  Used just below.
#define FACET_LIMIT 4000
static int facet_array[FACET_LIMIT+1];

// For when we need both the original and relocated visible facet array ptrs.
static void __declspec(naked) substitute_facet_array(void)
{
    asm
      {
        inc dword ptr [ebx] ; old count
        mov ebx, offset facet_array
        mov dword ptr [ebx], eax ; new count
        mov word ptr [ebx+eax*4+4], dx ; replaced code
        ret
      }
}

// Extend the visible facet limit fore the new map.  Logic stolen from MMExt,
// and the code will only activate if the original was not already applied.
static void more_visible_facets(void)
{
    if (dword(0x4b136d) != 1000)
        return; // must be extended already; avoid conflicts
    patch_dword(0x4afebd, FACET_LIMIT);
    patch_dword(0x4b136d, FACET_LIMIT);
    static const uintptr_t refs[] = { 0x440b96, 0x440bc0, 0x440be4, 0x4b08de,
                                      0x4b08fa, 0x4c0cc4, 0x4c164b };
    for (int i = 0; i < sizeof(refs) / sizeof(uintptr_t); i++)
        patch_dword(refs[i], dword(refs[i]) - 0x51b5f8 + (int) &facet_array);
    hook_call(0x4afec7, substitute_facet_array, 5);
    hook_call(0x4b1377, substitute_facet_array, 5);
}

// Add one extra map to game data structures, using the empty 0th element.
static inline void one_more_map(void)
{
    erase_code(0x453fe9, 1); // mapstats.txt parse: start from 0
    patch_byte(0x4547e1, 4); // get_map_index function: start from 0
    patch_byte(0x454802, 0x7e); // jl -> jle (check last map)
    erase_code(0x476be1, 9); // npcdist.txt: don't fill map 0 with 10's
    patch_byte(0x476bc4, 0x7f); // jge -> jg (parse one more column)
    patch_dword(0x476bd9, dword(0x476bd9) - 64); // start from 0th map
    patch_dword(0x4774f1, dword(0x4774f1) - 64); // reading npcdist
    patch_dword(0x47750a, dword(0x47750a) - 64); // ditto
    // addresses taken from an MMExt script, with get_map_index calls removed
    static const int mapstats[] = {
        0x410dbb, 0x410dcb, 0x410fb2, 0x413c7a, 0x413f97, 0x41cc24, 0x42045c,
        0x42ec1c, 0x43331b, 0x43349c, 0x4334cd, 0x4334fb, 0x433969, 0x433b9f,
        0x433c1b, 0x4340d8, 0x438d72, 0x438e4e, 0x444577, 0x44496f, 0x4449d7,
        0x444bcb, 0x444d60, 0x444f02, 0x444f80, 0x448d7f, 0x450275, 0x4603c7,
        0x460b96, 0x47a404, 0x49595c, 0x497f94, 0x4abfe0, 0x4ac0d1, 0x4b2a1f,
        0x4b3518, 0x4b41ea, 0x4b69df, 0x4b6a91, 0x4b6de2, 0x4be05a, 0x433a78,
        0x433a7f, 0x433a86, 0x433a8d, 0x433a94, 0x433a9b };
    for (int idx = 0; idx < sizeof(mapstats) / sizeof(int); idx++)
        patch_dword(mapstats[idx], dword(mapstats[idx]) - SIZE_MAPSTAT);
    // map track reference at 0x4abf71 is tricky as it's overriden by mmext
    patch_word(0x4abf62, 0x9048); // dec eax; nop (adjust map index)
    patch_byte(0x4abf64, 0x7c); // jl ... (now "no map found" is -1)
    patch_byte(0x433b8a, 78); // update map count (some map change code)
    patch_byte(0x497f8a, 78); // ditto (perception glow check)
    hook_call(0x47184c, genie_projectile_trigger, 5);
    hook_call(0x460a07, new_game_genie_hook, 5);
    hook_call(0x433819, set_genie_beacon, 5);
    hook_call(0x410dbf, genie_beacon_map_name, 5);
    hook_call(0x433630, genie_recall_beacon_map_name, 5); // current map check
    hook_call(0x43369a, genie_recall_beacon_map_name, 5); // new map
}

// Provide names for new NPCs without discarding the old array.
static void __declspec(naked) new_hireling_names(void)
{
    asm
      {
        pop ecx
        cmp eax, LAST_OLD_NPC
        jg new
        push dword ptr [0x73c110+eax*4] ; replaced code
        jmp ecx
        new:
        push dword ptr [new_strings+STR_MOON_ACOLYTE*4+eax*4-LAST_OLD_NPC*4-4]
        jmp ecx
      }
}

// Only use two bytes for the per-area NPC chance totals.  Should be enough.
static void __declspec(naked) npcdist_totals_chunk(void)
{
    asm
      {
        xor ecx, ecx ; replaced code
        and word ptr [eax], cx ; changed from dword
      }
}

// Only use two bytes of the read totals (the rest are garbage).
static void __declspec(naked) truncate_npcdist_totals(void)
{
    asm
      {
        and ebx, 0xffff
        jmp dword ptr ds:random ; replaced call
      }
}

// Make sure to remove sacrificed house NPCs from the game forever.
// Overwrites a memset call, hence the three arguments.
static void *__cdecl sacrifice_hireling(struct npc *hireling, int c, int n)
{
    if (hireling->house)
        for (int i = dword(NPCS_LENGTH) - 1; i >= 0; i--)
            if (!strcmp(hireling->name, NPCS[i].name))
              {
                NPCS[i].house = 0;
                NPCS[i].bits &= ~NPC_HIRED;
                break;
              }
    return memset(hireling, c, n);
}

// Add a few more NPC professions and extend the relevant game arrays.
static inline void new_hireling_types(void)
{
    // replace parsed npcprof.txt; addresses actually taken from mmext
    patch_pointer(0x416B8F, &npcprof[0].description);
    patch_pointer(0x416BA3, &npcprof[0].join);
    patch_pointer(0x420CAB, &npcprof[0].cost);
    patch_pointer(0x44536E, &npcprof[0].action);
    // 0x44551D overwritten by delay_dismiss_hireling_reply()
    // 0x445526 overwritten by print_cook_reply()
    patch_pointer(0x445548, &npcprof[0].join);
    // 0x4455A7 also overwritten near delay_dismiss_hireling_reply()
    patch_pointer(0x4455B0, &npcprof[0].join);
    patch_pointer(0x49597F, &npcprof[0].cost);
    patch_pointer(0x4B1FE5, &npcprof[0].join);
    patch_pointer(0x4B228F, &npcprof[0].join);
    patch_pointer(0x4B2298, &npcprof[0].description);
    patch_pointer(0x4B22ED, &npcprof[0].cost);
    patch_pointer(0x4B2367, &npcprof[0].join);
    patch_pointer(0x4B3DDC, &npcprof[0].description);
    patch_pointer(0x4B4104, &npcprof[0].description);
    patch_pointer(0x4BC680, &npcprof[0].cost);
    patch_word(0x477183, 0xbb90); // nop; mov ebx, ...
    patch_pointer(0x477185, &npcprof[1].join); // npcprof parse
    patch_dword(0x477192, NPC_COUNT - 1); // ditto
    patch_dword(0x477261, NPC_COUNT); // count at the end
    patch_byte(0x476c17, NPC_COUNT); // npcdist parse
    patch_byte(0x476c37, NPC_COUNT); // calc totals
    hook_call(0x416c76, new_hireling_names, 7);
    hook_call(0x41e9da, new_hireling_names, 7);
    hook_call(0x445485, new_hireling_names, 7);
    hook_call(0x4b2b0d, new_hireling_names, 7);
    // Initiate was both Monk promotion and NPC.  Decouple.
    patch_pointer(0x453677, &new_strings[STR_SUN_INITIATE]);
    patch_pointer(0x476359, &new_strings[STR_SUN_INITIATE]);
    // sun/moon priest bonuses are in warlock_dark_bonus() above
    // Prevent Sun acolyte bonus from overwriting Moon bonus to Self.
    patch_dword(0x48f8d4, 0x02c68300 + byte(0x48f8d4)); // add esi, 2
    // ninja ability is in new_hireling_action() above
    // Create place in the npcdist array for the new NPCs.
    patch_dword(0x476bd9, dword(0x476bd9) - 3); // three more bytes
    patch_bytes(0x476c27, npcdist_totals_chunk, 5);
    patch_byte(0x476c31, 4 - 3); // three bytes earlier for totals
    hook_call(0x4774f5, truncate_npcdist_totals, 5);
    patch_dword(0x47750a, dword(0x47750a) - 2); // reading npcdist
    erase_code(0x477515, 1); // off by one
    hook_call(0x490c80, sacrifice_hireling, 5);
}

// The game could not properly display keys like F5 or ~ in the config menu.
// Some of these (like 1-6) do not actually work right, but whatever.
static int __stdcall more_key_names(char *buffer, int key)
{
    switch (key)
      {
        case 0:
            strcpy(buffer, "NONE"); // for the patch/mod keys only
            break;
        case VK_ESCAPE: // still opens the menu even if remapped
            strcpy(buffer, "ESC");
            break;
        case VK_F1:
        case VK_F2:
        case VK_F3:
        case VK_F4: // fullscreen, doesn't work well
        case VK_F5:
        case VK_F6:
        case VK_F7:
        case VK_F8:
        case VK_F9:
        case VK_F10: // doesn't work at all!
        case VK_F11:
        case VK_F12:
            sprintf(buffer, "F%d", key - VK_F1 + 1);
            break;
        case VK_OEM_3:
            buffer[0] = '~';
            goto single;
        case '1': // changing another key to 1-6 breaks both!
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
        case '0':
            buffer[0] = key;
            goto single;
        case VK_OEM_MINUS:
            buffer[0] = '_'; // '-' already taken
            goto single;
        case VK_OEM_PLUS:
            buffer[0] = '=';
            goto single;
        case VK_OEM_4:
            buffer[0] = '[';
            goto single;
        case VK_OEM_6:
            buffer[0] = ']';
        single:
            buffer[1] = 0;
            break;
        case VK_CAPITAL: // TODO: recheck this
            strcpy(buffer, "CAPS_LOCK");
            break;
        case VK_SHIFT: // does not work for most mappings
            strcpy(buffer, "SHIFT");
            break;
        case VK_LWIN:
            strcpy(buffer, "LOGO");
            break;
        case VK_RWIN:
            strcpy(buffer, "RLOGO");
            break;
        case VK_SNAPSHOT:
            strcpy(buffer, "PRINT_SCR");
            break;
        default:
            return FALSE;
      }
    return TRUE;
}

// Hook for the above.
static void __declspec(naked) more_key_names_hook(void)
{
    asm
      {
        push eax
        push esi
        call more_key_names
        test eax, eax
        jnz skip
        pop eax
        push 0x4e91dc ; replaced code
        jmp eax
        skip:
        add dword ptr [esp], 8 ; skip strcpy
        ret
      }
}

// Also recognize the new names when they're read from registry.
static int __cdecl parse_new_key_names(const char *name)
{
    if (!name[1])
      {
        int single = name[0];
        if (single >= 'A' && single <= 'Z' || single >= '0' && single <= '9')
            return single;
        switch (single)
          {
            case '~':
                return VK_OEM_3;
            case '_':
                return VK_OEM_MINUS;
            case '=':
                return VK_OEM_PLUS;
            case '[':
                return VK_OEM_4;
            case ']':
                return VK_OEM_6;
            default:
                return -1;
          }
      }
    if (!strcmp(name, "NONE"))
        return 0; // new hotkeys can be unset
    if (!strcmp(name, "ESC"))
        return VK_ESCAPE;
    if (!strcmp(name, "CAPS_LOCK"))
        return VK_CAPITAL;
    if (!strcmp(name, "SHIFT"))
        return VK_SHIFT;
    if (!strcmp(name, "LOGO"))
        return VK_LWIN;
    if (!strcmp(name, "RLOGO"))
        return VK_RWIN;
    if (!strcmp(name, "PRINT_SCR"))
        return VK_SNAPSHOT;
    if (name[0] == 'F')
      {
        int id = atoi(name + 1);
        if (id >= 1 && id <= 12)
            return VK_F1 + id - 1;
      }
    return -1;
}

// The extended key config screen data array (was [28] before).
static int config_keys[42];
// The loaded bitmap index for "page 3" pressed button image.
static int page_3_button;

// Draw the pressed button and print all the keys for the new, third page.
static void print_new_config_page(void)
{
    draw_background(DRAW_IMAGE_THIS, 19, 324, LOADED_BITMAPS[page_3_button]);
    void *dialog = pointer(DIALOG5);
    void *font = pointer(0x5c346c);
    static const char *const hotkeys[14] = { "STEP LEFT", "STEP RIGHT",
                                             "QUICK SAVE", "QUICK LOAD",
                                             "2X SPEED", "AUTORUN",
                                             "INVENTORY", "CHARACTER",
                                             "QUICK HEAL", "QUICK REPAIR",
                                             "CAST SPELL 2", "CAST SPELL 3",
                                             "CAST SPELL 4", "CAST SPELL 5" };
    for (int line = 0; line < 14; line++)
      {
        int y = line % 7, x = line / 7;
        print_string(dialog, font, 23 + x * 224, 142 + y * 21,
                     colors[CLR_WHITE], hotkeys[line], 0, 0, 0);
        print_string(dialog, font, 127 + x * 223, 142 + y * 21,
                     get_config_key_color(line + 28),
                     get_key_name(config_keys[line+28]), 0, 0, 0);
      }
}

// Hook for the above.
static void __declspec(naked) print_new_config_page_hook(void)
{
    asm
      {
        cmp dword ptr [0x506d88], 1 ; replaced code (current page)
        jb new_page ; our index is 0
        ret
        new_page:
        mov dword ptr [esp], 0x414d29 ; calling function end
        jmp print_new_config_page
      }
}

// Handle editing the keys on the new page.
static void __declspec(naked) third_page_field_press(void)
{
    asm
      {
        je first ; replaced jump
        ja second
        add eax, 14 ; total of 28
        second:
        add eax, 14 ; replaced code
        first:
        ret
      }
}

// Don't register two unmapped (zero) new keybindings as a conflict.
static void __declspec(naked) allow_empty_keys(void)
{
    asm
      {
        cmp esi, dword ptr [config_keys+eax*4] ; replaced code, almost
        jne ok
        test esi, esi
        jnz fail
        cmp ecx, 29
        ja ok
        cmp eax, 29
        ja ok
        fail:
        test ebx, ebx ; == 0
        ok:
        ret ; next op is jne
      }
}

// Register the [] strafing keys as repeatable.
static void __declspec(naked) smooth_strafing(void)
{
    asm
      {
        je ok ; replaced jump
        cmp eax, 26 ; replaced code
        je ok
        cmp eax, 28 ; step left
        je ok
        cmp eax, 29 ; step right
        ok:
        ret ; je is next
      }
}

// Remember the old keybindings so as not to write to registry needlessly.
static int old_step_left, old_step_right;

// Populate the extended keymap array with the current bindings.
// Also loads the 3rd page button gfx.
static void init_new_keys(void)
{
    for (int i = 0; i < HOTKEY_COUNT; i++)
        config_keys[30+i] = *hotkey_settings[i];
    old_step_left = dword(KEY_THIS + 12 + 28 * 4);
    old_step_right = dword(KEY_THIS + 12 + 29 * 4);
    page_3_button = load_bitmap(ICONS_LOD, "optkb_3", 2);
}

// Hook for the above.
static void __declspec(naked) init_new_keys_hook(void)
{
    asm
      {
        call init_new_keys
        xor eax, eax ; replaced code
        ret 48 ; stack fixup was replaced too
      }
}

// The names of registry entries for the new keybindings.
static const char *const registry_keys[] = {
    "KEY_QUICKSAVE", "KEY_QUICKLOAD", "KEY_2XSPEED", "KEY_AUTORUN",
    "KEY_INVENTORY", "KEY_CHARACTER", "KEY_QUICKHEAL", "KEY_QUICKREPAIR",
    "KEY_CASTSPELL2", "KEY_CASTSPELL3", "KEY_CASTSPELL4", "KEY_CASTSPELL5",
};

// Update and save the new keybindings on exiting the menu, also unload bitmap.
static void save_new_keys(void)
{
    if (old_step_left != config_keys[28])
        write_registry("KEY_STEPLEFT", config_keys[28] == VK_OEM_4 ? "DEFAULT"
                                              : get_key_name(config_keys[28]));
    if (old_step_right != config_keys[29])
        write_registry("KEY_STEPRIGHT", config_keys[29] == VK_OEM_6 ? "DEFAULT"
                                              : get_key_name(config_keys[29]));
    for (int i = 0; i < HOTKEY_COUNT; i++)
        if (*hotkey_settings[i] != config_keys[30+i])
          {
            write_registry(registry_keys[i], get_key_name(config_keys[30+i]));
            *hotkey_settings[i] = config_keys[30+i];
          }
    unload_bitmap(LOADED_BITMAPS[page_3_button]);
}

// Hook for the above.
static void __declspec(naked) save_new_keys_hook(void)
{
    asm
      {
        call save_new_keys
        mov ecx, KEY_THIS ; replaced code
        ret
      }
}

// For resetting the default values.
static int saved_hotkey_settings[8];

// Read the values stored in registry for the new keybindings.
static void read_registry_keys(void)
{
    char value[32];
    for (int i = 0; i < HOTKEY_COUNT; i++)
      {
        saved_hotkey_settings[i] = *hotkey_settings[i];
        read_registry(registry_keys[i], value, 32, "DEFAULT");
        if (strcmp(value, "DEFAULT"))
          {
            int parsed = parse_key_name(KEY_THIS, value);
            if (parsed != -1)
                *hotkey_settings[i] = parsed;
          }
      }
}

// Hook for the above.  Also sets the repeat flag for [] strafe keys.
static void __declspec(naked) read_registry_keys_hook(void)
{
    asm
      {
        push edi
        push 32
        call dword ptr ds:read_registry ; replaced call
        call read_registry_keys
        xor ebx, ebx ; smooth strafing
        ret
      }
}

// Unset all registry entries when pressing the "default" button.
static void default_new_keys(void)
{
    for (int i = 0; i < 8; i++)
      {
        write_registry(registry_keys[i], "DEFAULT");
        *hotkey_settings[i] = config_keys[30+i] = saved_hotkey_settings[i];
      }
    memset((void *) 0x506cec + 30, 0, 42 - 30); // conflict flags
}

// Hook for the above.
static void __declspec(naked) default_new_keys_hook(void)
{
    asm
      {
        call default_new_keys
        mov ecx, KEY_THIS ; replaced code
        ret
      }
}

// Disallow mapping to 1-6 because it breaks the game badly until restart.
// Also allow unsetting the new hotkeys, and forbid unrecognized keys.
static void __declspec(naked) forbid_character_keys(void)
{
    asm
      {
        movzx eax, byte ptr [0x69ad80] ; replaced code
        cmp eax, '1'
        jb ok
        cmp eax, '6'
        jbe buzz
        ok:
        cmp eax, VK_ESCAPE
        jne not_escape
        cmp dword ptr [0x506ce8], 30 ; hotkey id
        cmovae eax, ebx ; == 0
        ret
        not_escape:
        push eax
        call dword ptr ds:get_key_name
        push eax
        push 0x4e91dc ; "no key"
        call dword ptr ds:strcmp_ptr
        add esp, 8
        test eax, eax
        jne quit
        buzz:
        push ebx
        push ebx
        push ebx
        push ebx
        push -1
        push ebx
        push ebx
        push SOUND_BUZZ
        mov ecx, SOUND_THIS_ADDR
        call dword ptr ds:make_sound
        mov dword ptr [esp], 0x41439d ; past remap code
        quit:
        movzx eax, byte ptr [0x69ad80] ; restore
        mov edx, dword ptr [DIALOG5] ; ditto
        ret
      }
}

// Riding on a MM7Patch hook.  Requires care to emulate the original function.
static int __declspec(naked) __thiscall patch_active_player_check(void *player)
{
    asm
      {
        push ecx
        push ecx
        call dummy_call
        xor eax, eax ; must have failed for patch reasons
        ret
        dummy_call:
        push ebp
        mov ebp, esp
        push ebx
        push esi
        push edi
        call dword ptr ds:check_inactive_player
        test eax, eax
        jnz ok
        mov eax, 0x4685f6 ; inactive pc code
        jmp eax
        ok:
        leave
        add esp, 12
        ret
      }
}

// Get a bitfield of every active extra chest (except BoH).
static int get_active_chests(void)
{
    int result = 0;
    if (have_npc_hired(NPC_PORTER))
        result = 1 << 1;
    if (have_npc_hired(NPC_QUARTER_MASTER))
        result |= 1 << 2 | 1 << 3;
    if (have_npc_hired(NPC_GYPSY))
        result |= 1 << 4;
    if (NPCS[HORSE_HARMONDALE].bits & NPC_HIRED
        || NPCS[HORSE_DEYJA].bits & NPC_HIRED)
        result |= 1 << 5 | 1 << 6;
    else if (NPCS[HORSE_ERATHIA].bits & NPC_HIRED
             || NPCS[HORSE_TULAREAN].bits & NPC_HIRED)
        result |= 1 << 5;
    return result;
}

// Repurpose the vanilla delete-from-chest function for our new chests.
// NB: this bypasses a MM7Patch hook that fixes glitches from mid-game item
// size change; the bug shouldn't be applicable to my mod, unless misused.
static void __fastcall __declspec(naked) delete_extra_chest_item(int chest,
                                                                 int slot)
{
    asm
      {
        push ebp
        mov ebp, esp
        sub esp, 20
        push ebx
        push esi
        push edi
        mov dword ptr [ebp-8], ecx
        imul ecx, ecx, SIZE_CHEST
        movsx eax, word ptr [elemdata.extra_chests+ecx+edx*2].s_map_chest.slots
        lea ebx, [eax+eax*8]
        lea ebx, [elemdata.extra_chests+ecx+ebx*4-SIZE_ITEM].s_map_chest.items
        mov eax, offset elemdata.extra_chests - MAP_CHESTS_ADDR
        shr eax, 1
        add edx, eax
        mov dword ptr [ebp-12], edx
        mov edx, 9 ; chest width
        mov eax, 0x420af1 ; (part of) the vanilla func
        jmp eax
      }
}

// A new hotkey for chugging a healing potion.  Idea from MAW.
static void __fastcall quick_heal(int caster, int target)
{
    if (target < 0) return;
    struct player *player = &PARTY[target];
    int wounded = get_full_hp(player) - player->hp;
    if (wounded <= 0)
      {
        show_status_text(new_strings[STR_NOT_WOUNDED], 2);
        make_sound(SOUND_THIS, SOUND_BUZZ, 0, 0, -1, 0, 0, 0, 0);
        return;
      }
    int found_player = -2, found_slot, top_heal = -wounded;
    int chests = get_active_chests();
    replace_chest(-1);
    for (int p = -1; p < 4 + EXTRA_CHEST_COUNT; p++)
      {
        int limit = 14 * 9;
        if (p < 0)
            limit = 1; // no inner loop
        else if (p >= 4)
          {
            if (~chests & 1 << (p - 4))
                continue;
            limit = 9 * 9;
          }
        for (int i = limit - 1; i >= 0; i--)
          {
            struct item *check;
            if (p < 0)
                check = (void *) MOUSE_ITEM;
            else if (p < 4)
              {
                int slot = PARTY[p].inventory[i];
                if (slot <= 0)
                    continue;
                check = &PARTY[p].items[slot-1];
              }
            else
              {
                int slot = elemdata.extra_chests[p-4].slots[i];
                if (slot <= 0)
                    continue;
                check = &elemdata.extra_chests[p-4].items[slot-1];
              }
            int heal;
            switch (check->id)
              {
                case POTION_CURE_WOUNDS:
                    heal = check->bonus + 10 - wounded;
                    break;
                case POTION_DIVINE_CURE:
                    heal = check->bonus * 5 - wounded;
                    break;
                case POTION_ULTIMATE_CURE:
                    heal = check->bonus;
                    break;
                case BAG_OF_HOLDING:
                    if (check->flags & IFLAGS_ID)
                        chests |= 1 << BOH_CHEST_ID;
                    // fallthrough
                default:
                    continue;
              }
            // we want smallest overheal OR strongest non-full heal
            if (top_heal < 0 ? heal > top_heal : heal < top_heal && heal >= 0)
              {
                top_heal = heal;
                found_player = p;
                found_slot = i;
              }
          }
      }
    if (found_player == -2)
      {
        show_status_text(new_strings[STR_NO_HEALING_POTIONS], 2);
        make_sound(SOUND_THIS, SOUND_BUZZ, 0, 0, -1, 0, 0, 0, 0);
        return;
      }
    player->hp += top_heal + wounded; // assuming the player is not dead etc.
    show_face_animation(player, ANIM_SMILE, 0);
    make_sound(SOUND_THIS, SOUND_DRINK, 0, 0, -1, 0, 0, 0, 0);
    if (found_player < 0)
        remove_mouse_item(MOUSE_THIS);
    else if (found_player < 4)
        delete_backpack_item(PARTY + found_player, found_slot);
    else
        delete_extra_chest_item(found_player - 4, found_slot);
    recover_player(caster + 1, 100);
}

// Another hotkey that tries to repair every broken item carried by party.
static void quick_repair(void)
{
    int current = dword(CURRENT_PLAYER);
    if (!current)
        return;
    struct player *fixer = &PARTY[current-1];
    int total = 0, recover = 0, repaired = 0;
    int danger = byte(STATE_BITS) & 0x30; // enemies near
    int chests = get_active_chests();
    replace_chest(-1);
    for (int p = -1; p < 4 + EXTRA_CHEST_COUNT; p++)
      {
        int limit = PLAYER_MAX_ITEMS;
        if (p < 0)
            limit = 1; // no inner loop
        else if (p >= 4)
          {
            if (~chests & 1 << (p - 4))
                continue;
            limit = sizeof(elemdata.extra_chests[p-4].items) / SIZE_ITEM;
          }
        for (int i = 0; i < limit; i++)
          {
            struct item *item;
            if (p < 0)
                item = (void *) MOUSE_ITEM;
            else if (p < 4)
                item = &PARTY[p].items[i];
            else
                item = &elemdata.extra_chests[p-4].items[i];
            if (item->id == BAG_OF_HOLDING && item->flags & IFLAGS_ID)
                    chests |= 1 << BOH_CHEST_ID;
            if (item->flags & IFLAGS_BROKEN)
              {
                if (!total && !patch_active_player_check(fixer))
                    return;
                total++;
                int result = can_repair(fixer, item);
                if (!result)
                    continue;
                if (result == 1)
                  {
                    if (danger && recover)
                        continue;
                    recover++;
                  }
                item->flags &= ~IFLAGS_BROKEN;
                repaired++;
              }
          }
      }
    if (!total)
        return;
    show_face_animation(fixer, repaired ? ANIM_REPAIR : ANIM_REPAIR_FAIL, 0);
    elemdata.training[current-1][SKILL_REPAIR] += recover;
    if (recover)
        recover_player(current, recover * 100);
    char buffer[100];
    sprintf(buffer, new_strings[STR_QUICK_REPAIR], repaired, total);
    show_status_text(buffer, 2);
}

// Used just below to remember spell index between hooks.
static int quick_spell_type;

// React to pressing the mod-specific keys.  Main screen only!
static void __declspec(naked) new_hotkeys(void)
{
    asm
      {
        mov esi, 0x721458 ; replaced code
        push dword ptr [quick_heal_key]
        call dword ptr ds:check_key_pressed
        test al, al
        jz not_heal
        mov ecx, dword ptr [CURRENT_PLAYER]
        mov ecx, dword ptr [PC_POINTERS+ecx*4-4]
        call patch_active_player_check
        test eax, eax
        jz not_heal
        push dword ptr [CURRENT_PLAYER]
        dec dword ptr [esp]
        push SPL_QUICK_HEAL
        push ACTION_SCROLL
        mov ecx, ACTION_THIS_ADDR
        call dword ptr ds:add_action
        not_heal:
        push dword ptr [quick_repair_key]
        call dword ptr ds:check_key_pressed
        test al, al
        jz not_repair
        call quick_repair
        not_repair:
        push dword ptr [quick_spell_keys]
        call dword ptr ds:check_key_pressed
        test al, al
        jnz spell2
        push dword ptr [quick_spell_keys+4]
        call dword ptr ds:check_key_pressed
        test al, al
        jnz spell3
        push dword ptr [quick_spell_keys+8]
        call dword ptr ds:check_key_pressed
        test al, al
        jnz spell4
        push dword ptr [quick_spell_keys+12]
        call dword ptr ds:check_key_pressed
        test al, al
        jz skip
        inc edi
        spell4:
        inc edi
        spell3:
        inc edi
        spell2:
        inc edi
        skip:
        mov dword ptr [quick_spell_type], edi
        xor edi, edi ; restore
        ret
      }
}

// The loaded button graphics.
static void *quick_spell_loaded[8] = { NULL };
static const char *const quick_spell_bitmaps[] = {
    "quikspl2", "quikspl3", "quikspl4", "quikspl5",
    "quikspd2", "quikspd3", "quikspd4", "quikspd5",
};

// Register the spellbook buttons for setting quick spells 2-5.
static void __declspec(naked) extra_quick_spell_buttons(void)
{
    asm
      {
        mov dword ptr [0x506378], eax ; replaced code
        add ebx, 8
        load:
        push 2
        push dword ptr [quick_spell_bitmaps+ebx*4-4]
        mov ecx, ICONS_LOD_ADDR
        call dword ptr ds:load_bitmap
        lea eax, [eax+eax*8]
        lea eax, [LOADED_BITMAPS_ADDR+eax*8]
        mov dword ptr [quick_spell_loaded+ebx*4-4], eax
        dec ebx
        jnz load
        push ebx
        push ebp
        push ebx
        push ebx
        push ACTION_QUICK_SPELL_PRESS
        push ACTION_QUICK_SPELL_HINT
        push 1
        push 26
        push 23
        push 415
        push 517-24
        push esi
        call dword ptr ds:add_button
        add dword ptr [esp+4], 30+24
        inc dword ptr [esp+32]
        call dword ptr ds:add_button
        add dword ptr [esp+4], 24
        inc dword ptr [esp+32]
        call dword ptr ds:add_button
        add dword ptr [esp+4], 24
        inc dword ptr [esp+32]
        call dword ptr ds:add_button
        add esp, 48
        ret
      }
}

// Actually draw the new buttons.
// TODO: might want to spread them around if attack spell is disabled
static void draw_quick_spell_buttons(void)
{
    for (int i = 0; i < 4; i++)
        draw_background(DRAW_IMAGE_THIS, 517 - 24 + 24 * i + 30 * !!i, 415,
                        quick_spell_loaded[i+4*(i==pressed_quick_spell)]);
    pressed_quick_spell = -1; // reset
}

// Hook for the above.
static void __declspec(naked) draw_quick_spell_buttons_hook(void)
{
    asm
      {
        call draw_quick_spell_buttons
        mov eax, dword ptr [CURRENT_PLAYER] ; replaced code
        ret
      }
}

// Free the new buttons from memory when closing the spellbook.
static void __declspec(naked) unload_quick_spell_buttons(void)
{
    asm
      {
        mov esi, 8
        unload:
        mov ecx, dword ptr [quick_spell_loaded+esi*4-4]
        call dword ptr ds:unload_bitmap
        dec esi
        jnz unload
        mov esi, 0x5062d4 ; replaced code
        ret
      }
}

// Get the proper mouseover text for the new quick spell buttons.
static char *__stdcall get_quick_spell_hint(int button)
{
    int current = dword(CURRENT_PLAYER);
    if (!current--)
        return NULL;
    int quick = elemdata.quick_spells[current][button];
    int spell = dword(SELECTED_SPELL);
    if (spell)
        spell += PARTY[current].spellbook_page * 11;
    if (!quick && !spell)
        return GLOBAL_TXT[484]; // "select a spell and press button"
    if (quick == spell || !spell)
        return GLOBAL_TXT[584]; // "click to remove"
    static char buffer[100];
    sprintf(buffer, GLOBAL_TXT[483], pointer(SPELLS_TXT + spell * 36)); // name
    return buffer; // "set it as ready"
}

// Some shared code.
static int __declspec(naked) count_quick_spells(void)
{
    asm
      {
        setnz al ; true if vanilla quick spell set
        mov ecx, 4
        get_pc_id:
        cmp edx, dword ptr [PC_POINTERS+ecx*4-4]
        loopne get_pc_id
        shl ecx, 4
        mov edx, 3
        quick:
        cmp dword ptr [elemdata.quick_spells+ecx+edx*4], ebx ; == 0
        setnz ah
        add al, ah
        dec edx
        jge quick
        movzx eax, al
        ret
      }
}

// Used just below.
static const char x_of_5_qsp_format[] = "%s: %d / 5";
static const char x_of_5_short_format[] = "%d / 5";

// Just print "X/5 quick spells" on the stats screen until a right-click.
static void __declspec(naked) stat_screen_quick_spells(void)
{
    asm
      {
        mov edx, edi
        call count_quick_spells
        push eax
        push dword ptr [GLOBAL_TXT_ADDR+172*4]
#ifdef __clang__
        mov eax, offset x_of_5_qsp_format
        push eax
#else
        push offset x_of_5_qsp_format
#endif
        push esi
        call dword ptr ds:sprintf
        add esp, 16
        ret
      }
}

// Same, but for the quick reference screen.
static void __declspec(naked) quick_ref_quick_spells(void)
{
    asm
      {
        mov edx, ebp
        call count_quick_spells
        push eax
#ifdef __clang__
        mov eax, offset x_of_5_short_format
        push eax
#else
        push offset x_of_5_short_format
#endif
        push esi
        call dword ptr ds:sprintf
        add esp, 12
        mov eax, esi
        ret
      }
}

// How much to shift the active spell list down, based on quick spell count.
static int active_spell_offset;
// Composed in advance, so that we can know its height.
static char qspl_buffer[400];

// Print all the currently set quick spells.
static int __thiscall portrait_rmb_quick_spells(struct player *player)
{
    int qspell = player->quick_spell;
    int count = 0;
    int length = 0;
    for (int i = 0; i <= 4; i++)
      {
        count += !!qspell;
        if (qspell)
            length += sprintf(qspl_buffer + length, "\t130%s (%s)\n",
                              pointer(SPELLS_TXT + qspell * 36 + 4), // sh.name
                              get_key_name(i ? quick_spell_keys[i-1]
                                             : dword(KEY_THIS + 12 + 7 * 4)));
        qspell = elemdata.quick_spells[player-PARTY][i];
      }
    active_spell_offset = 0;
    if (!count)
        strcpy(qspl_buffer, GLOBAL_TXT[153]); // "none"
    else
        qspl_buffer[length-1] = 0; // remove the last '\n'
    static const int bounds[4] = { 0, 0, 1000, 1000 }; // whatever
    if (count > 1)
        active_spell_offset = get_text_height(pointer(ARRUS_FNT), qspl_buffer,
                                              bounds, 0, 0) - 30;
    return active_spell_offset;
}

// Hook for the above.
static void __declspec(naked) portrait_rmb_quick_spells_hook(void)
{
    asm
      {
        imul ebx, ecx ; replaced code
        push eax ; preserve
        mov ecx, esi
        call portrait_rmb_quick_spells
        add ebx, eax
        pop eax
        mov ecx, dword ptr [edi] ; also replaced code
        ret
      }
}

// Actually print the buffer when appropriate.
static void __declspec(naked) provide_qspl_buffer(void)
{
    asm
      {
#ifdef __clang__
        mov eax, offset qspl_buffer
        push eax
#else
        push offset qspl_buffer
#endif
        push ebx ; the rest of the text
        call dword ptr ds:strcat_ptr
        add esp, 8
        xor esi, esi ; replaced code
        ret 24 ; replaced stack fixup
      }
}

// In case of multi-line quick spell display, shift everything below downwards.
static void __declspec(naked) shift_active_spells_down(void)
{
    asm
      {
        add esi, 134 ; replaced code
        add esi, dword ptr [active_spell_offset]
        ret
      }
}

// Ditto, but for the "active spells" text itself.
static void __declspec(naked) shift_active_spell_header(void)
{
    asm
      {
        mov eax, dword ptr [active_spell_offset]
        add dword ptr [esp+8], eax ; print y
        jmp dword ptr ds:print_string ; replaced call
      }
}

// Also print the list of quick spells by right-clicking in the stats screen.
static char *__stdcall stats_rmb_quick_spells(char *description)
{
    static char buffer[1000];
    int current = dword(CURRENT_PLAYER) - 1;
    strcpy(buffer, description);
    char *rest = buffer + strlen(buffer);
    int qspell = PARTY[current].quick_spell;
    int found = FALSE;
    for (int i = 0; i <= 4; i++)
      {
        if (qspell)
          {
            found = TRUE;
            rest += sprintf(rest, "\n%s (%s)",
                            pointer(SPELLS_TXT + qspell * 36), // name
                            get_key_name(i ? quick_spell_keys[i-1]
                                           : dword(KEY_THIS + 12 + 7 * 4)));
          }
        qspell = elemdata.quick_spells[current][i];
      }
    if (!found)
      {
        *rest = '\n';
        strcpy(rest + 1, GLOBAL_TXT[153]); // "none"
      }
    return buffer;
}

// Hook for the above.
static void __declspec(naked) stats_rmb_quick_spells_hook(void)
{
    asm
      {
        mov dword ptr [ebp-4], eax ; replaced code
        push dword ptr [0x5c8998] ; static quick spell description
        call stats_rmb_quick_spells
        mov ebx, eax
        ret
      }
}

// Fall through to the quick spell code if any new key is pressed.
static void __declspec(naked) allow_extra_quick_spells(void)
{
    asm
      {
        cmp eax, 7 * 4 ; quick spell 1
        jne skip
        cmp dword ptr [quick_spell_type], edi ; == 0
        jz skip
        ret 4 ; al is nonzero
        skip:
        mov eax, dword ptr ds:check_key_pressed ; replaced call, almost
        sub eax, 17 ; but we don`t use the first few opcodes
        jmp eax
      }
}

// Fetch an appropriate quick spell, for now just for SP check etc. purposes.
static void __declspec(naked) provide_extra_quick_spell(void)
{
    asm
      {
        mov ecx, dword ptr [quick_spell_type]
        test ecx, ecx
        jnz extra
        mov bl, byte ptr [esi].s_player.quick_spell ; replaced code
        ret
        extra:
        lea ecx, [ecx+eax*4] ; eax is pc id
        mov ebx, dword ptr [elemdata.quick_spells+ecx*4-20]
        ret
      }
}

// Put the quick spell index into action param #2 (#1 is used by the patch).
static void __declspec(naked) quick_spell_param(void)
{
    asm
      {
        mov ecx, dword ptr [quick_spell_type]
        mov dword ptr [0x50c868+eax*4], ecx ; replaced code, almost
        ret
      }
}

// Now convert action param into the quick spell ID, and load a proper sound.
// Awkward place to hook, but MM7Patch already got the good one.
static void __declspec(naked) provide_quick_spell_for_action(void)
{
    asm
      {
        mov ebx, dword ptr [esp+56] ; action param 2
        test ebx, ebx
        jz skip
        lea ecx, [ebx+edx*4] ; pc id
        mov ecx, dword ptr [elemdata.quick_spells+ecx*4-4]
        skip:
        mov ebx, ecx ; spell id
        call dword ptr ds:aim_spell
        cmp dword ptr [esp+20], 0 ; 1 if attack spell
        jnz quit ; patch should load proper sound
        mov eax, dword ptr [CURRENT_PLAYER]
        imul ecx, eax, 0xafd8
        add ecx, 0xaa0ed8 - 0xafd8
        push eax
        push ebx
        call dword ptr ds:fetch_spell_sound
        quit:
        xor ebx, ebx ; restore
        mov eax, 0x4314ca ; post-action code
        jmp eax
      }
}

// Allow changing patch- and mod-specific hotkeys ingame.
// Also add the actual functionality to the mod hotkeys.
static inline void extra_key_config(void)
{
    hook_call(0x45afe3, more_key_names_hook, 5);
    hook_call(0x45ae44, parse_new_key_names, 5);
    erase_code(0x45ae4d, 20); // old A-Z key code
    hook_call(0x4143d0, print_new_config_page_hook, 7);
    hook_call(0x43156e, third_page_field_press, 5);
    patch_byte(0x431288, ACTION_THIRD_KEY_CONFIG_PAGE); // was "back"
    // Extend the configured keys array.
    static const uintptr_t refs[] = {
        0x414362, 0x414376, 0x4314bb, 0x4315b7, 0x4315dd,
        0x431621, 0x4324ac, 0x4324d0, 0x4324f4, 0x432531,
    };
    for (int i = 0; i < sizeof(refs) / sizeof(uintptr_t); i++)
        patch_pointer(refs[i], config_keys);
    // We also have one direct reference for every vanilla keybinding.
    static const uintptr_t keys[28] = {
        0x414432, 0x414484, 0x4144d5, 0x41452a, 0x41457d, 0x4145d1, 0x414623,
        0x414674, 0x4146c9, 0x41471d, 0x414771, 0x4147c5, 0x414815, 0x414865,
        0x4148cb, 0x41491e, 0x41496f, 0x4149c4, 0x414a17, 0x414a6b, 0x414abd,
        0x414b0e, 0x414b63, 0x414bb7, 0x414c0b, 0x414c5f, 0x414caf, 0x414cff,
    };
    for (int i = 0; i < 28; i++)
        patch_pointer(keys[i], config_keys + i);
    patch_byte(0x4314a7, 42 / 4); // extend the other array into the free space
    patch_byte(0x414359, 42 / 4 + 1); // also here (reset on remap)
    patch_byte(0x414394, 42); // loop that sets mapping conflict flags
    patch_byte(0x41439a, 42); // ditto
    patch_byte(0x432449, 42); // this loop checks for existing flags
    patch_byte(0x432543, 30); // add two hidden vanilla keybindings
    patch_byte(0x431633, 30); // also here (reset defaults)
    hook_call(0x41437a, allow_empty_keys, 7);
    hook_call(0x43251a, smooth_strafing, 5);
    hook_call(0x431495, init_new_keys_hook, 5);
    hook_call(0x43254a, save_new_keys_hook, 5);
    hook_call(0x45a8f1, read_registry_keys_hook, 5);
    hook_call(0x43158f, default_new_keys_hook, 5);
    hook_call(0x41434b, forbid_character_keys, 7);
    hook_call(0x42fc9d, new_hotkeys, 5);
    hook_call(0x4118da, extra_quick_spell_buttons, 5);
    hook_call(0x412b6f, draw_quick_spell_buttons_hook, 5);
    hook_call(0x4114a3, unload_quick_spell_buttons, 5);
    erase_code(0x418a5d, 22); // stats screen: don't fetch spell name
    hook_call(0x418a80, stat_screen_quick_spells, 5);
    erase_code(0x41aacf, 17); // same in the quick ref screen
    hook_call(0x41aae0, quick_ref_quick_spells, 5);
    patch_pointer(0x41d5d8, "%s: "); // don't print spell name yet
    hook_call(0x41d3c4, portrait_rmb_quick_spells_hook, 5);
    hook_call(0x41d5e9, provide_qspl_buffer, 5);
    hook_call(0x41d64b, shift_active_spells_down, 6);
    hook_call(0x41d6dc, shift_active_spell_header, 6);
    hook_call(0x41825d, stats_rmb_quick_spells_hook, 9);
    hook_call(0x42fcc3, allow_extra_quick_spells, 5);
    hook_call(0x4300a4, provide_extra_quick_spell, 6);
    hook_call(0x43014d, quick_spell_param, 7);
    hook_jump(0x433d47, provide_quick_spell_for_action);
}

// Display the damage numbers for unarmed-boosting gloves.
static void __declspec(naked) brass_knuckles_rmb(void)
{
    asm
      {
        cmp byte ptr [edi].s_items_txt_item.skill, SKILL_UNARMED
        je knuckles
        lea eax, [ebp-524] ; replaced code
        ret
        knuckles:
        pop eax
        movzx eax, byte ptr [edi].s_items_txt_item.mod1_dice_sides
        push eax
        movzx eax, byte ptr [edi].s_items_txt_item.mod1_dice_count
        push eax
        push dword ptr [GLOBAL_TXT_ADDR+53*4] ; "damage"
        push ecx ; full ac
        push dword ptr [GLOBAL_TXT_ADDR+11*4] ; "armor"
        mov ecx, 0x41dd28 ; to weapon stat code
        jmp ecx
      }
}

// Used just below.
static const char unarmed_skill[] = "unarmed";

// Recognize the unarmed skill in items.txt.
static void __declspec(naked) parse_unarmed_items(void)
{
    asm
      {
        push ebx
#ifdef __clang__
        mov eax, offset unarmed_skill
        push eax
#else
        push offset unarmed_skill
#endif
        call dword ptr ds:uncased_strcmp
        pop ecx
        pop ecx
        test eax, eax
        mov al, SKILL_UNARMED
        mov cl, SKILL_MISC ; this was in the replaced code
        cmove ecx, eax
        lea eax, [esi+esi*2]
        shl eax, 4
        mov byte ptr [edi+4+eax].s_items_txt_item.skill, cl ; replaced, almost
        ret
      }
}

// Substitute brass knuckle damage for the vanilla 1d3 unarmed die.
static void __declspec(naked) brass_knuckles_damage(void)
{
    asm
      {
        mov ecx, 3 ; replaced code, in spirit
        mov edx, dword ptr [edi+SLOT_GAUNTLETS*4].s_player.equipment
        test edx, edx
        jz skip
        lea edx, [edx+edx*8]
        lea edx, [edi+edx*4-SIZE_ITEM].s_player.items
        test byte ptr [edx].s_item.flags, IFLAGS_BROKEN
        jnz skip
        mov edx, dword ptr [edx]
        lea edx, [edx+edx*2]
        shl edx, 4
        cmp byte ptr [ITEMS_TXT_ADDR+edx].s_items_txt_item.skill, SKILL_UNARMED
        jne skip
        mov cl, byte ptr [ITEMS_TXT_ADDR+edx].s_items_txt_item.mod1_dice_sides
        skip:
        xor edx, edx ; replaced code, basically
        div ecx ; ditto
        ret
      }
}

// Also add the item quality to all unarmed damage evaluations.
// I had to reimplement some of the unarmed skill damage code here.
static void __declspec(naked) brass_knuckles_bonus(void)
{
    asm
      {
        and eax, SKILL_MASK
        xor edx, edx
        cmp ecx, SKILL_EXPERT
        cmovb eax, edx
        cmp ecx, SKILL_MASTER
        setae cl
        shl eax, cl
        test ebx, ebx ; tell the hooks apart
        jnz no_staff
        add eax, dword ptr [ebp-12] ; armsmaster dmg as per mm7patch
        no_staff:
        mov ecx, dword ptr [esi+SLOT_GAUNTLETS*4].s_player.equipment
        test ecx, ecx
        jz skip
        lea ecx, [ecx+ecx*8]
        lea ecx, [esi+ecx*4-SIZE_ITEM].s_player.items
        test byte ptr [ecx].s_item.flags, IFLAGS_BROKEN
        jnz skip
        mov ecx, dword ptr [ecx]
        lea ecx, [ecx+ecx*2]
        shl ecx, 4
        cmp byte ptr [ITEMS_TXT_ADDR+ecx].s_items_txt_item.skill, SKILL_UNARMED
        jne skip
        mov dl, byte ptr [ITEMS_TXT_ADDR+ecx].s_items_txt_item.mod2
        add eax, edx
        skip:
        mov ecx, 0x4900fa ; return from calling function
        jmp ecx
      }
}

// Also fix max damage for display purposes.
static void __declspec(naked) brass_knuckles_max_damage(void)
{
    asm
      {
        test eax, eax ; replaced check, in spirit
        jnz unarmed
        add dword ptr [esp], 8 ; replaced jump
        ret
        unarmed:
        mov edx, dword ptr [ebx+SLOT_GAUNTLETS*4].s_player.equipment
        test edx, edx
        jz skip
        lea edx, [edx+edx*8]
        lea edx, [ebx+edx*4-SIZE_ITEM].s_player.items
        test byte ptr [edx].s_item.flags, IFLAGS_BROKEN
        jnz skip
        mov edx, dword ptr [edx]
        lea edx, [edx+edx*2]
        shl edx, 4
        cmp byte ptr [ITEMS_TXT_ADDR+edx].s_items_txt_item.skill, SKILL_UNARMED
        jne skip
        movzx edi, byte ptr [ITEMS_TXT_ADDR+edx] \
                            .s_items_txt_item.mod1_dice_sides
        add dword ptr [esp], 3 ; after setting the damage
        skip:
        ret
      }
}

// Do not generate brass knuckles with numeric enchantments.
static void __declspec(naked) brass_knuckles_no_std(void)
{
    asm
      {
        cmp byte ptr [edi+4+eax].s_items_txt_item.skill, SKILL_UNARMED
        mov al, byte ptr [edi+4+eax].s_items_txt_item.equip_stat ; replaced
        jne skip
        cmp al, ITEM_TYPE_GAUNTLETS - 1
        je quit ; treat as weapon
        skip:
        cmp al, ITEM_TYPE_MISSILE - 1 ; also replaced code
        quit:
        ret
      }
}

// Activate brass knuckles damage or vampiric bonuses on eligible attacks.
static void __declspec(naked) brass_knuckles_elem_damage(void)
{
    asm
      {
        add dword ptr [ebp-36], 4 ; replaced code
        cmp dword ptr [ebp-28], 2 ; ditto, but changed
        jne quit
        mov ecx, edi ; the pc
        call dword ptr ds:is_bare_fisted
        test eax, eax
        jnz ok
        cmp word ptr [edi+SKILL_STAFF*2].s_player.skills, SKILL_GM
        jb skip
        push SLOT_MAIN_HAND
        mov ecx, edi
        call dword ptr ds:has_anything_in_slot
        test eax, eax
        jz skip
        push SLOT_MAIN_HAND
        mov ecx, edi
        call dword ptr ds:equipped_item_skill
        cmp eax, SKILL_STAFF
        jne skip
        ok:
        push SLOT_GAUNTLETS
        mov ecx, edi
        call dword ptr ds:equipped_item_skill
        cmp eax, SKILL_UNARMED
        jnz skip
        add dword ptr [ebp-28], SLOT_GAUNTLETS - 2
        add dword ptr [ebp-36], SLOT_GAUNTLETS * 4 - 2 * 4
        xor eax, eax ; set zf
        quit:
        ret
        skip:
        test edi, edi ; set greater
        ret
      }
}

// Let brass knuckles be affected by temporary enchantment spells.
static void __declspec(naked) brass_knuckles_aura_spells(void)
{
    asm
      {
        cmp byte ptr [eax].s_items_txt_item.skill, SKILL_UNARMED
        mov al, byte ptr [eax].s_items_txt_item.equip_stat ; replaced code
        jne skip
        cmp al, ITEM_TYPE_GAUNTLETS - 1
        je quit
        skip:
        test al, al ; replaced code
        quit:
        ret
      }
}

// Ditto, but for potions (except for the swift potion).
static void __declspec(naked) brass_knuckles_weapon_potions(void)
{
    asm
      {
        je quit ; replaced jump
        cmp dword ptr [ebp-4], ITEM_TYPE_WEAPON2 - 1 ; replaced code
        je quit
        cmp dword ptr [ebp-4], ITEM_TYPE_GAUNTLETS - 1
        jne quit
        mov edx, dword ptr [esi]
        lea edx, [edx+edx*2]
        shl edx, 4
        cmp byte ptr [ITEMS_TXT_ADDR+edx].s_items_txt_item.skill, SKILL_UNARMED
        quit:
        ret
      }
}


// Add a new type of gauntlet that strengthens the Monk class.
static inline void brass_knuckles(void)
{
    hook_call(0x41dcd3, brass_knuckles_rmb, 6);
    hook_call(0x4576e3, parse_unarmed_items, 5);
    hook_call(0x48cde7, brass_knuckles_damage, 6);
    hook_jump(0x48fd62, brass_knuckles_bonus); // bare-handed
    patch_word(0x48fe36, 0xdb31); // xor ebx, ebx; tell the hooks apart
    hook_jump(0x48fe38, brass_knuckles_bonus); // staff gm
    hook_call(0x48ed1f, brass_knuckles_max_damage, 5);
    hook_call(0x456a34, brass_knuckles_no_std, 6);
    hook_call(0x439a17, brass_knuckles_elem_damage, 8);
    hook_call(0x429104, brass_knuckles_aura_spells, 5); // fire aura etc.
    hook_call(0x42de36, brass_knuckles_aura_spells, 5); // vampiric weapon
    hook_call(0x416920, brass_knuckles_weapon_potions, 6); // white potions
    hook_call(0x416860, brass_knuckles_weapon_potions, 6); // slaying potion
}

#define BOUNTY_MONSTER 0xacd588
#define BOUNTY_DEADLINE 0xacce74
#define BOUNTY_COMPLETE 0xacd592
// The start of our new ten dynamic autonotes.
#define FIRST_BOUNTY_AUTONOTE 204

// Check whether we need to display dynamic autonotes for town hall bounties.
static void __declspec(naked) bounty_autonotes(void)
{
    asm
      {
        cmp edx, FIRST_BOUNTY_AUTONOTE
        jb skip
        cmp edx, FIRST_BOUNTY_AUTONOTE + 10
        jb bounty
        skip:
        jmp dword ptr ds:check_bit ; replaced call
        bounty:
        sub edx, FIRST_BOUNTY_AUTONOTE
        shr edx, 1
        sbb ecx, ecx
        cmp word ptr [BOUNTY_MONSTER+edx*2], 0
        jz fail
        mov eax, dword ptr [BOUNTY_DEADLINE+edx*8+4]
        cmp eax, dword ptr [CURRENT_TIME_ADDR+4]
        jg ok
        jl fail
        mov eax, dword ptr [BOUNTY_DEADLINE+edx*8]
        cmp eax, dword ptr [CURRENT_TIME_ADDR]
        jb fail
        ok:
        xor eax, eax
        add cx, word ptr [BOUNTY_COMPLETE+edx*2]
        setz al
        ret
        fail:
        xor eax, eax
        ret
      }
}

// Used just below.
static char bounty_buffer[200];

// Actually format the dynamic autonotes for printing.
static void __declspec(naked) print_bounty_autonote(void)
{
    asm
      {
        sub eax, FIRST_BOUNTY_AUTONOTE
        jb skip
        cmp eax, 10
        jae skip
        shr eax, 1
        sbb ecx, ecx
        movzx edx, word ptr [BOUNTY_MONSTER+eax*2]
        imul edx, edx, 88 ; sizeof(monsters_txt_item)
        movzx eax, byte ptr [MONSTERS_TXT+edx-44].s_map_monster.level
        imul eax, eax, 100
        mov edx, dword ptr [MONSTERS_TXT+edx-44].s_map_monster.name
        test ecx, ecx
        jz ok
        xchg eax, edx
        ok:
        mov ecx, offset bounty_buffer
        mov dword ptr [esp+16], ecx
        push eax
        push edx
        push edi ; raw autonote text
        mov edi, ecx ; for height calc
        push ecx
        call dword ptr ds:sprintf
        add esp, 16
        lea ecx, [esp+52] ; restore
        mov edx, dword ptr [0x5c3460] ; ditto
        skip:
        jmp dword ptr ds:print_string ; replaced call
      }
}

// Trigger all the new autonote animations when a new bounty is given.
static void __declspec(naked) new_bounty_autonote(void)
{
    asm
      {
        mov ecx, dword ptr [CURRENT_PLAYER]
        mov ecx, dword ptr [PC_POINTERS+ecx*4-4]
        push ebp ; == 0
        push ANIM_AWARD
        call dword ptr ds:show_face_animation
        mov edx, dword ptr [CURRENT_PLAYER]
        dec edx
        push edx
        push SPAN_EVT_SET
        mov ecx, dword ptr [CGAME]
        mov ecx, dword ptr [ecx+0xe50]
        call dword ptr ds:spell_face_anim
        push ebp
        push ebp
        push ebp
        push ebp
        push -1
        push ebp
        push ebp
        push SOUND_QUEST
        mov ecx, SOUND_THIS_ADDR
        call dword ptr ds:make_sound
        mov byte ptr [BLINK_AUTONOTES], 1
        mov dword ptr [AUTONOTES_PAGE], 4 ; traders page
        jmp dword ptr ds:random ; replaced call
      }
}

// Mark whether the player's just completed a bounty.
// Checked in harvest_seed() above.
static void __declspec(naked) check_bounty_kill(void)
{
    asm
      {
        cmp word ptr [eax], 0 ; bounty flag
        jnz quit
        inc word ptr [eax] ; replaced code, in spirit
        inc dword ptr [bounty_completed]
        quit:
        ret
      }
}

// Expand the autonotes text/category array.
static inline void more_autonotes(void)
{
    // NB: the array is 0-based, although the 0th entry is unused
#define AUTONOTE_COUNT 216
    static struct { char *text; int category; } autonote_txt[AUTONOTE_COUNT];
    static const int references[] = { 0x412656, 0x412665, 0x4137DC, 0x4137F1,
                                      0x41392B, 0x44ACE1, 0x44ACFC, 0x44B6A6,
                                      0x44B6C4, 0x476797 };
    for (int idx = 0; idx < sizeof(references) / sizeof(int); idx++)
        patch_dword(references[idx],
                    dword(references[idx]) - 0x723598 + (int) autonote_txt);
    patch_dword(0x47689D, (int) &autonote_txt[AUTONOTE_COUNT].category);
    patch_dword(0x412648, AUTONOTE_COUNT);
    patch_dword(0x413827, AUTONOTE_COUNT);
    patch_byte(0x44a0e2, 0x90); // fix broken autonote cmp
    patch_byte(0x44bfd6, 0); // also sub
    patch_pointer(0x476821, "misc"); // move barrels/cauldrons to the seer tab
    hook_call(0x412676, bounty_autonotes, 5); // initial open
    hook_call(0x413802, bounty_autonotes, 5); // changing pages
    hook_call(0x41393a, print_bounty_autonote, 5);
    hook_call(0x4bcd07, new_bounty_autonote, 5);
    hook_call(0x402dfe, check_bounty_kill, 5);
}

BOOL WINAPI DllMain(HINSTANCE const instance, DWORD const reason,
                    LPVOID const reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
      {
#ifdef CHECK_OVERWRITE
        owlog = fopen("overwrt.log", "w");
        binary = fopen("mm7.exe", "rb");
#endif
        spells_txt();
        monsters_txt();
        skip_monster_res();
        elemental_weapons();
        special_spell_elements();
        condition_resistances();
        undead_immunities();
        global_txt();
        new_potions();
        temp_enchants();
        misc_items();
        throw_potions();
        misc_spells();
        zombie_stuff();
        new_monster_spells();
        reputation();
        expand_global_evt();
        hp_sp_burnout();
        misc_rules();
        cure_spells();
        debuff_spells();
        spcitems_buffer();
        new_enchants();
        new_artifacts();
        ranged_blasters();
        wand_charges();
        damage_messages();
        npc_dialog();
        racial_traits();
        class_changes();
        skill_changes();
        patch_compatibility();
        new_enchant_item_types();
        throwing_knives();
        difficulty_level();
        horses();
        balance_tweaks();
        shop_changes();
        one_more_map();
        new_hireling_types();
        extra_key_config();
        brass_knuckles();
        more_autonotes();
      }
    return TRUE;
}
