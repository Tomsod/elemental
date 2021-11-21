#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define byte(address) (*(uint8_t *) (address))
#define word(address) (*(uint16_t *) (address))
#define dword(address) (*(uint32_t *) (address))

static void patch_byte(uintptr_t address, uint8_t value)
{
    DWORD OldProtect;
    VirtualProtect((LPVOID) address, 1, PAGE_EXECUTE_READWRITE, &OldProtect);
    byte(address) = value;
    VirtualProtect((LPVOID) address, 1, OldProtect, &OldProtect);
}

static void patch_word(uintptr_t address, uint16_t value)
{
    DWORD OldProtect;
    VirtualProtect((LPVOID) address, 2, PAGE_EXECUTE_READWRITE, &OldProtect);
    word(address) = value;
    VirtualProtect((LPVOID) address, 2, OldProtect, &OldProtect);
}

static void patch_dword(uintptr_t address, uint32_t value)
{
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
    DWORD OldProtect;
    VirtualProtect((LPVOID) address, size, PAGE_EXECUTE_READWRITE,
                   &OldProtect);
    memcpy((void *) address, src, size);
    VirtualProtect((LPVOID) address, size, OldProtect, &OldProtect);
}

typedef void *funcptr_t;

static void hook_jump(uintptr_t address, funcptr_t func)
{
    patch_byte(address, 0xe9);
    patch_dword(address + 1, (uintptr_t) func - address - 5);
}

static void hook_call(uintptr_t address, funcptr_t func, int length)
{
    DWORD OldProtect;
    VirtualProtect((LPVOID) address, length, PAGE_EXECUTE_READWRITE,
                   &OldProtect);
    byte(address) = 0xe8;
    dword(address + 1) = (uintptr_t) func - address - 5;
    if (length > 5)
        memset((void *) (address + 5), 0x90, length - 5);
    VirtualProtect((LPVOID) address, length, OldProtect, &OldProtect);
}

static void erase_code(uintptr_t address, int length)
{
    DWORD OldProtect;
    VirtualProtect((LPVOID) address, length, PAGE_EXECUTE_READWRITE,
                   &OldProtect);
    memset((void *) address, 0x90, length);
    if (length >= 2)
      {
        byte(address) = 0xeb;
        byte(address + 1) = length - 2;
      }
    VirtualProtect((LPVOID) address, length, OldProtect, &OldProtect);
}

// Some tricks to sidestep clang bugs.
#ifdef __clang__
#define STATIC
#define FIX(token) static const int _##token
#define REF(token) _##token
#else
#define STATIC static
#define FIX(token)
#define REF(token) token
#endif

//---------------------------------------------------------------------------//

enum elements
{
    FIRE = 0,
    ELECTRICITY = 1,
    COLD = 2,
    POISON = 3,
    PHYSICAL = 4,
    HOLY = 6,
    MIND = 7,
    MAGIC = 8,
    ENERGY = 9,
    FIRE_POISON = 10,
};

#define IMMUNE 200

#define GLOBAL_TXT 0x5e4000

enum spcitems_txt
{
    SPC_CARNAGE = 3,
    SPC_FROST = 5,
    SPC_ICE = 6,
    SPC_SPARKS = 7,
    SPC_LIGHTNING = 8,
    SPC_FLAME = 11,
    SPC_INFERNOS = 12,
    SPC_POISON = 13,
    SPC_VENOM = 14,
    SPC_VAMPIRIC = 16,
    SPC_DRAGON_SLAYING = 40,
    SPC_DARKNESS = 41,
    SPC_DRAGON = 46,
    SPC_SWIFT = 59,
    SPC_UNDEAD_SLAYING = 64,
    SPC_DAVID = 65,
    SPC_ASSASSINS = 67,
    SPC_BARBARIANS = 68,
    // 73+ are my addition
    SPC_SPECTRAL = 73,
    SPC_CURSED = 74,
    SPC_WRAITH = 75,
    SPC_SOUL_STEALING = 76,
    SPC_BACKSTABBING = 77,
    SPC_LIGHTWEIGHT = 78,
    SPC_LEAPING = 79,
    SPC_PERMANENCE = 80,
    SPC_STURDY = 81,
    SPC_COUNT = 81,
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
    STAT_FIRE_RES = 10,
    STAT_POISON_RES = 13,
    STAT_MELEE_DAMAGE_BASE = 26,
    STAT_HOLY_RES = 33,
    STAT_FIRE_POISON_RES = 47,
};

enum class
{
    CLASS_CHAMPION = 2,
    CLASS_BLACK_KNIGHT = 3,
    CLASS_MONK = 8,
    CLASS_MASTER = 10,
    CLASS_SNIPER = 19,
    CLASS_LICH = 35,
    CLASS_COUNT = 36,
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

#define IFLAGS_ID 1
#define IFLAGS_BROKEN 2

struct __attribute__((packed)) spell_buff
{
    uint64_t expire_time;
    uint16_t power;
    uint16_t skill;
    uint16_t overlay_id;
    uint8_t caster;
    uint8_t bits;
};

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
    SKILL_BLASTER = 7,
    SKILL_SHIELD = 8,
    SKILL_LEATHER = 9,
    SKILL_CHAIN = 10,
    SKILL_PLATE = 11,
    SKILL_AIR = 13,
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
    SKILL_THIEVERY = 34,
    SKILL_ALCHEMY = 35,
    SKILL_LEARNING = 36,
    SKILL_NONE = 37, // used by clubs
    SKILL_COUNT = 37,
};

#define PLAYER_MAX_ITEMS 138

struct __attribute__((packed)) player
{
    uint64_t conditions[20];
    SKIP(8);
    char name[16];
    SKIP(1);
    uint8_t class;
    SKIP(2);
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
    SKIP(2);
    uint16_t level_base;
    SKIP(44);
    uint16_t skills[SKILL_COUNT];
    SKIP(166);
    uint32_t black_potions[7];
    struct item items[PLAYER_MAX_ITEMS];
    uint32_t inventory[14*9];
    uint16_t fire_res_base;
    uint16_t shock_res_base;
    uint16_t cold_res_base;
    uint16_t poison_res_base;
    SKIP(6);
    uint16_t mind_res_base;
    uint16_t magic_res_base;
    SKIP(26);
    struct spell_buff spell_buffs[24];
    SKIP(32);
    int32_t sp;
    SKIP(4);
    uint32_t equipment[16];
    SKIP(272);
    int8_t hp_bonus;
    SKIP(1);
    int8_t sp_bonus;
    SKIP(161);
};

enum player_buffs
{
    PBUFF_FIRE_RES = 5,
    PBUFF_SHOCK_RES = 0,
    PBUFF_COLD_RES = 22,
    PBUFF_POISON_RES = 2,
    PBUFF_MIND_RES = 9,
    PBUFF_MAGIC_RES = 3,
    PBUFF_PAIN_REFLECTION = 10,
    PBUFF_PRESERVATION = 11,
};

enum skill_mastery
{
    NORMAL = 1,
    EXPERT = 2,
    MASTER = 3,
    GM = 4,
    // we mark the elemental immunity buffs
    // with a special mastery level of 5
    IMMUNITY_MARKER = 5,
};

#define MOUSE_ITEM 0xad458c

enum items
{
    BLASTER = 64,
    BLASTER_RIFLE = 65,
    STEEL_CHAIN_MAIL = 72,
    LAST_BODY_ARMOR = 78, // noble plate armor
    LAST_PREFIX = 134, // can be prefixed (sun amulet)
    FIRST_WAND = 135,
    LAST_WAND = 159,
    FIRST_REAGENT = 200,
    LAST_REAGENT = 214, // not counting gray
    FIRST_GRAY_REAGENT = 215,
    LAST_GRAY_REAGENT = 219,
    POTION_BOTTLE = 220,
    CATALYST = 221,
    FIRST_POTION = 222,
    FIRST_COMPLEX_POTION = 225,
    FIRST_LAYERED_POTION = 228,
    FIRST_WHITE_POTION = 240,
    FLAMING_POTION = 246,
    FREEZING_POTION = 247,
    NOXIOUS_POTION = 248,
    SHOCKING_POTION = 249,
    SWIFT_POTION = 250,
    FIRST_BLACK_POTION = 262,
    PURE_LUCK = 264,
    LAST_OLD_POTION = 271,
    POTION_MAGIC_IMMUNITY = 277,
    POTION_PAIN_REFLECTION = 278,
    LAST_POTION = 278,
    HOLY_WATER = 279, // not a potion
    PUCK = 500,
    CORSAIR = 503,
    GOVERNOR_S_ARMOR = 504,
    SPLITTER = 506,
    GHOULSBANE = 507,
    GIBBET = 508,
    CHARELE = 509,
    OLD_NICK = 517,
    KELEBRIM = 520,
    PHYNAXIAN_CROWN = 523,
    TWILIGHT = 525,
    JUSTICE = 527,
    HERMES_SANDALS = 529,
    ELFBANE = 531,
    MIND_S_EYE = 532,
    ELVEN_CHAINMAIL = 533,
    FORGE_GAUNTLETS = 534,
    SACRIFICIAL_DAGGER = 553,
    RED_DRAGON_SCALE_MAIL = 554,
    RED_DRAGON_SCALE_SHIELD = 555,
    FIRST_RECIPE = 740,
    LAST_RECIPE = 778,
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
};

#define BUFF_STRINGS 0x506798

#define TEMP_ENCH_MARKER 0xff

enum monster_group
{
    MG_UNDEAD = 1,
    MG_DEMON = 2,
    MG_DRAGON = 3,
    MG_TITAN = 7,
};

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
    SKIP(4);
    char *name;
    char *generic_name;
    SKIP(17);
    uint8_t skill;
    uint8_t mod1_dice_count;
    SKIP(1);
    uint8_t mod2;
    SKIP(15);
};

#define ITEMS_TXT_ADDR 0x5d2864
#define ITEMS_TXT ((struct items_txt_item *) ITEMS_TXT_ADDR)

#define AUTONOTES ((uint8_t *) 0xacd636)

enum face_animations
{
    ANIM_ID_FAIL = 9,
    ANIM_MIX_POTION = 16,
    ANIM_SMILE = 36,
    ANIM_SHAKE_HEAD = 67,
};

#define SOUND_BUZZ 27
#define SOUND_SPELL_FAIL 209
#define SOUND_DIE 18100

#define EVT_AUTONOTES 223
// my additions
#define EVT_REP_GROUP 400
#define EVT_DISABLED_SPELL 401

enum gender
{
    GENDER_MASCULINE = 0,
    GENDER_FEMININE,
    GENDER_NEUTER,
    GENDER_PLURAL,
};

#define EVENTS_LOD ((void *) 0x6be8d8)
#define SAVEGAME_LOD ((void *) 0x6a06a0)

#define MAP_VARS 0x5e4b10

// Number of barrels in the Wall of Mist.
#define WOM_BARREL_CNT 15

#define QBIT_LIGHT_PATH 99
#define QBIT_DARK_PATH 100
// my addition
#define QBIT_REFILL_WOM_BARRELS 350

// Not quite sure what this is, but it holds aimed spell data.
struct __attribute__((packed)) dialog_param
{
    uint16_t spell;
    uint16_t player;
    SKIP(6);
    uint16_t skill; // 0 if cast from spellbook
    SKIP(8);
};

enum objlist
{
    OBJ_FIREARROW = 550,
    OBJ_LASER = 555,
    OBJ_ACID_BURST = 3060,
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
};

#define ELEMENT(spell) byte(0x5cbecc + (spell) * 0x24)

#define PARTY_BUFFS 0xacd6c4

enum party_buffs
{
    BUFF_FEATHER_FALL = 5,
    BUFF_IMMOLATION = 10,
    BUFF_WATER_WALK = 18,
    BUFF_WIZARD_EYE = 19,
};

enum stditems_txt
{
    STD_ARMS = 22,
    STD_FIST = 24,
};

struct __attribute((packed)) spell_info
{
    SKIP(8);
    uint16_t cost_gm;
    uint16_t delay_normal;
    uint16_t delay_expert;
    SKIP(2);
    uint16_t delay_gm;
    uint8_t damage_fixed;
    uint8_t damage_dice;
};

#define SPELL_INFO ((struct spell_info *) 0x4e3c46)

enum spells
{
    SPL_TORCH_LIGHT = 1,
    SPL_FIRE_BOLT = 2,
    SPL_FIRE_AURA = 4,
    SPL_FIREBALL = 6,
    SPL_IMMOLATION = 8,
    SPL_WIZARD_EYE = 12,
    SPL_FEATHER_FALL = 13,
    SPL_RECHARGE_ITEM = 28,
    SPL_ENCHANT_ITEM = 30,
    SPL_ICE_BLAST = 32,
    SPL_STUN = 34,
    SPL_SLOW = 35,
    SPL_MASS_DISTORTION = 44,
    SPL_SPECTRAL_WEAPON = 47,
    SPL_TURN_UNDEAD = 48,
    SPL_SPIRIT_LASH = 52,
    SPL_REMOVE_FEAR = 56,
    SPL_BERSERK = 62,
    SPL_CURE_WEAKNESS = 67,
    SPL_HEAL = 68,
    SPL_FLYING_FIST = 76,
    SPL_LIGHT_BOLT = 78,
    SPL_DESTROY_UNDEAD = 79,
    SPL_DISPEL_MAGIC = 80,
    SPL_PARALYZE = 81,
    SPL_VAMPIRIC_WEAPON = 91,
    SPL_SHRINKING_RAY = 92,
    SPL_CONTROL_UNDEAD = 94,
    SPL_ARMAGEDDON = 98,
    LAST_REAL_SPELL = 99,
    SPL_ARROW = 100, // pseudo-spell for bows
    SPL_BLASTER = 102, // ditto for blasters
    SPL_FATE = 103, // was 47
    // new pseudo-spells
    SPL_FLAMING_POTION = 104,
    SPL_SHOCKING_POTION = 105,
    SPL_FREEZING_POTION = 106,
    SPL_NOXIOUS_POTION = 107,
    SPL_HOLY_WATER = 108,
};

struct __attribute__((packed)) map_monster
{
    SKIP(36);
    uint32_t bits;
    uint16_t hp;
    SKIP(35);
    uint8_t spell1;
    SKIP(7);
    uint8_t holy_resistance;
    SKIP(10);
    uint16_t id;
    SKIP(10);
    uint32_t max_hp;
    SKIP(26);
    uint16_t height;
    SKIP(2);
    int16_t x;
    int16_t y;
    int16_t z;
    SKIP(28);
    uint16_t ai_state;
    SKIP(5);
    uint8_t eradicated_flag; // was padding
    SKIP(28);
    struct spell_buff spell_buffs[22];
    SKIP(272);
};

#define MAP_MONSTERS_ADDR 0x5fefd8
#define MAP_MONSTERS ((struct map_monster *) MAP_MONSTERS_ADDR)

#define MON_TARGETS ((uint32_t *) 0x4f6c88)

enum target
{
    TGT_MONSTER = 3,
    TGT_PARTY = 4,
};

#define PARTY_ADDR 0xacd804
#define PARTY ((struct player *) PARTY_ADDR)

#define COND_AFRAID 3

struct __attribute__((packed)) mapstats_item
{
    SKIP(44);
    uint8_t reputation_group; // my addition
    SKIP(23);
};

#define MAPSTATS ((struct mapstats_item *) 0x5caa38)

#define CUR_MAP_FILENAME ((char *) 0x6be1c4)

// Indoor or outdoor reputation for the loaded map.
#define CURRENT_REP dword(dword(0x6be1e0) == 2 ? 0x6a1140 : 0x6be514)

enum profession
{
    NPC_PIRATE = 45,
    NPC_GYPSY = 48,
    NPC_DUPER = 50,
    NPC_BURGLAR = 51,
    NPC_FALLEN_WIZARD = 52,
};

// New max number of global.evt comands (was 4400 before).
#define GLOBAL_EVT_LINES 5250
// New max size of global.evt itself (was 46080 bytes before).
#define GLOBAL_EVT_SIZE 52000

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
    SKIP(3); // unused
};

// my addition
#define MBUFF_CURSED 0
// vanilla
#define MBUFF_FEAR 4
// also used for eradication in the mod
#define MBUFF_MASS_DISTORTION 10

// new NPC greeting count (starting from 1)
#define GREET_COUNT 220
// new NPC topic count
#define TOPIC_COUNT 592
// count of added NPC text entries
#define NEW_TEXT_COUNT 6

// exposed by MMExtension in "Class Starting Stats.txt"
#define RACE_STATS_ADDR 0x4ed658
#define RACE_STATS ((uint8_t (*)[7][4]) RACE_STATS_ADDR)

#define CLASS_HP_FACTORS ((uint8_t *) 0x4ed610)
#define CLASS_STARTING_HP ((uint8_t *) 0x4ed5f8)
#define CLASS_SP_FACTORS ((uint8_t *) 0x4ed634)
#define CLASS_STARTING_SP ((uint8_t *) 0x4ed604)
// this is actually a switchtable, and the first 5 entries are garbage
#define CLASS_SP_STATS ((uint8_t *) 0x48e62a)

#define STARTING_SKILLS 0x4ed6c8
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
    SKIP(20);
    struct item item;
    uint32_t spell_type;
    SKIP(36);
};

#define AI_REMOVED 11

static int __cdecl (*uncased_strcmp)(const char *left, const char *right)
    = (funcptr_t) 0x4caaf0;
static int __thiscall (*get_player_resistance)(const void *player, int stat)
    = (funcptr_t) 0x48e7c8;
static int __thiscall (*has_item_in_slot)(void *player, int item, int slot)
    = (funcptr_t) 0x48d6ef;
static int __fastcall (*rgb_color)(int red, int green, int blue)
    = (funcptr_t) 0x40df03;
static int __cdecl (*sprintf)(char *str, const char *format, ...)
    = (funcptr_t) 0x4cad70;
static funcptr_t ftol = (funcptr_t) 0x4ca74c;
static funcptr_t add_buff = (funcptr_t) 0x458519;
static funcptr_t elem_damage = (funcptr_t) 0x439e16;
static funcptr_t monster_resists = (funcptr_t) 0x427522;
static funcptr_t monster_in_group = (funcptr_t) 0x438bce;
static void __thiscall (*expire_temp_bonus)(struct item *item, long time)
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
static void __thiscall (*add_mouse_item)(void *this, void *item)
    = (funcptr_t) 0x4936d9;
#define MOUSE_THIS_ADDR 0xacce38
#define MOUSE_THIS ((void *) MOUSE_THIS_ADDR)
static int __thiscall (*put_in_backpack)(void *player, int slot, int item_id)
    = (funcptr_t) 0x4927a0;
static void __thiscall (*make_sound)(void *this, int sound, int object,
                                     int loops, int x, int y, int unknown,
                                     int volume, int playback_rate)
    = (funcptr_t) 0x4aa29b;
#define SOUND_THIS ((void *) 0xf78f58)
static void __thiscall (*evt_set)(void *player, int what, int amount)
    = (funcptr_t) 0x44a5ee;
static int __thiscall (*exists_in_lod)(void *lod, char *filename)
    = (funcptr_t) 0x461659;
static char *__thiscall (*load_from_lod)(void *lod, char *filename,
                                         int use_malloc)
    = (funcptr_t) 0x410897;
static void (*mm7_free)(void *ptr) = (funcptr_t) 0x4caefc;
#define QBITS ((void *) 0xacd59d)
static int __fastcall (*check_qbit)(void *qbits, int bit)
    = (funcptr_t) 0x449b7a;
static void __fastcall (*add_reply)(int number, int action)
    = (funcptr_t) 0x4b362f;
static void __fastcall (*spend_gold)(int amount) = (funcptr_t) 0x492bae;
static void __thiscall (*init_item)(void *item) = (funcptr_t) 0x402f07;
static int __thiscall (*get_attack_delay)(void *player, int ranged)
    = (funcptr_t) 0x48e19b;
static int __thiscall (*get_race)(void *player) = (funcptr_t) 0x490101;
static int __thiscall (*get_might)(void *player) = (funcptr_t) 0x48c922;
static int __thiscall (*get_intellect)(void *player) = (funcptr_t) 0x48c9a8;
static int __thiscall (*get_personality)(void *player) = (funcptr_t) 0x48ca25;
static int __thiscall (*get_endurance)(void *player) = (funcptr_t) 0x48caa2;
static int __thiscall (*get_accuracy)(void *player) = (funcptr_t) 0x48cb1f;
static int __thiscall (*get_speed)(void *player) = (funcptr_t) 0x48cb9c;
static int __thiscall (*get_luck)(void *player) = (funcptr_t) 0x48cc19;
static void (*change_weather)(void) = (funcptr_t) 0x48946d;
static int __fastcall (*is_hostile_to)(void *monster, void *target)
    = (funcptr_t) 0x40104c;
static int __fastcall (*color_stat)(int modified, int base)
    = (funcptr_t) 0x4178a7;
static void __thiscall (*set_specitem_bonus)(void *items_txt, void *item)
    = (funcptr_t) 0x456d51;
static int __thiscall (*timed_cure_condition)(void *player, int condition,
                                              int time1, int time2)
    = (funcptr_t) 0x4908a0;
static int __thiscall (*get_full_hp)(void *player) = (funcptr_t) 0x48e4f0;
static int __fastcall (*get_monsters_around_party)(int *buffer,
                                                   int buffer_size, int radius)
    = (funcptr_t) 0x46a8a2;
static void __fastcall (*damage_monster_from_party)(int source, int monster,
                                                    void *force_vector)
    = (funcptr_t) 0x439463;
static funcptr_t print_string = (funcptr_t) 0x44ce34;
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
static int __thiscall (*save_file_to_lod)(void *lod, const void *header,
                                          void *file, int unknown)
    = (funcptr_t) 0x461b85;
static int __thiscall (*get_map_index)(struct mapstats_item *mapstats,
                                       char *filename) = (funcptr_t) 0x4547cf;
static void (*on_map_leave)(void) = (funcptr_t) 0x443fb8;
static void *__thiscall (*find_in_lod)(void *lod, char *filename, int unknown)
    = (funcptr_t) 0x4615bd;
static int __cdecl (*fread)(void *buffer, int size, int count, void *stream)
    = (funcptr_t) 0x4cb8a5;
static int (*get_eff_reputation)(void) = (funcptr_t) 0x47752f;
static int __thiscall (*get_full_sp)(void *player) = (funcptr_t) 0x48e55d;
// Technically thiscall, but ecx isn't used.
static int __stdcall (*monster_resists_condition)(void *monster, int element)
    = (funcptr_t) 0x427619;
// Same.
static void __stdcall (*magic_sparkles)(void *monster, int unknown)
    = (funcptr_t) 0x4a7e19;
static int __thiscall (*has_enchanted_item)(void *player, int enchantment)
    = (funcptr_t) 0x48d6b6;
static int __fastcall (*player_has_item)(int item, void *player,
                                         int check_mouse)
    = (funcptr_t) 0x43ee38;
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
static int __thiscall (*get_base_level)(void *player) = (funcptr_t) 0x48c8dc;
static int __thiscall (*is_bare_fisted)(void *player) = (funcptr_t) 0x48d65c;
static funcptr_t reset_interface = (funcptr_t) 0x422698;
static int __thiscall (*get_perception_bonus)(void *player)
    = (funcptr_t) 0x491252;
static int __thiscall (*find_objlist_item)(void *this, int id)
    = (funcptr_t) 0x42eb1e;
#define OBJLIST_THIS ((void *) 0x680630)
static int __thiscall (*launch_object)(struct map_object *object,
                                       int direction, int speed, int player)
    = (funcptr_t) 0x42f5c9;
static int __thiscall (*item_value)(struct item *item) = (funcptr_t) 0x45646e;
static int __thiscall (*get_ac)(void *player) = (funcptr_t) 0x48e687;
static int __stdcall (*monster_hits_player)(void *monster, void *player)
    = (funcptr_t) 0x427464;

//---------------------------------------------------------------------------//

static const char *const elements[] = {"fire", "elec", "cold", "pois", "phys",
                                       0, "holy", "mind", "magic", "ener",
                                       "firepois"};

// Patch spells.txt parsing, specifically possible spell elements.
static inline void spells_txt(void)
{
    patch_pointer(0x45395c, elements[ELECTRICITY]);
    patch_pointer(0x453975, elements[COLD]);
    patch_pointer(0x45398e, elements[POISON]);
    patch_pointer(0x4539a7, elements[HOLY]);
    patch_pointer(0x4539d9, elements[PHYSICAL]);
    patch_byte(0x4539ea, PHYSICAL);
    patch_pointer(0x4539f2, elements[ENERGY]);
    patch_pointer(0x453a0b, elements[FIRE_POISON]);
    patch_byte(0x453a39, MAGIC); // was unused (5)
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

// Patch monsters.txt parsing: remove two resistance fields
// and change the possible attack elements.
static inline void monsters_txt(void)
{
    patch_byte(0x455108, byte(0x455108) - 2); // two less fields now
    patch_dword(0x4563fe, dword(0x456406)); // tweaking the jumptable
    patch_dword(0x456402, dword(0x45640a)); // ditto
    hook_jump(0x454ce0, attack_type); // replace the old function entirely
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

// Just (temporarily) change assassins to poison and barbarians to frost.
static void __declspec(naked) assassins_barbarians(void)
{
    asm
      {
        mov ebx, dword ptr [ebx+0xc]
        cmp ebx, SPC_ASSASSINS
        jne not_assassins
        mov ebx, SPC_POISON
        not_assassins:
        cmp ebx, SPC_BARBARIANS
        jne not_barbarians
        mov ebx, SPC_FROST
        not_barbarians:
        cmp ebx, SPC_DRAGON
        ret
      }
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

// Fix "of assassins" and "of barbarians" not dealing elemental damage.
// Also change poisoned weapons' damage from Body to Poison.
static inline void elemental_weapons(void)
{
    hook_call(0x439e6b, assassins_barbarians, 6);
    hook_call(0x439f47, poisoned_weapons, 7);
    patch_bytes(0x439f70, poison_chunk, 2);
    patch_dword(0x439f6c, POISON); // was 2 (water) for some reason
    patch_dword(0x439f7d, POISON); // was 8 (body)
    patch_dword(0x439e67, dword(0x439e67) + 7); // Old Nick
    patch_byte(0x439f82, 13); // this is now Old Nick's posion damage
}

// Fire-poison resistance is the minimum of the two.
static void __declspec(naked) fire_poison_monster(void)
{
    asm
      {
        movzx edx, byte ptr [eax+0x50]
        movzx eax, byte ptr [eax+0x53]
        cmp eax, edx
        jbe fire
        mov eax, edx
        fire:
        push 0x427583
        ret
      }
}

// Recognise element 10 (fire-poison) as the stat 47 (hitherto unused).
static void __declspec(naked) fire_poison_stat(void)
{
    asm
      {
        jnz not_magic
        push 0x48d4c1
        ret
        not_magic:
        dec eax
        dec eax
        jz fire_poison
        xor edi, edi
        push 0x48d4e4
        ret
        fire_poison:
        push STAT_FIRE_POISON_RES
        push 0x48d4db
        ret
      }
}

// Can't just compare resistance values in-function, as player resistances
// are quite complex.  So we're replacing the call entirely and calling
// the original function twice.
static int __thiscall fire_poison_player(const void *player, int stat)
{
    if (stat != STAT_FIRE_POISON_RES)
        return get_player_resistance(player, stat);
    int fire_res = get_player_resistance(player, STAT_FIRE_RES);
    int poison_res = get_player_resistance(player, STAT_POISON_RES);
    if (fire_res < poison_res)
        return fire_res;
    else
        return poison_res;

}

// Implement dual fire-poison damage as element 10 (formerly Dark).
// So far only used by Dragon Breath.
static inline void fire_poison(void)
{
    patch_dword(0x427611, dword(0x427601)); // disable Light resistance
    patch_pointer(0x427615, fire_poison_monster); // patch jumptable
    hook_jump(0x48d4bb, fire_poison_stat);
    hook_call(0x48d4dd, fire_poison_player, 5);
}

static void __declspec(naked) eff_stat_chunk(void)
{
    asm
      {
        shl ebx, 2
        _emit 0xe9 ; jmp
      }
}

// Tweak which stats protect against which conditions.  Most importantly,
// for conditions that are governed by a base stat's effective value,
// this value is now multiplied x4.
static inline void condition_resistances(void)
{
    patch_dword(0x48dd3b, 0x48c9a8 - 0x48dd3a - 5); // call get intellect
    patch_bytes(0x48dd4b, eff_stat_chunk, 4); // multiply eff. stat by 4
    patch_dword(0x48dd4f, 0x48deea - 0x48dd4e - 5); // address for the 0xe9
    patch_dword(0x48dd13, 0x48dd3f - 0x48dd12 - 5); // personality jump
    patch_dword(0x48dd1f, 0x48dd3f - 0x48dd1e - 5); // endurance jump

    // Reorder the jumptable:
    uint32_t poison_res = dword(0x48e109);
    patch_dword(0x48e0e5, poison_res); // poisoned 1
    patch_dword(0x48e0e9, poison_res); // poisoned 2
    patch_dword(0x48e0ed, poison_res); // poisoned 3
    uint32_t magic_res = dword(0x48e105);
    patch_dword(0x48e109, magic_res); // stoned
    patch_dword(0x48e121, magic_res); // aged
}

// Undead players are either liches (returns 1) or zombies (returns 2).
static int __thiscall __declspec(naked) is_undead(void *player)
{
    asm
      {
        xor eax, eax
        cmp dword ptr [ecx+0x88], 0
        jnz zombie
        cmp dword ptr [ecx+0x8c], 0
        jnz zombie
        cmp byte ptr [ecx+0xb9], CLASS_LICH
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
// (lich or artifact), 0 if no immunity.
static int __thiscall is_immune(struct player *player, unsigned int element)
{
    // dragon breath; we don't return 2 here
    if (element == FIRE_POISON)
        return is_immune(player, FIRE) && is_immune(player, POISON);

    // elemental resistance/immunity buffs
    static const int buffs[] = { PBUFF_FIRE_RES, PBUFF_SHOCK_RES,
                                 PBUFF_COLD_RES, PBUFF_POISON_RES, -1, -1, -1,
                                 PBUFF_MIND_RES, PBUFF_MAGIC_RES };
    if (element <= MAGIC && buffs[element] != -1
        && player->spell_buffs[buffs[element]].skill == IMMUNITY_MARKER)
        return 2;

    int undead = is_undead(player);
    if (undead)
      {
        if (element == POISON || element == MIND)
            return undead;
      }
    else
      {
        if (element == HOLY)
            return 1;
      }

    switch (element)
      {
    case FIRE:
        if (has_item_in_slot(player, SPLITTER, SLOT_MAIN_HAND)
            || has_item_in_slot(player, FORGE_GAUNTLETS, SLOT_GAUNTLETS)
            || has_item_in_slot(player, RED_DRAGON_SCALE_MAIL, SLOT_BODY_ARMOR)
            || has_item_in_slot(player, RED_DRAGON_SCALE_SHIELD, SLOT_OFFHAND))
            return 1;
        break;
    case COLD:
        if (has_item_in_slot(player, PHYNAXIAN_CROWN, SLOT_HELM))
            return 1;
        break;
    case POISON:
        if (has_item_in_slot(player, TWILIGHT, SLOT_CLOAK))
            return 1;
        break;
    case MIND:
        if (has_item_in_slot(player, MIND_S_EYE, SLOT_HELM))
            return 1;
        break;
      }
    return 0;
}

// Calls the old, replaced function.
static int __thiscall __declspec(naked) inflict_condition(void *player,
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
static int __thiscall condition_immunity(struct player *player, int condition,
                                         int can_resist)
{
    if (can_resist)
      {
        int bit = 1 << condition;
        int element = -1;
        if (bit & 0x540) // poisoned 1, 2, 3
            element = POISON;
        else if (bit & 0x1028) // afraid, insane, paralyzed
            element = MIND;
        else if (bit & 0x1c000) // dead, stoned, eradicated
            element = MAGIC;
        if (element != -1 && is_immune(player, element))
            return FALSE;
        // Preservation now gives a 50% chance to avoid instant death.
        if ((bit & 0x14000) // dead or eradicated
            && player->spell_buffs[PBUFF_PRESERVATION].expire_time
            && random() & 1)
            return FALSE;
      }
    return inflict_condition(player, condition, can_resist);
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
        jz permanent
        xor ecx, ecx
        mov edx, 0xff
        push ecx
        call dword ptr ds:rgb_color
        permanent:
        mov ecx, dword ptr [esp+4]
        push dword ptr [GLOBAL_TXT+625*4]
        push eax
        push dword ptr [GLOBAL_TXT+ecx*4]
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
        mov edx, dword ptr [0x5c3468]
        ret
      }
}

static void __declspec(naked) display_elec_immunity(void)
{
    asm
      {
        push ELECTRICITY
        push 6
        call display_immunity
        mov edx, dword ptr [0x5c3468]
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
        mov edx, dword ptr [0x5c3468]
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
        mov edx, dword ptr [0x5c3468]
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

// Rewrite and expand the old lich immunity system.  Now one can also
// get an immunity from zombification, potions, or artifacts.
static inline void undead_immunities(void)
{
    hook_jump(0x492d5d, condition_immunity);
    hook_call(0x48dd27, monster_bonus_immunity, 5);
    hook_call(0x48e85f, holy_is_not_magic, 5);
    hook_call(0x48e764, holy_is_not_magic_base, 5);
    hook_call(0x48d4e7, immune_to_damage, 7);
    erase_code(0x48d4f3, 10);

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
}

#define NEW_STRING_COUNT 41
STATIC char *new_strings[NEW_STRING_COUNT];
FIX(new_strings);

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

// Defined in the temp enchants section below.
static void replace_duration_strings(void);

// Instead of replacing every instance of e.g. "water" with "cold",
// overwrite string pointers themselves.  Note that spell school names
// are stored separately by now and are thus not affected.
static void new_element_names(void)
{
    // fire is unchanged
    dword(GLOBAL_TXT + 6 * 4) = dword(GLOBAL_TXT + 71 * 4); // electricity
    dword(GLOBAL_TXT + 240 * 4) = dword(GLOBAL_TXT + 43 * 4); // cold
    dword(GLOBAL_TXT + 70 * 4) = dword(GLOBAL_TXT + 166 * 4); // poison
    dword(GLOBAL_TXT + 214 * 4) = (uintptr_t) new_strings[0]; // holy
    // mind is unchanged
    dword(GLOBAL_TXT + 29 * 4) = dword(GLOBAL_TXT + 138 * 4); // magic
    dword(GLOBAL_TXT + 133 * 4) = (uintptr_t) new_strings[1]; // energy
    // dark is not displayed anymore
}

// We need to do a few things after global.txt is parsed.
static void __declspec(naked) global_txt_tail(void)
{
    asm
      {
        mov dword ptr [0x5067f4], eax
        call replace_duration_strings
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

// Behind the scenes, elemental immunity uses the same buff ID as elemental
// resistance.  Thus, it's impossible to have both at the same time
// (not that it would be useful anyway).  So, if you drink one potion
// while under effect of other, the new effect will replace the old.
static void __declspec(naked) resistance_replaces_immunity(void)
{
    asm
      {
        adc edx, dword ptr [0xacce68]
        cmp word ptr [ecx+10], IMMUNITY_MARKER
        jne not_immunity
        and dword ptr [ecx], 0
        and dword ptr [ecx+4], 0
        not_immunity:
        ret
      }
}

static const uint32_t new_potion_buffs[] = { PBUFF_FIRE_RES, PBUFF_SHOCK_RES,
                                             PBUFF_COLD_RES, PBUFF_POISON_RES,
                                             PBUFF_MIND_RES, PBUFF_MAGIC_RES,
                                             PBUFF_PAIN_REFLECTION };

static void throw_potions_jump(void); // defined below

// Add elemental immunity potions and the pain reflection potion.
// Magic immunity lasts 3 min/level, the rest are 10 min/level.
// TODO: do we really need to use floats just to divide by 30?
static void __declspec(naked) new_potion_effects(void)
{
    asm
      {
        cmp edx, LAST_OLD_POTION
        ja new
        jmp dword ptr [0x468ebe+eax*4]
        new:
        cmp edx, HOLY_WATER
        je throw_potions_jump
        mov ecx, offset new_potion_buffs
        mov ecx, dword ptr [ecx+eax*4-52*4]
        shl ecx, 4
        lea ecx, [esi+0x17a0+ecx]
        push ebx
        push ebx
        cmp edx, POTION_PAIN_REFLECTION
        je pain_reflection
        push ebx
        push IMMUNITY_MARKER
        cmp word ptr [ecx+10], IMMUNITY_MARKER
        je set_duration
        and dword ptr [ecx], 0
        and dword ptr [ecx+4], 0
        jmp set_duration
        pain_reflection:
        ; power is meaningless for this buff, but let`s compute it anyway
        mov eax, dword ptr [MOUSE_ITEM+4]
        shr eax, 1
        add eax, 5
        push eax
        push GM ; black = gm, not that it matters much
        set_duration:
        cmp edx, POTION_MAGIC_IMMUNITY
        mov eax, dword ptr [MOUSE_ITEM+4]
        je magic
        imul eax, eax, 128 * 60 * 10
        jmp multiply
        magic:
        imul eax, eax, 128 * 60 * 3
        multiply:
        push eax
        fild dword ptr [esp]
        add esp, 4
        fmul dword ptr [0x4d8470]
        call dword ptr ds:ftol
        add eax, dword ptr [0xacce64]
        adc edx, dword ptr [0xacce68]
        push edx
        push eax
        call dword ptr ds:add_buff
        push 0x4687a8
        ret
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

// Display e.g. "fire imm" instead of "fire res" player buff when appropriate.
static void __declspec(naked) immunity_strings(void)
{
    asm
      {
        mov eax, dword ptr [ebp-20]
        cmp word ptr [eax+10], IMMUNITY_MARKER
        mov eax, dword ptr [ebp-4]
        jne quit
        xor ecx, ecx
        cmp eax, BUFF_STRINGS + 5*4
        je fire
        cmp eax, BUFF_STRINGS + 0*4
        je shock
        cmp eax, BUFF_STRINGS + 22*4
        je cold
        cmp eax, BUFF_STRINGS + 2*4
        je poison
        cmp eax, BUFF_STRINGS + 9*4
        je mind
        cmp eax, BUFF_STRINGS + 3*4
        jne quit
        inc ecx
        mind:
        inc ecx
        poison:
        inc ecx
        cold:
        inc ecx
        shock:
        inc ecx
        fire:
        mov eax, offset new_strings + 2 * 4
        lea eax, [eax+ecx*4]
        quit:
        movzx ecx, byte ptr [edi-1]
        ret
      }
}

// Add new black potions.  Also some holy water code.
static inline void new_potions(void)
{
    hook_call(0x468c50, resistance_replaces_immunity, 6);
    // holy water is handled below but the jump is here
    patch_byte(0x46878a, HOLY_WATER - POTION_BOTTLE);
    hook_jump(0x468791, new_potion_effects);
    hook_call(0x4163b1, mix_new_potions_1, 6);
    hook_call(0x4163d7, mix_new_potions_2, 6);
    patch_byte(0x41d653, byte(0x41d657)); // move an instruction
    hook_call(0x41d654, immunity_strings, 7);
    patch_byte(0x4b8fd4, LAST_RECIPE - FIRST_RECIPE + 1); // sell new recipes
    patch_dword(0x490f1f, LAST_RECIPE); // allow selling new recipes
    patch_dword(0x4bda2b, LAST_RECIPE); // ditto
}

// We now store a temporary enchantment in the bonus strength field,
// with the bonus ID set to 0xff.  The following patches
// make the game ignore this ID where appropriate.
// The first one deals with the displayed name.
static void __declspec(naked) ignore_temp_ench_name(void)
{
    asm
      {
        cmp dword ptr [esi+4], eax
        jz ignore
        cmp dword ptr [esi+4], TEMP_ENCH_MARKER
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
        mov eax, dword ptr [ecx+4]
        cmp eax, TEMP_ENCH_MARKER
        jz quit
        cmp eax, ebx
        quit:
        ret
      }
}

// Next, we handle the price.
static void __declspec(naked) ignore_temp_ench_price(void)
{
    asm
      {
        cmp dword ptr [esi+4], eax
        jz ignore
        cmp dword ptr [esi+4], TEMP_ENCH_MARKER
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
        cmp dword ptr [edi+4], TEMP_ENCH_MARKER
        quit:
        ret
      }
}

// Replace the calls to the weapon elemental damage function with
// our code that calls it twice, for both permanent and temporary bonus.
static void __declspec(naked) temp_elem_damage(void)
{
    asm
      {
        push ecx
        push eax
        call dword ptr ds:elem_damage
        pop ecx
        cmp dword ptr [ecx+4], TEMP_ENCH_MARKER
        jne quit
        push eax
        xor edx, edx
        push edx
        push edx
        sub esp, 32
        push 1
        and dword ptr [esp+20], 0
        mov ecx, dword ptr [ecx+8]
        mov dword ptr [esp+12], ecx
        mov ecx, esp
        lea edx, [esp+36]
        lea eax, [esp+40]
        push eax
        call dword ptr ds:elem_damage
        add esp, 36
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

// Defined below.
static void __stdcall blaster_eradicate(struct player *, struct map_monster *,
                                        struct map_object *);

// The projectile damage code needs an extra instruction.
// Also here: check for blaster eradication.
static void __declspec(naked) bow_temp_damage(void)
{
    asm
      {
        and dword ptr [ebp-12], 0
        push eax
        push ecx
        push edx
        push ebx
        push esi
        push edi
        call blaster_eradicate
        pop edx
        pop ecx
        pop eax
        jmp temp_elem_damage
      }
}

// Check for temporary swiftness enchantments.
static void __declspec(naked) temp_swiftness(void)
{
    asm
      {
        cmp dword ptr [edx+4], TEMP_ENCH_MARKER
        jne no_temp
        mov ecx, dword ptr [edx+8]
        cmp ecx, SPC_SWIFT
        je swift
        cmp ecx, SPC_DARKNESS
        je swift
        no_temp:
        mov ecx, dword ptr [edx+12]
        cmp ecx, SPC_SWIFT
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
        lea ebx, [edi+0x1f0+eax*4]
        mov ecx, ebx
        push dword ptr [0xacce68] ; current time, high dword
        push dword ptr [0xacce64] ; current time, low dword
        call dword ptr ds:expire_temp_bonus
        ret
      }
}

// Store temp enchant in eax for the next chunk.
// Also here: fix "of David" not being checked for.
static void __declspec(naked) temp_bane_bow_1(void)
{
    asm
      {
        xor eax, eax
        xor edx, edx
        cmp dword ptr [ebx+4], TEMP_ENCH_MARKER
        jne no_temp
        mov eax, dword ptr [ebx+8]
        no_temp:
        mov ebx, dword ptr [ebx+12]
        cmp ebx, SPC_DAVID
        jne not_david
        mov edx, MG_TITAN
        not_david:
        cmp ebx, SPC_UNDEAD_SLAYING
        ret
      }
}

// Check monster bane twice for both possible enchants.
// Also lower Undead Slaying extra damage to 150%.
static void __declspec(naked) temp_bane_bow_2(void)
{
    asm
      {
        mov edi, eax
        cmp edx, MG_UNDEAD
        sete bl
        call dword ptr ds:monster_in_group
        and ebx, eax
        cmp edi, SPC_UNDEAD_SLAYING
        je undead
        cmp edi, SPC_DRAGON_SLAYING
        jne quit
        mov edx, MG_DRAGON
        jmp temp
        undead:
        mov edx, MG_UNDEAD
        test eax, eax
        setz bh
        temp:
        mov ecx, dword ptr [ebp+8]
        push eax
        call dword ptr ds:monster_in_group
        pop ecx
        and bh, al
        or eax, ecx
        quit:
        mov ecx, esi
        test ebx, ebx
        jz not_undead
        shr ecx, 1
        not_undead:
        ret
      }
}

// Avoid skipping the code below for non-bane weapons.
static void __declspec(naked) temp_bane_melee_1(void)
{
    asm
      {
        cmp eax, SPC_DAVID ; replaced code
        pop edx
        jne no_bane
        push MG_TITAN ; replaced code
        jmp edx
        no_bane:
        push 0
        jmp edx
      }
}

// Check bane twice for melee weapons.  Also fixes Gibbet.
// We also check for backstab damage here.
// Also, ensures that Undead Slaying only adds +50% damage.
static void __declspec(naked) temp_bane_melee_2(void)
{
    asm
      {
        test byte ptr [esp+40], 4 ; 1st param, double damage flag
        jz check_bane
        xor eax, eax ; double damage doesn`t stack
        ret
        check_bane:
        push 0 ; undead flag
        cmp ebp, CORSAIR
        je backstab
        cmp ebp, OLD_NICK
        je backstab
        cmp eax, SPC_BACKSTABBING
        je backstab
        cmp eax, SPC_ASSASSINS
        jne no_backstab
        backstab:
        test byte ptr [esp+44], 2 ; 1st param, backstab bit
        mov eax, 1 ; return true
        jnz quit
        no_backstab:
        cmp edx, MG_UNDEAD
        jne not_undead
        inc dword ptr [esp] ; undead flag
        not_undead:
        call dword ptr ds:monster_in_group
        and dword ptr [esp], eax ; reset flag if not undead
        cmp ebp, GIBBET
        je dragon
        cmp dword ptr [ebx+4], TEMP_ENCH_MARKER
        jne quit
        mov ecx, dword ptr [ebx+8]
        cmp ecx, SPC_UNDEAD_SLAYING
        je undead
        cmp ecx, SPC_DRAGON_SLAYING
        je dragon
        quit:
        pop edx
        mov ecx, esi
        test edx, edx
        jle dont_halve
        shr ecx, 1
        dont_halve:
        ret
        dragon:
        mov edx, MG_DRAGON
        jmp temp
        undead:
        test eax, eax
        jnz quit
        mov edx, MG_UNDEAD
        add dword ptr [esp], 2
        temp:
        mov ecx, dword ptr [esp+52]
        push eax
        call dword ptr ds:monster_in_group
        pop ecx
        sub dword ptr [esp], eax
        or eax, ecx
        cmp ebp, GIBBET
        jne quit
        inc ebp
        mov edx, MG_DEMON
        jmp temp
      }
}

static char enchant_buffer[100];

// Print the temp enchantment description.
static void __declspec(naked) display_temp_enchant(void)
{
    asm
      {
        add dword ptr [ebp-8], 100
        skip:
        dec dword ptr [ebp-24]
        jz quit
        cmp dword ptr [ebp-24], 1
        jne quit
        mov ecx, dword ptr [ebp-4]
        cmp dword ptr [ecx+4], TEMP_ENCH_MARKER
        jne skip
        mov dword ptr [ebp-8], offset enchant_buffer
        cmp ebx, 1
        quit:
        ret
      }
}

// New buffer for enchantment data.  Mostly used in spcitems_buffer() below.
STATIC struct spcitem spcitems[SPC_COUNT];
FIX(spcitems);

// Adjust description screen height to fit the new line.
// Also compose the line itself while we're at it.
static void __declspec(naked) temp_enchant_height(void)
{
    asm
      {
        add dword ptr [ebp-12], 100
        skip:
        dec dword ptr [ebp-24]
        jz quit
        cmp dword ptr [ebp-24], 1
        jne quit
        mov ecx, dword ptr [ebp-4]
        cmp dword ptr [ecx+4], TEMP_ENCH_MARKER
        jne skip
        mov eax, dword ptr [ecx+8]
        imul eax, eax, 28
        add eax, offset spcitems - 24
        push dword ptr [eax]
        push dword ptr [new_strings + 8*4]
        push 0x4e2e80
        ; for some reason clang crashes if I try to push offsets directly
        mov eax, offset enchant_buffer
        push eax
        call dword ptr ds:sprintf
        add esp, 16
        mov dword ptr [ebp-12], offset enchant_buffer
        cmp ebx, 1
        quit:
        ret
      }
}

// Temp enchantment duration strings weren't localized.
// Also here: the "N/A" string for the (lack of) ranged damage.
static void replace_duration_strings(void)
{
    patch_pointer(0x41e0cc, new_strings[9]);
    patch_pointer(0x41e0f2, new_strings[10]);
    patch_pointer(0x41e126, new_strings[11]);
    patch_pointer(0x41e162, new_strings[12]);
    patch_pointer(0x41e1a6, new_strings[13]);
    patch_pointer(0x41e1f2, new_strings[14]);
    patch_pointer(0x48d3cc, new_strings[22]);
}

// Rules for temporary enchantments: weapons that already
// attack with the same element are forbidden, as are
// bows of carnage; items with a numeric bonus also cannot
// get a temp enchantment.  If an artifact or an enchanted item
// is targeted by a GM-level spell, it's enchanted temporarily.
static void __declspec(naked) enchant_weapon(void)
{
    asm
      {
        jnz temporary
        cmp dword ptr [ebp-24], GM
        jne temporary
        cmp dword ptr [esi+12], 0
        jnz temporary
        mov eax, dword ptr [esp+8]
        mov dword ptr [esi+12], eax
        ret 8
        temporary:
        cmp dword ptr [esi+4], 0
        jnz fail
        cmp dword ptr [esi+12], SPC_CARNAGE
        je fail
        cmp dword ptr [esp+8], SPC_SPECTRAL
        je spectral
        xor eax, eax
        push eax
        push eax
        mov ecx, esi
        lea edx, [esp+4]
        push esp
        call dword ptr ds:elem_damage
        pop edx
        pop ecx
        or eax, edx
        jz okay
        cmp dword ptr [esp+4], ecx
        je fail
        okay:
        mov dword ptr [esi+4], TEMP_ENCH_MARKER
        mov eax, dword ptr [esp+8]
        mov dword ptr [esi+8], eax
        test eax, eax
        ret 8
        spectral:
        cmp dword ptr [esi+12], SPC_SPECTRAL
        je fail
        cmp dword ptr [esi+12], SPC_WRAITH
        jne okay
        fail:
        xor esi, esi
        push 0x4290a7
        ret 16
      }
}

// Rehaul Fire Aura according to the above rules.
// Spectral Weapon code also arrives here (FIRE is ignored).
static void __declspec(naked) fire_aura(void)
{
    asm
      {
        mov esi, dword ptr [ebp-28]
        push dword ptr [ebp-4]
        push FIRE
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
        push 10
        call enchant_weapon
        ret
      }
}

// Make the new checks for the weapon-enchanting potions.
// Bows of carnage can be enchanted by swift potions only.
// Also handles holy water.
static void __declspec(naked) weapon_potions(void)
{
    asm
      {
        mov ebx, eax
        cmp ebx, SPC_SWIFT
        je swift
        cmp dword ptr [esi+12], SPC_CARNAGE
        je fail
        cmp ebx, SPC_UNDEAD_SLAYING
        je undead
        cmp ebx, SPC_DRAGON_SLAYING
        je dragon
        xor edi, edi
        cmp ebx, SPC_FLAME
        je fire
        cmp ebx, SPC_SPARKS
        je shock
        cmp ebx, SPC_FROST
        je frost
        cmp ebx, SPC_POISON
        jne fail
        inc edi
        frost:
        inc edi
        shock:
        inc edi
        fire:
        inc ebx ; buff elemental enchants a little
        xor eax, eax
        push eax
        push eax
        mov ecx, esi
        lea edx, [esp+4]
        push esp
        call dword ptr ds:elem_damage
        pop edx
        pop ecx
        or eax, edx
        jz okay
        cmp ecx, edi
        je fail
        okay:
        mov dword ptr [esi+4], TEMP_ENCH_MARKER
        mov dword ptr [esi+8], ebx
        fmul dword ptr [0x4d8470]
        ret
        swift:
        cmp dword ptr [esi+12], SPC_DARKNESS
        je fail
        cmp dword ptr [esi], PUCK
        je fail
        jmp dupe
        undead:
        cmp dword ptr [esi], GHOULSBANE
        je fail
        cmp dword ptr [esi], JUSTICE
        je fail
        dragon:
        cmp dword ptr [esi], GIBBET
        je fail
        dupe:
        cmp dword ptr [esi+12], ebx
        jne okay
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
        cmp ebx, SPC_INFERNOS
        je red
        cmp ebx, SPC_LIGHTNING
        je purple
        cmp ebx, SPC_ICE
        je blue
        cmp ebx, SPC_VENOM
        je green
        cmp ebx, SPC_SWIFT
        je green
        cmp ebx, SPC_DRAGON_SLAYING
        je red
        cmp ebx, SPC_UNDEAD_SLAYING
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

// Prevent the game from applying the enchantment
// too early and in the wrong place.
static void __declspec(naked) slaying_potion_chunk(void)
{
    asm
      {
        mov eax, SPC_DRAGON_SLAYING
        nop
        nop
      }
}

// Allow slaying potions to enchant weapons permanently if possible.
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
        cmp dword ptr [ebp-4], 2 ; equip stat, 0-2 = weapon
        ja quit
        mov dword ptr [esi+12], SPC_DRAGON_SLAYING
        or dword ptr [esi+20], 16 ; red aura
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
    hook_call(0x48d260, temp_bane_bow_1, 6);
    patch_byte(0x48d28b, 11); // redirect a jump to always reach the below hook
    hook_call(0x48d297, temp_bane_bow_2, 5);
    patch_word(0x48d2a0, 0xce01); // add esi, ecx
    // melee bane code is repeated for either hand
    hook_call(0x48ce11, expire_weapon, 7);
    hook_call(0x48ceb6, temp_bane_melee_1, 7);
    hook_call(0x48cecf, temp_bane_melee_2, 5);
    patch_word(0x48ced8, 0xce01); // add esi, ecx
    hook_call(0x48cf42, expire_weapon, 7);
    hook_call(0x48cfe1, temp_bane_melee_1, 7);
    hook_call(0x48cffa, temp_bane_melee_2, 5);
    patch_word(0x48d003, 0xce01); // add esi, ecx
    hook_call(0x41e025, display_temp_enchant, 7);
    patch_dword(0x41dfe5, 4); // one more cycle
    hook_call(0x41de8d, temp_enchant_height, 7);
    patch_dword(0x41de37, 4); // ditto
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
    erase_code(0x416872, 12);
    erase_code(0x41690b, 9);
    erase_code(0x416932, 12);
    // pass the enchantment to our code in eax
    patch_bytes(0x416884, slaying_potion_chunk, 7);
    hook_call(0x41684e, permanent_slaying, 6);
    erase_code(0x416953, 3);
}

// Bug fix: Kelebrim wasn't penalizing earth (now poison) resistance.
static void __declspec(naked) kelebrim(void)
{
    asm
      {
        cmp esi, STAT_POISON_RES
        jne quit
        sub edi, 30
        quit:
        push 0x48f0c3
        ret
      }
}

// Compound buff potions like Bless or Stoneskin always granted the minimal
// possible bonus (+5, corresponding to the spell skill of 0), irrespective
// of the potion's power.  Now this bonus is increased by half the power.
static void __declspec(naked) buff_potions_power(void)
{
    asm
      {
        cmp dword ptr [esp+12], MASTER
        jne quit
        cmp dword ptr [esp+16], 5
        jne quit
        mov eax, dword ptr [MOUSE_ITEM+4]
        shr eax, 1
        add dword ptr [esp+16], eax
        quit:
        push 0x458519 ; replaced call
        ret
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
                //TODO: respect power limiting if added
                brews[0].power = ITEMS_TXT[id].mod1_dice_count
                               + (get_skill(player, SKILL_ALCHEMY)
                                  & SKILL_MASK);
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
        int note = recipes[potion-FIRST_COMPLEX_POTION].variants[i].note - 1;
        if (!(AUTONOTES[note >> 3] & (128 >> (note & 7))))
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
        sprintf(message, new_strings[15], player->name,
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
            show_status_text(new_strings[16], 2);
          }
        else
          {
            // don't know recipe
            show_face_animation(player, ANIM_ID_FAIL, 0);
            sprintf(message, new_strings[17], ITEMS_TXT[-result].name);
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
        show_status_text(new_strings[18], 2);
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
    add_mouse_item(MOUSE_THIS, &brewn_potion);
        show_face_animation(player, ANIM_MIX_POTION, 0); // successful brew
}

// Hooks in the backpack code to implement autobrew on ctrl-click.
static void __declspec(naked) autobrew(void)
{
    asm
      {
        lea esi, [ebx+0x1f0+eax*4]
        push 0x11
        call dword ptr ds:0x4d8260
        test ax, ax
        js ctrl
        quit:
        mov ecx, 9
        ret
        ctrl:
        mov eax, dword ptr [esi]
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
        mov word ptr [esi+0x1934], bx ; recovery delay
        cmp dword ptr [0xacd6b4], ebx ; turn-based flag
        jz quit
        mov ecx, dword ptr [0x4f86d8+12] ; count of tb actors
        cmp ecx, ebx ; just in case
        jle quit
        mov eax, dword ptr [ebp+8] ; player id
        dec eax
        shl eax, 3
        add eax, TGT_PARTY
        mov edx, 0x4f86d8 + 16
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
        mov edx, dword ptr [MOUSE_ITEM+4] ; potion power
        test edx, edx ; 0 power potions have no permanent effect
        jnz has_power
        push 0x4687a8 ; skip set-drunk-bit code
        ret 4
        has_power:
        add dx, word ptr [esi+188+ecx*4] ; base attribute
        test dh, dh ; can`t raise higher than 255
        jz not_above_limit
        mov dx, 255
        not_above_limit:
        mov word ptr [esi+188+ecx*4], dx
        ret
      }
}

static void wand_price(void); // defined below

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
        mov edi, dword ptr [ITEMS_TXT_ADDR+eax+16] ; base value
        cmp byte ptr [ITEMS_TXT_ADDR+eax+28], 14 ; potion or bottle
        je potion
        cmp byte ptr [ITEMS_TXT_ADDR+eax+28], 12 ; wand
        je wand_price
        xor edx, edx ; set zf
        ret
        potion:
        movzx eax, byte ptr [ITEMS_TXT_ADDR+eax+30] ; value multiplier
        mul dword ptr [esi+4] ; potion power
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

// Exploit fix: barrels in Walls of Mist were refilled on each visit.
// Now the barrel contents are stored in the savefile.
// Called in save_game_hook() below.
// (Note that leaving a map also forces an autosave.)
static void save_wom_barrels(void)
{
    if (uncased_strcmp(CUR_MAP_FILENAME, "d11.blv")) // walls of mist
        return;
    // name could be shorter, I'm guessing here
    static const struct { char name[20]; int size; int unknown; } header
        = { "barrels.bin", 15, 0 };
    save_file_to_lod(SAVEGAME_LOD, &header, (void *) (MAP_VARS + 75), 0);
}

// Restore the saved barrels, unless a quest bit is set.
// The quest bit should be reset every year.
// Called in load_map_hook() below.
// This is actually called on each savegame reload as well, but it's okay.
static void load_wom_barrels(void)
{
    if (uncased_strcmp(CUR_MAP_FILENAME, "d11.blv")) // walls of mist
        return;
    if (check_qbit(QBITS, QBIT_REFILL_WOM_BARRELS))
        return;
    void *file = find_in_lod(SAVEGAME_LOD, "barrels.bin", 1);
    // barrel data occupies map vars 75 to 89
    // it would be more proper to dynamically determine barrel count, but eeh
    if (file)
        fread((void *) (MAP_VARS + 75), 1, WOM_BARREL_CNT, file);
}

// Make the genie lamps give +5 to +20 to stats instead of +1 to +4.
static void __declspec(naked) lamp_quadruple(void)
{
    asm
      {
        mov eax, dword ptr [0xacd54c] ; week of month
        lea eax, [eax*4+eax+4]
        ret
      }
}

// Put Intellect and Personality on the same month to fit.
static void __declspec(naked) lamp_int_or_per(void)
{
    asm
      {
        test dword ptr [0xacd550], 1 ; day of month
        jz per
        push 0x4682a4
        ret
        per:
        mov ecx, dword ptr [0x507a00] ; "personality"
        mov dword ptr [ebp-8], ecx
        push 0x4682b0
        ret
      }
}

// Shift the base stat names according to the change.
static void __declspec(naked) lamp_stat_name(void)
{
    asm
      {
        mov ecx, eax
        cmp ecx, 2
        jb okay
        inc ecx
        okay:
        mov ecx, dword ptr [0x5079f8+ecx*4] ; replaced code
        ret
      }
}

// The function to generate a random item of specified tlvl
// had a off-by-one error that resulted in a small chance
// for a first (and worst) item in the class to be generated
// at any tlvl.  This was most apparent in shops.
static void __declspec(naked) fix_random_treasure(void)
{
    asm
      {
        idiv dword ptr [ebp-8] ; replaced code
        lea ebx, [edx+1] ; add one
        ret
      }
}

// Misc item tweaks.
static inline void misc_items(void)
{
    patch_pointer(0x48f698, kelebrim); // jump table
    // phynaxian crown now grants poison instead of water resistance
    patch_byte(0x48f113, STAT_POISON_RES);
    // make blasters ignore resistances like in mm6
    patch_dword(0x43963c, ENERGY); // blaster element
    // remove splitter and forge gauntlets' fire res bonus
    // now that they give an immunity
    patch_dword(0x48f660, dword(0x48f664));
    erase_code(0x48f258, 8);
    hook_call(0x468c58, buff_potions_power, 5);
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
    patch_byte(0x450a15, 7); // enable white barrels
    hook_call(0x46825f, lamp_quadruple, 5);
    // Change genie lamp rewards alike MM6: first six months are base stats
    // (Int and Per share a month), last six months are resistances.
    // We're rewriting a jumptable here.
    patch_pointer(0x468e92, lamp_int_or_per);
    // move the rest of base stats one up
    patch_dword(0x468e96, dword(0x468e9a));
    patch_dword(0x468e9a, dword(0x468e9e));
    patch_dword(0x468e9e, dword(0x468ea2));
    patch_dword(0x468ea2, dword(0x468ea6));
    hook_call(0x468274, lamp_stat_name, 7);
    // the code for resistances exists, but it's not in the table
    patch_dword(0x468ea6, 0x4683f0);
    patch_dword(0x468eaa, 0x4683de);
    patch_dword(0x468eae, 0x4683cc);
    patch_dword(0x468eb2, 0x4683ba);
    patch_dword(0x468eb6, 0x4683a8);
    patch_dword(0x468eba, 0x468396);
    hook_call(0x45685f, fix_random_treasure, 5);
}

static uint32_t potion_damage;

// Allow using Flaming, Freezing, Shocking and Noxious potions
// to deal splash elemental damage at a short range.
static void __declspec(naked) throw_potions_jump(void)
{
    asm
      {
        cmp dword ptr [0x4e28d8], 23 ; current screen
        je fail
        cmp dword ptr [0x4e28d8], 13 ; inside a house
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
        mov eax, dword ptr [MOUSE_ITEM+4] ; item bonus
        mov dword ptr [potion_damage], eax
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

// Provide the proper spell power for the potion throw event.
// We hijacked the scroll cast event for this,
// which uses a fixed power, so we store the power in a static var.
static void __declspec(naked) throw_potions_power(void)
{
    asm
      {
        pop eax
        cmp dword ptr [esp+28], SPL_FLAMING_POTION ; param 1 = spell
        jb ordinary
        cmp dword ptr [esp+28], SPL_HOLY_WATER
        ja ordinary
        push dword ptr [potion_damage]
        push eax
        ret
        ordinary:
        push 0x85 ; scroll power = M5
        push eax
        ret
      }
}

static void aim_remove_fear(void); // defined below

// Pretend that the thrown potion is Fire Bolt for aiming purposes.
// There's also a Remove Fear aiming hook here now.
// Also handles the new Fate spell ID.
static void __declspec(naked) aim_potions_type(void)
{
    asm
      {
        cmp ecx, SPL_REMOVE_FEAR
        je aim_remove_fear
        cmp ecx, SPL_FATE
        jne not_fate
        mov ecx, SPL_HEAL ; same aiming mode
        not_fate:
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
static void __thiscall aim_potions_refund(struct dialog_param *this)
{
    int item_id;
    switch (this->spell)
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
    int slot = put_in_backpack(&PARTY[this->player], -1, item_id);
    if (slot)
        PARTY[this->player].items[slot-1] = (struct item) { .id = item_id,
                                                          .bonus = this->skill,
                                                          .flags = IFLAGS_ID };
    return;
}

// Hook for the above.
static void __declspec(naked) aim_potions_refund_hook(void)
{
    asm
      {
        mov ecx, dword ptr [0x507a54] ; current dialog, I think
        cmp ecx, ebx
        jz quit
        mov ecx, dword ptr [ecx+28] ; dialog param
        call aim_potions_refund
        mov ecx, dword ptr [0x507a54]
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
        mov ax, word ptr [0x4e3ab0+eax*4-4]
        ret
      }
}

static void forbid_spell(void); // defined below

// Used in damage_messages() below.
static int last_hit_player;

// Redirect potion pseudo-spell code to the attack spell code.
// This hook is also reused for spell disabling.
// The new Fate spell ID is also handled here.
static void __declspec(naked) cast_potions_jump(void)
{
    asm
      {
        mov dword ptr [last_hit_player], esi ; reset to 0
        jna forbid_spell
        cmp eax, SPL_FATE - 1
        je fate
        cmp eax, SPL_FLAMING_POTION - 1
        jb not_it
        cmp eax, SPL_HOLY_WATER - 1
        ja not_it
        mov dword ptr [ebp-0xb4], 100 ; recovery
        push 0x4289c6
        ret 4
        not_it:
        push 0x428295
        ret 4
        fate:
        mov word ptr [ebx], SPL_SPECTRAL_WEAPON ; for the sound
        push 0x42b91d ; fate code
        ret 4
      }
}

// Let the throw velocity depend on strength.
static void __declspec(naked) cast_potions_speed(void)
{
    asm
      {
        movzx eax, word ptr [eax+ecx+48]
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
        movsx eax, word ptr [0x4edf30+eax*2] ; spell sound
        ret
      }
}

// Redirect the explode action for the new potions to fireball.
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
        mov eax, OBJ_ACID_BURST
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
        movsx eax, word ptr [0x4edf30+eax*2] ; spell sound
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
        ; the higher bits of the potion`s power are here:
        mov ecx, dword ptr [ebx+0x50] ; spell mastery
        ; this will only work properly with power < 192
        ; thankfully, potions with power > 135 are not legitimately brewable
        dec ecx
        shl ecx, 6
        add ecx, dword ptr [ebx+0x4c] ; the rest of potion/spell power
        mov edx, 3
        and eax, 1
        sub edx, eax ; d2 for elec and poison, d3 for fire, cold, and holy
        call dword ptr ds:roll_dice
        push 0x439767
        ret 8
        ordinary:
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
        mov eax, dword ptr [ebx+0x48] ; spell id
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
        mov ecx, dword ptr [ebx+0x50] ; spell mastery
        ; this will only work properly with power < 192
        ; thankfully, potions with power > 135 are not legitimately brewable
        dec ecx
        shl ecx, 6
        add ecx, dword ptr [ebx+0x4c] ; the rest of potion/spell power
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
static void __declspec(naked) holy_water_jump(void)
{
    asm
      {
        cmp ecx, HOLY_WATER
        je quit
        cmp ecx, SWIFT_POTION ; replaced code
        quit:
        ret
      }
}

// Supply the Undead Slaying enchantment when applying holy water.
static void __declspec(naked) holy_water_enchant(void)
{
    asm
      {
        cmp eax, HOLY_WATER
        je holy
        mov eax, dword ptr [0x4e28fc+eax*4-FLAMING_POTION*4] ; replaced code
        ret
        holy:
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

// Supply yhe text to the new "bless water" reply
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
        mov eax, dword ptr [0x507a40] ; parent dialogue or smth
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
        jne not_dark
        skip:
        and dword ptr [reply_buffer], 0
        inc edi
        jmp ordinary
        not_dark:
        push ecx
        imul eax, eax, 52 ; 2devents struct size
        fld dword ptr [0x5912b8+eax+32] ; val field = temple cost
        push 10
        fimul dword ptr [esp]
        fistp dword ptr [esp]
        push dword ptr [new_strings+19*4]
        ; for some reason clang crashes if I try to push offsets directly
        mov eax, offset reply_buffer
        push eax
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
        mov eax, dword ptr [0x507a40] ; parent dialogue or smth
        mov eax, dword ptr [eax+28] ; param = temple id
        imul eax, eax, 52 ; 2devents struct size
        fld dword ptr [0x5912b8+eax+32] ; val field = temple cost
        fistp dword ptr [esp] ; don`t need the return address anymore
        pop ebx
        lea ecx, [ebx*4+ebx] ; price = heal cost x 10
        shl ecx, 1
        cmp dword ptr [0xacd56c], ecx ; party gold
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
        sub esp, 36
        mov ecx, esp
        call dword ptr ds:init_item
        mov dword ptr [esp], HOLY_WATER ; id
        mov dword ptr [esp+4], ebx ; power
        mov dword ptr [esp+20], 1 ; identified flag
        mov ecx, MOUSE_THIS_ADDR
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
    // Armageddon element wasn't updated from MM6, where it was 5 (then magic).
    // As in MM7 resistance 5 is unused, armageddon became irresistible.
    patch_byte(0x401b74, ELEMENT(SPL_ARMAGEDDON)); // to monsters
    patch_byte(0x401bfb, ELEMENT(SPL_ARMAGEDDON)); // to players
    // Not sure if the next two do anything, but just in case.
    patch_byte(0x46c9ea, ELEMENT(SPL_PARALYZE));
    patch_byte(0x46c9e6, ELEMENT(SPL_SHRINKING_RAY));
}

// Defined below.
static void parse_statrate(void);

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
        cmp word ptr [PARTY_BUFFS+16*BUFF_FEATHER_FALL+10], GM
        jne no_ff
        fadd dword ptr [jump_multiplier]
        no_ff:
        mov ecx, 4
        check_boots:
        mov eax, dword ptr [0xa74f44+ecx*4] ; PC pointers
        mov edx, dword ptr [eax+0x1968] ; boots slot
        test edx, edx
        jz next_pc
        lea edx, [edx+edx*8]
        cmp dword ptr [eax+0x214+edx*4-36], HERMES_SANDALS
        je leaping
        cmp dword ptr [eax+0x214+edx*4-36+12], SPC_LEAPING
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
static void __declspec(naked) enchant_item_noon_check(void)
{
    asm
      {
        mov dword ptr [enchant_item_gm_noon], esi ; esi == 0
        cmp dword ptr [0xacd554], 11 ; hour of day
        jb quit
        cmp dword ptr [0xacd554], 12 ; hour of day
        ja quit
        cmp ecx, GM
        jae gm
        inc ecx
        quit:
        add eax, PARTY_ADDR ; replaced code
        ret
        gm:
        inc dword ptr [enchant_item_gm_noon]
        jmp quit
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

// Halve "of Arms", "of Dodging", and "of the Fist".
// This branch of code may be unused in practice, but whatever.
static void __declspec(naked) enchant_item_halve_expert(void)
{
    asm
      {
        add edx, ecx ; replaced code
        cmp dword ptr [esi+4], STD_ARMS
        jb normal
        cmp dword ptr [esi+4], STD_FIST
        ja normal
        ; note that the minimum is 3, so we don`t need to check for zero
        shr edx, 1
        normal:
        mov dword ptr [esi+8], edx ; replaced code
        ret
      }
}

// Halve "of Arms", "of Dodging", and "of the Fist".
// Covers both the Master and GM cases, and also the unused Normal case.
static void __declspec(naked) enchant_item_halve_others(void)
{
    asm
      {
        add edx, ecx ; replaced code
        cmp dword ptr [edi+4], STD_ARMS
        jb normal
        cmp dword ptr [edi+4], STD_FIST
        ja normal
        ; note that the minimum is 3, so we don`t need to check for zero
        shr edx, 1
        normal:
        mov dword ptr [edi+8], edx ; replaced code
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
        imul ecx, ecx, 6972 ; sizeof(struct player)
        add ecx, PARTY_ADDR
        mov esi, ecx
        call dword ptr ds:player_active ; exclude dead etc. players
        test eax, eax
        jz quit
        push 1 ; can resist -- arguable, but avoids abuse
        push 5 ; insane condition
        mov ecx, esi
        call condition_immunity ; our wrapper for inflict_condition()
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
        mov eax, dword ptr [0xacd4ec] ; party.x
        nop
        nop
      }
}

// This chunk deals with Y coordinate.
static void __declspec(naked) spirit_lash_y_chunk(void)
{
    asm
      {
        mov eax, dword ptr [0xacd4f0] ; party.y
        nop
        nop
      }
}

// This chunk deals with Z coordinate.  Some further code is erased.
static void __declspec(naked) spirit_lash_z_chunk(void)
{
    asm
      {
        mov ecx, dword ptr [0xacd4f4] ; party.z
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
        push 16 * 8 ; all conditions except zombie
        push 0 ; zero out
        push edi ; conditions are at beginning of struct player
        call dword ptr ds:memset_ptr
        add esp, 12
        and word ptr [edi+222], 0 ; cure aging
        add edi, 6972 ; replaced code
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
        movzx eax, word ptr [PARTY_BUFFS+16*BUFF_WIZARD_EYE+10] ; replaced code
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
        cmp esi, PARTY_BUFFS + 16 * BUFF_WIZARD_EYE
        jne not_eye
        cmp word ptr [esi+10], GM
        je quit ; caller will also check zf later
        not_eye:
        mov word ptr [esi+10], bx ; replaced code
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
        cmp word ptr [PARTY_BUFFS+16*BUFF_WIZARD_EYE+10], MASTER
        jg quit ; caller will also check flags
        cmp dword ptr [PARTY_BUFFS+16*BUFF_WIZARD_EYE+4], 0 ; replaced code
        quit:
        ret
      }
}

// Handle durationless GM Wizard Eye when counting buffs to display.
static void __declspec(naked) wizard_eye_display_count(void)
{
    asm
      {
        cmp eax, PARTY_BUFFS + 16 * BUFF_WIZARD_EYE
        jne not_eye
        cmp word ptr [eax+10], MASTER
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
        cmp ecx, PARTY_BUFFS + 16 * BUFF_WIZARD_EYE
        jne not_eye ; note that WE is last buff so it`ll never be greater
        cmp word ptr [ecx+10], MASTER
        not_eye:
        mov ecx, dword ptr [ecx+4] ; replaced code
        jg quit ; caller will also check flags
        test ecx, ecx ; replaced code
        quit:
        ret
      }
}

// Direct calls from assembly are not relocated.
static funcptr_t strcpy_ptr = strcpy;
static funcptr_t strcat_ptr = strcat;

// Display GM Wizard Eye duration as "Permanent".
static void __declspec(naked) wizard_eye_display_duration(void)
{
    asm
      {
        cmp dword ptr [ebp-8], PARTY_BUFFS + 16 * BUFF_WIZARD_EYE
        jne not_eye
        cmp word ptr [PARTY_BUFFS+16*BUFF_WIZARD_EYE+10], GM
        je permanent
        not_eye:
        push 0x41d1b6 ; replaced function call
        ret
        permanent:
        push 0x4e323c ; right-align code
        push 0x5c5c30 ; buffer used by the replaced function
        call dword ptr ds:strcpy_ptr
        push dword ptr [GLOBAL_TXT+121*4] ; "permanent"
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
// Casting it the second time will cancel it.
// TODO: cancelling could have a different sound?
static void __declspec(naked) wizard_eye_cast(void)
{
    asm
      {
        cmp dword ptr [ebp-24], GM
        je permanent
        shl eax, 7 ; replaced code
        mov dword ptr [ebp-20], eax ; replaced code
        ret
        permanent:
        mov di, word ptr [PARTY_BUFFS+16*BUFF_WIZARD_EYE+10]
        mov ecx, PARTY_BUFFS + 16 * BUFF_WIZARD_EYE
        call dword ptr ds:remove_buff
        mov word ptr [PARTY_BUFFS+16*BUFF_WIZARD_EYE+10], si ; == 0
        cmp di, GM
        je remove
        add word ptr [PARTY_BUFFS+16*BUFF_WIZARD_EYE+10], GM
        remove:
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
        cmp word ptr [PARTY_BUFFS+16*BUFF_WIZARD_EYE+10], GM
        je skip
        mov dword ptr [ebp-24], MASTER ; no GM
        fild qword ptr [0xacce64] ; replaced code
        ret
        skip:
        push 0x42deaa ; post-cast code
        ret 4
      }
}

// When re-casting Immolation or GM Wizard Eye to switch them off,
// do not charge spell points.
static void __declspec(naked) switch_off_spells_for_free(void)
{
    asm
      {
        mov dword ptr [ebp-180], eax ; replaced code
        jnz quit ; not casting from a spellbook
        cmp word ptr [ebx], SPL_IMMOLATION
        jne not_immolation
        mov eax, dword ptr [PARTY_BUFFS+16*BUFF_IMMOLATION]
        or eax, dword ptr [PARTY_BUFFS+16*BUFF_IMMOLATION+4]
        ret ; zf will be checked shortly
        not_immolation:
        cmp word ptr [ebx], SPL_WIZARD_EYE
        jne set_zf
        cmp dword ptr [ebp-24], GM
        jne set_zf
        cmp word ptr [PARTY_BUFFS+16*BUFF_WIZARD_EYE+10], GM
        jne set_zf
        cmp esi, 1 ; clear zf
        ret
        set_zf:
        test esi, esi
        quit:
        ret
      }
}

// Allow cancelling Immolation by casting it a second time.
static void __declspec(naked) switch_off_immolation(void)
{
    asm
      {
        mov ecx, dword ptr [PARTY_BUFFS+16*BUFF_IMMOLATION]
        or ecx, dword ptr [PARTY_BUFFS+16*BUFF_IMMOLATION+4]
        jz cast
        cmp word ptr [ebx+10], si ; only if casting from spellbook
        jz remove
        cast:
        shl eax, 7 ; replaced code
        mov dword ptr [ebp-44], eax ; replaced code
        ret
        remove:
        mov ecx, PARTY_BUFFS + 16 * BUFF_IMMOLATION
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

// Make Water Walk drain power only every 20 minutes, as per description.
static void __declspec(naked) water_walk_power_drain(void)
{
    asm
      {
        movzx edi, word ptr [PARTY_BUFFS+16*BUFF_WATER_WALK+8] ; power field
        add eax, edi
        xor edx, edx
        mov edi, 4 ; every 4th 5th min == every 20th min
        div edi
        mov word ptr [PARTY_BUFFS+16*BUFF_WATER_WALK+8], dx ; store remainder
        mov edx, 1 ; restore previous value
        add ecx, 6464 ; replaced code
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
        or dword ptr [esi+20], 0x10 ; replaced code
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
        push dword ptr [GLOBAL_TXT+221*4] ; "fate"
        jmp edx
      }
}

// Let the scrolls cast a spell according to mod1 in items.txt,
// as opposed to their item ID.  Allows retaining Fate scrolls.
static void __declspec(naked) scroll_spell_id(void)
{
    asm
      {
        lea ecx, [eax+eax*2]
        shl ecx, 4
        movzx esi, byte ptr [ITEMS_TXT_ADDR+ecx+30] ; mod1
        ret
      }
}

// Item-targeting spells sometimes got confused when targeting the first item
// in the PC's inventory, as its ID of 0 was mistaken for no chosen target,
// and with software 3D the game sometimes attempted to target a nearby
// monster instead, which resulted in a wrong item being chosen.
static void __declspec(naked) zero_item_spells(void)
{
    asm
      {
        mov eax, dword ptr [ebx+12] ; replaced code
        cmp eax, esi ; replaced code
        jnz quit
        cmp word ptr [ebx], SPL_FIRE_AURA
        je item
        cmp word ptr [ebx], SPL_RECHARGE_ITEM
        je item
        cmp word ptr [ebx], SPL_ENCHANT_ITEM
        je item
        cmp word ptr [ebx], SPL_SPECTRAL_WEAPON
        je item
        cmp word ptr [ebx], SPL_VAMPIRIC_WEAPON
        jne not_item
        item:
        cmp ebx, esi ; clear zf
        quit:
        ret
        not_item:
        xor eax, eax ; set zf
        ret
      }
}

// Misc spell tweaks.
static inline void misc_spells(void)
{
    // Charm and control undead were buggy: grandmaster control undead had
    // a very high value for duration (to simulate permanence) and due to
    // integer overflow it would become negative at a later point; thus,
    // the control effect was removed the next tick.
    // The charm spell had largely the same bug, except it also had a bug
    // wherein expert spell worked as master, master as GM, and GM as expert;
    // so, it was the master level charm that was broken.
    // Both bugs are fixed below.
    patch_dword(0x42e06a, 0xffffff); // control undead overflow
    patch_dword(0x428ea5, 0xffffff); // charm overflow
    patch_byte(0x428e8f, MASTER); // charm master
    patch_byte(0x428e9f, GM); // charm GM
    // Another bug: in the inter-monster combat, when one monster cast a spell
    // on another, the spell's element was read from the defending monster's
    // data.  Fixed below:
    patch_byte(0x43b2d1, 0x4f);
    patch_byte(0x43b2e2, 0x4f);
    // Some mod-specific tweaks for a change: let's swap the effects of
    // earth (now poison) and body (now magic) resistance spells.
    // (In MM6 poison res was a Body spell, and magic res was an Earth spell.)
    uint32_t poison = dword(0x48f7ec);
    patch_dword(0x48f7ec, dword(0x48f81c));
    patch_dword(0x48f81c, poison);
    poison = dword(0x48f7f3);
    patch_dword(0x48f7f3, dword(0x48f823));
    patch_dword(0x48f823, poison);
    // Shift the mind resistance icon a few pixels (for aesthetic reasons).
    patch_dword(0x4e5d58, dword(0x4e5d58) + 4);
    // Change the elements of some hardcoded spell effects.
    // This cannot be done on startup, but is delayed until spells.txt is read.
    hook_jump(0x453b35, spells_txt_tail);
    // Poison chest traps are also hardcoded.
    patch_dword(0x438f11, POISON); // was body (8)
    // Buff Ice Blast a little (d3 -> d6 damage).  Stolen from MM8.
    SPELL_INFO[SPL_ICE_BLAST].damage_dice = 6;
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
    hook_call(0x42ab30, enchant_item_noon_check, 5);
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
    hook_call(0x42e362, sacrifice_conditions, 6);
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
    hook_call(0x493a1e, water_walk_power_drain, 6);
    // Implement the Spectral Weapon spell (replaces Fate).
    patch_pointer(0x42ea21, spectral_weapon);
    patch_byte(0x427ccc, 1); // targets an item
    hook_jump(0x429161, spectral_aura);
    hook_call(0x41f0ec, monster_fate, 7); // first spell
    hook_call(0x41f13c, monster_fate, 7); // second spell
    hook_call(0x468654, scroll_spell_id, 6); // for fate scrolls
    // Set the same delays as Vampiric Weapon.
    SPELL_INFO[SPL_SPECTRAL_WEAPON].delay_normal = 120;
    SPELL_INFO[SPL_SPECTRAL_WEAPON].delay_expert = 100;
    // BTW, GM Vampiric Weapon for some reason had a larger delay?  Fixed here:
    SPELL_INFO[SPL_VAMPIRIC_WEAPON].delay_gm = 90;
    // Another MM8 idea: buff Flying Fist a little.
    SPELL_INFO[SPL_FLYING_FIST].damage_fixed = 20;
    SPELL_INFO[SPL_FLYING_FIST].damage_dice = 10;
    hook_call(0x427e6a, zero_item_spells, 5);
}

// For consistency with players, monsters revived with Reanimate now have
// their resistances changed the same way as zombie players
// (immune to poison and mind, not immune to holy).
static void __declspec(naked) zombify(void)
{
    asm
      {
        mov byte ptr [edi+0x53], IMMUNE
        mov byte ptr [edi+0x54], IMMUNE
        cmp byte ptr [edi+0x55], IMMUNE
        jne not_immune
        mov byte ptr [edi+0x55], 0
        not_immune:
        lea ecx, [edi+0x164]
        ret
      }
}

// Replace the call to the "monster type" function with a check
// for holy immunity, so the zombified monsters will be affected.
static void __declspec(naked) destroy_undead_chunk(void)
{
    asm
      {
        cmp byte ptr [eax+0x55], IMMUNE
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
        cmp byte ptr [MAP_MONSTERS_ADDR+eax+0x55], IMMUNE
      }
}

// There's a couple more places where the game checks for undead-ness,
// but these three are the most important ones.  Notably, I didn't change
// "of undead slayer" modifier, but that's because I plan to rework it
// entirely in the future versions.
static void __declspec(naked) turn_undead_chunk(void)
{
    asm
      {
        cmp byte ptr [edi+0x55], IMMUNE
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
        cmp byte ptr [esi+0xb9], CLASS_LICH
        _emit 0x74
        _emit 0x0d
        mov eax, dword ptr [ebp-0x2c]
        or eax, dword ptr [ebp-0x28]
        or eax, dword ptr [ebp-0x24]
        or eax, dword ptr [ebp-0x20]
        nop
      }
}

// Let the Undead Slaying weapons attack with Holy instead of Physical
// when it's preferable.  Together with ghosts now immune to Physical,
// makes holy water useful.  If dual-wielding, only 50% of damage is affected.
// The new Spectral/Wraith weapons are also handled here.  Undead Slaying
// always takes precedence over Spectral, which is okay since
// all undead are at least as vulnerable to Holy as to Magic.
// TODO: check if this works properly with Day of Protection
static void __declspec(naked) undead_slaying_element(void)
{
    asm
      {
        and dword ptr [ebp-20], 0 ; zero out the damage just in case
        cmp dword ptr [ebp-8], PHYSICAL ; main attack element
        jne skip
        mov al, byte ptr [esi+89] ; monster physical res
        cmp al, byte ptr [esi+85] ; monster holy res
        seta dl
        cmp al, byte ptr [esi+86] ; monster magic res
        seta dh
        test dx, dx
        jz skip
        test ebx, ebx ; projectile
        jz prepare
        cmp dword ptr [ebx+72], SPL_ARROW
        jne skip
        prepare:
        push ebx ; backup
        push 0 ; count of weapons
        push 0 ; count of undead slaying weapons
        push 0 ; count of spectral weapons
        test ebx, ebx
        movzx ebx, dx
        jz weapon
        ; bow
        mov ecx, 1 ; no looping
        mov eax, dword ptr [edi+0x1950] ; bow slot
        jmp check_slot
        weapon:
        mov ecx, 2 ; main hand first
        check_hand:
        mov eax, dword ptr [edi+ecx*4+0x1944] ; one of hand slots
        check_slot:
        test eax, eax
        jz other_hand
        lea eax, [eax+eax*8]
        lea eax, [edi+0x214+eax*4-36]
        test byte ptr [eax+20], 2 ; broken bit
        jnz other_hand
        mov edx, dword ptr [eax] ; id
        lea edx, [edx+edx*2]
        shl edx, 4
        cmp byte ptr [ITEMS_TXT_ADDR+edx+28], 2 ; equip stat 0-2 = weapon
        ja other_hand
        inc dword ptr [esp+8] ; have a weapon
        test bl, bl
        jz skip_undead
        cmp dword ptr [eax], GHOULSBANE
        je undead
        cmp dword ptr [eax], GIBBET
        je undead
        cmp dword ptr [eax], JUSTICE
        je undead
        cmp dword ptr [eax+12], SPC_UNDEAD_SLAYING
        je undead
        cmp dword ptr [eax+4], TEMP_ENCH_MARKER
        jne skip_undead
        cmp dword ptr [eax+8], SPC_UNDEAD_SLAYING
        jne skip_undead
        undead:
        inc dword ptr [esp+4] ; have an undead slaying weapon
        jmp other_hand
        skip_undead:
        test bh, bh
        jz other_hand
        cmp dword ptr [eax+12], SPC_SPECTRAL
        je spectral
        cmp dword ptr [eax+12], SPC_WRAITH
        je spectral
        cmp dword ptr [eax+4], TEMP_ENCH_MARKER
        jne other_hand
        cmp dword ptr [eax+8], SPC_SPECTRAL
        je spectral
        cmp dword ptr [eax+8], SPC_WRAITH
        jne other_hand
        spectral:
        inc dword ptr [esp] ; have a spectral weapon
        other_hand:
        dec ecx
        jnz check_hand
        pop edx ; spectral
        pop ebx ; undead sl.
        pop ecx ; total
        test ebx, ebx
        jnz holy
        test edx, edx
        jz quit
        cmp edx, ecx
        je just_magic
        holy:
        cmp ebx, ecx
        je just_holy
        ; split the damage in half
        mov eax, dword ptr [ebp-12]
        shr eax, 1
        sub dword ptr [esp+8], eax ; pushed damage
        push eax
        cmp ebx, edx ; only equal here if both == 1 and two weapons
        je both
        push PHYSICAL
        jmp either
        both:
        push MAGIC
        either:
        push esi
        call dword ptr ds:monster_resists
        mov dword ptr [ebp-20], eax ; lesser half of damage
        test ebx, ebx
        jz just_magic
        just_holy:
        mov dword ptr [ebp-8], HOLY
        jmp quit
        just_magic:
        mov dword ptr [ebp-8], MAGIC
        quit:
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

// Tweaks of zombie players and monsters.
static inline void zombie_stuff(void)
{
    hook_call(0x42dcd0, zombify, 6);
    patch_bytes(0x428987, destroy_undead_chunk, 7);
    patch_bytes(0x42e0ad, control_undead_chunk, 7);
    patch_bytes(0x42bce1, turn_undead_chunk, 7);
    patch_bytes(0x4b75e3, zombificable_chunk, 22);
    hook_call(0x4398c3, undead_slaying_element, 5);
    hook_call(0x4398d1, add_damage_half, 5);
}

// Calls the original function.
static int __fastcall __declspec(naked) parse_spell(char **words,
                                                    int *extra_words)
{
    asm
      {
        push ebp
        mov ebp, esp
        push ecx
        push ecx
        push 0x454913
        ret
      }
}

// Parse "turn undead" and "destory undead" in monsters.txt.
static int __fastcall parse_new_spells(char **words, int *extra_words)
{
    char *first_word = words[1];
    if (!first_word)
        return 0;
    if (!uncased_strcmp(first_word, "turn"))
      {
        ++*extra_words;
        return SPL_TURN_UNDEAD;
      }
    if (!uncased_strcmp(first_word, "destroy"))
      {
        ++*extra_words;
        return SPL_DESTROY_UNDEAD;
      }
    return parse_spell(words, extra_words);
}

// Calls the original function.
static int __thiscall __declspec(naked) monster_considers_spell(void *this,
                                                                void *monster,
                                                                int spell)
{
    asm
      {
        push ebp
        mov ebp, esp
        mov eax, dword ptr [ebp+12]
        push 0x4270bf
        ret
      }
}

// Monsters can now cast turn undead (only on party, only if liches or zombies
// present) and destoy undead (on any undead PC or monster).
static int __thiscall consider_new_spells(void *this,
                                          struct map_monster *monster,
                                          int spell)
{
    int monster_id = monster - MAP_MONSTERS;
    unsigned int target = MON_TARGETS[monster_id];
    if (spell == SPL_TURN_UNDEAD)
      {
        // Make sure we're targeting the party (no effect on monsters so far).
        if (target != TGT_PARTY)
            return 0;

        // I *think* this is the line-of-sight bit,
        // although it's inconsistent on peaceful monsters.
        if (!(monster->bits & 0x200000))
            return 0;

        for (int i = 0; i < 4; i++)
            if (is_undead(&PARTY[i]) && player_active(&PARTY[i])
                && !PARTY[i].conditions[COND_AFRAID])
                return 1;
        return 0;
      }
    else if (spell == SPL_DESTROY_UNDEAD)
      {
        if (target == TGT_PARTY)
          {
            if (!(monster->bits & 0x200000)) // has line of sight
                return 0;
            for (int i = 0; i < 4; i++)
                if (is_undead(&PARTY[i]) && player_active(&PARTY[i]))
                    return 1;
            return 0;
          }
        else if ((target & 7) == TGT_MONSTER) 
            return MAP_MONSTERS[target>>3].holy_resistance != IMMUNE;
        else // shouldn't happen
            return 0;
      }
    else
        return monster_considers_spell(this, monster, spell);
}

// Calls the original function.
static void __fastcall __declspec(naked) monster_casts_spell(int monster,
                                                             void *vector,
                                                             int spell,
                                                             int action,
                                                             int skill)
{
    asm
      {
        push ebp
        mov ebp, esp
        sub esp, 0xbc
        push 0x404ad0
        ret
      }
}

//Defined below.
static int __thiscall absorb_spell(struct player *player, int spell);

// Turn undead scares all undead PCs, with no chance to resist.
// Destroy undead damages one undead PC or monster with Holy.
// We also handle the Cursed monster debuff here.
static void __fastcall cast_new_spells(int monster, void *vector, int spell,
                                       int action, int skill)
{
    if (MAP_MONSTERS[monster].spell_buffs[MBUFF_CURSED].expire_time
        && random() & 1) // 50% chance
      {
        make_sound(SOUND_THIS, SOUND_SPELL_FAIL, 0, 0, -1, 0, 0, 0, 0);
        return;
      }

    int spell_sound = word(0x4edf30 + spell * 2);
    if (spell == SPL_TURN_UNDEAD)
      {
        // we must be targeting the party
        for (int i = 0; i < 4; i++)
            if (is_undead(&PARTY[i]) && player_active(&PARTY[i])
                && !absorb_spell(&PARTY[i], spell))
                inflict_condition(&PARTY[i], COND_AFRAID, 0);
        make_sound(SOUND_THIS, spell_sound, 0, 0, -1, 0, 0, 0, 0);
      }
    else if (spell == SPL_DESTROY_UNDEAD)
      {
        unsigned int target = MON_TARGETS[monster];
        if (target == TGT_PARTY)
          {
            struct player *target_player;
            int count = 0;
            for (int i = 0; i < 4; i++)
                if (is_undead(&PARTY[i]) && player_active(&PARTY[i])
                    && !(random() % ++count)) // randomly choose one player
                    target_player = &PARTY[i];
            if (count && !absorb_spell(target_player, spell))
              {
                int mastery = skill_mastery(skill);
                skill &= SKILL_MASK;
                int damage = spell_damage(spell, skill, mastery, 0);
                damage_player(target_player, damage, ELEMENT(spell));
              }
          }
        else if ((target & 7) == TGT_MONSTER)
          {
            int attack_type;
            // hack to determine which spell (first or second) we're casting
            if (MAP_MONSTERS[monster].spell1 == spell)
                attack_type = 2;
            else
                attack_type = 3;
            uint32_t force[3];
            memset(force, 0, 12); // no knockback so far
            attack_monster(monster * 8 + TGT_MONSTER, target >> 3, force,
                           attack_type);
          }
        make_sound(SOUND_THIS, spell_sound, 0, 0, -1, 0, 0, 0, 0);
      }
    else
        monster_casts_spell(monster, vector, spell, action, skill);
}

// Make Turn Undead and Destroy Undead castable by monsters.
static inline void new_monster_spells(void)
{
    hook_jump(0x45490e, parse_new_spells);
    hook_jump(0x4270b9, consider_new_spells);
    hook_jump(0x404ac7, cast_new_spells);
}

// Calling atoi directly from assembly doesn't seem to work,
// probably because it's not relocated.
static funcptr_t atoi_ptr = atoi;

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
        imul ecx, ebx, 68 ; struct size
        mov byte ptr [esi+ecx+44], al ; unused byte
        push 0x45472a ; default case
        ret 4
      }
}

#define REP_GROUP_COUNT 16
// Stored reputation for the game's different regions.
// 12-15 are unused.  0 is always neutral.
static int regional_reputation[REP_GROUP_COUNT];
#define REP_STACK_SIZE 8
// Current reputation group.  Stores multiple values
// to be pushed/popped by the game script.
static int reputation_group[REP_STACK_SIZE];
// Top of the reputation group stack.
static int reputation_index;

// Zero out all reputation on a new game.
static void __declspec(naked) new_game_rep(void)
{
    asm
      {
        mov dword ptr [0xacd4f8], eax ; replaced code
        xor eax, eax
        mov dword ptr [reputation_group], eax
        mov dword ptr [reputation_index], eax
        push ecx
        push edi
        cld
        mov edi, offset regional_reputation
        mov ecx, REP_GROUP_COUNT
        rep stosd
        pop edi
        pop ecx
        ret
      }
}

// Load reputation data from the savegame, if said data exists.
static void load_game_rep(void)
{
    void *file = find_in_lod(SAVEGAME_LOD, "reputatn.bin", 1);
    if (file)
        fread(regional_reputation, sizeof(int), REP_GROUP_COUNT, file);
    else // new or unpatched game; zero out all rep
        memset(regional_reputation, 0, REP_GROUP_COUNT * sizeof(int));
    reputation_group[0] = 0; // will be set on map load
    reputation_index = 0;
}

// For bank_interest() below, stores the last week the interest was applied.
// On a reload it's reset to 0 and then overwriten properly on the next tick.
// On a new game it's lowered to the current week, which is also 0.
static int last_bank_week;

// Hook for the above.
// Also inits bank interest counter and resets hit messages.
static void __declspec(naked) load_game_hook(void)
{
    asm
      {
        call load_game_rep
        and dword ptr [last_bank_week], 0
        and dword ptr [last_hit_player], 0
        pop eax
        push 0x4e958c ; replaced code
        jmp eax
      }
}

// Update and save reputation into the savefile.
static void save_game_rep(void)
{
    // name could be shorter, I'm guessing here
    static const struct { char name[20]; int size; int unknown; } header
        = { "reputatn.bin", REP_GROUP_COUNT * sizeof(int), 0 };
    int group = reputation_group[reputation_index];
    if (group) // do not store group 0
        regional_reputation[group] = CURRENT_REP;
    save_file_to_lod(SAVEGAME_LOD, &header, regional_reputation, 0);
}

// Hook for the above.  Also handles WoM barrels.
static void __declspec(naked) save_game_hook(void)
{
    asm
      {
        call save_game_rep
        call save_wom_barrels
        lea eax, [ebp-68] ; replaced code
        ret 8
      }
}

// Set the map's default reputation group and update current reputation.
static void load_map_rep(void)
{
    reputation_index = 0;
    int map_index = get_map_index(MAPSTATS, CUR_MAP_FILENAME);
    reputation_group[0] = MAPSTATS[map_index].reputation_group;
    CURRENT_REP = regional_reputation[reputation_group[0]];
}

// Hook for the above.  It's somewhat awkward, but Grayface has
// already claimed all good places to fit a call into.
// Also handles WoM barrels, resetting disabled spells, and weather,
// which was not initialized properly on visiting a new map.
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
        cmp dword ptr [0x6be1e0], 2 ; test if outdoors
        jne quit
        cmp dword ptr [0x6a1160], esi ; last visit time, 0 if just refilled
        jnz quit
        cmp dword ptr [0x6a1164], esi ; second half (esi == 0, btw)
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
        regional_reputation[group] = CURRENT_REP;
}

// Hook for the above.  Again, inserted in a somewhat inconvenient place.
// This function governs the LeaveMap event, as I understand,
// but it wasn't called on boat/horse travel, which is fixed below.
static void __declspec(naked) leave_map_hook(void)
{
    asm
      {
        jle quit
        call leave_map_rep
        pop eax
        push esi ; replaced code
        mov esi, 0x5b645c ; replaced code
        jmp eax
        quit:
        call leave_map_rep
        push 0x443ffd ; replaced jump
        ret 4
      }
}

// Bug fix: trigger the LeaveMap event when traveling by horse or boat.
static void __declspec(naked) leave_horse_boat(void)
{
    asm
      {
        call dword ptr ds:on_map_leave
        movzx eax, byte ptr [esi] ; replaced code
        imul eax, eax, 68 ; replaced code
        ret
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
        ; clang refuses to compile [rep_group+ecx*4], so I have to improvise
        mov edx, offset reputation_group
        cmp dword ptr [edx+ecx*4], eax
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

// Hook for the new gamescript cmp code.
static void __declspec(naked) evt_cmp_hook(void)
{
    asm
      {
        cmp eax, EVT_REP_GROUP
        je rep
        cmp eax, EVT_DISABLED_SPELL
        je spell
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
      }
}

// Add pushes new group on the stack, while preserving the original value.
// Useful for temporarily changing the group.
static void __stdcall add_rep(int new_group)
{
    int old_group = reputation_group[reputation_index];
    if (old_group) // do not store group 0
        regional_reputation[old_group] = CURRENT_REP;
    if (reputation_index < REP_STACK_SIZE - 1) // guard from overflow
        reputation_index++;
    reputation_group[reputation_index] = new_group;
    CURRENT_REP = regional_reputation[new_group];
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
        sub eax, 307 ; replaced code
        ret
        rep:
        push dword ptr [ebp+12]
        call add_rep
        jmp quit
        spell:
        push dword ptr [ebp+12]
        call disable_spell
        quit:
        push 0x44b90d
        ret 4
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
                    regional_reputation[group_to_remove] = CURRENT_REP;
                CURRENT_REP = regional_reputation[reputation_group[i-1]];
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
        sub eax, 308 ; replaced code
        ret
        rep:
        push dword ptr [ebp+12]
        call sub_rep
        jmp quit
        spell:
        push dword ptr [ebp+12]
        call enable_spell
        quit:
        push 0x44bb0d
        ret 4
      }
}

// Set discards the stack and changes the current group to the given value.
// Can be used to "permanently" change the group,
// as long as it's done on every game/map reload.
static void __stdcall set_rep(int new_group)
{
    int old_group = reputation_group[reputation_index];
    if (old_group) // do not store group 0
        regional_reputation[old_group] = CURRENT_REP;
    reputation_index = 0;
    reputation_group[0] = new_group;
    CURRENT_REP = regional_reputation[new_group];
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
        sub eax, 307 ; replaced code
        ret
        rep:
        push dword ptr [ebp+12]
        call set_rep
        jmp quit
        spell:
        push dword ptr [ebp+12]
        call disable_spell
        quit:
        push 0x44af3b
        ret 4
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

// Armageddon did not affect reputation, even if it killed peasants.
// Let's overcompensate by adding an unconditional rep penalty.
static void armageddon_rep(void)
{
    uint32_t *rep = &CURRENT_REP;
    *rep += 20;
    if ((signed) *rep > 10000) // vanilla rep code often has this limit
        *rep = 10000;
}

// Hook for the above.
static void __declspec(naked) armageddon_hook(void)
{
    asm
      {
        call armageddon_rep
        cmp dword ptr [0x6650a8], esi ; replaced code
        ret
      }
}

// Let the town hall bounties affect reputation slightly.
static void __stdcall bounty_rep(int level)
{
    int rep = (level + 10) / 20; // 0 to 5
    if (rep)
        CURRENT_REP -= rep;
}

// Hook for the above.
static void __declspec(naked) bounty_hook(void)
{
    asm
      {
        movzx ebx, byte ptr [0x5cccc0+eax+8] ; monsters.txt level
        push ebx
        call bounty_rep
        mov eax, ebx
        ret
      }
}

// Change "evil" hireable NPC penalty: instead of temporary -5 rep
// in all regions, give a permanent -5 in their home region.
static void __stdcall hire_npc_rep(int profession)
{
    if (profession == NPC_PIRATE || profession == NPC_GYPSY
        || profession == NPC_DUPER || profession == NPC_BURGLAR
        || profession == NPC_FALLEN_WIZARD)
      {
        uint32_t *rep = &CURRENT_REP;
        *rep += 5;
        if ((signed) *rep > 10000) // vanilla rep code often has this limit
            *rep = 10000;
      }
}

// Hook for the above.
static void __declspec(naked) hire_npc_hook(void)
{
    asm
      {
        push dword ptr [ebp+24] ; npc profession
        call hire_npc_rep
        cmp dword ptr [0xad44f4], esi ; replaced code
        ret
      }
}

// Let the reputation values be shared between different locations
// in the same region.  Among other things, this makes quests
// completed in castles affect your reputation properly.
static inline void reputation(void)
{
    hook_call(0x45403c, parse_mapstats_rep, 7);
    patch_byte(0x454739, 30); // one more column
    hook_call(0x460a97, new_game_rep, 5);
    hook_call(0x45f0f2, load_game_hook, 5);
    hook_call(0x45f911, save_game_hook, 5);
    hook_call(0x444011, load_map_hook, 6);
    hook_call(0x443fc1, leave_map_hook, 8);
    hook_call(0x4b6a89, leave_horse_boat, 6);
    hook_call(0x41ab0f, show_zero_rep, 5);
    hook_call(0x44a111, evt_cmp_hook, 6);
    hook_call(0x44b85f, evt_add_hook, 5);
    hook_call(0x44bff0, evt_sub_hook, 5);
    hook_call(0x44ae96, evt_set_hook, 5);

    // Some further reputation tweaks.
    hook_call(0x42ec41, pickpocket_rep, 5);
    // Related: fix a wrong pickpocket message.
    patch_pointer(0x48da92, &new_strings[20]);
    // Do not decrease rep on successful shoplift.
    patch_byte(0x4b13bf, 0);
    hook_call(0x401b4e, armageddon_hook, 6);
    hook_call(0x4bd223, bounty_hook, 7);
    hook_call(0x4bc695, hire_npc_hook, 6);
    // Remove an ongoing NPC rep penalty.
    erase_code(0x477549, 72);
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
    patch_dword(0x446709, GLOBAL_EVT_LINES * 12);
    patch_pointer(0x44670e, global_evt_lines);
    // The next constant is shared with the map event lines buffer,
    // but there's no harm in increasing it.
    patch_dword(0x4468b9, GLOBAL_EVT_LINES * 12);
    patch_pointer(0x4468e9, global_evt_lines);
    // Both times the buffer is read, it's copied into another
    // statically allocated buffer, both of which also need to be replaced.
    static uint32_t evt_lines_buffer[GLOBAL_EVT_LINES*3];
    patch_pointer(0x446713, evt_lines_buffer);
    patch_pointer(0x446754, evt_lines_buffer);
    patch_pointer(0x44675c, evt_lines_buffer + 1);
    patch_pointer(0x446764, evt_lines_buffer + 2);
    static uint32_t evt_lines_buffer_2[GLOBAL_EVT_LINES*3];
    patch_pointer(0x446904, evt_lines_buffer_2);
    patch_pointer(0x44694d, evt_lines_buffer_2);
    patch_pointer(0x44695d, evt_lines_buffer_2 + 1);
    patch_pointer(0x446969, evt_lines_buffer_2 + 2);
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
        sub eax, dword ptr [esi+6460] ; current hp
        jge no_burnout
        sar eax, 2 ; 25%, rounded up
        add dword ptr [esi+6460], eax ; burnout
        push 0x493d93 ; skip hp regen code
        ret 4
        no_burnout:
        mov ecx, esi
        push SKILL_BODYBUILDING
        call dword ptr ds:get_skill
        cmp eax, SKILL_GM
        jb no_bb_regen
        and eax, SKILL_MASK
        xor edx, edx
        mov ecx, 5
        div ecx
        add ebx, eax
        no_bb_regen:
        test ebx, ebx
        jz no_regen
        mov eax, dword ptr [esi+112] ; replaced code
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
// Also here: handle SP regen from GM Meditation.
static void __declspec(naked) sp_burnout(void)
{
    asm
      {
        xor eax, eax ; zombies have no sp
        cmp dword ptr [ebp-24], 0 ; zombie
        jnz compare_sp
        mov ecx, esi
        call dword ptr ds:get_full_sp
        cmp dword ptr [ebp-16], 0 ; lich wo jar
        jz compare_sp
        shr eax, 1 ; jar-less liches have half sp
        compare_sp:
        sub eax, dword ptr [esi+6464] ; current sp
        jg meditation_regen
        je quit
        sar eax, 2 ; 25%, rounded up
        add dword ptr [esi+6464], eax ; burnout
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
        mov ecx, 6
        div ecx
        cmp eax, edi
        cmova eax, edi
        add dword ptr [esi+6464], eax
        jmp quit
      }
}

// Do not remove HP above maximum when healing.
// Allow healing potions to cure above max HP (only if HP wasn't full before).
static void __declspec(naked) healing_potions(void)
{
    asm
      {
        cmp dword ptr [esi+6460], eax
        jge skip
        add dword ptr [esi+6460], ecx ; replaced code
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
        cmp dword ptr [edx+6460], eax ; current vs max hp
        jge quit
        mov dword ptr [edx+6460], eax ; replaced code
        quit:
        ret
      }
}

// Do not lower SP to maximum during a Divine Intervention.
static void __declspec(naked) divine_intervention_sp(void)
{
    asm
      {
        cmp dword ptr [ecx+6464], eax ; current vs max sp
        jge quit
        mov dword ptr [ecx+6464], eax ; replaced code
        quit:
        ret
      }
}

// Do not lower HP to maximum after a Sacrifice.
static void __declspec(naked) sacrifice_hp(void)
{
    asm
      {
        cmp dword ptr [edi+6460], eax ; current vs max hp
        jge quit
        mov dword ptr [edi+6460], eax ; replaced code
        quit:
        ret
      }
}

// Do not lower SP to maximum after a Sacrifice.
static void __declspec(naked) sacrifice_sp(void)
{
    asm
      {
        cmp dword ptr [edi+6464], eax ; current vs max sp
        jge quit
        mov dword ptr [edi+6464], eax ; replaced code
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
        cmp dword ptr [esi+6460], eax ; current vs max hp
        jge quit
        mov dword ptr [esi+6460], eax ; replaced code
        quit:
        ret
      }
}

// Prevent expert healer NPC from lowering HP to maximum.
static void __declspec(naked) expert_healer_hp(void)
{
    asm
      {
        cmp dword ptr [esi+6340], eax ; current vs max hp
        jge quit
        mov dword ptr [esi+6340], eax ; replaced code
        quit:
        ret
      }
}

// Prevent master healer NPC from lowering HP to maximum.
static void __declspec(naked) master_healer_hp(void)
{
    asm
      {
        cmp dword ptr [esi+6180], eax ; current vs max hp
        jge quit
        mov dword ptr [esi+6180], eax ; replaced code
        quit:
        ret
      }
}


// Prevent temples from lowering SP to maximum.
static void __declspec(naked) temple_sp(void)
{
    asm
      {
        cmp dword ptr [esi+6464], eax ; current vs max sp
        jge quit
        mov dword ptr [esi+6464], eax ; replaced code
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
    hook_call(0x42dad9, divine_intervention_sp, 6);
    hook_call(0x42e351, sacrifice_hp, 6);
    hook_call(0x42e35c, sacrifice_sp, 6);
    erase_code(0x42e6c4, 36); // allow Souldrinker to heal above maximum
    // BTW, Souldrinker cures flat (7*skill+25) per visible monster,
    // irrespective of the actual damage.  Should this be documented?
    erase_code(0x4399e2, 26); // allow vampiric melee weapons to overheal
    erase_code(0x439951, 26); // allow vampiric bows to overheal
    hook_call(0x4bb83f, healer_or_temple_hp, 6); // healer
    hook_call(0x4bb816, expert_healer_hp, 6);
    hook_call(0x4bb76c, master_healer_hp, 6);
    // Bug fix: master healer erased armor skills.
    // A very strange code that was overwriting the armor skill data
    // with the duration of unused condition 19.
    // I've no clue what it was supposed to be.
    erase_code(0x4bb762, 5);
    hook_call(0x4b755e, healer_or_temple_hp, 6); // temple
    hook_call(0x4b7569, temple_sp, 6);
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

// Bug fix: display minutes in buff duration if it's over a day long
// but there are no hours to display -- i.e.  "X days Y minutes".
static void __declspec(naked) days_minutes_buff(void)
{
    asm
      {
        cmp dword ptr [esp+56], 0 ; replaced code (days)
        jz quit
        cmp ebp, 0 ; hours
        quit:
        ret
      }
}

// Bug fix: do not display seconds in buff duration if at least two
// of days, hours, or minutes have been printed already.
static void __declspec(naked) seconds_buff(void)
{
    // skip seconds if zf == 0
    asm
      {
        jnz have_seconds
        cmp eax, 1 ; clear zf
        ret
        have_seconds:
        cmp dword ptr [esp+56], 0 ; days
        jz no_days
        cmp ebp, 0 ; hours
        jnz quit
        minutes:
        cmp dword ptr [esp+36], 0 ; minutes
        ret
        no_days:
        cmp ebp, 0 ; hours
        jnz minutes
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
        mov eax, dword ptr [0x507a40] ; parent dialogue or smth
        mov eax, dword ptr [eax+28] ; param = temple id
        imul eax, eax, 52 ; 2devents struct size
        fld dword ptr [0x5912b8+eax+32] ; val field = temple cost
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
        mov eax, dword ptr [0x507a40] ; parent dialogue or smth
        mov eax, dword ptr [eax+28] ; param = temple id
        imul eax, eax, 52 ; 2devents struct size
        fld dword ptr [0x5912b8+eax+32] ; val field = temple cost
        push 5
        fidiv dword ptr [esp] ; temple power = cost / 5
        fistp dword ptr [esp]
        pop eax
        lea edx, [edx+1+eax+SKILL_MASTER] ; spell pwr = temple pwr + weekday
        ret
      }
}

// Since blasters have a different min recovery, we need to check for them.
static void __declspec(naked) recovery_check_blaster(void)
{
    asm
      {
        cmp eax, SKILL_BLASTER
        jne not_it
        mov dword ptr [ebp+8], 2 ; store in ranged param (which was 1)
        not_it:
        movzx eax, word ptr [0x4edd80+eax*2] ; replaced code
        ret
      }
}

// Set min weapon recovery to 10 for blasters and 20 otherwise.
// TODO: move the hook slightly below once I can disable mm7patch hooks
static void __declspec(naked) min_weapon_recovery(void)
{
    asm
      {
        add ecx, dword ptr [ebp-20] ; replaced code
        add ecx, dword ptr [ebp-4] ; replaced code
        mov eax, 20
        cmp dword ptr [ebp+8], 2
        jne not_blaster
        mov eax, 10
        not_blaster:
        cmp ecx, eax
        jge quit
        mov ecx, eax
        quit:
        ret
      }
}

// MM7Patch has a hardcoded cap of 30 on melee recovery.
// As such, we need to correct the displayed number if it should be lower.
static void __stdcall display_melee_recovery(char *buffer)
{
    struct player *current = &PARTY[dword(0x507a6c)-1];
    int recovery = get_attack_delay(current, 0);
    if (recovery >= 30)
        return;
    char *number = strstr(buffer, "30");
    if (!number)
        return;
    // don't need printf for this
    number[0] = recovery / 10 + '0';
    number[1] = recovery % 10 + '0';
}

static char *__stdcall resistance_hint(char *description, int resistance)
{
    static char buffer[400];
    struct player *current = &PARTY[dword(0x507a6c)-1];
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
            element = ELECTRICITY;
            base = current->shock_res_base;
            if (race == RACE_GOBLIN)
                racial_bonus = 5 + current->level_base / 2;
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
                racial_bonus = 5 + current->level_base / 2;
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
    int total = get_player_resistance(current, resistance - 9);
    if (total)
        total += get_effective_stat(get_luck(current));
    strcpy(buffer, description);
    if (total > 0 && !is_immune(current, element))
      {
        // the math is complicated, but it should be correct
        double chance = total / 2.0 / (total + 30);
        double square = chance * chance;
        double percent = (chance + square) * (square + 1) * 100;
        sprintf(buffer + strlen(buffer), "\n\n%s: %.1f%%",
                new_strings[33], percent);
      }
    else if (!base_immune)
        strcat(buffer, "\n");
    if (!base_immune)
      {
        sprintf(buffer + strlen(buffer), "\n%s: %d", new_strings[26], base);
        if (racial_bonus)
            sprintf(buffer + strlen(buffer), " (%d %s)",
                    base + racial_bonus, new_strings[34]);
      }
    return buffer;
}

// Hook for the above.  Also deals with resistance messages.
// TODO: could also call stat_hint()
static void __declspec(naked) display_melee_recovery_hook(void)
{
    asm
      {
        cmp edi, 15 ; screen area id
        jne not_recovery
        push ebx
        call display_melee_recovery
        not_recovery:
        cmp edi, 19 ; fire
        jb not_resistance
        cmp edi, 24 ; body
        ja not_resistance
        push edi
        push ebx
        call resistance_hint
        mov ebx, eax
        not_resistance:
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
        lea edx, [esi+0x1948+SLOT_MAIN_HAND*4]
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
        mov ebx, dword ptr [0xacd570] ; bank gold
        push 100
        interest:
        mov eax, ebx
        xor edx, edx
        div dword ptr [esp]
        add ebx, eax
        loop interest
        mov dword ptr [0xacd570], ebx ; new bank gold
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
    struct player *current = &PARTY[dword(0x507a6c)-1];
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
            new_strings[25], statrates[rating].rating, bonus,
            new_strings[26], base);
    int race = get_race(current);
    int adj = base * RACE_STATS[race][stat][3] / RACE_STATS[race][stat][2];
    if (adj != base)
        sprintf(buffer + strlen(buffer), " (%d %s)", adj, new_strings[34]);
    if (current->black_potions[potion])
      {
        strcat(buffer, "\n");
        strcat(buffer, new_strings[32]);
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

// Give the two-handed swords and axes doubled quality bonus to damage.
// Charele also gets this bonus (as an unique artifact property).
static void __declspec(naked) th_weapons_damage(void)
{
    asm
      {
        movzx eax, byte ptr [ITEMS_TXT_ADDR+esi+32] ; replaced code (dmg bonus)
        cmp ebp, CHARELE
        je doubled
        cmp byte ptr [ITEMS_TXT_ADDR+esi+28], 1 ; two-handed weapon
        jne quit
        cmp byte ptr [ITEMS_TXT_ADDR+esi+29], SKILL_SWORD
        je doubled
        cmp byte ptr [ITEMS_TXT_ADDR+esi+29], SKILL_AXE
        jne quit
        doubled:
        shl eax, 1
        quit:
        ret
      }
}

// Display new two-handed weapon stats correctly.
static void __declspec(naked) th_weapons_description(void)
{
    asm
      {
        lea eax, [ebp-204] ; replaced code
        mov ecx, dword ptr [ebp-4] ; item
        cmp dword ptr [ecx], CHARELE
        je doubled
        cmp byte ptr [edi+28], 1
        jne quit
        cmp byte ptr [edi+29], SKILL_SWORD
        je doubled
        cmp byte ptr [edi+29], SKILL_AXE
        jne quit
        doubled:
        shl dword ptr [esp+4], 1 ; pushed bonus damage
        quit:
        ret
      }
}

// Calculate the new minimum damage for two-handed weapons.
static void __declspec(naked) th_weapons_min_damage(void)
{
    asm
      {
        movzx edi, byte ptr [ITEMS_TXT_ADDR+eax+32] ; replaced code (dmg bonus)
        cmp edx, CHARELE
        je doubled
        cmp byte ptr [ITEMS_TXT_ADDR+eax+28], 1 ; two-handed weapon
        jne quit
        cmp byte ptr [ITEMS_TXT_ADDR+eax+29], SKILL_SWORD
        je doubled
        cmp byte ptr [ITEMS_TXT_ADDR+eax+29], SKILL_AXE
        jne quit
        doubled:
        shl edi, 1
        quit:
        ret
      }
}

// Calculate the new maximum damage for two-handed weapons.
static void __declspec(naked) th_weapons_max_damage(void)
{
    asm
      {
        cmp edx, CHARELE
        je damage
        cmp byte ptr [ITEMS_TXT_ADDR+eax+28], 1 ; two-handed weapon
        jne damage
        cmp byte ptr [ITEMS_TXT_ADDR+eax+29], SKILL_SWORD
        je damage
        cmp byte ptr [ITEMS_TXT_ADDR+eax+29], SKILL_AXE
        damage:
        movzx eax, byte ptr [ITEMS_TXT_ADDR+eax+32] ; replaced code (dmg bonus)
        jne skip
        shl eax, 1
        skip:
        ret
      }
}

// Not sure if this is ever used, but just in case.
static void __declspec(naked) th_weapons_damage_bonus(void)
{
    asm
      {
        movzx edi, byte ptr [ITEMS_TXT_ADDR+eax+32] ; replaced code (dmg bonus)
        cmp esi, STAT_MELEE_DAMAGE_BASE
        jne quit
        cmp eax, CHARELE * 48
        je doubled
        cmp byte ptr [ITEMS_TXT_ADDR+eax+28], 1 ; two-handed weapon
        jne quit
        cmp byte ptr [ITEMS_TXT_ADDR+eax+29], SKILL_SWORD
        je doubled
        cmp byte ptr [ITEMS_TXT_ADDR+eax+29], SKILL_AXE
        jne quit
        doubled:
        shl edi, 1
        quit:
        ret
      }
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
        test byte ptr [esi+36+2], 8 ; hostile
        jnz quit
        mov ecx, esi
        xor edx, edx
        call dword ptr ds:is_hostile_to
        test eax, eax
        quit:
        ret
      }
}

// Allow resting for less than 12 hours in dark region taverns.
// Previously, it was until next dawn and then 13 more hours,
// which sometimes amounted to more than 24 hours.
// Now, it's until 17:00 and then one more hour.
// TODO: dark training halls have the same bug, but it's less pronounced
// as they close one hour after dawn anyway.  Still, may want to fix it later.
static void __declspec(naked) dark_region_taverns(void)
{
    asm
      {
        cmp eax, 13 * 60 ; will be more if it`s past 17h now
        jg less
        add eax, 12 * 60 ; replaced code
        ret
        less:
        sub eax, 12 * 60 ; 24h less
        ret
      }
}

// Give clubs a base recovery of 100.  Dunno why Grayface hadn't fixed it.
static void __declspec(naked) club_recovery(void)
{
    asm
      {
        cmp eax, SKILL_NONE
        jne not_club
        xor eax, eax ; default (staff) recovery
        not_club:
        movzx eax, word ptr [0x4edd80+eax*2] ; replaced code
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
        mov edx, dword ptr [ebp+0x1948+ecx*4-4] ; equipped items
        test edx, edx
        jz next
        lea edx, [edx+edx*8]
        lea edx, [ebp+0x214+edx*4-36]
        test byte ptr [edx+20], 2 ; broken bit
        jz next
        mov ecx, 255 ; red
        xor edx, edx
        push edx
        call dword ptr ds:rgb_color
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

// Implement the CheckSkill 0x2b command properly.  From what I understand,
// it's supposed to check for effective skill (multiplied by mastery).
// Some skills (such as Perception) are multiplied before adding NPC etc.
// bonuses, others are after; I chose the uniform approach here (always after).
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
        player = dword(0x507a6c) - 1;
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
              {
                current_skill = 10000;
                break;
              }
            /* else fall through */
        // these two cap at x3 now
        case SKILL_BODYBUILDING:
        case SKILL_MEDITATION:
            if (current_mastery == GM)
                current_mastery = MASTER;
            /* fall through */
        // skills that are x1/2/3/5 dep. on mastery
        case SKILL_PERCEPTION:
        case SKILL_LEARNING:
        case SKILL_THIEVERY:
            if (current_mastery == GM)
                current_mastery++;
            current_skill *= current_mastery;
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
static void __declspec(naked) evt_add_specitem(void)
{
    asm
      {
        push eax
        push eax
        mov ecx, ITEMS_TXT_ADDR - 4
        call dword ptr ds:set_specitem_bonus
        pop eax
        mov ecx, MOUSE_THIS_ADDR ; replaced code
        ret
      }
}

// Initalise pickpocketed specitems, e.g. Lady Carmine's Dagger.
static void __declspec(naked) pickpocket_specitem(void)
{
    asm
      {
        lea esi, [ebp-52] ; replaced code
        push esi
        mov ecx, ITEMS_TXT_ADDR - 4
        call dword ptr ds:set_specitem_bonus
        mov ecx, 9 ; replaced code
        ret
      }
}

// Bug fix: drowning dealt fire damage for some reason.
// Not sure if it should be cold or physical or energy, but the canonical
// reason for drowning is that "the water is very cold", so there.
static void __declspec(naked) drowning_element(void)
{
    asm
      {
        mov dword ptr [esp+8], COLD
        jmp dword ptr ds:damage_player ; replaced call
      }
}

// When searching for a place to put a new object into, only consider
// the first (map objects count) objects as existant.
// Previously all 1000 object slots were checked, and since walk travel
// does not overwrite old objects with zeroes, they were duplicated.
static void __declspec(naked) check_object_chunk(void)
{
    asm
      {
        cmp ebx, dword ptr [0x6650ac] ; map object count
      }
}

// This is called on a game save to cull expired objects, and suffers from
// much the same bug.  Together with the above chunk, duplication is fixed.
// TODO: it's possible the first obj could be duplicated still; check that
static void __declspec(naked) recount_objects(void)
{
    asm
      {
        cmp ebp, dword ptr [0x6650ac] ; map object count
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
        cmp dword ptr [0x4e28d8], 0 ; current screen
        jz version
        quit:
        cmp eax, 70 ; replaced code
        ret
        version:
        xor eax, eax
        push eax
        push eax
        push eax
        push dword ptr [new_strings+31*4]
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

// Set the 2H flag for already equipped spear (if applicable).
// This will prevent equipping anything in the left hand.
static void __declspec(naked) th_spear_worn(void)
{
    asm
      {
        je th ; zf == actual 2h weapon
        cmp byte ptr [ITEMS_TXT_ADDR+eax+29], SKILL_SPEAR
        jne quit
        mov ecx, ebx
        push SKILL_SPEAR
        call dword ptr ds:get_skill
        cmp eax, SKILL_MASTER
        jae quit
        th:
        inc dword ptr [ebp-16] ; 2h flag
        quit:
        ret
      }
}

// Same for a spear held in cursor.
// The necessary checks are already present here.
// This will allow replacing a single offhand weapon with it.
static void __declspec(naked) th_spear_mouse(void)
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

// Some uncategorized gameplay changes.
static inline void misc_rules(void)
{
    // Now that archers have fire arrows, we need to handle them properly.
    hook_call(0x43a48f, shield_fire_arrow, 10);
    hook_call(0x41d2c9, days_minutes_buff, 5);
    hook_call(0x41d307, seconds_buff, 6);
    // Make temple donation rewards stronger.
    hook_call(0x4b73a9, temple_wizard_eye_power, 6); // wizard eye (5 rep)
    hook_call(0x4b73cd, temple_other_spells_power, 6); // preservation (10 rep)
    hook_call(0x4b73fb, temple_other_spells_power, 6); // immutability (15 rep)
    hook_call(0x4b7429, temple_other_spells_power, 6); // hour of pow. (20 rep)
    hook_call(0x4b7457, temple_other_spells_power, 6); // day of prot. (25 rep)
    // Lower minimum recovery for weapon attacks.
    hook_call(0x48e1ff, recovery_check_blaster, 8);
    hook_call(0x48e4dd, min_weapon_recovery, 6);
    erase_code(0x406498, 8); // turn based recovery limit
    erase_code(0x42efcb, 7); // melee attack recovery limit
    erase_code(0x42ec54, 7); // theft recovery limit
    hook_call(0x418437, display_melee_recovery_hook, 5);
    hook_call(0x48fd79, melee_damage_check_main_weapon_first, 6);
    patch_bytes(0x48fda6, melee_damage_weapon_loop_chunk, 8);
    hook_call(0x4b1bd9, bank_interest, 5);
    hook_call(0x4940b1, bank_interest_2, 5);
    hook_call(0x4180ae, stat_hint_hook, 6);
    hook_jump(0x48ea13, new_stat_thresholds);
    hook_call(0x48ce6a, th_weapons_damage, 7);
    hook_call(0x41dd47, th_weapons_description, 6);
    hook_call(0x48ebee, th_weapons_min_damage, 7);
    hook_call(0x48ed95, th_weapons_max_damage, 7);
    hook_call(0x48ecb0, th_weapons_damage_bonus, 7);
    hook_call(0x4506a5, rest_encounters, 13);
    hook_call(0x433fc7, dark_region_taverns, 5);
    hook_call(0x48e27c, club_recovery, 8);
    // Upgrade Castle Harmondale (now Nighon) potion shop to item level 5.
    patch_word(0x4f045e, 5);
    patch_word(0x4f069e, 5);
    hook_call(0x41a810, color_broken_ac, 5);
    hook_call(0x4189be, color_broken_ac_2, 5);
    // Localization fix: separate hunter-as-npc and hunter-as-class strings.
    patch_pointer(0x452fa6, &new_strings[30]);
    patch_pointer(0x48c310, &new_strings[30]);
    patch_pointer(0x4484f3, check_skill_hook);
    hook_call(0x44b360, evt_add_specitem, 5);
    hook_call(0x48dab0, pickpocket_specitem, 6);
    hook_call(0x49431f, drowning_element, 5);
    patch_bytes(0x42f5f0, check_object_chunk, 6);
    hook_call(0x42fa30, recount_objects, 5);
    // Let mace paralysis be physical-elemental (was earth/poison).
    patch_byte(0x439cd3, PHYSICAL);
    hook_call(0x415745, print_version, 6);
    // Treat equipped spears below Master as 2H weapons
    // instead of refusing to swap them for swords etc. outright.
    hook_call(0x468fdc, th_spear_worn, 5);
    hook_jump(0x46901f, th_spear_mouse);
    // old checks for sword, shield, dagger replacing spear
    erase_code(0x469034, 46);
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
        movzx ecx, word ptr [eax+298] ; mind skill
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
        imul edi, edi, 60*60*24 ; one day (M duration)
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

// Bug fix: failing to cure insanity would still inflict weakness.
static void __declspec(naked) failed_cure_weakness(void)
{
    asm
      {
        test al, al ; result of curing attempt
        jz skip
        imul ecx, ecx, 6972 ; replaced code
        ret
        skip:
        push 0x42deaa ; post-cast code
        ret 4
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
        add edi, 5
        lea edi, [edi*4+edi]
        shl edi, 1
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
    hook_call(0x42c91e, failed_cure_weakness, 6); // might as well
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
}

// Let the magic skill affect the chance of debuffs working.
// Shrinking Ray requires special handling here.
// Also handles Cursed monsters.
static void __declspec(naked) pierce_debuff_resistance(void)
{
    asm
      {
        add ecx, esi
        xor esi, esi
        cmp dword ptr [ebp+4], 0x46bf98 ; gm shrinking ray code
        jne not_gm_ray
        mov esi, dword ptr [ebp-8] ; stored edi
        jmp shrinking_ray
        not_gm_ray:
        cmp dword ptr [ebp+4], 0x46ca24 ; projectile impact code
        jne not_projectile
        mov esi, dword ptr [ebp-4] ; stored esi
        shrinking_ray:
        mov esi, dword ptr [esi+76] ; spell skill
        jmp not_spell
        not_projectile:
        cmp dword ptr [ebp+4], 0x427db8 ; start of cast spell function
        jb not_spell
        cmp dword ptr [ebp+4], 0x42e968 ; end of cast spell function
        ja not_spell
        mov esi, dword ptr [ebp] ; stored ebp
        mov esi, dword ptr [esi-56] ; spell skill
        not_spell:
        shl esi, 1 ; double the skill to make the effect noticeable
        mov edx, dword ptr [edi+212+MBUFF_CURSED*16]
        or edx, dword ptr [edi+212+MBUFF_CURSED*16+4]
        jz not_cursed
        add esi, 10 ; effectively lowers res by 25% before skill bonus
        not_cursed:
        add esi, 30 ; standard difficulty check
        cdq ; replaced code
        add ecx, esi
        ret
      }
}

// Make sure to compare the roll with the new difficulty check.
static void __declspec(naked) debuff_resist_chunk(void)
{
    asm
      {
        cmp edx, esi
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
// Instead, skill reduces recovery.
static void __declspec(naked) turn_undead_duration_chunk(void)
{
    asm
      {
        ; edx == 3
        sub edx, 2 ; normal 5 min
        jmp duration
        shl edx, 1 ; gm 1 hour
        shl edx, 1 ; master 30 min
        duration:
        imul eax, edx, 60 * 5 ; expert 15 min
        sub dword ptr [ebp-180], edi ; recovery
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
    hook_call(0x4276a1, pierce_debuff_resistance, 5);
    erase_code(0x428fc8, 6); // do not multiply shrinking ray's skill by 300
    patch_bytes(0x4276aa, debuff_resist_chunk, 3);
    patch_bytes(0x428d6b, slow_5min_chunk, 6);
    patch_bytes(0x428d73, slow_20min_chunk, 6);
    patch_bytes(0x428d8b, slow_20min_chunk, 6);
    patch_bytes(0x428d95, slow_20min_chunk, 6);
    patch_bytes(0x428df5, slow_multiply_duration_chunk, 6);
    // Make Turn Undead duration fixed, for symmetry with other debuffs.
    patch_bytes(0x42bbed, turn_undead_duration_chunk, 21);
    patch_byte(0x42bbe6, 15); // expert jump
    patch_byte(0x42bbe9, 10); // master jump
    patch_word(0x42bbeb, 0x0574); // new GM jump: jnz N -> jz GM
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
        mov edx, offset spcitems + 8
        nop
      }
}

// The item generator needs the enchantment level address.
static void __declspec(naked) spcitems_level_address_chunk(void)
{
    asm
      {
        mov ecx, offset spcitems + 24
        nop
      }
}

// Calculate probability address from level address provided earlier.
static void __declspec(naked) spcitems_probability_from_level_chunk(void)
{
    asm
      {
        movzx eax, byte ptr [ecx-16+eax]
      }
}

// Address for probabilities again, but into a different register.
static void __declspec(naked) spcitems_probability_address_chunk_2(void)
{
    asm
      {
        mov ebx, offset spcitems + 8
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
    patch_bytes(0x456c37, spcitems_probability_from_level_chunk, 5);
    erase_code(0x456c3c, 4);
    patch_bytes(0x456c7e, spcitems_probability_address_chunk_2, 6);
    patch_bytes(0x456cbd, spcitems_probability_address_chunk_2, 5);
    // item name
    patch_pointer(0x456616, spcitems - 1);
    // the other reference is handled in prefix_gender() above
    patch_pointer(0x41ddf7, &(spcitems-1)->description); // item description
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

// Recognize some of the new enchantment names as prefixes.
static void __declspec(naked) new_prefixes(void)
{
    asm
      {
        je quit ; replaced jump
        cmp eax, SPC_BARBARIANS ; replaced code
        je quit
        cmp eax, SPC_SPECTRAL
        je quit
        cmp eax, SPC_CURSED
        je quit
        cmp eax, SPC_SOUL_STEALING
        je quit
        cmp eax, SPC_LIGHTWEIGHT
        je quit
        cmp eax, SPC_STURDY
        quit:
        ret ; zf will be checked shortly
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
        mov ecx, dword ptr [GLOBAL_TXT+52*4]
        push 0x41ecd8 ; fate code
        ret 4
      }
}

// Cursed monsters now miss 50% of their attacks against PCs.
static void __declspec(naked) cursed_monster_hits_player(void)
{
    asm
      {
        mov ecx, dword ptr [esp+8] ; monster
        mov edx, dword ptr [ecx+212+MBUFF_CURSED*16]
        or edx, dword ptr [ecx+212+MBUFF_CURSED*16+4]
        jz success
        call dword ptr ds:random
        and eax, 1
        jnz success
        pop ecx
        ret 8 ; force a miss (eax == 0)
        success:
        pop eax
        push esi ; replaced code
        mov esi, dword ptr [esp+8] ; replaced code
        jmp eax ; check for hit as normal
      }
}

// Cursed monsters also miss 50% of attacks against other monsters.
// Because spells in MvM combat also have a to-hit roll for some reason,
// only 25% of such spells will succeed if attacker is cursed!  Oh well.
static void __declspec(naked) cursed_monster_hits_monster(void)
{
    asm
      {
        mov ecx, dword ptr [esp+12] ; attacker
        mov edx, dword ptr [ecx+212+MBUFF_CURSED*16]
        or edx, dword ptr [ecx+212+MBUFF_CURSED*16+4]
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

// In addition, resistances of a cursed monster are considered 25% lower.
static void __declspec(naked) cursed_monster_resists_damage(void)
{
    asm
      {
        add eax, edx ; replaced code
        lea esi, [eax+30] ; replaced code
        mov ecx, dword ptr [ebp+8] ; monster
        mov edx, dword ptr [ecx+212+MBUFF_CURSED*16]
        or edx, dword ptr [ecx+212+MBUFF_CURSED*16+4]
        jz quit
        shr eax, 2
        sub esi, eax ; reduce by 25%
        quit:
        ret
      }
}

// Implement cursed weapons; the debuff is inflicted with a 20% chance.
// Black Knights treat all melee weapons (or even fists) as cursed.
// TODO: should it make a sound?
static void __declspec(naked) cursed_weapon(void)
{
    asm
      {
        test ebx, ebx
        jz melee
        cmp dword ptr [ebx+72], SPL_ARROW
        jne fail
        mov eax, dword ptr [edi+0x1950] ; bow slot
        jmp check
        melee:
        cmp byte ptr [edi+0xb9], CLASS_BLACK_KNIGHT
        je cursed
        mov eax, dword ptr [edi+0x194c] ; main hand
        test eax, eax
        jz offhand
        lea eax, [eax+eax*8]
        lea eax, [edi+0x214+eax*4-36]
        test byte ptr [eax+20], 2 ; broken bit
        jnz offhand
        cmp dword ptr [eax+12], SPC_CURSED
        je cursed
        cmp dword ptr [eax+12], SPC_WRAITH
        je cursed
        offhand:
        mov eax, dword ptr [edi+0x1948] ; offhand
        check:
        test eax, eax
        jz fail
        lea eax, [eax+eax*8]
        lea eax, [edi+0x214+eax*4-36]
        test byte ptr [eax+20], 2 ; broken bit
        jnz fail
        cmp dword ptr [eax+12], SPC_CURSED
        je cursed
        cmp dword ptr [eax+12], SPC_WRAITH
        jne fail
        cursed:
        call dword ptr ds:random
        mov ecx, 5 ; 20% chance
        xor edx, edx
        div ecx
        test edx, edx
        jnz fail
        push MAGIC
        push esi ; monster
        call dword ptr ds:monster_resists_condition
        test eax, eax
        jz fail
        xor ebx, ebx
        mov eax, 128 * 60 * 20 / 30 ; 20 min
        mov edx, dword ptr [0xacce68] ; current time, high dword
        add eax, dword ptr [0xacce64] ; current time, low dword
        adc edx, ebx
        lea ecx, [esi+212] ; cursed debuff
        push ebx
        push ebx
        push ebx
        push ebx
        push edx
        push eax
        call dword ptr ds:add_buff
        push ebx
        push esi
        call dword ptr ds:magic_sparkles
        fail:
        mov ecx, 0x5c5c30 ; replaced code
        ret
      }
}

// We need this for damage_messages() below,
// as the murder code overwrites ebx which stored it.
static int stored_projectile;

// Implement soul stealing weapons: when used to kill a monster,
// they add SP equal to monster's level.  Just like vampiric weapons,
// overheal is possible, and wielding two such weapons will double SP gain.
// The new Sacrificial Dagger is also soul stealing.
// Also here: store the damaging projectile for later use.
static void __declspec(naked) soul_stealing_weapon(void)
{
    asm
      {
        mov dword ptr [stored_projectile], ebx
        test ebx, ebx
        jnz quit
        movzx eax, byte ptr [edi+0xb9] ; class
        cmp byte ptr [0x4ed634+eax], bl ; sp multiplier
        jz quit
        mov eax, dword ptr [edi+0x194c] ; main hand
        test eax, eax
        jz offhand
        lea eax, [eax+eax*8]
        lea eax, [edi+0x214+eax*4-36]
        test byte ptr [eax+20], 2 ; broken bit
        jnz offhand
        cmp dword ptr [eax], SACRIFICIAL_DAGGER
        je soul_mainhand
        cmp dword ptr [eax+12], SPC_SOUL_STEALING
        jne offhand
        soul_mainhand:
        movzx eax, byte ptr [esi+52] ; monster level
        add dword ptr [edi+6464], eax ; add SP -- overheal is OK here
        offhand:
        mov eax, dword ptr [edi+0x1948] ; offhand
        test eax, eax
        jz quit
        lea eax, [eax+eax*8]
        lea eax, [edi+0x214+eax*4-36]
        test byte ptr [eax+20], 2 ; broken bit
        jnz quit
        cmp dword ptr [eax], SACRIFICIAL_DAGGER
        je soul_offhand
        cmp dword ptr [eax+12], SPC_SOUL_STEALING
        jne quit
        soul_offhand:
        movzx eax, byte ptr [esi+52] ; monster level
        add dword ptr [edi+6464], eax ; add SP -- overheal is OK here
        quit:
        mov ecx, dword ptr [ebp-24] ; replaced code
        xor edx, edx ; replaced code
        ret
      }
}

// If the monster can be backstabbed, add 2 to the first parameter
// of melee damage function.  If skill-based backstab triggers,
// add 4 instead.
static void __declspec(naked) check_backstab(void)
{
    asm
      {
        mov edx, dword ptr [0xacd4f8] ; party direction
        sub dx, word ptr [esi+154] ; monster direction
        test dh, 6 ; we want no more than +/-512 mod 2048 difference
        jnp quit ; PF == 1 will match 0x000 and 0x110 only
        add dword ptr [esp+4], 2 ; backstab flag
        push SKILL_THIEVERY
        call dword ptr ds:get_skill
        mov edx, eax
        and edx, SKILL_MASK
        jz no_thievery
        mov ecx, edx
        cmp eax, SKILL_EXPERT
        jb roll
        add edx, ecx
        cmp eax, SKILL_MASTER
        jb roll
        add edx, ecx
        cmp eax, SKILL_GM
        jb roll
        lea edx, [edx+ecx*2]
        roll:
        push edx
        call dword ptr ds:random
        xor edx, edx
        mov ecx, 100
        div ecx
        pop ecx
        cmp edx, ecx
        jae no_thievery
        add dword ptr [esp+4], 2 ; 4 = double total damage flag
        no_thievery:
        mov ecx, edi ; restore
        quit:
        mov dword ptr [ebp-8], 4 ; replaced code
        ret
      }
}

// Since we repurposed the second bit of the first parameter
// to the melee damage function, we must rewrite its original read
// to only check the first bit.
static void __declspec(naked) melee_might_check_chunk(void)
{
    asm
      {
        test byte ptr [esp+36], 1
      }
}

// Make afraid monsters face away from you in turn-based mode,
// for easier backstabbing.  Will only work on hostile monsters.
// If the monster fights someone else, it will face away from them.
static void __declspec(naked) turn_afraid_monster(void)
{
    asm
      {
        test byte ptr [ebx+38], 8 ; hostile bit
        jz skip
        mov edx, dword ptr [ebx+212+MBUFF_FEAR*16]
        or edx, dword ptr [ebx+212+MBUFF_FEAR*16+4]
        jnz turn
        cmp byte ptr [ebx+60], 1 ; ai type
        jb skip ; suicidal
        je turn ; wimp
        movzx edx, word ptr [ebx+40] ; monster hp
        lea edx, [edx+edx*4] ; 1/5th == 20%
        cmp byte ptr [ebx+60], 3 ; aggressive
        jne check_hp
        shl edx, 1 ; 1/10th == 10%
        check_hp:
        cmp edx, dword ptr [ebx+108] ; full hp
        ja skip
        turn:
        xor ax, 0x400 ; turn around
        skip:
        mov word ptr [ebx+154], ax ; replaced code
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
        mov ecx, dword ptr [esi+0x1954] ; armor slot
        lea ecx, [ecx+ecx*8]
        cmp dword ptr [esi+0x214+ecx*4-36], ELVEN_CHAINMAIL
        je lightweight
        cmp dword ptr [esi+0x214+ecx*4-36], RED_DRAGON_SCALE_MAIL
        je lightweight
        cmp dword ptr [esi+0x214+ecx*4-36+12], SPC_LIGHTWEIGHT
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
        mov ecx, dword ptr [esi+0x1948] ; offhand slot
        lea ecx, [ecx+ecx*8]
        cmp dword ptr [esi+0x214+ecx*4-36+12], SPC_LIGHTWEIGHT
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
        push 0
        push KELEBRIM
        call dword ptr ds:has_item_in_slot
        dec eax ; set flags
        jz immune
        mov ecx, dword ptr [esi]
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
        mov esi, PARTY_BUFFS
        check_buff:
        mov cl, byte ptr [esi+14] ; caster
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
        add esi, 16
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

// Prevent sturdy armor from breaking on unconsciousness.
static void __declspec(naked) sturdy_body_armor(void)
{
    asm
      {
        cmp dword ptr [ecx-8], SPC_STURDY
        je sturdy
        mov eax, dword ptr [ecx] ; replaced code
        test ah, 2 ; replaced code
        ret
        sturdy:
        test ecx, ecx ; clear zf
        ret
      }
}

// Also prevent sturdy items from being broken by monsters.
static void __declspec(naked) mon_breaks_sturdy_item(void)
{
    asm
      {
        mov ebx, dword ptr [ebp-4] ; replaced code
        cmp dword ptr [ebx+12], SPC_STURDY
        je sturdy
        test byte ptr [ebx+21], 2 ; replaced code
        ret
        sturdy:
        test ebx, ebx ; clear zf
        ret
      }
}

// Sturdy items also shouldn't be broken by alchemical explosions.
// This also fixes a bug wherein some alchemical explosions
// (those not from black potions) were checking the hardened bit
// on the wrong items.  Now hardened items are excluded from
// the eligible items list, so the wrong check is harmless.
static void __declspec(naked) alchemy_breaks_items(void)
{
    asm
      {
        cmp ecx, 134 ; replaced code
        jg quit
        cmp dword ptr [eax+12], SPC_STURDY
        je sturdy
        test byte ptr [eax+21], 2 ; hardened
        ; test sets flags perfectly for jg later
        quit:
        ret
        sturdy:
        cmp eax, 0 ; set flags for jg
        ret
      }
}

// Let's add some new item enchantments.
static inline void new_enchants(void)
{
    // Some new enchant names are prefixes.
    hook_call(0x4565fc, new_prefixes, 5);
    // Spectral weapons are handled in undead_slaying_element() above.
    // Implement the monster cursed condition.
    patch_dword(0x41ec01, 212); // start from debuff 0 (cursed)
    hook_call(0x41ec1e, display_cursed_debuff, 13);
    erase_code(0x41ede3, 1); // one more cycle
    // effect on spells handled in cast_new_spells() above
    hook_call(0x427464, cursed_monster_hits_player, 5);
    hook_call(0x427373, cursed_monster_hits_monster, 5);
    hook_call(0x4275a0, cursed_monster_resists_damage, 5);
    // condition resistance is handled in pierce_debuff_resistance() above
    hook_call(0x439bf2, cursed_weapon, 5);
    // For symmetry, indirectly penalize cursed players' resistances
    // through reducing luck to 10% of base.
    patch_byte(0x4ede62, 10);
    hook_call(0x439b0b, soul_stealing_weapon, 5);
    hook_call(0x439863, check_backstab, 7);
    // backstab damage doubled in temp_bane_melee_2() above
    patch_bytes(0x48d04f, melee_might_check_chunk, 5);
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
    hook_call(0x48dcad, sturdy_body_armor, 5);
    hook_call(0x48dff2, mon_breaks_sturdy_item, 7);
    hook_call(0x41611a, alchemy_breaks_items, 6);
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

// Bug fix: let the bow skill boni from artifacts increase damage at GM.
static void __declspec(naked) bow_skill_bonus_damage(void)
{
    asm
      {
        mov ecx, dword ptr [ebp-16]
        push SKILL_BOW
        call dword ptr ds:get_skill
        and eax, SKILL_MASK
        ret
      }
}

// Display the modified bow damage.
static void __declspec(naked) bow_skill_bonus_damage_display(void)
{
    asm
      {
        mov ecx, esi
        push SKILL_BOW
        call dword ptr ds:get_skill
        ret
      }
}

// Implement the Sacrificial Dagger SP bonus.
static void __declspec(naked) sacrificial_dagger_sp_bonus(void)
{
    asm
      {
        cmp eax, SACRIFICIAL_DAGGER
        jne not_it
        cmp esi, 8 ; sp stat
        jne not_it
        add edi, 30
        not_it:
        sub eax, PUCK ; replaced code
        ret
      }
}

// Restrict the Sacrificial Dagger to goblins in the same way as Elfbane.
static void __declspec(naked) sacrificial_dagger_goblin_only(void)
{
    asm
      {
        mov edx, MIND_S_EYE ; replaced code
        cmp eax, SACRIFICIAL_DAGGER
        jne not_it
        mov eax, ELFBANE
        not_it:
        ret
      }
}

// Set a (previously unused) bit if we should display RDSM.
static void __declspec(naked) check_for_worn_rdsm(void)
{
    asm
      {
        push ebp
        mov ecx, RED_DRAGON_SCALE_MAIL
        call dword ptr ds:player_has_item
        or byte ptr [0x511087], al
        mov edx, edi
        mov ecx, ELVEN_CHAINMAIL ; replaced code
        ret
      }
}

// Count RDSM as proper body armor for the characted doll code.
static void __declspec(naked) display_worn_rdsm(void)
{
    asm
      {
        cmp edx, RED_DRAGON_SCALE_MAIL
        jne not_it
        cmp byte ptr [0x511087], 0
        jz not_it
        ; edx already contains what we need
        push 0x43cbe7
        ret 4
        not_it:
        lea eax, [edx-504] ; replaced code
        ret
      }
}

// Graphics info for worn RDSM.
static uint32_t rdsm_display_vars[12];

// Insert RDSM into body armor display loop.
static void __declspec(naked) display_worn_rdsm_loop(void)
{
    asm
      {
        cmp eax, LAST_BODY_ARMOR + 1
        jne quit
        mov dword ptr [esp+20], RED_DRAGON_SCALE_MAIL
        lea edx, [edi+edi*2]
        shl edx, 2
        add edx, offset rdsm_display_vars - 8
        mov dword ptr [esp+24], edx
        cmp eax, LAST_BODY_ARMOR + 2 ; set flags
        quit:
        ret
      }
}

// Substitute our coordinates for worn RDSM (w/o right arm).
static void __declspec(naked) display_worn_rdsm_body(void)
{
    asm
      {
        cmp ecx, RED_DRAGON_SCALE_MAIL
        je rdsm
        sub eax, GOVERNOR_S_ARMOR ; replaced code
        ret
        rdsm:
        mov eax, dword ptr [esp+40] ; body type
        lea ecx, [eax+eax*2]
        mov ebx, offset rdsm_display_vars
        mov ebx, dword ptr [ebx+ecx*4] ; also put gfx info
        dec eax
        jz female
        dec eax
        jz dwarf
        dec eax
        jz femdwarf
        ; male
        mov eax, 491
        mov ecx, 101
        jmp quit
        female:
        mov eax, 496
        mov ecx, 107
        jmp quit
        dwarf:
        mov eax, 488
        mov ecx, 137
        jmp quit
        femdwarf:
        mov eax, 497
        mov ecx, 140
        quit:
        mov dword ptr [esp+24], eax
        push 0x43d49a ; code after setting coords
        ret 4
      }
}

#define RDSM_INDEX 18

// Pass the check for displaying armor left arm.
static void __declspec(naked) display_worn_rdsm_arm(void)
{
    asm
      {
        cmp ecx, RED_DRAGON_SCALE_MAIL
        je rdsm
        sub eax, GOVERNOR_S_ARMOR ; replaced code
        ret
        rdsm:
        mov edi, RDSM_INDEX ; unused index
        push 0x43db65 ; code after choosing index
        ret 4
      }
}

// Supply graphics info and coordinates for RDSM left arm
// when the PC is holding a two-handed weapon.
// There's a check for whether the gfx are present which we skip.
static void __declspec(naked) display_worn_rdsm_arm_2h(void)
{
    asm
      {
        cmp edi, RDSM_INDEX
        je rdsm
        imul eax, eax, 17 ; replaced code
        add edi, eax ; replaced code
        ret
        rdsm:
        lea ecx, [eax+eax*2]
        mov ebx, offset rdsm_display_vars + 8
        mov ebx, dword ptr [ebx+ecx*4] ; gfx info
        dec eax
        jz female
        dec eax
        jz dwarf
        dec eax
        jz femdwarf
        ; male
        mov ecx, 530
        mov eax, 105
        jmp quit
        female:
        mov ecx, 541
        mov eax, 108
        jmp quit
        dwarf:
        mov ecx, 529
        mov eax, 137
        jmp quit
        femdwarf:
        mov ecx, 533
        mov eax, 143
        quit:
        mov dword ptr [esp+28], ecx
        push 0x43dc10 ; code after setting coords
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
        imul eax, eax, 17 ; replaced code
        add edi, eax ; replaced code
        ret
        rdsm:
        lea ecx, [eax+eax*2]
        mov ebx, offset rdsm_display_vars + 4
        mov ebx, dword ptr [ebx+ecx*4] ; gfx info
        mov edx, dword ptr [esp+52] ; replaced code (worn item)
        mov edx, dword ptr [edx+0x1f0+20] ; replaced code (item bits)
        dec eax
        jz female
        dec eax
        jz dwarf
        dec eax
        jz femdwarf
        ; male
        mov eax, 582
        mov ecx, 104
        jmp quit
        female:
        mov eax, 580
        mov ecx, 106
        jmp quit
        dwarf:
        mov eax, 577
        mov ecx, 135
        jmp quit
        femdwarf:
        mov eax, 593
        mov ecx, 144
        quit:
        mov dword ptr [esp+28], ecx
        push 0x43dd7d ; code after setting coords
        ret 8
      }
}

// Add the new properties to some old artifacts.
static inline void new_artifacts(void)
{
    // remove old (and nonfunctional) elven chainmail recovery bonus
    erase_code(0x48ea64, 12);
    // elven chainmail is lightweight now
    hook_call(0x48f24e, elven_chainmail_bow_bonus, 5);
    hook_call(0x48d2c0, bow_skill_bonus_damage, 5);
    hook_call(0x48d15e, bow_skill_bonus_damage_display, 6);
    hook_call(0x48d1cb, bow_skill_bonus_damage_display, 6);
    hook_call(0x48eee0, sacrificial_dagger_sp_bonus, 5);
    hook_call(0x492c4a, sacrificial_dagger_goblin_only, 5);
    // corsair and old nick can backstab now
    erase_code(0x48ceae, 8); // old nick elf slaying
    erase_code(0x48cfd9, 8); // ditto
    // old nick poison damage increased in elemental_weapons() above
    patch_byte(0x48f086, 13); // old nick disarm bonus
    // kelebrim protects from dispel
    // hermes' sandals grant leaping
    // rdsm is lightweight
    hook_call(0x43c170, check_for_worn_rdsm, 5);
    hook_call(0x43c952, display_worn_rdsm, 6);
    hook_call(0x43c52c, display_worn_rdsm_loop, 6);
    hook_call(0x43d42f, display_worn_rdsm_body, 5);
    hook_call(0x43db2b, display_worn_rdsm_arm, 5);
    hook_call(0x43dba8, display_worn_rdsm_arm_2h, 5);
    hook_call(0x43dd38, display_worn_rdsm_arm_idle, 5);
}

// When calculating missile damage, take note of the weapon's skill.
static void __declspec(naked) check_missile_skill(void)
{
    asm
      {
        movzx eax, byte ptr [ITEMS_TXT_ADDR+esi+29] ; item skill
        mov dword ptr [ebp-8], eax ; unused var
        movzx eax, byte ptr [ITEMS_TXT_ADDR+esi+32] ; replaced code
        ret
      }
}

// Do not add GM Bow damage if we're using blasters.
static void __declspec(naked) check_missile_skill_2(void)
{
    asm
      {
        cmp dword ptr [ebp-8], SKILL_BLASTER
        je quit
        mov ax, word ptr [edi] ; replaced code
        test ax, ax ; replaced code
        quit:
        ret
      }
}

// Use ranged recovery time when shooting blasters.
static void __declspec(naked) blaster_ranged_recovery(void)
{
    asm
      {
        inc dword ptr [esp+4] ; melee -> ranged
        push 0x48e19b ; replaced call
        ret
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
        mov dword ptr [use_melee_attack], ebx ; == 0 if we fall from quick cast
        or ebx, 1 ; restore the proper value
        mov eax, dword ptr [0x50ca50] ; replaced code
        ret
      }
}

// Similarly, allow shooting in melee by shift-clicking with no quick spell.
// TODO: could also check SP for symmetry
static void __declspec(naked) missile_on_shift_click(void)
{
    asm
      {
        movzx ecx, byte ptr [eax+0x1a4f] ; replaced code
        test ecx, ecx
        jz no_spell
        ret
        no_spell:
        mov dword ptr [use_melee_attack], ecx ; == 0
        mov eax, dword ptr [0x50ca50] ; actions count
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
        mov eax, dword ptr [0x50ca50] ; replaced code
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

// Do not draw equipped small blaster behind the body.
static void __declspec(naked) postpone_drawing_blaster(void)
{
    asm
      {
        and dword ptr [draw_blaster], 0
        mov eax, dword ptr [ebx+0x1948+SLOT_MISSILE*4] ; replaced code
        test eax, eax ; replaced code
        jz quit
        lea edx, [eax+eax*8]
        cmp dword ptr [ebx+0x214+edx*4-36], BLASTER
        jne quit
        mov byte ptr [draw_blaster], 1
        ; we will skip drawing it now because zf == 1
        quit:
        ret
      }
}

// Instead, draw it between body and a belt.
static void __declspec(naked) draw_blaster_behind_belt(void)
{
    asm
      {
        cmp dword ptr [draw_blaster], 1
        je blaster
        mov eax, dword ptr [ebx+0x1948+SLOT_BELT*4] ; replaced code
        ret
        blaster:
        mov eax, dword ptr [ebx+0x1948+SLOT_MISSILE*4]
        add dword ptr [draw_blaster], 1 ; now it == 2
        push 0x43d043 ; missile draw code
        ret 4
      }
}

// After drawing the blaster out of order, return to the belt code.
static void __declspec(naked) return_from_drawing_blaster(void)
{
    asm
      {
        cmp dword ptr [draw_blaster], 2
        je belt
        mov eax, dword ptr [eax+0x1948+SLOT_CLOAK*4] ; replaced code
        ret
        belt:
        mov ebx, eax
        mov eax, dword ptr [ebx+0x1948+SLOT_BELT*4]
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
        cmp byte ptr [eax+184], 1 ; sex
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
        cmp byte ptr [0x6be244], 0 ; replaced code
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
        mov eax, dword ptr [ecx+0x1948+SLOT_MISSILE*4]
        test eax, eax
        jnz have_missile
        no_missile:
        push dword ptr [new_strings+22*4]
        jmp print
        have_missile:
        lea eax, [eax+eax*8]
        test byte ptr [ecx+0x214+eax*4-36+20], 2 ; broken bit
        jnz no_missile
        mov eax, dword ptr [ecx+0x214+eax*4-36]
        lea eax, [eax+eax*2]
        shl eax, 4
        cmp byte ptr [ITEMS_TXT_ADDR+eax+28], 12 ; wand
        je always
        cmp byte ptr [ecx+0xb9], CLASS_SNIPER
        jne not_always
        cmp byte ptr [ITEMS_TXT_ADDR+eax+29], SKILL_BOW
        jne not_always
        always:
        push dword ptr [new_strings+21*4]
        print:
        push dword ptr [GLOBAL_TXT+203*4]
        push 0x4e2e18 ; "%s %s" format string
        push esi
        call dword ptr ds:sprintf
        add esp, 16
        not_always:
        mov edx, dword ptr [0x5c3468] ; replaced code
        ret
      }
}

// Ditto, but in the quick reference screen.
static void __declspec(naked) print_wand_to_hit_ref(void)
{
    asm
      {
        mov ecx, ebp
        mov eax, dword ptr [ecx+0x1948+SLOT_MISSILE*4]
        test eax, eax
        jnz have_missile
        no_missile:
        push dword ptr [new_strings+22*4]
        jmp print
        have_missile:
        lea eax, [eax+eax*8]
        test byte ptr [ecx+0x214+eax*4-36+20], 2 ; broken bit
        jnz no_missile
        mov eax, dword ptr [ecx+0x214+eax*4-36]
        lea eax, [eax+eax*2]
        shl eax, 4
        cmp byte ptr [ITEMS_TXT_ADDR+eax+28], 12 ; wand
        je always
        cmp byte ptr [ecx+0xb9], CLASS_SNIPER
        jne not_always
        cmp byte ptr [ITEMS_TXT_ADDR+eax+29], SKILL_BOW
        jne not_always
        always:
        push dword ptr [new_strings+21*4]
        print:
        push esi
        call dword ptr ds:strcpy_ptr
        add esp, 8
        not_always:
        mov edx, dword ptr [0x5c3468] ; replaced code
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
        movzx ecx, byte ptr [ITEMS_TXT_ADDR+eax+30] ; mod1
        ret
      }
}

// Put blasters and wands in the missile weapon slot.
// TODO: fix wand recovery being displayed incorrectly
static inline void ranged_blasters(void)
{
    // actual shooting
    patch_dword(0x42ed08, 0x1950); // check missile slot for wands and blasters
    erase_code(0x439633, 4); // extraneous blaster damage function params
    patch_dword(0x439641, 0x48d1e4 - 0x439645); // melee -> ranged damage
    hook_call(0x48d24d, check_missile_skill, 7);
    hook_call(0x48d2ab, check_missile_skill_2, 6);
    hook_call(0x4282e6, blaster_ranged_recovery, 5);
    patch_dword(0x4283ac, 0x1950); // attach missile weapon to blaster proj
    // displaying the damage range
    patch_dword(0x48d382, 0x1950); // check missile slot for blasters
    patch_byte(0x48d39d, 31); // ranged damage min stat
    patch_byte(0x48d3a6, 32); // ranged damage max stat
    // missiles in melee
    erase_code(0x43019a, 1); // set ebx to 0 in quick cast
    hook_call(0x43019b, missile_on_quick_cast, 5);
    hook_call(0x42241a, missile_on_shift_click, 7);
    hook_call(0x422559, melee_on_normal_click, 5);
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
    patch_dword(0x43ce6c, 0x1950); // draw missile weapon in a wetsuit
    hook_call(0x43cea9, adjust_wetsuit_blaster, 7);
    erase_code(0x43ceb0, 9);
    erase_code(0x43cebf, 2);
    // use wands from missile slot
    patch_dword(0x42ee6d, dword(0x42ee6d) + 4); // main hand -> missile slot
    patch_dword(0x42ee89, 0x1950);
    patch_dword(0x42ee9b, 0x1950);
    patch_dword(0x42eeb7, 0x1950);
    patch_dword(0x42f02f, 0x1950);
    patch_dword(0x42f055, 0x1950);
    patch_dword(0x42f067, 0x1950);
    patch_dword(0x42f085, 0x1950);
    patch_byte(0x469863, 2); // equip wands in missile slot
    patch_byte(0x4e8354, 2); // ditto
    // status screen
    patch_dword(0x48d40b, 0x1950); // check for wand in missile slot
    hook_call(0x418cc3, print_wand_to_hit, 6);
    hook_call(0x41a910, print_wand_to_hit_ref, 6);
    // replace some wand spells
    patch_bytes(0x457772, parse_sxx_items_txt_chunk, 6);
    hook_call(0x42ee7b, get_parsed_wand_spell, 7);
    hook_call(0x42f047, get_parsed_wand_spell, 7);
}

// Make sure to disable ranged attack with an empty wand equipped.
static void __declspec(naked) empty_wand_chunk(void)
{
    asm
      {
        mov dword ptr [ebp-16], edi ; unset bow var
      }
}

// Color equipped empty wands red, as if broken.
static void __declspec(naked) red_empty_wands(void)
{
    asm
      {
        and ecx, 0xf0 ; replaced code
        jnz quit
        cmp dword ptr [edi], FIRST_WAND
        jb not_it
        cmp dword ptr [edi], LAST_WAND
        ja not_it
        cmp dword ptr [edi+16], ecx ; charges vs. 0
        jnz not_it
        or al, 2 ; broken bit (for display only)
        not_it:
        test ecx, ecx ; zf = 1
        quit:
        ret
      }
}

// Displays charges; the string is colored red.
// TODO: may be nicer to call rgb_color() instead of hardcoding item color
static const char red_charges[] = "\f63683%s: %u/%u";

// Display current and max wand charges, even if it's empty.
static void __declspec(naked) display_wand_charges(void)
{
    asm
      {
        cmp byte ptr [edi+28], 12 ; wand
        je wand
        xor eax, eax ; set zf
        ret
        wand:
        pop edx
        movzx eax, byte ptr [ecx+25] ; max charges
        push eax
        mov eax, dword ptr [ecx+16] ; replaced code
        test eax, eax
        jnz quit
        push eax
        push dword ptr [GLOBAL_TXT+464*4]
        mov eax, offset red_charges
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
        movzx ecx, byte ptr [ITEMS_TXT_ADDR+eax+32] ; mod2 (default charges)
        shl ecx, 1
        movzx eax, byte ptr [esi+25] ; max charges
        add eax, dword ptr [esi+16] ; charges
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
        mov ebx, dword ptr [esi+16] ; charges
        mov byte ptr [esi+25], bl ; max charges
        shr ebx, 1 ; up to 50%
        jz quit
        call dword ptr ds:random
        xor edx, edx
        div ebx
        inc edx
        sub dword ptr [esi+16], edx
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
        mov dword ptr [ebp-52+16], eax ; replaced code
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
static void __declspec(naked) charge_shop_wands_common(void)
{
    asm
      {
        mov dword ptr [ecx+20], 1 ; replaced code (item flags)
        cmp dword ptr [ecx], FIRST_WAND
        jb quit
        cmp dword ptr [ecx], LAST_WAND
        ja quit
        movzx edx, byte ptr [ecx+25] ; max charges
        mov dword ptr [ecx+16], edx ; charges
        quit:
        ret
      }
}

// Standard shop items hook.
static void __declspec(naked) charge_shop_wands_standard(void)
{
    asm
      {
        lea ecx, [0xad45b4+ecx*4]
        jmp charge_shop_wands_common
      }
}

// Special shop items hook.
static void __declspec(naked) charge_shop_wands_special(void)
{
    asm
      {
        lea ecx, [0xad9f24+eax*4]
        jmp charge_shop_wands_common
      }
}

static char recharge_buffer[100];
static const float shop_recharge_multiplier = 0.2; // from 30% to 80%

// Wand recharge dialog: print cost and resulting number of charges.
// TODO: may be nicer to call rgb_color() instead of hardcoding item color
static void __declspec(naked) shop_recharge_dialog(void)
{
    asm
      {
        lea esi, [edi+0x214+eax*4-36] ; replaced code
        cmp dword ptr [esi], FIRST_WAND
        jb not_wand
        cmp dword ptr [esi], LAST_WAND
        jbe wand
        not_wand:
        test byte ptr [esi+20], 2 ; replaced code
        ret
        wand:
        mov edx, dword ptr [0x507a40]
        imul edx, dword ptr [edx+28], 52
        fld dword ptr [0x5912d8+edx] ; store price multiplier
        fmul dword ptr [shop_recharge_multiplier]
        movzx eax, byte ptr [esi+25] ; max charges
        push eax
        fimul dword ptr [esp]
        fisttp dword ptr [esp]
        pop ebx ; == charges after recharge
        cmp ebx, 0
        jbe worn_out
        cmp ebx, dword ptr [esi+16] ; current charges
        jg rechargeable
        xor ebx, ebx ; set zf
        ret
        rechargeable:
        push dword ptr [0x5912d8+edx]
        mov ecx, edi
        call dword ptr ds:identify_price
        shl eax, 2 ; 4x as expensive as identification
        push eax
        push ebx
        worn_out:
        mov ecx, esi
        call dword ptr ds:item_name
        push eax
        cmp ebx, 0
        cmova eax, dword ptr [new_strings+24*4]
        cmovbe eax, dword ptr [new_strings+23*4]
        push eax
        mov eax, offset recharge_buffer
        push eax
        call dword ptr ds:sprintf
        add esp, 12
        cmp ebx, 0
        jbe no_adjust
        add esp, 8
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
// and calculate price and new charges if so.
static void __declspec(naked) prepare_shop_recharge(void)
{
    asm
      {
        cmp dword ptr [esi], FIRST_WAND
        jb not_wand
        cmp dword ptr [esi], LAST_WAND
        jbe wand
        not_wand:
        fstp st(0) ; discard store price multiplier
        mov dword ptr [ebp-8], eax ; replaced code
        test byte ptr [esi+20], 2 ; replaced code
        ret
        wand:
        fld st(0)
        fmul dword ptr [shop_recharge_multiplier]
        movzx eax, byte ptr [esi+25] ; max charges
        push eax
        fimul dword ptr [esp]
        fisttp dword ptr [esp]
        pop eax ; == charges after recharge
        cmp eax, 0
        jbe cannot_recharge
        cmp eax, dword ptr [esi+16] ; current charges
        jg recharge
        cannot_recharge:
        fstp st(0) ; discard store price multiplier
        xor eax, eax ; set zf
        ret
        recharge:
        mov dword ptr [new_charges], eax
        mov ecx, edi
        sub esp, 4
        fstp dword ptr [esp] ; store price multiplier
        call dword ptr ds:identify_price
        shl eax, 2 ; 4x as expensive as identification
        mov dword ptr [ebp-8], eax ; store the price
        ret ; zf should be unset now
      }
}

// After passing all the checks, actually recharge the wand.
static void __declspec(naked) perform_shop_recharge(void)
{
    asm
      {
        cmp dword ptr [esi], FIRST_WAND
        jb not_wand
        cmp dword ptr [esi], LAST_WAND
        ja not_wand
        mov eax, dword ptr [new_charges]
        mov dword ptr [esi+16], eax ; charges
        mov byte ptr [esi+25], al ; max charges
        not_wand:
        mov eax, dword ptr [esi+20] ; replaced code
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
    patch_pointer(0x41de17, "%s: %u/%u"); // new format
    patch_byte(0x41de29, 20); // call fixup
    hook_call(0x456a78, preused_wands, 6);
    hook_call(0x44b357, preused_wands_2, 6);
    hook_call(0x48da1a, preused_wands_3, 7);
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
        cmp word ptr [esi+40], bx ; check if mon hp > 0
        jg message
        push 0x439cba ; skip over message code
        ret 8
        message:
        pop ecx
        push dword ptr [ebp-12] ; damage
        lea eax, [edi+168] ; replaced code
        jmp ecx
      }
}

// Same, but for paralysis and MM7Patch's halved armor.
static void __declspec(naked) paralysis_message(void)
{
    asm
      {
        cmp word ptr [esi+40], 0 ; mon hp
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
        mov edx, dword ptr [new_strings+27*4] ; new message
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
        sprintf(buffer, new_strings[29], player->name, total_damage, hit_count,
                dead_count);
    else
        sprintf(buffer, new_strings[28], player->name, total_damage,
                hit_count);
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
        mov eax, dword ptr [ecx+88] ; owner
        cmp eax, dword ptr [last_hit_player]
        je check_spell
        mov dword ptr [last_hit_player], eax
        mov eax, dword ptr [ecx+72] ; spell id
        reset_spell:
        mov dword ptr [last_hit_spell], eax
        record_hit:
        mov eax, dword ptr [ebp-12] ; damage
        mov dword ptr [total_damage], eax
        mov dword ptr [only_target], esi
        mov byte ptr [killed_only_target], dl
        ret ; zf == 0 here
        check_spell:
        mov eax, dword ptr [ecx+72] ; spell id
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
        movsx eax, word ptr [edi+138] ; replaced code
        ret
      }
}

// Condense consecutive damage messages for AOE spells and the like
// into a single message for each cast.
static inline void damage_messages(void)
{
    hook_call(0x439c93, stun_message, 6);
    patch_byte(0x439cac, 20); // call fixup
    hook_call(0x439d50, paralysis_message, 5);
    patch_byte(0x439d63, 20); // call fixup
    hook_call(0x439b56, multihit_message_check, 6);
    patch_byte(0x439b77, -16); // total damage  == [ebp-16]
    hook_call(0x439bb3, multihit_message_check, 7);
    patch_byte(0x439bc5, -16); // total damage  == [ebp-16]
    hook_call(0x42ef8a, splitter_fireball_message, 7);
}

// Storage for the new NPC text entries.
STATIC char *new_npc_text[NEW_TEXT_COUNT];
FIX(new_npc_text);

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
        mov eax, dword ptr [0x7214e4+eax*8] ; replaced code
        ret
        new:
        mov eax, dword ptr [REF(new_npc_text)+eax*4-790*4]
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
    patch_dword(0x476b17, 0x7214e8 + TOPIC_COUNT * 8); // more NPC topics
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
        movzx edx, word ptr [esi+0xbc+edx*4] ; base stat
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
static int __thiscall get_new_full_hp(struct player *player)
{
    int level = get_level(player);
    int bonus = get_effective_stat(get_endurance(player))
              + get_bodybuilding_bonus(player);
    int base = CLASS_HP_FACTORS[player->class];
    int race = get_race(player);
    if (race == RACE_ELF)
        base--;
    else if (race != RACE_HUMAN)
        base++;
    int total = CLASS_STARTING_HP[player->class>>2];
    if (level <= 20)
        total += base * (level + bonus);
    else
        total += base * level * (bonus + 20) / 20;
    total += get_stat_bonus_from_items(player, STAT_HP, 0);
    total += player->hp_bonus;
    if (total <= 1)
        return 1;
    return total;
}

// Ditto, but for get_full_sp(), spellcasting stats, and Meditation.
// NB: goblins get one less SP per 2 levels, so we operate in half-points.
static int __thiscall get_new_full_sp(struct player *player)
{
    int stat = CLASS_SP_STATS[player->class];
    if (player->class < 5 || stat == 3)
        return 0;
    int level = get_level(player);
    int bonus = get_meditation_bonus(player);
    if (stat != 1)
        bonus += get_effective_stat(get_intellect(player));
    if (stat != 0)
        bonus += get_effective_stat(get_personality(player));
    int base = CLASS_SP_FACTORS[player->class] * 2;
    int race = get_race(player);
    if (race == RACE_ELF)
        base += 2;
    else if (race == RACE_GOBLIN)
        base--;
    int total = (base * level + 1) / 2; // round up for goblins
    if (level <= 20)
        total += base * bonus / 2;
    else
        total = total * (bonus + 20) / 20;
    total += CLASS_STARTING_SP[player->class>>2];
    total += get_stat_bonus_from_items(player, STAT_SP, 0);
    total += player->sp_bonus;
    if (total <= 0)
        return 0;
    return total;
}

// Instead of HP/SP boni, let humans gain an extra skill point on level up.
static void __declspec(naked) human_skill_point(void)
{
    asm
      {
        add dword ptr [ebx+0x1938], eax ; replaced code
        call dword ptr ds:get_race
        cmp eax, RACE_HUMAN
        jne not_human
        inc dword ptr [ebx+0x1938]
        not_human:
        mov ecx, ebx ; restore
        ret
      }
}

// Also correct the level-up message.
static void __declspec(naked) human_skill_point_message(void)
{
    asm
      {
        lea ecx, [ebx-168]
        call dword ptr ds:get_race
        cmp eax, RACE_HUMAN
        jne not_human
        inc dword ptr [esp+20] ; skill points count
        not_human:
        jmp dword ptr ds:sprintf ; replaced call
      }
}

// Replace the starting weapon skill with the racial skill
// when initializing a character.  Monks are exempt.
// Humans just get an extra Learning instead.
static void __declspec(naked) init_racial_skill(void)
{
    asm
      {
        mov dl, byte ptr [STARTING_SKILLS+eax+edi] ; replaced, sorta
        mov ecx, esi
        call dword ptr ds:get_race
        cmp eax, RACE_HUMAN
        je human
        cmp edi, SKILL_BLASTER
        jae skip
        cmp byte ptr [esi+0xb9], CLASS_MONK
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
        cmp byte ptr [ecx+0xb9], CLASS_MONK
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
        cmp byte ptr [STARTING_SKILLS+ebx+eax], 2 ; replaced code
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
STATIC const int added_picks[9] = { SKILL_NONE, SKILL_NONE, SKILL_NONE,
                                    SKILL_NONE, SKILL_CHAIN, SKILL_NONE,
                                    SKILL_STAFF, SKILL_AIR, SKILL_NONE };
FIX(added_picks);

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
        movzx edx, byte ptr [ecx+0xb9]
        cmp eax, dword ptr [REF(added_picks)+edx]
        je quit
        skip:
        cmp byte ptr [STARTING_SKILLS+ebx+eax], 1 ; replaced code, basically
        jmp quit
        nonhuman:
        cmp eax, SKILL_BLASTER
        jae skip
        cmp byte ptr [ecx+0xb9], CLASS_MONK
        je monk
        cmp byte ptr [STARTING_SKILLS+ebx+eax], 1 ; replaced code, again
        jae race
        jmp quit
        monk:
        cmp byte ptr [STARTING_SKILLS+ebx+eax], 1 ; also replaced code
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
        cmp byte ptr [ecx+0xb9], CLASS_MONK
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
        movzx esi, byte ptr [ecx+0xb9] ; replaced code, sort of
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
STATIC const int excluded_picks[9] = { SKILL_NONE, SKILL_PERCEPTION,
                                       SKILL_SWORD, SKILL_DAGGER, SKILL_NONE,
                                       SKILL_NONE, SKILL_REPAIR,
                                       SKILL_PERCEPTION, SKILL_MERCHANT };
FIX(excluded_picks);

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
        cmp eax, dword ptr [REF(excluded_picks)+esi]
        je substitute
        cmp eax, SKILL_BLASTER
        jae skip
        cmp byte ptr [ecx], 0
        ja show
        jmp not_it
        monk:
        cmp eax, ebx
        je show
        cmp eax, dword ptr [REF(excluded_picks)+esi]
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
        cmp eax, dword ptr [REF(added_picks)+esi]
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
        mov byte ptr [PARTY_ADDR+0xba], 17
        mov byte ptr [PARTY_ADDR+0x1b3+0xba], 3
        mov byte ptr [PARTY_ADDR+0x1b3c*2+0xba], 14
        mov byte ptr [PARTY_ADDR+0x1b3c*3+0xba], 10
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
        mov byte ptr [edi+0xba], dl
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
        mov word ptr [edi+0x108+SKILL_LEARNING*2], 0
        mov ecx, dword ptr [esp+20] ; player id
        push eax
        call unshift_human_buttons
        pop eax
        movzx ecx, byte ptr [edi+0xb9]
        mov edx, dword ptr [REF(added_picks)+ecx]
        cmp edx, SKILL_NONE
        je no_extra
        mov word ptr [edi+0x108+edx*2], 0
        no_extra:
        cmp byte ptr [edi+0xb9], CLASS_MONK
        je new_race
        shr ecx, 2
        imul ecx, ecx, SKILL_COUNT
        or edx, -1
        was_human_loop:
        inc edx
        cmp byte ptr [STARTING_SKILLS+ecx+edx], 2
        jne was_human_loop
        mov word ptr [edi+0x108+edx*2], 0
        jmp new_race
        was_elf:
        mov word ptr [edi+0x108+SKILL_BOW*2], 0
        jmp new_race
        was_goblin:
        cmp byte ptr [edi+0xb9], CLASS_MONK ; monks know sword
        je new_race
        mov word ptr [edi+0x108+SKILL_SWORD*2], 0
        jmp new_race
        was_dwarf:
        mov word ptr [edi+0x108+SKILL_AXE*2], 0
        new_race:
        cmp eax, RACE_ELF
        je elf
        cmp eax, RACE_GOBLIN
        je goblin
        cmp eax, RACE_DWARF
        je dwarf
        mov word ptr [edi+0x108+SKILL_LEARNING*2], 1
        mov ecx, dword ptr [esp+20] ; player id
        call shift_human_buttons
        cmp byte ptr [edi+0xb9], CLASS_MONK
        je quit
        movzx ecx, byte ptr [edi+0xb9]
        shr ecx, 2
        imul ecx, ecx, SKILL_COUNT
        or edx, -1
        human_loop:
        inc edx
        cmp byte ptr [STARTING_SKILLS+ecx+edx], 2
        jne human_loop
        mov word ptr [edi+0x108+edx*2], 1
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
        movzx ecx, byte ptr [edi+0xb9]
        shr ecx, 2
        imul ecx, ecx, SKILL_COUNT
        cmp byte ptr [STARTING_SKILLS+ecx+edx], 0
        jne not_removed
        movzx ecx, byte ptr [edi+0xb9]
        mov ecx, dword ptr [REF(excluded_picks)+ecx]
        mov word ptr [edi+0x108+ecx*2], 0
        not_removed:
        cmp byte ptr [edi+0xb9], CLASS_MONK
        je quit
        mov word ptr [edi+0x108+edx*2], 1
        quit:
        movzx eax, byte ptr [edi+0xba]
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
        mov edx, dword ptr [0xae3150+SKILL_LEARNING*4] ; skill name
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
static int __cdecl get_max_skill_level(int class, int race, int skill)
{
    int level = CLASS_SKILLS[class][skill];
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

// Colorize skill ranks more informatively (also respect racial skills).
static int __fastcall get_skill_color(struct player *player,
                                      int skill, int rank)
{
    int class = player->class;
    int race = get_race(player);
    if (get_max_skill_level(class, race, skill) >= rank)
        return rgb_color(255, 255, 255); // white
    int stage = class & 3;
    if (!stage && get_max_skill_level(class + 1, race, skill) >= rank)
        return rgb_color(255, 255, 0); // yellow
    if (stage < 2)
      {
        int good = get_max_skill_level(class - stage + 2, race, skill) >= rank;
        int evil = get_max_skill_level(class - stage + 3, race, skill) >= rank;
        if (good && evil)
            return rgb_color(0, 255, 0); // green
        if (good)
            return rgb_color(0, 255, 255); // blue
        if (evil)
            return rgb_color(255, 0, 255); // purple
      }
    return rgb_color(255, 0, 0); // red
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

// Check if a skill can be learned.  Racial skills always can be,
// although only Monks don't have them pre-learned.
static void __declspec(naked) learn_skill_check(void)
{
    asm
      {
        cmp byte ptr [CLASS_SKILLS_ADDR+ecx+eax], 0 ; replaced code
        jnz quit
        cmp eax, SKILL_LEARNING
        je human
        cmp eax, SKILL_BOW
        je elf
        cmp eax, SKILL_SWORD
        je goblin
        cmp eax, SKILL_AXE
        je dwarf
        xor edx, edx ; set zf
        quit:
        ret
        human:
        mov edx, RACE_HUMAN
        jmp check
        elf:
        mov edx, RACE_ELF
        jmp check
        goblin:
        mov edx, RACE_GOBLIN
        jmp check
        dwarf:
        mov edx, RACE_DWARF
        check:
        push eax
        mov ecx, ebx
        call dword ptr ds:get_race
        cmp eax, edx
        pop eax
        sete dl ; invert zf
        test edx, edx
        ret
      }
}

// Same, but registers are different here.
static void __declspec(naked) learn_skill_check_2(void)
{
    asm
      {
        mov ebx, dword ptr [ebp-12] ; player
        call learn_skill_check
        mov ebx, 0 ; restore
        ret
      }
}

// Another variation.
static void __declspec(naked) learn_skill_check_3(void)
{
    asm
      {
        mov ebx, esi ; player
        call learn_skill_check
        mov ebx, 0 ; restore
        ret
      }
}

// There's a lot of them.
static void __declspec(naked) learn_skill_check_4(void)
{
    asm
      {
        mov ebx, dword ptr [ebp-24] ; player
        call learn_skill_check
        mov ebx, 0 ; restore
        ret
      }
}

// There's a lot of duplicate code!
static void __declspec(naked) learn_skill_check_5(void)
{
    asm
      {
        mov ebx, dword ptr [ebp-16] ; player
        call learn_skill_check
        mov ebx, 0 ; restore
        ret
      }
}

// Apparently there's a separate function for each type of building.
static void __declspec(naked) learn_skill_check_6(void)
{
    asm
      {
        mov ebx, dword ptr [ebp-20] ; player
        call learn_skill_check
        mov ebx, 0 ; restore
        ret
      }
}

// This one is for actually buying, and it differs a lot.
static void __declspec(naked) learn_skill_check_7(void)
{
    asm
      {
        push ecx
        mov ecx, eax
        mov eax, esi
        mov ebx, edi
        call learn_skill_check
        pop ecx
        ret
      }
}

// This one doesn't even convert dialog parameter to skill.
static void __declspec(naked) learn_skill_check_8(void)
{
    asm
      {
        mov ebx, ecx
        mov ecx, edx
        sub eax, 36
        call learn_skill_check
        mov ecx, ebx
        mov ebx, 0
        lea eax, [eax+36]
        ret
      }
}

// Another location related to buying.
static void __declspec(naked) learn_skill_check_9(void)
{
    asm
      {
        push ecx
        push ebx
        mov ebx, edi
        mov ecx, edx
        sub eax, 36
        call learn_skill_check
        lea eax, [eax+36]
        pop ebx
        pop ecx
        ret
      }
}

// Describe PC's chosen race as well as class.
static void __declspec(naked) race_hint(void)
{
    asm
      {
        imul eax, eax, 0x1b3c ; replaced code
        mov edx, dword ptr [esi+8] ; PC area width
        shr edx, 1
        add edx, dword ptr [esi] ; PC area left
        cmp edx, dword ptr [ebp-8] ; mouse x
        jg race
        ret
        race:
        push ecx
        lea ecx, [ebx+eax]
        lea edi, [ecx+0xa8] ; PC name
        call dword ptr ds:get_race
        mov eax, dword ptr [REF(new_strings)+35*4+eax*4]
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
        call dword ptr ds:get_base_level
        cmp dword ptr [esp+28], 10
        jae big_bonus
        shr eax, 1
        jmp add_bonus
        big_bonus:
        dec eax
        add_bonus:
        add dword ptr [esp+28], eax
        mov ecx, esi ; restore
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
        call dword ptr ds:get_base_level
        cmp esi, 10
        jae big_bonus
        shr eax, 1
        jmp add_bonus
        big_bonus:
        dec eax
        add_bonus:
        add esi, eax
        mov ecx, ebx ; restore
        no_bonus:
        jmp dword ptr ds:get_stat_bonus_from_items ; replaced call
      }
}

// Save the PC's race on lichification
// (as we cannot determine it from portrait anymore).
static void __declspec(naked) preserve_lich_race(void)
{
    asm
      {
        call dword ptr ds:get_race
        mov word ptr [esi+0x177c], ax ; unused field
        mov ecx, esi ; restore
        ret
      }
}

// Provide the preserved race value for liches.
static void __declspec(naked) get_lich_race(void)
{
    asm
      {
        movsx eax, byte ptr [ecx+0xba] ; replaced code, almost
        cmp eax, 19
        jg lich
        mov ecx, eax
        ret
        lich:
        movzx eax, word ptr [ecx+0x177c]
        pop ecx ; skip a stack frame
        ret
      }
}

// There can be dwarf liches now, but liches still don't have a dwarf body.
// So we restore original behavior when race is checked for paperdolls.
static void __declspec(naked) get_lich_paperdoll(void)
{
    asm
      {
        movsx ecx, byte ptr [ecx+0xba]
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
    hook_call(0x4b4c26, human_skill_point_message, 5);
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
    hook_call(0x4b4836, learn_skill_check, 8);
    hook_call(0x4b492a, learn_skill_check, 8);
    hook_call(0x4b550c, learn_skill_check_2, 7);
    hook_call(0x4b55ff, learn_skill_check_2, 7);
    hook_call(0x4b70fe, learn_skill_check_3, 7);
    hook_call(0x4b71fb, learn_skill_check_3, 7);
    hook_call(0x4b83b7, learn_skill_check_4, 7);
    hook_call(0x4b84b0, learn_skill_check_4, 7);
    hook_call(0x4b9638, learn_skill_check_5, 7);
    hook_call(0x4b972b, learn_skill_check_5, 7);
    hook_call(0x4b9d52, learn_skill_check_6, 7);
    hook_call(0x4b9e45, learn_skill_check_6, 7);
    hook_call(0x4bae54, learn_skill_check, 8);
    hook_call(0x4baf48, learn_skill_check, 8);
    hook_call(0x4be1bb, learn_skill_check_7, 8);
    hook_call(0x4b617e, learn_skill_check_8, 7);
    hook_call(0x4b6298, learn_skill_check_8, 7);
    hook_call(0x4bd485, learn_skill_check_9, 8);
    hook_call(0x417372, race_hint, 6);
    hook_call(0x48e8a3, racial_resistances, 5);
    patch_word(0x48e87f, 0x15eb); // dwarf poison res used different var
    hook_call(0x48e79d, base_racial_resistances, 5);
    hook_call(0x44a76f, preserve_lich_race, 9);
    hook_call(0x490101, get_lich_race, 7);
    hook_call(0x43bd5f, get_lich_paperdoll, 5);
    hook_call(0x43cccc, get_lich_paperdoll, 5);
    hook_call(0x43eda1, get_lich_paperdoll, 5);
    hook_call(0x43edeb, get_lich_paperdoll, 5);
    hook_call(0x43ef6e, get_lich_paperdoll, 5);
}

// Implement Champion special ability, Leadership: for each Champion
// in the party, everyone's weapon and armor skills get a +2 bonus.
static void __declspec(naked) champion_leadership(void)
{
    asm
      {
        mov esi, eax
        cmp byte ptr [PARTY_ADDR+0xb9], CLASS_CHAMPION
        setz al
        add esi, eax
        cmp byte ptr [PARTY_ADDR+0x1b3c+0xb9], CLASS_CHAMPION
        setz al
        add esi, eax
        cmp byte ptr [PARTY_ADDR+0x1b3c*2+0xb9], CLASS_CHAMPION
        setz al
        add esi, eax
        cmp byte ptr [PARTY_ADDR+0x1b3c*3+0xb9], CLASS_CHAMPION
        setz al
        add esi, eax
        shl esi, 1
        ret
      }
}

// Implement Sniper special ability: 100% chance to hit with a bow.
static void __declspec(naked) sniper_accuracy(void)
{
    asm
      {
        test ebx, ebx
        jz not_it
        cmp dword ptr [ebx+72], SPL_ARROW
        jne not_it
        cmp byte ptr [edi+0xb9], CLASS_SNIPER
        jne not_it
        mov eax, 1
        ret
        not_it:
        push 0x4272ac ; replaced call
        ret
      }
}

// Let Warlock's familiar also boost Dark magic (and Light, but it's not used).
static void __declspec(naked) warlock_dark_bonus(void)
{
    asm
      {
        jg extra
        ret
        extra:
        cmp edi, SKILL_DARK
        jg skip
        push 0x48f8f5 ; warlock check
        ret 4
        skip:
        push 0x48fb1e ; replaced jump
        ret 4
      }
}

// Defined below.
static int __stdcall maybe_instakill(struct player *, struct map_monster *);

// New Lich bonus: drain life with unarmed (or GM Staff) attacks.
// Also here: apply Hammerhands bonus to GM Staff attacks,
// and check for the new GM Unarmed perk.
static void __declspec(naked) lich_vampiric_touch(void)
{
    asm
      {
        call dword ptr ds:is_bare_fisted ; replaced call
        test eax, eax
        jnz unarmed
        mov ecx, dword ptr [edi+0x194c] ; mainhand item
        test ecx, ecx
        jz skip
        lea ecx, [ecx+ecx*8]
        lea ecx, [edi+0x214+ecx*4-36]
        mov ecx, dword ptr [ecx] ; id
        lea ecx, [ecx+ecx*2]
        shl ecx, 4
        cmp byte ptr [ITEMS_TXT_ADDR+ecx+29], SKILL_STAFF
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
        cmp byte ptr [edi+0xb9], CLASS_LICH
        jne not_lich
        mov eax, dword ptr [ebp-20] ; damage
        xor edx, edx
        mov ecx, 5
        div ecx
        add dword ptr [edi+0x193c], eax ; HP (overheal is ok)
        not_lich:
        mov eax, 1 ; hammerhands applies as well
        skip:
        ret
      }
}

// In vanilla the interface only changed color after the arbiter movie.
// As there are now other ways to choose a path, let's set it along with qbit.
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
            if (check_qbit(QBITS,
                           quests[align==QBIT_LIGHT_PATH][player->class/4]))
                return 0;
            /* else fallthrough */
        case 0:
        default:
            return check_qbit(QBITS, align);
      }
}

// Make light and dark promotions more distinct.
static inline void class_changes(void)
{
    // yeah, it's not very readable, but I *really*
    // don't want to depend on MMExtension
    static const uint8_t skills[CLASS_COUNT][SKILL_COUNT] = {
          {2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 2, 2, 2, 0, 2, 1, 0, 1, 2, 2, 0, 2, 0, 0, 1},
          {2, 3, 2, 3, 3, 2, 3, 1, 3, 2, 3, 3, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 2, 3, 3, 0, 2, 1, 0, 1, 2, 2, 0, 3, 0, 0, 1},
          {2, 4, 2, 3, 4, 3, 3, 1, 4, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 2, 4, 4, 0, 2, 1, 0, 1, 2, 2, 0, 4, 0, 0, 1},
          {2, 4, 2, 3, 4, 2, 3, 1, 4, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 2, 4, 4, 0, 2, 1, 0, 2, 2, 2, 0, 4, 1, 0, 1},
          {0, 2, 2, 0, 0, 2, 2, 2, 1, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2, 2, 1, 2, 0, 2, 0, 0, 2, 2, 2, 0, 2, 2, 2, 2},
          {0, 3, 3, 0, 0, 2, 2, 3, 1, 3, 2, 0, 2, 2, 0, 0, 0, 0, 0,
            0, 0, 3, 3, 1, 2, 0, 3, 0, 0, 3, 3, 2, 0, 3, 3, 3, 2},
          {0, 3, 4, 0, 0, 2, 2, 4, 1, 4, 2, 0, 2, 3, 0, 0, 0, 0, 0,
            0, 0, 4, 3, 1, 2, 0, 4, 0, 0, 4, 3, 2, 0, 3, 4, 3, 2},
          {0, 3, 4, 0, 0, 2, 2, 4, 1, 4, 2, 0, 3, 2, 0, 0, 0, 0, 0,
            0, 0, 4, 3, 1, 2, 0, 3, 0, 0, 4, 3, 2, 0, 3, 4, 4, 2},
          {2, 2, 2, 0, 2, 1, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 2, 0, 2, 1, 0, 1, 2, 2, 2, 2, 1, 0, 2},
          {3, 2, 2, 0, 2, 1, 0, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 2,
            0, 0, 0, 0, 0, 3, 0, 2, 1, 0, 2, 3, 3, 2, 3, 1, 0, 3},
          {4, 2, 2, 0, 2, 1, 0, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 3, 3,
            0, 0, 0, 0, 0, 4, 0, 2, 1, 0, 2, 4, 4, 2, 3, 1, 0, 4},
          {4, 2, 2, 0, 2, 1, 0, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 2, 2,
            0, 0, 0, 0, 0, 4, 0, 2, 1, 0, 3, 4, 4, 2, 3, 2, 0, 4},
          {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 2, 1, 1,
            0, 0, 0, 2, 2, 2, 2, 1, 2, 0, 0, 0, 1, 0, 2, 0, 0, 1},
          {1, 3, 2, 2, 2, 2, 3, 2, 3, 2, 2, 3, 0, 0, 0, 0, 3, 2, 2,
            0, 0, 0, 3, 3, 3, 2, 1, 3, 0, 0, 0, 1, 0, 2, 0, 0, 1},
          {1, 3, 2, 2, 2, 2, 4, 2, 4, 2, 2, 3, 0, 0, 0, 0, 4, 3, 3,
            3, 0, 0, 4, 4, 3, 2, 1, 4, 0, 0, 0, 1, 0, 2, 0, 0, 1},
          {1, 3, 2, 2, 2, 2, 4, 2, 4, 2, 2, 3, 0, 0, 0, 0, 4, 3, 3,
            0, 2, 0, 3, 4, 3, 2, 1, 4, 0, 0, 0, 1, 0, 3, 2, 0, 1},
          {1, 2, 2, 2, 2, 2, 0, 2, 0, 2, 2, 0, 1, 2, 1, 1, 0, 0, 0,
            0, 0, 0, 2, 2, 2, 2, 2, 0, 0, 1, 2, 1, 0, 2, 0, 0, 2},
          {1, 2, 2, 2, 3, 3, 0, 3, 0, 3, 3, 0, 2, 3, 2, 2, 0, 0, 0,
            0, 0, 0, 2, 2, 2, 2, 3, 0, 0, 1, 2, 1, 0, 2, 0, 0, 3},
          {1, 2, 2, 2, 3, 4, 0, 4, 0, 3, 4, 0, 3, 4, 4, 3, 0, 0, 0,
            2, 0, 0, 2, 2, 2, 2, 4, 0, 0, 2, 2, 1, 0, 2, 0, 0, 3},
          {1, 2, 2, 2, 3, 4, 0, 4, 0, 3, 4, 0, 4, 4, 3, 3, 0, 0, 0,
            0, 2, 0, 2, 2, 2, 2, 4, 0, 0, 2, 2, 1, 0, 2, 0, 0, 3},
          {1, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1, 1, 1, 2, 0, 2, 2, 0, 2, 2, 1, 2, 2, 2, 1, 2},
          {1, 2, 2, 3, 3, 3, 0, 3, 2, 3, 3, 0, 2, 0, 2, 3, 2, 2, 0,
            0, 0, 1, 1, 1, 2, 1, 3, 2, 0, 2, 2, 1, 3, 2, 2, 1, 2},
          {1, 2, 2, 4, 3, 3, 0, 3, 2, 3, 3, 0, 2, 0, 3, 4, 3, 2, 0,
            0, 0, 2, 2, 2, 2, 1, 4, 2, 0, 2, 2, 1, 4, 3, 2, 2, 2},
          {1, 2, 2, 4, 3, 3, 0, 3, 2, 3, 3, 0, 2, 0, 2, 4, 3, 3, 0,
            0, 0, 1, 1, 1, 2, 1, 4, 2, 0, 3, 2, 1, 4, 3, 3, 1, 2},
          {2, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 2, 2, 2,
            0, 0, 0, 2, 2, 1, 2, 2, 2, 0, 0, 0, 0, 2, 0, 0, 2, 2},
          {2, 0, 0, 0, 0, 0, 3, 2, 3, 2, 2, 1, 0, 0, 0, 0, 3, 3, 3,
            0, 0, 0, 3, 3, 1, 3, 2, 3, 0, 0, 0, 0, 2, 0, 0, 2, 3},
          {2, 0, 0, 0, 0, 0, 4, 2, 3, 2, 2, 2, 0, 0, 0, 0, 4, 4, 4,
            4, 0, 0, 4, 3, 1, 3, 2, 3, 0, 0, 0, 0, 2, 0, 0, 2, 3},
          {2, 0, 0, 0, 0, 0, 3, 2, 3, 2, 2, 1, 0, 0, 0, 0, 4, 4, 4,
            0, 4, 0, 4, 3, 1, 4, 2, 3, 0, 0, 0, 0, 2, 0, 0, 3, 3},
          {1, 0, 2, 0, 0, 0, 2, 2, 2, 2, 0, 0, 2, 2, 2, 2, 2, 2, 2,
            0, 0, 2, 2, 0, 0, 2, 2, 0, 0, 0, 1, 0, 2, 1, 0, 2, 2},
          {1, 0, 3, 0, 0, 0, 2, 3, 2, 3, 0, 0, 2, 3, 3, 3, 2, 3, 3,
            0, 0, 2, 2, 0, 0, 3, 2, 0, 0, 0, 1, 0, 3, 1, 0, 3, 3},
          {1, 0, 3, 0, 0, 0, 2, 3, 2, 3, 0, 0, 2, 4, 4, 3, 3, 3, 4,
            0, 0, 2, 2, 0, 0, 4, 2, 0, 0, 0, 1, 0, 4, 1, 0, 4, 3},
          {1, 0, 3, 0, 0, 0, 2, 3, 2, 3, 0, 0, 3, 3, 3, 4, 2, 4, 3,
            0, 3, 2, 2, 0, 0, 4, 2, 0, 0, 0, 1, 0, 3, 1, 0, 4, 3},
          {2, 0, 2, 0, 0, 0, 0, 2, 0, 2, 0, 0, 2, 2, 2, 2, 0, 0, 0,
            0, 0, 2, 1, 2, 0, 2, 2, 1, 0, 0, 1, 0, 2, 0, 0, 2, 2},
          {3, 0, 2, 0, 0, 0, 0, 3, 0, 2, 0, 0, 3, 3, 3, 3, 0, 0, 0,
            0, 0, 3, 1, 2, 0, 3, 2, 1, 0, 0, 1, 0, 3, 0, 0, 3, 3},
          {3, 0, 3, 0, 0, 0, 0, 4, 0, 3, 0, 0, 4, 4, 4, 4, 0, 0, 0,
            4, 0, 4, 1, 2, 0, 3, 2, 1, 0, 0, 1, 0, 3, 0, 0, 3, 4},
          {4, 0, 2, 0, 0, 0, 0, 4, 0, 2, 0, 0, 4, 4, 4, 4, 0, 0, 0,
            0, 4, 3, 1, 2, 0, 4, 2, 1, 0, 0, 1, 1, 3, 0, 0, 3, 3}
    };
    patch_bytes(0x4ed818, skills, CLASS_COUNT * SKILL_COUNT);
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
    patch_byte(0x439914, 0x01); // mov -> add
    // Enable class hints on the stats screen.
    patch_dword(0x418088, dword(0x418088) + 8);
    hook_call(0x44a8c8, set_light_dark_path, 5);
    // Make Masters a little bit more magic-capable.
    CLASS_HP_FACTORS[CLASS_MASTER] = 7;
    CLASS_SP_FACTORS[CLASS_MASTER] = 2;
    hook_call(0x492c8d, equip_aligned_relic, 10);
}

// Let the Perception skill increase gold looted from monsters.
static void __declspec(naked) perception_bonus_gold(void)
{
    asm
      {
        mov ecx, dword ptr [0x507a6c] ; current player
        dec ecx
        jl no_player
        mov ecx, dword ptr [0xa74f48+ecx*4] ; player pointers
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
        xor esi, esi
        mov ecx, dword ptr [0x507a6c] ; current player
        dec ecx
        jl no_player
        mov ecx, dword ptr [0xa74f48+ecx*4] ; player pointers
        call dword ptr ds:get_perception_bonus
        lea esi, [eax+eax]
        no_player:
        call dword ptr ds:random
        xor edx, edx
        lea ecx, [esi+100]
        div ecx
        sub edx, esi
        ret
      }
}

// Double total melee damage if the flag is set.
// Currently used by Thievery backstab.
static void __declspec(naked) double_total_damage(void)
{
    asm
      {
        add esi, eax ; replaced code, sorta
        add esi, ebx ; ditto
        test byte ptr [esp+40], 4
        jz no_double
        add esi, esi
        no_double:
        ret
      }
}

// Let potions be brewable even without the requisite Alchemy skill,
// but with a possibility of explosion (up to 83% for black).
static void __declspec(naked) lenient_alchemy(void)
{
    asm
      {
        push eax
        call dword ptr ds:random
        xor edx, edx
        mov ecx, 6
        div ecx
        dec edx
        pop eax
        cmp eax, edx
        cmovl eax, edx
        cmp edx, ebx ; ebx == 0
        jbe quit
        inc dword ptr [ebp-44] ; alchemy flag
        quit:
        mov ecx, dword ptr [MOUSE_ITEM] ; replaced code
        ret
      }
}

// Length of blaster eradication animation.
#define ERAD_TIME 64
// The animation for the central explosion (temporary).
#define BERZERK 6060

// Let a GM blaster shot have a small chance to eradicate the target,
// killing it without leaving a corpse.  For testing purposes,
// blasters of Carnage (unobtainable) always trigger this effect.
// Called from bow_temp_damage() above.
static void __stdcall blaster_eradicate(struct player *player,
                                        struct map_monster *monster,
                                        struct map_object *projectile)
{
    if (projectile->spell_type != SPL_BLASTER)
        return;
    int skill = get_skill(player, SKILL_BLASTER);
    if (skill > SKILL_GM && (skill & SKILL_MASK) > random() % 200
        && monster->hp <= random() % monster->max_hp
        && monster_resists_condition(monster, MAGIC)
        || projectile->item.bonus2 == SPC_CARNAGE)
      {
        monster->spell_buffs[MBUFF_MASS_DISTORTION].expire_time
        // same var as for actual mdist, seems to be some anim timer
            = dword(0x50ba5c) + ERAD_TIME;
        monster->eradicated_flag = 1;
        monster->hp = 0;
        struct map_object anim = { BERZERK,
                                   find_objlist_item(OBJLIST_THIS, BERZERK),
                                   monster->x, monster->y,
                                   monster->z + monster->height / 2 };
        launch_object(&anim, 0, 0, 0);
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
                   - dword(0x50ba5c) /* anim timer */) / (double) ERAD_TIME;
    sprite_params[0] = sprite_params[0] * scale; // sprite width
    sprite_params[1] = sprite_params[1] * scale; // sprite height
}

// Hook for the above.
static void __declspec(naked) draw_erad_hook(void)
{
    asm
      {
        cmp byte ptr [ecx+183], 0 ; eradicated flag
        jnz draw
        cmp dword ptr [ecx+372], eax ; replaced code
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
        cmp byte ptr [edi+37], 0 ; eradicated flag
        jnz draw
        cmp dword ptr [edi+226], edx ; replaced code
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
        || !monster->eradicated_flag)
        return 0;
    int time = monster->spell_buffs[MBUFF_MASS_DISTORTION].expire_time
               - dword(0x50ba5c); // anim timer
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
        cmp byte ptr [esi+183], 1 ; eradicated flag
        jz quit
        mov ax, word ptr [esi+176] ; replaced code
        cmp ax, AI_REMOVED ; replaced code
        quit:
        ret
      }
}

// Make enchanted items more difficult to ID and repair.
static void __declspec(naked) raise_ench_item_difficulty(void)
{
    asm
      {
        xor eax, eax
        mov ecx, dword ptr [esp+24] ; item
        cmp dword ptr [ecx+4], 0
        jz no_std
        cmp dword ptr [ecx+4], TEMP_ENCH_MARKER
        je no_std
        mov eax, dword ptr [ecx+8]
        add eax, eax
        mov ecx, 5
        jmp divide
        no_std:
        mov edx, dword ptr [ecx+12]
        test edx, edx
        jz no_ench
        imul edx, edx, 28
        mov eax, dword ptr [REF(spcitems)+edx-8] ; value
        cmp eax, 10
        ja spc
        add eax, eax
        jmp no_ench
        spc:
        mov ecx, 250
        divide:
        xor edx, edx
        div ecx
        no_ench:
        movzx edx, byte ptr [esi+46] ; replaced code, almost
        add eax, edx
        cmp edi, eax ; replaced code
        ret
      }
}

// Don't count enchantment cost when trying to sell an un-ID'd item.
// For wands, cap the cost at base item cost.
// This will also ignore variable potion cost, but those are always ID'd.
static void __declspec(naked) unid_item_sell_price(void)
{
    asm
      {
        test byte ptr [ecx+20], IFLAGS_ID
        jz unid
        call dword ptr ds:item_value
        ret
        unid:
        mov edx, dword ptr [ecx]
        lea eax, [edx+edx*2]
        shl eax, 4
        mov eax, dword ptr [ITEMS_TXT_ADDR+eax+16] ; base value
        cmp edx, FIRST_WAND
        jb quit
        cmp edx, LAST_WAND
        ja quit
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
        test byte ptr [MOUSE_ITEM+20], IFLAGS_ID
        jz unid
        mov eax, [MOUSE_ITEM] ; replaced code
        ret
        unid:
        mov ecx, dword ptr [new_strings+39*4]
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
        test byte ptr [MOUSE_ITEM+20], IFLAGS_ID
        jz unid
        lea edi, [edx-400] ; replaced code
        ret
        unid:
        mov ecx, dword ptr [new_strings+39*4]
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
static void __declspec(naked) cant_enchant_blasters(void)
{
    asm
      {
        cmp eax, BLASTER_RIFLE
        jg ok
        cmp eax, BLASTER - 1
        ret
        ok:
        cmp eax, LAST_PREFIX ; replaced code
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
        push 0x476399 ; hireling check func
        ret
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

// Implement M Shield bonus: whenever another party member is attacked,
// there's a chance to substitute the shield-wearer's AC if it's higher.
static int __thiscall maybe_cover_ally(struct player *player)
{
    int ac = get_ac(player);
    for (int i = 0; i < 4; i++)
      {
        if (PARTY + i == player)
            continue;
        int offhand = PARTY[i].equipment[SLOT_OFFHAND];
        int skill = get_skill(&PARTY[i], SKILL_SHIELD);
        if (offhand && skill >= SKILL_MASTER)
          {
            struct item *shield = &PARTY[i].items[offhand-1];
            if (!(shield->flags & IFLAGS_BROKEN)
                && ITEMS_TXT[shield->id].skill == SKILL_SHIELD
                && (skill & SKILL_MASK) > random() % 100)
              {
                int new_ac = get_ac(&PARTY[i]);
                if (new_ac > ac)
                    ac = new_ac;
              }
          }
      }
    return ac;
}

// Hook for the above.
static void __declspec(naked) maybe_cover_ally_hook(void)
{
    asm
      {
        call maybe_cover_ally
        pop ecx
        push eax
        jmp ecx
      }
}

// Retrieve the calculated AC instead of a second call.
static void __declspec(naked) recall_covered_ac_chunk(void)
{
    asm
      {
        pop eax
        jmp quit
        nop
        nop
        quit:
      }
}

// New Master Leather perk: chance to absorb enemy spells, restoring SP.
// Only works if SP won't overflow the natural limit.
static int __thiscall absorb_spell(struct player *player, int spell)
{
    if (spell == SPL_LIGHT_BOLT)
        return 0; // can't be blocked by anything
    int body = player->equipment[SLOT_BODY_ARMOR];
    if (!body)
        return 0;
    struct item *armor = &player->items[body-1];
    if (armor->flags & IFLAGS_BROKEN
        || ITEMS_TXT[armor->id].skill != SKILL_LEATHER)
        return 0;
    int skill = get_skill(player, SKILL_LEATHER);
    if (skill < SKILL_MASTER || (skill & SKILL_MASK) <= random() % 100)
        return 0;
    // TODO: support variable cost
    int new_sp = player->sp + SPELL_INFO[spell].cost_gm;
    if (new_sp <= get_full_sp(player))
      {
        player->sp = new_sp;
        static char message[128];
        sprintf(message, new_strings[40], player->name);
        show_status_text(message, 2);
        return 1;
      }
    return 0;
}

// Hook for monster spells.
static void __declspec(naked) absorb_monster_spell(void)
{
    asm
      {
        jnz spell
        ret
        spell:
        mov ecx, edi
        push dword ptr [ebx+72] ; spell id
        call absorb_spell
        test eax, eax
        jz hit
        push 0x43a99a ; skip hit code
        ret 4
        hit:
        push 0x43a5ac ; replaced jump
        ret 4
      }
}

// Hook for non-monster spells.
static void __declspec(naked) absorb_other_spell(void)
{
    asm
      {
        push dword ptr [ebx+72] ; spell id
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
    // TODO: "none" checks for wetsuits; replace this with a robe check later
    return skill == SKILL_LEATHER && player->skills[SKILL_LEATHER] >= SKILL_GM
           || skill >= SKILL_NONE;
}

// Hook for the above.
static void __declspec(naked) maybe_dodge_hook(void)
{
    asm
      {
        mov ecx, dword ptr [esp+8] ; player
        call maybe_dodge
        test eax, eax
        jnz dodge
        jmp dword ptr ds:monster_hits_player ; replaced call
        dodge:
        mov edi, dword ptr [esp+8] ; player
        push 0x43a630 ; dodge code
        ret 12
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
        && monster->hp <= random() % monster->max_hp
        && monster_resists_condition(monster, PHYSICAL))
      {
        monster->hp = 0;
        make_sound(SOUND_THIS, SOUND_DIE, 0, 0, -1, 0, 0, 0, 0);
        return 1;
      }
    return 0;
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
    hook_call(0x426c02, perception_extra_item, 11);
    erase_code(0x491276, 12); // remove 100% chance on GM
    // thievery backstab is checked in check_backstab() above
    hook_call(0x48d087, double_total_damage, 5);
    hook_call(0x4162ac, lenient_alchemy, 6);
    hook_call(0x402e18, preserve_mdist_on_death, 5);
    hook_call(0x4401df, draw_erad_hook, 6);
    hook_call(0x47b9ee, draw_erad_hook_out, 6);
    hook_call(0x43ffe1, erad_z_hook, 5);
    hook_call(0x47b66d, erad_z_hook_out, 7);
    hook_call(0x470707, erad_stop_moving, 11);
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
    hook_call(0x42ab66, cant_enchant_blasters, 5);
    hook_call(0x491191, npcs_cant_repair_blasters, 5);
    hook_call(0x4bdbe6, shops_cant_repair_blasters, 5);
    hook_call(0x490f91, shops_cant_repair_blasters_msg, 11);
    hook_call(0x48d5a3, resist_phys_damage_hook, 5);
    erase_code(0x48d5a8, 94); // old plate/chain code
    erase_code(0x43a57d, 35); // old GM shield bonus
    hook_call(0x4274c9, maybe_cover_ally_hook, 5);
    patch_bytes(0x4274e5, recall_covered_ac_chunk, 5);
    hook_call(0x43a4cf, absorb_monster_spell, 6);
    // absorb_other_spell() called from damage_potions_player()
    // Also see cast_new_spells() and dispel_immunity() above.
    patch_byte(0x49002c, 0x4d); // remove old leather & shield M boni
    patch_dword(0x490097, 0xf08bce8b); // swap instructions
    hook_call(0x49009b, leather_dodging, 5);
    patch_byte(0x4900ab, 0xfa); // eax -> edx
    erase_code(0x48e7f9, 75); // old Leather GM bonus
    hook_call(0x43a03f, maybe_dodge_hook, 5);
    hook_call(0x43a4dc, maybe_dodge_hook, 5);
}

BOOL WINAPI DllMain(HINSTANCE const instance, DWORD const reason,
                    LPVOID const reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
      {
        spells_txt();
        monsters_txt();
        skip_monster_res();
        elemental_weapons();
        fire_poison();
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
      }
    return TRUE;
}
