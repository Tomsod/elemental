#include <windows.h>
#include <stdint.h>
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

//---------------------------------------------------------------------------//

static const char *const elements[] = {"fire", "elec", "cold", "pois", "phys",
                                       0, "holy", "mind", "magic", "ener",
                                       "firepois"};

// Patch spells.txt parsing, specifically possible spell elements.
static inline void spells_txt(void)
{
    patch_pointer(0x45395c, elements[1]);
    patch_pointer(0x453975, elements[2]);
    patch_pointer(0x45398e, elements[3]);
    patch_pointer(0x4539a7, elements[6]);
    patch_pointer(0x4539d9, elements[4]);
    patch_byte(0x4539ea, 4); // body (8) -> phys (4)
    patch_pointer(0x4539f2, elements[9]);
    patch_pointer(0x453a0b, elements[10]);
    patch_byte(0x453a39, 8); // unused (5) -> magic (8)
}

static int __cdecl (*uncased_strcmp)(const char *left, const char *right)
    = (funcptr_t) 0x4caaf0;

// The original function compared the first letter only.
// This is why some monsters attacked with earth instead of energy.
static int __fastcall attack_type(const char *attack)
{
    if (!attack)
        return 4;
    for (int idx = 0; idx <= 9; idx++)
        if (elements[idx] && !uncased_strcmp(attack, elements[idx]))
            return idx;
    return 4;
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
        cmp dword ptr [ebp-0xb0], 200
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
        cmp dword ptr [ebp-0xb0], 200
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

#define GLOBAL_TXT 0x5e4000

// Change school names in the spellbook from e.g. "Fire" to "Fire Magic".
// It's necessary because we changed "Air", "Body", etc. strings
// to the new element names.
static inline void spell_scholls(void)
{
    patch_dword(0x45332f, GLOBAL_TXT + 283 * 4);
    patch_dword(0x453347, GLOBAL_TXT + 284 * 4);
    patch_dword(0x45335f, GLOBAL_TXT + 285 * 4);
    patch_dword(0x45338f, GLOBAL_TXT + 286 * 4);
    patch_dword(0x4533bf, GLOBAL_TXT + 289 * 4);
    patch_dword(0x4533e3, GLOBAL_TXT + 290 * 4);
    patch_dword(0x453407, GLOBAL_TXT + 291 * 4);
    patch_dword(0x45342b, GLOBAL_TXT + 287 * 4);
    patch_dword(0x45344f, GLOBAL_TXT + 288 * 4);
}

// Just (temporarily) change assassins to poison and barbarians to frost.
static void __declspec(naked) assassins_barbarians(void)
{
    asm
      {
        mov ebx, dword ptr [ebx+0xc]
        cmp ebx, 0x43
        jne not_assassins
        mov ebx, 0xd
        not_assassins:
        cmp ebx, 0x44
        jne not_barbarians
        mov ebx, 5
        not_barbarians:
        cmp ebx, 0x2e
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
    patch_dword(0x439f6c, 3); // was 2 (water) for some reason
    patch_dword(0x439f7d, 3); // was 8 (body)
    patch_dword(0x439e67, dword(0x439e67) + 7); // Old Nick
    patch_byte(0x439f82, 8); // this is now Old Nick's posion damage
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

// Recognise element 10 (fire-poison) as the stat 0x2f (hitherto unused).
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
        _emit 0x6a
        _emit 0x2f
        push 0x48d4db
        ret
      }
}

static int __thiscall (*get_player_resistance)(const void *player, int stat)
    = (funcptr_t) 0x48e7c8;

// Can't just compare resistance values in-function, as player resistances
// are quite complex.  So we're replacing the call entirely and calling
// the original function twice.
static int __thiscall fire_poison_player(const void *player, int stat)
{
    if (stat != 0x2f)
        return get_player_resistance(player, stat);
    int fire_res = get_player_resistance(player, 0xa);
    int poison_res = get_player_resistance(player, 0xd);
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
        _emit 0xe9
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

// Undead players are either liches or zombies.
static int __thiscall __declspec(naked) is_undead(void *player)
{
    asm
      {
        xor eax, eax
        cmp byte ptr [ecx+0xb9], 35
        je undead
        cmp dword ptr [ecx+0x88], 0
        jnz undead
        cmp dword ptr [ecx+0x8c], 0
        jnz undead
        ret
        undead:
        inc eax
        ret
      }
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

// Undead are normally immune to poison, fear, insanity, and paralysis,
// i.e. all that is resisted by Poison or Mind.
static int __thiscall undead_conditions(void *player, int condition,
                                        int can_resist)
{
    if (can_resist && is_undead(player) && 1 << condition & 0x1568) // bitmask
        return 0;
    return inflict_condition(player, condition, can_resist);
}

// The original code equaled body (now magic) and spirit (now holy) resistance
// for players.  Now that holy is relevant, I need to separate it.
static void __declspec(naked) holy_is_not_magic(void)
{
    asm
      {
        mov edi, 8
        cmp ebp, 0x21
        jne not_holy
        mov edi, 6
        mov ebx, 4
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
        mov edi, 8
        cmp dword ptr [esp+20], 0x21
        jne not_holy
        mov edi, 6
        mov eax, 4
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
// and their resistances aren't even checked for this purpose.  The code below
// is probably not even necessary, but just in case, it raises the relevant
// resistances to 200 if less.
static void __declspec(naked) at_least_200(void)
{
    asm
      {
        push eax
        mov ecx, esi
        call is_undead
        test eax, eax
        pop eax
        jz not_undead
        cmp ebp, 0xd
        je immune
        cmp ebp, 0xe
        jne not_immune
        immune:
        mov ecx, 200
        cmp eax, ecx
        jge quit
        mov eax, ecx
        not_immune:
        quit:
        ret
        not_undead:
        cmp ebp, 0x21
        je immune
        ret
      }
}

// Ditto, but for base resistances.
static void __declspec(naked) at_least_200_base(void)
{
    asm
      {
        xchg ebx, ecx
        call is_undead
        test eax, eax
        mov eax, dword ptr [esp+16]
        jz not_undead
        cmp eax, 0xd
        je immune
        cmp eax, 0xe
        jne not_immune
        immune:
        mov eax, 200
        cmp ebx, eax
        jle quit
        mov eax, ebx
        quit:
        ret
        not_undead:
        cmp eax, 0x21
        je immune
        not_immune:
        mov eax, ebx
        ret
      }
}

// The most important part: if an immunity applies, zero out all damage.
static void __declspec(naked) immune_if_200(void)
{
    asm
      {
        push eax
        mov ecx, esi
        call is_undead
        test eax, eax
        pop eax
        mov ecx, dword ptr [ebp+8]
        jz not_undead
        cmp ecx, 3
        je immune
        cmp ecx, 7
        jne not_immune
        immune:
        xor eax, eax
        ret
        not_undead:
        cmp ecx, 6
        je immune
        not_immune:
        test eax, eax
        ret
      }
}

// Note: I'm only guessing at what these functions are.
funcptr_t color_stat = (funcptr_t) 0x4178a7;
funcptr_t compose_string = (funcptr_t) 0x4cad70;

// This code changes the stats screen to always display "Immune" for undead
// instead of only when the relevant resistance is >= 200.
static void __declspec(naked) display_immunity(void)
{
    asm
      {
        push ecx
        mov ecx, edi
        call is_undead
        test eax, eax
        jz not_undead
        mov ecx, dword ptr [esp+36]
        mov edx, 200
        call dword ptr ds:color_stat
        pop ecx
        push dword ptr [GLOBAL_TXT+0x9c4]
        push eax
        push dword ptr [GLOBAL_TXT+ecx]
        push 0x4e2de0
        push esi
        call dword ptr ds:compose_string
        add esp, 20
        ret
        not_undead:
        pop ecx
        ret
      }
}

// The unmodded game did not have the immunity code for earth (now poison)
// resistance, so I'm adding the instruction I owerwrote at the end here.
static void __declspec(naked) display_poison_immunity(void)
{
    asm
      {
        mov ecx, 0x118
        call display_immunity
        mov edx, dword ptr [0x5c3468]
        ret
      }
}

static void __declspec(naked) display_mind_immunity(void)
{
    asm
      {
        mov ecx, 0x238
        call display_immunity
        ret
      }
}

// Make undead characters immune to poison and mind, and all others, immune
// to holy.
static void undead_immunities(void)
{
    hook_jump(0x492d5d, undead_conditions);
    hook_call(0x48e85f, holy_is_not_magic, 5);
    hook_call(0x48e764, holy_is_not_magic_base, 5);
    hook_call(0x48e8d1, at_least_200, 7);
    erase_code(0x48e8db, 13);
    hook_call(0x48e7af, at_least_200_base, 7);
    erase_code(0x48e7b8, 13);
    hook_call(0x48d4e7, immune_if_200, 7);
    erase_code(0x48d4f3, 10);

    // Tweak bonus resistances on lichification: remove 200 body and mind,
    // but add 20 holy and 20 magic.
    patch_dword(0x44a758, dword(0x44a758) + 10); // earth -> magic
    patch_dword(0x44a769, dword(0x44a769) - 2); // mind -> holy
    patch_word(0x44a76d, 20); // 200 res -> 20 res
    erase_code(0x44a76f, 9); // remove body

    hook_call(0x418f0c, display_poison_immunity, 6);
    hook_call(0x418f91, display_mind_immunity, 5);
    erase_code(0x418f96, 51); // old mind immunity code
    erase_code(0x41904e, 56); // old body immunity code
}

// Bug fix: Kelebrim wasn't penalizing earth (now poison) resistance.
static void __declspec(naked) kelebrim(void)
{
    asm
      {
        cmp esi, 13
        jne quit
        sub edi, 30
        quit:
        push 0x48f0c3
        ret
      }
}

// Tweak the Phynaxian Crown: instead of +50 Water Res.,
// give it +30 Cold and Poison Res.
// Reason: it's supposed to protect against all of Water Magic.
static void __declspec(naked) phynaxian(void)
{
    asm
      {
        cmp esi, 12
        je boost
        cmp esi, 13
        jne quit
        boost:
        add edi, 30
        quit:
        ret
      }
}

// One of the more satisfying tweaks: make blasters shoot energy!
// That is, they now ignore physical immunity (as well as all others).
static void __declspec(naked) blasters(void)
{
    asm
      {
        cmp dword ptr [ebx+36], 64
        je blaster
        cmp dword ptr [ebx+36], 65
        jne ordinary
        blaster:
        mov dword ptr [ebp-8], 9
        ret
        ordinary:
        mov dword ptr [ebp-8], 4
        ret
      }
}

// Misc item tweaks.
static void misc_items(void)
{
    patch_pointer(0x48f698, kelebrim); // jump table
    hook_call(0x48f111, phynaxian, 8);
    hook_call(0x439639, blasters, 7);
}

#define ELEMENT(spell) byte(0x5cbecc + (spell) * 0x24)

// Some spell elements are hardcoded.  I could just re-hardcode them to
// my new elements, but it's much cooler to use the data from spells.txt.
// Thus, this function is called just after spells.txt is parsed.
static void spell_elements(void)
{
    patch_byte(0x439c48, ELEMENT(34)); // shock
    patch_byte(0x428dc6, ELEMENT(35)); // slow
    patch_byte(0x428748, ELEMENT(44)); // mass distortion
    patch_byte(0x428cce, ELEMENT(81)); // paralysis
    patch_byte(0x46bf8c, ELEMENT(92)); // shrinking ray
    patch_byte(0x42e0be, ELEMENT(94)); // control undead
    // Armageddon element wasn't updated from MM6, where it was 5 (then magic).
    // As in MM7 resistance 5 is unused, armageddon became irresistible.
    patch_byte(0x401b74, ELEMENT(98)); // armageddon (to monsters)
    patch_byte(0x401bfb, ELEMENT(98)); // armageddon (to players)
    // Not sure if the next two do anything, but just in case.
    patch_byte(0x46c9ea, ELEMENT(81)); // paralysis
    patch_byte(0x46c9e6, ELEMENT(92)); // shrinking ray
}

// Let's ride on the tail of the spells.txt parsing function.
static void __declspec(naked) spells_txt_tail(void)
{
    asm
      {
        pop ebx
        add esp, 16
        call spell_elements
        ret
      }
}

// Misc spell tweaks.
static void misc_spells(void)
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
    patch_byte(0x428e8f, 3); // charm master
    patch_byte(0x428e9f, 4); // charm GM
    // Another bug: in the inter-monster combat, when one monster cast a spell
    // on another, the spell's element was read from the defending monster's
    // data.  Fixed below:
    patch_byte(0x43b2d1, 0x4f);
    patch_byte(0x43b2e2, 0x4f);
    // Some mod-specific tweaks for a change: let's swap the effects of
    // earth (now poison) and body (now magic) resistance spells.
    // (In MM6 poison res. was a Body spell, and magic res was an Earth spell.)
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
    patch_dword(0x438f11, 3); // body (8) to poison (3)
}

// For consistency with players, monsters revived with Reanimate now have
// their resistances changed the same way as zombie players
// (immune to poison and mind, not immune to holy).
static void __declspec(naked) zombify(void)
{
    asm
      {
        mov dword ptr [edi+0x53], 200
        mov dword ptr [edi+0x54], 200
        cmp dword ptr [edi+0x55], 200
        jne not_immune
        mov dword ptr [edi+0x54], 0
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
        cmp dword ptr [eax+0x55], 200
      }
}

// Ditto.
static void __declspec(naked) control_undead_chunk(void)
{
    asm
      {
        cmp dword ptr [eax+0x5fefd8+0x55], 200
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
        cmp dword ptr [edi+0x55], 200
      }
}

// Change the conditions for zombification in the dark temples.
// Previously, stoned, dead or eradicated players became zombies.
// Now, liches and stoned players are exempt.
static void __declspec(naked) zombificable_chunk(void)
{
    asm
      {
        cmp byte ptr [esi+0xb9], 35
        _emit 0x74
        _emit 0x0d
        mov eax, dword ptr [ebp-0x2c]
        or eax, dword ptr [ebp-0x28]
        or eax, dword ptr [ebp-0x24]
        or eax, dword ptr [ebp-0x20]
        nop
      }
}

// Tweaks of zombie players and monsters.
static void zombie_stuff(void)
{
    hook_call(0x42dcd0, zombify, 6);
    patch_bytes(0x428987, destroy_undead_chunk, 7);
    patch_bytes(0x42e0a5, control_undead_chunk, 10);
    erase_code(0x42e0af, 5);
    patch_bytes(0x42bce1, turn_undead_chunk, 7);
    patch_bytes(0x4b75e3, zombificable_chunk, 22);
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
        return 48;
      }
    if (!uncased_strcmp(first_word, "destroy"))
      {
        ++*extra_words;
        return 79;
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

// Not dead, stoned, paralyzed, etc.
static int __thiscall (*player_active)(void *player) = (funcptr_t) 0x492c03;

// Monsters can now cast turn undead (only on party, only if liches or zombies
// present) and destoy undead (on any undead PC or monster).
static int __thiscall consider_new_spells(void *this, void *monster, int spell)
{
    int monster_id = ((uintptr_t) monster - 0x5fefd8) / 0x344;
    unsigned int target = dword(0x4f6c88 + monster_id * 4);
    if (spell == 48) // turn undead
      {
        // Make sure we're targeting the party (no effect on monsters so far).
        if (target != 4)
            return 0;

        for (int i = 0; i < 4; i++)
          {
            void *player = (void *) (0xacd804 + i * 0x1b3c);
            uint64_t *conditions = player;
                                                           // not afraid
            if (is_undead(player) && player_active(player) && !conditions[3])
                return 1;
          }
        return 0;
      }
    else if (spell == 79) // destroy undead
      {
        if (target == 4) // party
          {
            for (int i = 0; i < 4; i++)
              {
                void *player = (void *) (0xacd804 + i * 0x1b3c);
                if (is_undead(player) && player_active(player))
                    return 1;
              }
            return 0;
          }
        else if ((target & 7) == 3) // monster
          {
            uintptr_t target_monster = 0x5fefd8 + (target >> 3) * 0x344;
            return byte(target_monster + 0x55) != 200; // not immune to holy
          }
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

static void __thiscall (*make_sound)(void *this, int sound, int param_2,
                                     int param_3, int param_4, int param_5,
                                     int param_6, int param_7, int param_8)
    = (funcptr_t) 0x4aa29b;
static int __fastcall (*spell_damage)(int spell, int skill, int mastery,
                                      int monster_hp) = (funcptr_t) 0x43b006;
static int __thiscall (*damage_player)(void *player, int damage, int element)
    = (funcptr_t) 0x48dc04;
static void __fastcall (*attack_monster)(int attacker, int defender,
                                         void *force, int attack_type)
    = (funcptr_t) 0x43b1d3;
static int __fastcall (*skill_mastery)(int skill) = (funcptr_t) 0x45827d;
static int (*random)(void) = (funcptr_t) 0x4caac2;

// Turn undead scares all undead PCs, with no chance to resist.
// Destroy undead damages one undead PC or monster with Holy.
static void __fastcall cast_new_spells(int monster, void *vector, int spell,
                                       int action, int skill)
{
    void *sound_this = (void *) 0xf78f58;
    int spell_sound = word(0x4edf30 + spell * 2);
    if (spell == 48) // turn undead
      {
        // we must be targeting the party
        for (int i = 0; i < 4; i++)
          {
            void *player = (void *) (0xacd804 + i * 0x1b3c);
            if (is_undead(player) && player_active(player))
                inflict_condition(player, 3, 0); // cause fear unconditionally
          }
        make_sound(sound_this, spell_sound, 0, 0, -1, 0, 0, 0, 0);
      }
    else if (spell == 79) // destroy undead
      {
        unsigned int target = dword(0x4f6c88 + monster * 4);
        if (target == 4) // party
          {
            void *target_player;
            int count = 1;
            for (int i = 0; i < 4; i++)
              {
                void *player = (void *) (0xacd804 + i * 0x1b3c);
                if (is_undead(player) && player_active(player)
                    && !(random() % count)) // randomly choose one player
                  {
                    target_player = player;
                    count++;
                  }
              }
            if (count > 1)
              {
                int mastery = skill_mastery(skill);
                skill &= 0x3f;
                int damage = spell_damage(spell, skill, mastery, 0);
                damage_player(target_player, damage, ELEMENT(spell));
              }
          }
        else if ((target & 7) == 3) // monster
          {
            int attack_type;
            // hack to determine which spell (first or second) we're casting
            if (byte(0x5fefd8 + monster * 0x344 + 0x4d) == spell)
                attack_type = 2;
            else
                attack_type = 3;
            uint32_t force[3];
            memset(force, 0, 12); // no knockback so far
            attack_monster(monster * 8 + 3, target >> 3, force, attack_type);
          }
        make_sound(sound_this, spell_sound, 0, 0, -1, 0, 0, 0, 0);
      }
    else
        monster_casts_spell(monster, vector, spell, action, skill);
}

// Make Turn Undead and Destroy Undead castable by monsters.
static void new_monster_spells(void)
{
    hook_jump(0x45490e, parse_new_spells);
    hook_jump(0x4270b9, consider_new_spells);
    hook_jump(0x404ac7, cast_new_spells);
}

BOOL WINAPI DllMain(HINSTANCE const instance, DWORD const reason,
                    LPVOID const reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
      {
        spells_txt();
        monsters_txt();
        skip_monster_res();
        spell_scholls();
        elemental_weapons();
        fire_poison();
        condition_resistances();
        undead_immunities();
        misc_items();
        misc_spells();
        zombie_stuff();
        new_monster_spells();
      }
    return TRUE;
}
