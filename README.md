# AnyNZ
a project aimed at mimicking the famous project "AnyPS5" and extending it to the famous console by nintendo the "Switch". we do use llm's and such and we condone their use for development. this is a heavy work in progress. WE DO NOT CONDONE PIRACY AND DO NOT PROVIDE GAMES, KEYS OR SUCH THINGS

## nx-decode

A small command-line tool that reads and decrypts Nintendo Switch **XCI** and
**NSP** container files (and the **NCA** files inside them) that you own, using
**your own** `prod.keys`. It is a local file-format utility: it shows what is in
a file, checks its integrity and extracts its contents.

> **Bring your own keys and files.** nx-decode does not include, download or
> distribute keys, firmware, title keys or games, and never will. You supply
> your own `prod.keys` (dumped from your own console) and your own game dumps.
> It does not modify, sign, re-encrypt or bypass anything. Updates are applied
> only to a base game you supply, and personalized (console-bound) tickets only
> decrypt with the `eticket_rsa_keypair` from your own console's keys.

### Install

Requires Python 3.10 or newer. CI tests 3.10, 3.12 and 3.14 on Linux and Windows.

```sh
git clone <this repo> nx-decode
cd nx-decode
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install .
```

The only runtime dependency is [`cryptography`](https://cryptography.io).

### Keys

nx-decode reads a hactool-style keys file: one `name = hexvalue` per line,
`#` for comments. It is looked up in this order:

1. `--keys PATH`
2. the `SWITCH_KEYS` environment variable
3. `~/.switch/prod.keys`

Pre-derived keys (`header_key`, `key_area_key_{application,ocean,system}_XX`,
`titlekek_XX`) are used when present. Otherwise they are derived from
`master_key_XX` and the `*_source` entries (`aes_kek_generation_source`,
`aes_key_generation_source`, `key_area_key_*_source`, `titlekek_source`,
`header_kek_source`, `header_key_source`).

Personalized tickets (eShop purchases dumped from your console) also need
`eticket_rsa_keypair`, the console-unique eTicket RSA key that Lockpick_RCM
writes into `prod.keys`. Without it, nx-decode says it is missing; with another
console's key, it says the ticket belongs to another console.

Error messages name missing keys (for example `missing key:
key_area_key_application_10 (... key generation 17; your keys may be older than
this title)`) but never print key values.

### Usage

```sh
nx-decode info    game.nsp                 # title ID, version, name, publisher, NCA status
nx-decode list    game.xci                 # files in the container (secure/xxxx.nca, ...)
nx-decode extract game.xci -o out/         # dump NCAs, tickets, certs as-is
nx-decode extract game.xci -o out/ --partition secure
nx-decode nca-extract game.nsp -o out/     # decrypt every NCA: ExeFS, PFS0, RomFS trees
nx-decode nca-extract game.nsp -o out/ --nca 0123...cdef.nca --section 1
nx-decode nca-extract program.nca -o out/ --ticket 0100...0b.tik
nx-decode nca-extract update.nsp --base game.xci -o out/            # update applied to its base
nx-decode nca-extract game.xci --update v1.nsp --update v2.nsp -o out/  # highest version applied
nx-decode nca-extract game.xci --update v1.nsp --update v2.nsp --update-version 65536 -o out/
nx-decode verify  game.nsp                 # content IDs, CNMT hashes, hash tables
nx-decode verify  game.xci --quick         # header-level checks only (fast)
nx-decode verify  update.nsp --base game.xci  # also checks the patched RomFS hash tree
nx-decode titles  games/ updates/ dlc.nsp  # group files into base + latest update + DLC
```

`info`, `verify`, `list` (for an `.nca`), `nca-extract` and `titles` accept `--keys PATH`;
`info`, `verify` and `nca-extract` accept `--base FILE` when FILE is an update.
Exit status is 0 on success and 1 if something failed or could not be decoded
(each problem is reported on its own line). `--debug` shows tracebacks for
unexpected errors.

`nca-extract` writes, per NCA, `section<N>_exefs/` (a PFS0 with `main.npdm`),
`section<N>_pfs0/` (other PFS0 sections, such as the CNMT or logo) and
`section<N>_romfs/` (the RomFS directory tree). DLC data NCAs extract like any
other RomFS section.

An update's RomFS is not a whole RomFS: its BKTR section holds only what changed,
plus tables that say which ranges come from the base game. With `--base BASE`
(FILE is the update) or `--update UPDATE` (FILE is the base game; repeat it for
several updates, the highest version is used unless `--update-version N`),
`nca-extract` writes the updated title: the update's NCAs with their RomFS
patched from the base game, and the base game's contents the update does not
replace (such as a manual). The update's ExeFS is a plain section and extracts as
is. NCAs are paired by content type and ID offset from the two CNMTs, and the
update's CNMT must name the base game as its application.

`titles` takes any mix of files and folders (searched recursively for
`.xci`/`.nsp`/`.nca`), reads every content set's CNMT and groups them by the
CNMT's ApplicationId (the title-ID convention is only a fallback when a CNMT has
none). For each title it prints the base, the highest update found and the DLC,
then lists system updates separately. It warns about DLC or updates without
their base, several update versions, duplicate content, and CNMTs whose
ApplicationId disagrees with their title ID. Warnings keep exit status 0;
unreadable or compressed files are errors (exit status 1).

All reads are streamed in 1 MiB chunks, so multi-gigabyte XCIs are never loaded
into memory.

When a name inside a container can't be a file on your system (`..` or a drive
letter anywhere; on Windows also characters such as `?` or `|`, a trailing dot or
space, or device names like `CON` and `NUL`), that one file is skipped and listed,
the rest still extracts, and the exit status is 1. Nothing is renamed. On Windows,
paths longer than 260 characters work even with Windows' long-path setting off.

### Supported

| Area | Supported |
| --- | --- |
| Containers | XCI (with or without the 0x1000-byte key-area prefix), NSP, standalone NCA |
| Partition FS | PFS0, HFS0 (incl. XCI update / normal / secure / logo partitions) |
| NCA headers | NCA3, NCA2, already-decrypted (plaintext) headers |
| NCA keys | key generations 0x00 to 0x1F, application/ocean/system key-area keys, rights-ID NCAs via common tickets, and personalized tickets with your `eticket_rsa_keypair` (RSA-2048-OAEP) |
| Section crypto | none, AES-CTR, AES-XTS, AES-CTR-EX (update BKTR sections, with the base game) |
| Hash layers | HierarchicalSha256 (PFS0), HierarchicalIntegrity / IVFC (RomFS) |
| Metadata | CNMT (title ID, version, type, content records, ApplicationId / PatchId from the extended header, system-update content meta records), NACP (name, publisher, display version) |
| Content meta types | Application, Patch and AddOnContent are grouped into titles; Delta, DataPatch and SystemUpdate are listed only |
| DLC (AddOnContent) | `info`, `verify` and `nca-extract` via common or personalized tickets, like any RomFS |
| Updates (Patch) | grouped by `titles`; BKTR sections (relocation and subsection bucket trees of any size, AES-CTR-EX, indirect storage) decoded against the base game with `--base` / `--update` in `info`, `verify` and `nca-extract` |
| Verify | content ID = SHA-256[:16], CNMT hash and size, FS-header hashes, master hashes, full hash tables (for an update with `--base`, over the patched RomFS), XCI root/partition HFS0 hashes |

### Not supported (reported clearly, never a crash)

| Feature | What you get |
| --- | --- |
| An update's BKTR section without its base game | "BKTR patch section: needs the base game (pass --base)" (the ExeFS and Control NCA still decode) |
| Personalized tickets without `eticket_rsa_keypair` | `missing key: eticket_rsa_keypair (needed for personalized tickets ...)` |
| BKTR with skip-layer-hash encryption (14.0.0+) | "... not supported" |
| Keys for a newer key generation than your keys file has | `missing key: ...` naming the key and the key generation |
| NSZ / XCZ / NCZ (compressed) | "compressed; decompress first" |
| NCA0, sparse sections, compressed sections, metadata hash layers, SHA3 hash layers, skip-layer-hash encryption, unknown types | "... not supported" |
| Header / NPDM RSA signature checks, XCI header decryption | not implemented |

Out of scope: downloading anything (keys, games, updates), hosting or distributing
keys, modifying, signing or re-packing games, or bypassing online checks.

### Specification sources

The layouts were first taken from the open-source reference implementations
hactool (ISC) and libnintendo-hac / libnintendo-es (MIT, used by nstool),
read-only. All code here is original.

They were then checked against the [Switchbrew wiki](https://switchbrew.org/wiki/)
pages for [XCI](https://switchbrew.org/wiki/XCI), [NCA](https://switchbrew.org/wiki/NCA)
(header, FS header, section and hash types, PartitionFS),
[Ticket](https://switchbrew.org/wiki/Ticket), [CNMT](https://switchbrew.org/wiki/CNMT)
(incl. the Application, Patch, AddOnContent, Delta and SystemUpdate extended headers
and content meta records),
[NCM services](https://switchbrew.org/wiki/NCM_services) (content meta and content
type enums) and [NACP](https://switchbrew.org/wiki/NACP). Module docstrings say
`Spec:` for what was checked against the wiki and `Reference:` for what relies on
hactool/libnintendo only.

Switchbrew does not document these, so they rest on the reference implementations
alone:

- the RomFS header and directory/file entry layout (there is no RomFS page);
- the AES-CTR section counter (8 bytes from FS header 0x140, then offset >> 4);
- key derivation (`header_key`, key-area keys, `titlekek`, title-key unwrapping);
- the IVFC level count convention, NCA content ID = first 16 bytes of the
  SHA-256, and whether the XCI `PartitionFsHeaderAddress` counts from the card
  header;
- the CNMT file order (extended header, then content records, then content meta
  records; the wiki lists the structures but does not say how they are laid out);
- the title-ID convention (update = base + 0x800, DLC = base + 0x1000 + n), which
  `titles` only uses when a CNMT has no ApplicationId.

BKTR (updates) and personalized tickets were checked against Switchbrew's
[NCA](https://switchbrew.org/wiki/NCA#PatchInfo) and
[Ticket](https://switchbrew.org/wiki/Ticket) pages and the read-only reference
implementations hactool (ISC) and nxdumptool (GPL-3.0). LibHac and Lockpick_RCM
were no longer reachable.

- **Confirmed by Switchbrew and both references:** PatchInfo offsets, the
  BucketTreeHeader, the relocation and subsection table and entry layouts.
- **Both references agree, Switchbrew is silent:** the AES-CTR-EX counter
  (SecureValue, then the subsection's generation, then offset >> 4), both tables
  read with the section's normal counter (Switchbrew only says "normal crypto"),
  and a relocation entry ending where the next one starts.
- **nxdumptool only:** the subsection "encryption" byte at 0x8 (0 = encrypted,
  1 = not; Switchbrew calls it unused), the entry-node capacities, pairing base
  and update NCAs by content type and ID offset, and that a personalized title
  key block is RSA-2048-OAEP with SHA-256 and an empty label, which unwraps to
  the same titlekek-wrapped key a common ticket holds. Switchbrew only says
  "RSA-2048".
- **Atmosphère only** (`fssystem_bucket_tree`, GPL-2.0): the second offset level of
  very large bucket trees (more than 0x7FE entry sets, about 1.6 million relocation
  entries). nxdumptool ports the lookup but refuses such tables; Switchbrew and
  hactool do not describe them.
- **Not confirmed by any source reached:** the exact `eticket_rsa_keypair` layout
  in a Lockpick_RCM keys file. nx-decode reads D, N and E at 0, 0x100 and 0x200
  (nxdumptool's field order without the CTR) and checks the keypair works before
  using it, so a different layout is a clear error, never a wrong key.

The three details that were previously unconfirmed:

- **Ticket signature type byte order:** still unconfirmed. Switchbrew lists the
  types and sizes but not their byte order, so both orders are accepted.
- **Newer NCA FS-header fields:** confirmed by Switchbrew (sparse info at 0x148,
  compression info at 0x178, metadata hash type at 0x5 and info at 0x1A0, SHA3
  hash types 4-6, skip-layer-hash encryption types 5-6). These are only used to
  *detect and refuse* such sections, never to decode them.
- **XCI dumps with the 0x1000-byte key area:** confirmed by Switchbrew: the
  CardKeyArea precedes the card header on the card and is hidden from raw reads,
  so `HEAD` is at 0x100 in a normal dump and 0x1100 with the key area.

### Testing on your own files

```sh
python scripts/smoke.py ~/.switch/prod.keys /path/to/game.xci            # info, list, quick verify
python scripts/smoke.py ~/.switch/prod.keys /path/to/game.nsp --full --extract
```

The smoke script only prints to the terminal. `--extract` uses a temporary
directory outside the repository and deletes it afterwards. Output contains
title IDs and file names but never key values. Please don't paste anything
else from your keys file when reporting issues.

### Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for setup on Windows and Linux/macOS, the
module layout, conventions, and what still needs checking on real files.

```sh
pip install -e ".[dev]"
git config core.hooksPath .githooks   # enable the pre-commit safety hook
ruff check . && ruff format --check . && pytest -q
python scripts/demo.py                # every command on a synthetic library, no keys needed
```

The test suite builds tiny synthetic PFS0/HFS0/XCI/NSP/NCA/RomFS/ticket files at
runtime with randomly generated keys. The encryption side of those builders is
an independent implementation, so the tests check decryption against it. **No
real keys or Nintendo data are in this repository or its tests.**

`scripts/check_forbidden.py` runs as a git pre-commit hook, as an optional
[pre-commit](https://pre-commit.com) hook and in CI. It rejects any file that
contains a keys-file-like line (`name = <32 or 64 hex digits>`), any Switch
container (by magic bytes), any `.keys/.xci/.nsp/.nca/.tik/.cert/...` file and
any archive (`.rar/.7z/.zip`). It reads only the first 4 MiB of each file.

### License

MIT, see [LICENSE](LICENSE). "Nintendo Switch" is a trademark of Nintendo. This
project is not affiliated with or endorsed by Nintendo.
