# Compatibility evidence — Jarvis-HOOK

## Reproduced failure and address proof

The installed original 1.1.1 loader logged `Invalid game version. Unable to find proper hook values.` Its five FFX admission witnesses match the old executable **5/5** and the new executable **0/5** at the old addresses. The module loader itself successfully loaded the DLL; the external file component rejected the game.

| Site/function | FFX legacy RVA | FFX Steam RVA | X-2 legacy RVA | X-2 Steam RVA |
| --- | --- | --- | --- | --- |
| Native open-VBF routine | `21C0D0` | `21BF10` | `542BA0` | `542A00` |
| Native existence routine | `21C000` | `21BE40` | `542AD0` | `542930` |
| Before open patch | `2081AF` | `207FEF` | `49134F` | `49124F` |
| Open hook | `2081B3` | `207FF3` | `491353` | `491253` |
| After open patch | `2081B8` | `207FF8` | `491358` | `491258` |
| Existence hook | `20805F` | `207E9F` | `4911EF` | `4910EF` |
| Optional archive check | `2797AE` | `2795FE` | `94C6E` | `94CEE` |

FFX correspondences use complete old/new function bodies, HIGHLOW operands and callee graphs. The X-2 open/existence routines are respectively 204/206-byte complete CFG-bounded matches, with equal masked relocation/call structure and one current match each. The X-2 caller sites use unique 160-byte windows, the archive check a unique 96-byte window. Both native CALL destinations were checked independently against the matched routines. The different X-2 call displacements are included in its profile witnesses.

## Checks

- Portable RT0: **115/115** header, coordinate, native-site/callee, bounds and mutation checks.
- Windows: x86 Release builds with MSVC `/W4 /WX`; public CTest passes.
- Private Windows RT1: every recorded executable is mapped using `DONT_RESOLVE_DLL_REFERENCES`. Its entrypoint/import initialization is never run.
- Every profile exercises explicit configuration opt-in, disabled/no-write behavior, full-file SHA/header/site admission, foreign-site rejection before any earlier write, post-admission foreign mutation under the thread barrier, the native patch transaction, external existence/open/handle/content, selected native-address thiscall fallback with stubbed archive endpoints, optional archive bypass and exact byte restoration.
- A same-header/same-size copy with a flipped final byte is rejected by SHA admission and owns no native patches.

The stubbed archive endpoint establishes forwarding/address/stack behavior, not real VBF object parsing. The real direct-file endpoint uses Windows `CreateFileW`/`ReadFile` and verifies payload bytes. No gameplay or X-2 game-session pass is inferred from these isolated checks.

## Live test record

Pending for this compatibility fork. Required observations: exact deployed DLL/executable hashes, `File loader ready` for the selected profile, a bounded `Reading DIR`/`Exists DIR` record for an existing override, successful corresponding in-game asset/resource use, archive fallback and absence of crash/restore-pending evidence. Use a disposable save and record configuration/mod paths. A later live record must state its actual case and limits.
