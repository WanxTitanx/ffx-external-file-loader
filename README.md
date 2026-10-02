# FFX / X-2 External File Loader — Steam compatibility fork

Compatibility fork of [ffgriever's FFX X-2 HD External File Loader](https://gitlab.com/ffgriever/ffx-x-2-hd-external-file-loader), maintained by WanxTitanx / Jarvis-HOOK. The original author, BSD license, loader exports and external-file routing are retained.

The October 2026 Steam update moved the game's native file routines and patch sites. The original loader reports `Invalid game version. Unable to find proper hook values.` This fork selects explicit executable profiles and checks the complete executable file hash, native bytes and original call targets before installing the patches.

## Supported executable identities

| Profile | PE timestamp | File bytes | SHA-256 |
| --- | --- | ---: | --- |
| FFX Steam BuildID 25501027 | `6AA2219C` | 10,687,744 | `0537b2a1047f3266e73495cd4e35f63f0777f4231d417699f979954686da686d` |
| FFX legacy reference | `55D2F3CC` | 10,675,712 | `78ce34397da5e6f49b72c2aebadedaf4cd3f6720e1949d46a1b8ed67d3db5ced` |
| FFX-2 Steam BuildID 25501027 | `6AA2217B` | 12,281,600 | `6ea7f142f129a43bdaea7eaabda4477a9057e60d12fdae367530c63e9a14cd69` |
| FFX-2 legacy LAA-unaware reference | `55D433A4` | 12,271,104 | `d7f08cda89dbcd6f429814e9523ce7a63a094417442a025573afbbef3251ef20` |

Other builds and executable modifications are rejected. The legacy X-2 reference is specifically the recorded LAA-unaware binary; this is not a claim that every legacy X-2 variant is supported. All profiles are PE32/I386; addresses are RVAs relative to the actual loaded module base.

## Install

Keep the existing FF10 Module Loader (`dinput8.dll`) and its `simpleLog.dll` in the game's directory. This repository builds the **external file component**, `ff10-file-loader.dll`.

1. Close FFX and FFX-2.
2. Back up `modules/ff10-file-loader.dll` and any existing `modules/config/ff10-file-loader.ini` outside the autoload directory.
3. Copy the package's `modules` folder into the game directory. If an INI already exists, preserve its path entries and explicitly add `enabled=1` under `[General]` rather than overwriting it.
4. Leave the unpacked mod files under their existing paths. The default path is `data/mods`; the VBF archives remain required by default.
5. Start the game and check `hook.log` for `File loader ready:` and the selected profile. `logAccess=true` under `[Logging]` records actual `Reading DIR` / `Exists DIR` accesses for validation.

Missing configuration or missing `General/enabled=1` means **OFF**. The included sample INI is an explicit installation opt-in. `allowNoVbf` remains OFF unless explicitly requested. The normal archive fallback is retained when an external file does not exist.

The loader pins its DLL for the process lifetime. Configuration changes or removal require a game restart. Restore the backed-up DLL and configuration with the game closed to roll back.

## Build and test

Windows requires Visual Studio 2022 C++ tools, an installed Windows SDK and CMake. Build **Win32**, not x64:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A Win32
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The DLL is under `build/bin/Release`. Linux can build/run the portable profile tests with `cmake -S . -B build`, `cmake --build build`, and `ctest --test-dir build --output-on-failure`.

For the isolated Windows harness, add `-DFF10_BUILD_PRIVATE_RT1=ON`, place the Module Loader's `simpleLog.dll` beside `native_rt1.exe`, and supply your own supported executable as an argument:

```powershell
./build/bin/Release/native_rt1.exe C:/private/FFX.exe C:/private/fresh-test-directory
```

The harness maps the PE without executing the game entrypoint or resolving the game's imports. It exercises executable admission, mutations, external file handles/content, selected-address/thiscall fallback, optional archive bypass and restoration in its disposable image. Game executables, saves, VBF assets and IDA databases are not included in this repository or its packages.

## Validation and lifecycle

The portable profile/mutation tests pass. The private native harness passes for all four recorded executable identities. These are offline/isolated results; a game-session result must identify the actual external file read and the observation case. No blanket live-game compatibility or Production claim follows from compilation. See [validation evidence and address provenance](docs/VALIDATION.md).

Filesystem/configuration, cryptography and patch installation run on a worker outside DllMain. Before patching, the loader suspends peer threads and checks instruction pointers and frame return addresses, then revalidates the native witnesses. Changed/foreign code prevents installation. A failed patch transaction restores its touched bytes and page protection; failure to restore code terminates the process rather than continuing with a partial patch. The process-lifetime pin keeps installed callback addresses valid until process exit.

## License and credits

The code is **BSD-2-Clause**. Retain [LICENSE](LICENSE) when distributing source or binaries. The imported logging interface/library has its own [BSD-2-Clause notice](ff10-file-loader/external/LICENSE), crediting Philipp Krähenbühl and ffgriever; retain that notice too.

Original loader and routing: **ffgriever**. Steam profile migration, admission/lifecycle/transaction checks, tests and packaging: **WanxTitanx / Jarvis-HOOK**. [Provenance](PROVENANCE.md) records the exact upstream commit and adapted components.
