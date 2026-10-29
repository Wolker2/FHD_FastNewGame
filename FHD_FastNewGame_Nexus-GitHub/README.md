# FHD_FastNewGame Native 0.2.3 FIXED

Исходники самого плагина FHD_FastNewGame для GitHub/Nexus. Исходный C-код и конфигурация сохранены. Плагин и настройки — **9/9 оригинальных файлов** — пересобираются побайтово точно. Сторонние DLL загрузчика и XenoStable исключены и обозначены как зависимости; их исходников в присланном архиве нет. Вручную восстанавливать `.dat`, `.scr` или `.rson` не требуется.

## Review scope

The supplied ZIP contains the FHD plugin source and also precompiled third-party `dsound.dll`, `XenoCore.dll`, and `XenoStable.Runtime.dll`. This repository provides the complete **supplied FHD plugin source**, its build tools, exact settings and verification. It does not claim to rebuild the entire original bundled loader distribution. Source for those three external binaries was not supplied, and no binary-only substitutes are placed in this source repository.

`source-provenance.json` records the original archive SHA-256, nineteen verified entries from its supplied manifest, unchanged source hashes and hashes of excluded external components. XenoStable's separate manifest and settings are excluded along with its DLL. No FHD C code was altered and no new release status was invented.

## Files and behavior preserved

- `SOURCE/Native/fast_new_game.c`, `.def`, `build.sh`, and `elf_to_coff.py`: unchanged original x86 C implementation and build pipeline.
- `SOURCE/CFG/Main.txt`: original ScriptLibs declaration and inline OnStart/OnLoad import/init callbacks.
- `SOURCE/ModuleInfo.txt`: editable UTF-8 metadata; the builder restores original CP1251 bytes.
- `settings/`: unchanged mod README, local plugin INI, global plugin manifest/config, and the original root `XenoNative.ini`.
- `tools/compile_srhd_dat.py`: reused local compiler for the supplied editable configuration.
- `tools/verify_native.py`: offline tests of the actual rebuilt plugin instructions.

There was no separate SCR or RSON file in the upload. The game-event code is included in Main.txt and compiled into Main.dat. Both plugin installation locations are reproduced from the same C build, so their DLL bytes are identical.

Global loading is intentional: `XenoNative/Plugins/FHD_FastNewGame/XenoNativePlugin.ini` has `Enabled=1`, while the mod-local `Native/FHD_FastNewGame.XenoPlugin.ini` has `Enabled=0`. The original design reads the active mod list before generation and uses `AutoRestartNativeMods=0` to avoid a loader-triggered process restart. Do not interpret the local setting alone as an accidentally disabled plugin.

## Exact build instructions

The verified path uses **Linux x86-64, Python 3.12, GCC 12.2.0 and GNU binutils 2.40**. GCC 13/binutils 2.42 also compiled the source but produced different code; this is why the exact historical toolchain is pinned.

On Ubuntu 24.04 x86-64 or a compatible Linux environment, install Python with venv support, `dpkg-deb`, and the compiler runtime dependencies (`libisl23`, `libmpc3`, `libmpfr6`, `libzstd1`, `zlib1g`, `libjansson4`). Then, from the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python build.py --verify-original
```

The builder automatically downloads four exact Debian compiler/assembler/linker packages from the URLs pinned in `toolchain-packages.json`, verifies their sizes and SHA-256 values, and extracts them under `.toolchain/`. It does not install packages into the operating system. The compiler packages themselves are not included in this source archive. Subsequent builds reuse the verified downloads. Source compilation uses the original shell command, object converter and DEF file without binary normalization or patching.

Internet access is needed for the initial Python/toolchain setup. The build and native probes do not contact game services or send network traffic. Windows users can use Linux through WSL2, or the supplied GitHub Actions workflow; a native Windows build path was not verified.

Outputs:

```text
dist/FHD_FastNewGame_0.2.3_MOD_ONLY_FROM_SOURCE.zip
dist/build-report.json
```

`--verify-original` checks all nine scoped runtime paths against their original SHA-256 values. The generated plugin is exactly 11597 bytes with SHA-256:

```text
3225b73c06e2e82cfb7ec21a20951fd3b6a1e3584093a77f4ceef51f01e1d08d
```

Both copies, Main.dat, ModuleInfo, the original README and all scoped INIs match the supplied bytes. The original archive and precompiled binaries are not build inputs. The installation ZIP additionally contains `INSTALL_SCOPE_RU.txt`, which explains the difference between this mod-only build and the historical bundled distribution.

## Offline native verification

A normal build validates the DAT roundtrip, all original hashes, PE32/i386 format, five exact ABI export names, absence of imported DLLs, equality of both plugin copies and the original loader settings.

To repeat the native probes, supply the separately available reference `Rangers.exe`:

```sh
python build.py --verify-original --exe /path/to/Rangers.exe
```

The fixture must have SHA-256:

```text
83300344af802bc51e64389c58f047e5afdf195c133048098be3881fae29ed98
```

The harness maps that real PE image and the rebuilt DLL into Unicorn, constructs a synthetic Windows module list and exported API functions, and executes the actual plugin code. Windows protection/cache/pinning APIs and the final game calculation/worker calls are instrumented stubs. No Windows game process is started and the EXE file is not modified or redistributed.

The fresh `build-verification.json` records **54 passed checks**, including:

- Plugin query/initialization ABI, standalone ScriptLibs initialization and repeated initialization.
- Live enable/disable through the in-memory mod list, lowercase matching, NoMods, null and empty lists.
- Configured 1/60/300-day limits and both direct/original worker routes. The loop boundaries are days+1, so the default 60-day configuration uses 61 and the disabled 300-day path uses 301.
- Execution of the generated job stubs and dispatch to the original calculation entry, with its final body mocked.
- Rejection of invalid host/config values, altered PE identities/signatures, nonpreferred module addresses and failed VirtualProtect calls without unintended game-image changes.

This does not benchmark generation speed or validate simulation results. Full game startup, actual worker scheduling, full RScript execution, loader restart behavior and menu interaction in Windows were not executed here. The original C matcher is tied to the specific game build and preferred base address; it is not a generic patch for all EXEs.

## Install scope and external dependencies

Read `INSTALL_SCOPE_RU.txt` before using the mod-only installation ZIP. A compatible XenoNativeLoader must already be installed separately. The original supplied README labels its loader bundle as 0.6.8; this preparation does not independently rebuild or validate that loader or XenoStable.

The output preserves `Mods/FHD_MODS/FHD_FastNewGame/` and `XenoNative/Plugins/FHD_FastNewGame/`. The included root `XenoNative.ini` is an exact original file, including `AutoRestartNativeMods=0` and the supplied BigGalaxy settings. It applies to the whole loader installation; automatic merging with unrelated settings is not implemented.

The unchanged historical README still describes a complete loader bundle. Its original bytes are retained for traceability; the added scope notice and this README describe the current mod-only output. Excluding third-party loader components does not imply they have been reconstructed or verified from source.

## GitHub automation and attribution

`.github/workflows/build.yml` prepares Python, fetches the pinned compiler packages, rebuilds the plugin and configuration, checks original hashes and publishes the mod-only ZIP/report. It does not bundle or download the game EXE and therefore omits the optional native probe. The workflow has not been run on GitHub in this preparation.

The supplied mod metadata credits FHD. No new ownership or project-wide redistribution license is asserted. The exact compiler packages have their own Debian/GNU licensing; they are separately downloaded dependencies. The copied DAT compiler is identified in the provenance notes as a reused source-preparation tool.
