# Source provenance — Jarvis-HOOK

- Origin: https://gitlab.com/ffgriever/ffx-x-2-hd-external-file-loader
- Upstream commit: `b8433c3e3c3abff10ae026f1759dadc4fd4e8e4b` (2021-06-24).
- Original author/copyright: ffgriever, 2020.
- License: BSD-2-Clause; original `LICENSE` is retained byte-for-byte.
- Imported logging interface and `simpleLog.lib`: upstream `ff10-file-loader/external/`; BSD-2-Clause, Philipp Krähenbühl (2018) and ffgriever (2020). Original notice retained byte-for-byte.
- Adapted parts: `hook.cpp`, `hook.h`, `dllmain.cpp`, module metadata/version. External-file routing and the original native callback ABI are retained. Exact profile tables, file SHA admission, bounded worker bootstrap, transactional thread-aware patching, tests, CMake/CI, configuration sample and documentation are compatibility-fork additions.
- Adaptation date: 2026-10-02.
- Upstream history is preserved. This is a GitHub-hosted compatibility fork of the GitLab project.

Native addresses were derived from the user's local old/new executable bytes. FFX whole-function/relocation/callee correspondences and X-2 complete CFG-bounded routine matches plus unique instruction windows provide the evidence. Historical function labels are not treated as proof of a prototype. Only identities, addresses and bounded patch witnesses are included publicly. The executable files, raw image dumps, game assets and IDA databases remain private.
