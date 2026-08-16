# Zstandard Notice

- Upstream project: Zstandard
- Upstream URL: https://github.com/facebook/zstd
- Upstream version: 1.5.7
- Source tag: `v1.5.7`
- License: BSD 3-Clause, copied in `LICENSE.txt`
- Third-party licensing note: these bundled files are governed by the license above, and Ksword's project `LICENSE` does not replace it.
- Imported files: `zstd.h`, `zstd_errors.h`, and the official single-file-library amalgamation `zstd.c`
- Amalgamation command: `python combine.py -r ../../lib -x legacy/zstd_legacy.h -o zstd.c zstd-in.c`
- Local use: lossless compression of ETW archive blocks

The amalgamated source was generated from the unmodified upstream `v1.5.7`
release with the upstream `build/single_file_libs/combine.py` tool.
