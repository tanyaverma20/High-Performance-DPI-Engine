# Legacy / Reference Implementations

These files are preserved for historical reference and are **not compiled** by the CMake build.

| File | Original Path | Purpose | Reason moved |
|------|--------------|---------|--------------|
| `main_viewer.cpp` | `src/main.cpp` | Single-threaded PCAP viewer only | Superseded by `main_dpi.cpp`; no DPI functionality |
| `main_simple.cpp` | `src/main_simple.cpp` | Viewer + raw SNI extraction (manual offsets) | Superseded; parseIP duplicated from dpi_engine.cpp |
| `main_working.cpp` | `src/main_working.cpp` | Single-threaded DPI with substring domain blocking | Superseded by modular multi-threaded stack; contained D6 domain blocking bug |
| `dpi_mt.cpp` | `src/dpi_mt.cpp` | Self-contained multi-threaded DPI (entire stack in one file) | Superseded by the modular implementation; contained D5/D9 bugs |

The **canonical production entry point** is `src/main_dpi.cpp`, which uses the modular
`DPIEngine` class hierarchy in `src/dpi_engine.cpp`.

To build the project, see the top-level [README.md](../README.md).
