# ESQCat Core Implementation

## Introduction

ESQCat is a C++ research implementation of encrypted candidate filtering for labeled subgraph queries. This repository contains the core implementation of ESQCat. Benchmarking scripts, comparison baselines, and experimental datasets are not included.

The executable mines frequent subgraphs, builds the Graph Look-up Table, Triplet Look-up Table, Complete Feature Bitmap Index (CFBI), and Graphlet B+ trees, and generates query trapdoors. It handles TCFG, FG, IFG, and CFBI fallback in one process. Labeled VF2 verifies the returned candidates.

## Requirements

The project requires a C++17 compiler, OpenSSL Crypto development files, and Boost headers including Boost.Graph. CMake declares version 3.16 as its minimum. The build commands use Ninja.

For Windows, use the MSYS2 UCRT64 packages for GCC, CMake, Ninja, OpenSSL, and Boost (`mingw-w64-ucrt-x86_64-` prefix). Add `ucrt64/bin` to `PATH`.

Verified on Windows with MSYS2 UCRT64, GCC 15.2.0, CMake 4.2.1, Ninja 1.13.2, OpenSSL 3.6.0, and Boost 1.90.0.

## Build

Run from the repository root in PowerShell.

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target esqcat
```

## Run

Run from the repository root with your own `graphs.tve` and `queries.tve`.

```powershell
.\build\esqcat.exe --help
.\build\esqcat.exe --dataset graphs.tve --query queries.tve --sigma 0.25
```

The program creates or reuses `keys_v2.bin` in the working directory. Keep that file private.

Standard output is TSV with `query_id`, `candidate_ids`, and `match_ids`. IDs are zero-based graph positions in their respective files. ID lists are comma-separated and `-` denotes an empty list. `match_ids` contains VF2-confirmed candidates. Errors go to standard error.

## Command Line Arguments

| Argument | Description |
| --- | --- |
| `--dataset <file>` | Dataset TVE file (required). |
| `--query <file>` | Query TVE file (required). |
| `--sigma <ratio>` | Minimum support ratio, positive and finite (default `0.1`). |
| `--delta <value>` | Delta tolerance, nonnegative and finite (default `0.1`). |
| `--hide-graphlet-type-access` | Select all eight Graphlet types for IFG and CFBI fallback, including zero-count types, when thresholds are available. |
| `--help`, `-h` | Print usage when supplied alone. |

By default, Graphlet filtering selects only positive-count types. Early exits can limit tree visits even when all eight tokens are generated. Both modes returned the same candidates and matches on the small inputs tested. Full access-pattern hiding and leakage equivalence remain unproven.

## Input File Format

The dataset and query files use the same TVE format.

| Record | Meaning |
| --- | --- |
| `t # <graph-id>` | Begins a graph with an integer ID. |
| `v <vertex-id> <label>` | Declares a vertex with a unique integer ID within the graph and a single-token label. |
| `e <source-id> <target-id> <label>` | Declares an undirected edge. Declare both endpoints first and use one edge per endpoint pair. |
| `t # -1` | Optional end-of-file marker. |

Use the same label encoding in both files.

## Project Structure

`src/` contains the main program and its implementation. `include/` contains the required headers. `CMakeLists.txt` builds the `esqcat` executable.
