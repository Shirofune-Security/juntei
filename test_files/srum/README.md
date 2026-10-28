# SRUM test databases

Both databases come from [DFIRArtifactMuseum](https://github.com/AndrewRathbun/DFIRArtifactMuseum)
(`Windows/SRUM/`, MIT license), the same files ys-srum-parser tests with.

| File | Source | Entries (`parse-srum`) |
| --- | --- | --- |
| `win10_rathbunvm_SRUDB.dat` | `Win10/RathbunVM/Clean/SRUDB.dat` | 309: AppResourceUseInfo 118, AppTimelineProvider 163, NetworkConnections 1, NetworkUsages 23, vfuprov 4 |
| `server2022_aptsimulatorvm_SRUDB.dat` | `Server2022/APTSimulatorVM/APTSimulatorVM_SRUM_Clean_Server2022_1DayLater.7z` (`SRU/SRUDB.dat`) | 167: AppResourceUseInfo 153, NetworkBytes 2, NetworkConnections 4, ProcessorTime 2, SizeInBytes 2, TotalUsed 4 |

Every column of every entry `parse-srum` writes for these and nine other real databases
(45,255 entries) equals a decoding written independently from dissect.esedb's values.

The SOFTWARE hives of the tests (account and Wi-Fi names) are built by `tests/cli.rs`.
