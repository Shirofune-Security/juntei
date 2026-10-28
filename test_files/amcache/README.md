# Amcache test hives

Both hives come from [DFIRArtifactMuseum](https://github.com/AndrewRathbun/DFIRArtifactMuseum)
(`Windows/Amcache/`, MIT license), the same files ys-amcache-parser tests with.

| File | Source | Schema | Expected (`parse-amcache`) |
| --- | --- | --- | --- |
| `amcache_win10.hve` | `Win10/APTSimulatorVM/Amcache.hve` | modern (`Root\InventoryApplicationFile`) | 123 file entries, 189 device entries, 4 findings (medium) |
| `amcache_2012r2_old.hve` | `Win2012R2/StolenSzechuan/Amcache.hve` | legacy (`Root\File`) | 136 file entries, 0 device entries, 2 findings (medium) |

The counts match the `ys-amcache-parser` command (upstream's `amcache4n6`), which was
cross-validated against Eric Zimmerman's AmcacheParser and regipy.
