# USN journal test file

`win11_rathbunvm_$J` is 32 KiB from the middle of the Windows 11 `$J` of
[DFIRArtifactMuseum](https://github.com/AndrewRathbun/DFIRArtifactMuseum) (`Windows/NTFSArtifacts/J/Win11/RathbunVM/$J`,
offset 8,282,112; MIT License), the slice ys-usn-journal-parser tests with: 199 V2 records,
2022-02-05 18:56:53 – 18:57:00 UTC, every field checked there against dfir_ntfs.

The other journals of the tests are built by `tests/cli.rs` from Microsoft's record layout, on
the `$MFT` of `test_files/mft/`.
