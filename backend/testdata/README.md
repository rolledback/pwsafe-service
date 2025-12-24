# Test Password Safe Files

This directory contains Password Safe v3 (.psafe3) files for development and testing purposes.

## Test Files

### 1. simple.psafe3
**Password:** `password`

**Source:** [gopwsafe test database](https://github.com/tkuhlman/gopwsafe/tree/master/pwsafe/test_dbs)

**Structure:**
- **Total Records:** 1
- **Groups:**
  - `test`
    - **Entry:** Test entry
      - UUID: `c4dcfb52-b944-f141-af96-b746f184afe2`
      - Username: `test`
      - Password: `password`
      - URL: `http://test.com`
      - Notes: `no notes`

**Use Case:** Basic single-entry testing, simple group structure.

---

### 2. three.psafe3
**Password:** `three3#;`

**Source:** [gopwsafe test database](https://github.com/tkuhlman/gopwsafe/tree/master/pwsafe/test_dbs)

**Structure:**
- **Total Records:** 3
- **Groups:**
  - `group1`
    - **Entry:** three entry 1
      - UUID: `6f1738b6-4a22-314a-8bbf-5c3507f0d489`
      - Username: `three1_user`
      - Password: `three1!@$%^&*()`
      - URL: `http://group1.com`
      - Notes: `three DB\nentry 1`
  
  - `group2`
    - **Entry:** three entry 2
      - UUID: `0e3b2a77-777f-754e-b175-23cce0340b1a`
      - Username: `three2_user`
      - Password: `three2_-+=\\|][}{';:`
      - URL: `http://group2.com`
      - Notes: `three DB\nsecond entry`
  
  - `group 3`
    - **Entry:** three entry 3
      - UUID: `6c8d029c-6b72-454a-b605-1af8f93f01d3`
      - Username: `three3_user`
      - Password: `,./<>?~0`
      - URL: `https://group3.com`
      - Notes: `three DB\nentry 3\nlast one`

**Use Case:** Multi-group testing, special characters in passwords, multiple entries.

---

## Notes

- All test files are committed to the repository for development purposes only
- These files contain test data only and should never be used for storing real passwords
- File extensions: `.dat` files from gopwsafe have been renamed to `.psafe3` for consistency
- All files are compatible with Password Safe v3 format and can be opened with the gopwsafe library

## License

These test files are sourced from [gopwsafe](https://github.com/tkuhlman/gopwsafe), which is licensed under the ISC License (a permissive open-source license). The original test databases were created using [Loxodo](https://github.com/sommer/loxodo).

**Copyright Notice:**
```
Copyright (c) 2014 Tim Kuhlman <tim@backgroundprocess.com>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.
```

## Verification

To verify these files can be opened, use them directly with the gopwsafe library:

```go
import "github.com/tkuhlman/gopwsafe/pwsafe"

// Open simple.psafe3
db, err := pwsafe.OpenPWSafeFile("./testdata/simple.psafe3", "password")
if err != nil {
    // handle error
}

// Open three.psafe3
db, err := pwsafe.OpenPWSafeFile("./testdata/three.psafe3", "three3#;")
if err != nil {
    // handle error
}
```
