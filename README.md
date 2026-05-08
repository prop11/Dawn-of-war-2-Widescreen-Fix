# DoW2 Ultrawide UI Fix — Build & Install Guide

## What this does

Injects into Dawn of War II at startup and patches the UI scale cap that causes
interface elements to run off-screen at ultrawide (21:9, 32:9) resolutions.

Two complementary strategies are applied:
1. Patches the `1.0f` cap constant in `.rdata` → `4.0f` (covers up to ~7680px wide)
2. NOPs the conditional branch in `.text` that enforces the cap

A log file `DoW2_UIFix.log` is written next to `DOW2.exe` so you can confirm it worked.

## Install

### Get the ASI Loader
Download `msacm32.zip` from:
https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/Win32-latest/msacm32.zip

Extract `msacm32.dll`.

### Drop files into the game folder
```
Steam\steamapps\common\Dawn of War II\
  ├── DOW2.exe
  ├── msacm32.dll      ← ASI loader (renames itself as a system DLL to get loaded)
  └── Injected.asi     
```

### Also fix the monitor count (ultrawide only)
Open:
```
Documents\My Games\Dawn of War II\Settings\configuration.lua
```
Find `horizontalmonitorcount` and set it to **1**.
If that still looks wrong, try **2** or **3**.

You can also increase `UIscale` in the same file if elements are still small.

---

## Troubleshooting

Check `DoW2_UIFix.log` (created next to `DOW2.exe` on first launch).

- **Log file not created**: The ASI loader isn't finding `Injected.asi` — confirm
  `msacm32.dll` is in the right folder and is the 32-bit version.
