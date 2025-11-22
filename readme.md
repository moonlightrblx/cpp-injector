# Ellii's Manual Map Injector 🛠️

[![License](https://img.shields.io/badge/License-None-lightgrey)](LICENSE) 
[![C++](https://img.shields.io/badge/Language-C++17-blue)](https://isocpp.org/) 
[![Platform](https://img.shields.io/badge/Platform-Windows-blueviolet)](.) 

A modern, research-oriented manual map injector, built as a secure and improved redesign of TheCruZ's original injector. Focused on stability, PE mapping, and low-level Windows internals exploration.

---

## ✨ Features

- **Fully manual PE mapping**
  - Import resolution, relocations, TLS, entry execution.
- **Custom shellcode**
  - Optimized internal stubs for relocation, import fixing, and memory preparation.
- **Improved diagnostics**
  - Detailed logging for understanding mapping flow and debugging failures.
- **Safer design**
  - Additional checks for target process access, PE consistency, memory safety.
- **LoadLibrary Injection**
  - Direct injection with LoadLibraryA
- **Manual Mapping**
  - Manual Map the injection
> ⚠️ Still not “perfect,” but significantly more robust than the original injector it’s based on.

---

## 🧩 Credits

- **TheCruZ** — Original injector this project evolved from  
- **Conspiracy** — Help with assembly routines & shellcode improvements  
- **m417z** — Creator of the syscall documentation resource *ntdoc.m417z.com*  
- **Me** — Full rewrite, architecture redesign, syscall integration, improvements  
- **Testers & helpers** — Assisted in debugging and stress testing  

---

## 📜 Disclaimer

This project is for **research and educational purposes only**.  
You are fully responsible for how you use this code.

---

## 📜 License
Moonlight is licensed under the **Moonlight Attribution License**.  
See the full text here: [license.txt](license.txt)

