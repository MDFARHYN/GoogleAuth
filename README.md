# Google Authenticator Desktop 🔐

[![Rust](https://img.shields.io/badge/Rust-1.99%2B-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Tauri v2](https://img.shields.io/badge/Tauri-v2-blue.svg?logo=tauri)](https://tauri.app/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Windows%20%7C%20macOS-brightgreen.svg)]()

A sleek, lightweight, privacy-first desktop version of **Google Authenticator** built with **Rust** and **Tauri v2**. Features authentic Android **Google Material Design 3** aesthetics, real-time animated 30-second countdown rings, and **AES-256-GCM + Argon2id** encrypted vault storage.

---

## 💡 Why This App? (Purpose & Overview)

Constantly switching between your computer and your smartphone just to check a 6-digit two-factor authentication (2FA) code is one of the most annoying interruptions when working on a desktop:

* **Eliminate Phone Distraction & Context Switching:** When browsing, working, or developing on your desktop, having to pick up your mobile device every time you log in slows down your workflow. With this app, your 2FA codes are right at your fingertips with 1-click clipboard copying.
* **No More Dead Battery or Missing Phone Hassles:** Often, your phone isn't charged, is plugged in across the room, or is on silent mode. You never have to pause work because your phone is unavailable.
* **Peace of Mind if Your Phone is Lost or Damaged:** Losing or breaking your smartphone can instantly lock you out of all your accounts. Having your 2FA accounts securely set up on your desktop acts as a reliable companion and emergency lifeline.
* **100% Offline & Private:** Zero cloud servers, zero sync, zero telemetry. All authentication secrets and account data are stored **100% offline on your local device**, protected by your **Master Password** using state-of-the-art **AES-256-GCM** authenticated encryption and **Argon2id** password hashing.

---

## ✨ Features

- 📁 **QR Image File Upload**: Browse and upload any `.png`, `.jpg`, `.jpeg`, or `.webp` QR code image.
- 🎯 **Drag & Drop QR Images**: Drag QR images directly from any web browser tab or file explorer into the app window.
- 📋 **Clipboard Paste (`Ctrl + V`)**: Copy or screenshot any QR code (`PrintScreen` / screenshot tool) and press `Ctrl+V` to scan and import instantly.
- ⌨️ **Manual Key Entry**: Add accounts manually with Issuer, Account Name, Secret Key (Base32), and Algorithm (SHA1, SHA256, SHA512).
- 📲 **Google Authenticator Batch Transfer**: Decode and import Google Authenticator export QR codes (`otpauth-migration://offline?data=...`).
- 🎨 **Official Brand Icons**: Includes customized high-resolution brand icons for Google, Microsoft, AWS, Namecheap, GoDaddy, GitHub, GitLab, Binance, Coinbase, Epic Games, Discord, Twitter/X, and more.
- 🔄 **Smart Deduplication**: Automatically detects existing accounts by provider and email/secret key and updates them without creating duplicate clutter.
- 🔒 **Master Password Encryption**: All 2FA secret keys are stored locally on your machine encrypted with **AES-256-GCM** authenticated cipher and **Argon2id** key derivation. Zero cloud servers, zero telemetry.
- ⏱️ **Material 3 Countdown Rings**: 30-second circular SVG countdown timer with smooth animations that pulse warning red in the final 5 seconds.
- 🔍 **Instant Search**: Quickly filter through your accounts by provider name or email.
- 💾 **Encrypted Backup & Restore**: Export and restore your 2FA accounts at any time via encrypted JSON backup.

---

## 🚀 Quick Install (No Build Required)

Pre-compiled, ready-to-install binaries are provided directly in the repository so you can get started right away without needing Rust, Node.js, or any build tools installed:

### 🐧 Linux (Ubuntu, Debian, Linux Mint)
Pre-built `.deb` package is located in the [`linux_deb/`](linux_deb/) folder:
* **Package**: `linux_deb/Google Authenticator_1.0.0_amd64.deb`
* **Install via Terminal**:
  ```bash
  sudo dpkg -i "linux_deb/Google Authenticator_1.0.0_amd64.deb"
  # Fix any missing dependencies if needed:
  sudo apt-get install -f
  ```
* **Install via GUI**: Open your file manager, navigate to `linux_deb/`, and double-click `Google Authenticator_1.0.0_amd64.deb` to install through Software Center / GDebi.

### 🪟 Windows (64-bit)
Pre-built installers are located in the [`windows64EXE/`](windows64EXE/) folder:
* **One-Click Setup (`.exe` - Recommended)**:
  - **Path**: `windows64EXE/nsis/Google Authenticator_1.0.0_x64-setup.exe`
  - Double-click to run the setup installer and install Google Authenticator on your PC.
* **Windows Installer Package (`.msi`)**:
  - **Path**: `windows64EXE/msi/Google Authenticator_1.0.0_x64_en-US.msi`
  - Standard enterprise/Windows installer package.

---

## 📲 Google Account Transfer (Exporting from Phone to Desktop)

### ⚠️ Crucial: Max 10 Accounts at a Time
> **By default, Google Authenticator checks and selects ALL your accounts.**  
> However, **Google Authenticator strictly limits each single QR code to a MAXIMUM of 10 accounts**.  
> If you have more than 10 accounts selected, Google Authenticator splits them across multiple QR codes (requiring you to tap "Next" on your phone screen for each batch).  
> **Recommended Workflow:** Select **up to 10 accounts at a time** when exporting from your phone.

### Step-by-Step Instructions:

1. **Open Google Authenticator on your phone**:
   - Tap the menu icon `☰` (or your profile picture) in the top corner.
   - Tap **"Transfer accounts"** ➔ **"Export accounts"**.
   - Authenticate with your fingerprint, face unlock, or PIN.

2. **Select Up to 10 Accounts**:
   - Google Authenticator automatically checks all accounts by default.
   - Tap the checkmarks to **uncheck** accounts so that you have a **maximum of 10 accounts selected** for the current batch.
   - Tap **"Export"** (or **"Next"**).

3. **Capture the QR Code**:
   - Google Authenticator will display a large QR code on your phone screen.
   - Take a photo of your phone screen using your computer's webcam, phone camera, or transfer a screenshot to your computer.

4. **Import into Google Authenticator Desktop**:
   - In the desktop application, click the **`+`** floating button (or **"Upload QR Image"** on the empty state).
   - Select the image file, drag & drop it into the window, or paste it using **`Ctrl + V`**.
   - A modal will show the accounts found (up to 10 accounts).
   - Click **"Import All"**.

5. **Repeat for Remaining Batches**:
   - Return to your phone, select the next batch of up to 10 accounts, and upload the QR code.
   - The desktop app will automatically **deduplicate** and merge all accounts seamlessly into your single encrypted vault.

---

## 📦 Building from Source (Optional)

### 🐧 1. Building Linux Packages (`.deb` & `.AppImage`)

#### System Prerequisites (Ubuntu / Debian / Linux Mint):
```bash
sudo apt update && sudo apt install -y \
  build-essential \
  curl \
  wget \
  file \
  pkg-config \
  libssl-dev \
  libgtk-3-dev \
  libwebkit2gtk-4.1-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev
```

#### Node.js & Rust Setup:
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Install Node.js (v20+ or v22 LTS)
nvm install 22
nvm use 22
```

#### Build Commands:
From the root of the project:

```bash
# Install NPM dependencies
npm install

# 1. Build Ubuntu/Debian .deb package only
npm run build:deb

# 2. Build standalone .AppImage package only
npm run build:appimage

# 3. Build both .deb and .AppImage packages
npm run build
```

#### Output Locations:
- **`.deb` installer**:  
  `src-tauri/target/release/bundle/deb/google-authenticator_1.0.0_amd64.deb`
- **`.AppImage` standalone binary**:  
  `src-tauri/target/release/bundle/appimage/google-authenticator_1.0.0_amd64.AppImage`

#### Installing the `.deb` package on Ubuntu/Debian:
```bash
sudo dpkg -i src-tauri/target/release/bundle/deb/*.deb
```

---

### 🪟 2. Building Windows Executables (`.exe` NSIS & `.msi`)

#### Prerequisites on Windows:
1. **Rust**: Download and run [rustup-init.exe](https://rustup.rs/).
2. **Node.js**: Install Node.js v20+ or v22 LTS from [nodejs.org](https://nodejs.org/).
3. **C++ Build Tools**: Install [Visual Studio C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (select *"Desktop development with C++"*).
4. **WebView2**: Built into Windows 10/11.

#### Build Command (on Windows):
Open PowerShell or Command Prompt in the project folder:
```powershell
npm install
npm run build
```

#### Output Locations:
- **One-Click `.exe` Installer (NSIS)**:  
  `src-tauri\target\release\bundle\nsis\google-authenticator_1.0.0_x64-setup.exe`
- **Windows `.msi` Installer**:  
  `src-tauri\target\release\bundle\msi\google-authenticator_1.0.0_x64_en-US.msi`

---

### 🤖 3. Automated Cross-Platform Builds (GitHub Actions CI/CD)

To automatically build `.deb`, `.AppImage`, and Windows `.exe` installers on every release tag, create `.github/workflows/release.yml`:

```yaml
name: Release Build
on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    permissions:
      contents: write
    strategy:
      fail-fast: false
      matrix:
        platform: [ubuntu-22.04, windows-latest]
    runs-on: ${{ matrix.platform }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - uses: dtolnay/rust-toolchain@stable

      - name: Install Linux Dependencies
        if: matrix.platform == 'ubuntu-22.04'
        run: |
          sudo apt-get update
          sudo apt-get install -y libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf

      - name: Install NPM dependencies
        run: npm install

      - name: Build Tauri Desktop App
        uses: tauri-apps/tauri-action@v0
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          tagName: ${{ github.ref_name }}
          releaseName: 'Google Authenticator Desktop ${{ github.ref_name }}'
          releaseBody: 'Automated release build for ${{ matrix.platform }}'
```

---

## 💻 Running Locally in Development Mode

```bash
# Install dependencies
npm install

# Run desktop dev server with live hot-reloading
npm run dev
```

---

## 🛡️ Security Model

- **No Remote Servers**: Your 2FA secrets never leave your device.
- **Key Derivation**: Master Password is hashed using **Argon2id** with a unique 16-byte random salt per vault.
- **Authenticated Encryption**: Secrets are encrypted on disk using **AES-256-GCM** with a cryptographically secure 12-byte random nonce per save operation.
- **Memory Security**: Vault tokens are decrypted into memory only while the vault is actively unlocked and flushed upon locking.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
