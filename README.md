# 🦀 Secure Rust Messenger

![Rust](https://img.shields.io/badge/rust-stable-orange?logo=rust)
![License](https://img.shields.io/badge/license-MIT-blue)
![Status](https://img.shields.io/badge/status-MVP-green)

A high-performance, secure messaging application written in **Rust**.
This project focuses on **low-level implementation of cryptographic primitives** and secure communication protocols from scratch, demonstrating a deep understanding of system programming and memory safety.

---

## 🚀 Key Features

* **End-to-End Encryption (E2EE):** Messages are encrypted locally before transmission.
* **Custom Cryptography Stack:** Manual implementation of major cryptographic algorithms (AES, Twofish, RSA, etc.) for educational and research purposes.
* **Memory Safety:** Leverages Rust's ownership model to prevent common vulnerabilities.
* **Modular Architecture:** Cryptographic primitives are isolated in separate modules/crates.

## 🛠️ Implemented Algorithms

Unlike standard wrappers around OpenSSL, this project contains custom implementations of the following algorithms:

### Symmetric Ciphers (Block Ciphers)
* **AES (Rijndael):** 128/192/256-bit key support.
* **Twofish:** Symmetric key block cipher with a block size of 128 bits and key sizes up to 256 bits.
* **LOKI97:** A 128-bit block cipher (AES candidate).

### Asymmetric Cryptography
* **RSA:** Key generation, encryption, and decryption primitives.

### Architecture
* `symmetric_cipher`: Abstract trait/interface for block ciphers to allow easy swapping of algorithms.
* `messenger`: Core logic handling the transport layer and message routing.

## ⚙️ Tech Stack

* **Language:** Rust 🦀
* **Build System:** Cargo
* **Transport:** TCP / WebSocket (укажи, что реально используешь, например TCP streams)
* **Serialization:** Serde (если используешь)

## 📦 Installation & Usage

### Prerequisites
* Rust toolchain (cargo, rustc)

### Build and Run
```bash
# Clone the repository
git clone [https://github.com/idOgItt/messenger-project.git](https://github.com/idOgItt/messenger-project.git)

# Build the project
cargo build --release

# Run the client (example)
cargo run --bin client

⚠️ Disclaimer

This project is created for educational purposes and to demonstrate knowledge of cryptographic algorithms. While it implements standard algorithms, "rolling your own crypto" is generally not recommended for critical production environments without a professional security audit.
🔜 Roadmap

    [x] Core crypto primitives (AES, RSA, Twofish)

    [x] Basic text messaging

    [ ] Diffie-Hellman Key Exchange

    [ ] TUI (Text User Interface) or GUI

    [ ] Voice Calls (VoIP)
