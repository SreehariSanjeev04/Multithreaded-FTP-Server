# 🚀 Simple C++ Concurrent FTP Server Framework

## 1️⃣ Project Overview

This is a foundational framework for a basic, concurrent **File Transfer Protocol (FTP) server** written in C++.  
It demonstrates essential modern programming techniques, including **multithreading (`std::thread`)** for concurrency and **secure password hashing (BCrypt)**.

The architecture uses a **one-thread-per-client** model and features clean separation of logic into dedicated classes for authentication, file system handling, and event processing.

---

## 2️⃣ Key Features

- **Concurrency**: Uses a one-thread-per-client model for simultaneous client handling.  
- **Security**: Employs BCrypt for secure, salted password hashing (storage, not transport).  
- **Isolation**: The `FTPShell` restricts users to their own dedicated home directories (e.g., `username_home`).  
- **Core Commands Implemented**:
  - `USER`, `PASS`, `QUIT` (Connection/Auth)  
  - `PWD`, `CWD`, `CDUP`, `MKD` (Filesystem)  
  - `LIST` (Simple text-based listing)  

---

## 3️⃣ Prerequisites & Build

### 3.1 Dependencies
- C++17 compliant compiler (GCC/Clang 8.0+)  
- C++ BCrypt library  
- Threading support  

### 3.2 Build Instructions
Use the following command (adjust linker flags as necessary):

## Credits
https://github.com/trusch/libbcrypt
