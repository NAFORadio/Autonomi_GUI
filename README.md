# Autonomi Network GUI
***
UPDATE
Vault support is "questionable" as I didn't totally understand what was going on with them when I made the GUI. 

I'm working on a better implementation of the vaults.

Also, I'm trying to buffer files in memory on download from Autonomi so I can do something like, stream music or movies. This way, the files never hit the disk. 
I don't know if this technically possible but since I don't know how to program, I don't really care. It is Cursors problem to solve and mine to endure. 

***
## Support Development

ETH: 0x4AcD49Aca41E31aa54f43e3109e7b0dB47369B65

## Requirements

### 1. Autonomi CLI
The `ant` CLI tool must be installed and in your system PATH. Follow the installation guide at [Autonomi CLI Documentation](https://github.com/maidsafe/autonomi/blob/main/ant-cli/README.md#installation)

### 2. Python Requirements
- Python 3.x
- Tkinter (GUI framework)
- PIL/Pillow (Image handling)
- PIL.ImageTk (Image display in GUI)

### 3. System Packages

#### Debian/Ubuntu:

sudo apt-get install python3-tk python3-pil python3-pil.imagetk

### 4. File Storage Locations

The application stores its data in the following locations:
- History and uploads data: `~/.local/share/autonomi/client/gui/`
  - Operations history: `operations_history.txt`
  - File uploads tracking: `file_uploads.json`
- Register signing key: `~/.local/share/autonomi/client/register_signing_key`

A graphical user interface wrapper for the Autonomi Network CLI tool, making the decentralized internet more accessible to everyone.

## Overview

This project demonstrates how Autonomi Network's powerful CLI functionality can be wrapped in a user-friendly GUI. Autonomi Network is building "an Internet controlled by no-one, owned by us all" - secure, encrypted, and autonomous infrastructure for the next web.

## Project Goals

Aligned with Autonomi Network's vision:
- Support the creation of a decentralized internet infrastructure
- Enable users to participate in the quantum-secure, private network
- Make network operations accessible to non-technical users
- Help utilize the untapped storage capacity of everyday devices
- Facilitate the growth of a truly decentralized web

## Features

### Register Operations
- Create and manage human-readable names on the network
- Associate names with values
- View all registered names
- Secure operations with signing keys

### Key Management
- Generate quantum-secure signing keys
- Option to overwrite existing keys
- Automatic key detection and management

### Vault Operations
- Create and manage network vaults
- Participate in the decentralized storage network
- Configure vault settings (delay, local mode)
- Monitor vault status and health
- Contribute to the network's storage capacity (currently at 61.94 PiB)

### Wallet Operations
- Create new wallets
- Import existing MetaMask wallets
- Check wallet balance
- Secure password handling
- Manage ANT tokens for network operations

### File Operations
- Upload files with quantum-secure encryption
- Public or private file sharing options
- Download files using addresses
- Calculate one-time storage costs
- Track and manage stored files
- Zero-knowledge, no-tracking file storage

### History Tracking
- Log all operations with timestamps
- Track uploaded files and their addresses
- Maintain comprehensive operation history
- Monitor network interactions

## Technical Details

The network employs:
- Multilayered encryption
- Self-encrypting data systems
- Zero-knowledge architecture
- Non-blockchain DLT technology
- Stigmergy-based consensus mechanism

## Requirements

- Python 3.x
- Tkinter
- Pillow (PIL)
- Autonomi Network CLI tool installed

## Purpose

This GUI wrapper aims to make Autonomi Network's revolutionary technology accessible to everyone, supporting the vision of a decentralized internet owned by its users. It demonstrates how complex decentralized operations can be simplified for everyday use.

## Note

This is a community contribution to the Autonomi Network ecosystem. For production use, please refer to the official documentation and tools.

## License

MIT License

## Credits

Created by NAFO Radio

## Learn More

For more information about Autonomi Network:
- [Official Website](https://autonomi.com/)
- [Documentation](https://autonomi.com/docs)
- [White Paper](https://autonomi.com/whitepaper)
- [Project Repository](https://github.com/NAFORadio/Autonomi_GUI) 
