# Lantenna

Lantenna is a Tauri-based Mac OS X program that scans the local LAN and displays discovered hosts, host names, and open ports.

**Latest release:** v<!-- version -->1.0.1<!-- /version --> · [Download](https://github.com/L-K-M/Lantenna/releases/latest)

![Screenshot of Lantenna showing a list of discovered hosts with their IP addresses, host names, and open ports](./media-sources/screenshot.png)

> [!IMPORTANT]
> LLM Disclosure: This project was developed with the assistance of large language models (AI coding tools).

## Installation

```bash
# Clone the repository
git clone https://github.com/L-K-M/Lantenna.git
cd Lantenna

# Install dependencies
npm install

# Run in development mode
npm run tauri dev

# Build for production
npm run tauri build
```

The built program will be in `src-tauri/target/release/bundle/dmg/`