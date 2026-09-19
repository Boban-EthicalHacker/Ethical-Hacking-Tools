# MoravaSploit

MoravaSploit is an open-source tool for testing the security of systems and networks. It is designed as a small, readable, and extensible framework that organizes modules by target operating system, category, and purpose.

The project is in an early stage of development. It currently contains only the basic structure and the foundations on which modules will be built.

## Purpose

MoravaSploit is intended exclusively for authorized security testing. This means testing systems and networks for which you have prior, explicit, and written permission from the owner.

The tool is intended for:

- security researchers working in controlled environments;
- administrators auditing their own infrastructure;
- students and trainees in the field of security;
- developers building and testing their own systems.

The tool is not intended for unauthorized access, disruption of systems, collection of data without permission, or any other activity that violates the law.

Each user bears sole responsibility for the legality of their use of this tool. The author accepts no responsibility for damage caused by misuse.

## Development Principles

MoravaSploit is built on several core principles:

- **Clarity.** Every module is clear, short, and understandable without deep knowledge of the entire system.
- **Organization by target.** Modules are organized by the target operating system, then by category and purpose.
- **No hidden actions.** Every action the tool performs is visible to the user and recorded in the activity log.
- **Restriction to authorized scope.** The tool does not permit operation outside a predefined target scope.
- **Openness.** The source code is available, documented, and extensible.

## Supported Target Systems

Modules are organized into five main groups:

- Linux
- macOS
- Windows
- Android
- iOS

Within each group there are four categories:

- **recon** — information gathering and service detection
- **exploits** — verified and documented vulnerability tests
- **post** — actions after gaining access, within the permitted scope
- **payloads** — benign test content for verification

## Project Status

The project is in the foundation phase. Currently present:

- basic directory structure
- license
- this document

Planned for upcoming phases:

- command-line interface and interactive console
- module loading system
- authorization check and scope definition
- activity log
- first modules in the recon category
- tests and laboratory environment

## Installation

The project requires Python 3.11 or newer.

Installation instructions will be added when the first working version is released.

## Usage

Usage instructions will be added together with the first working version.

## Project Structure

moravasploit/
├── README.md
├── LICENSE
├── .gitignore
├── pyproject.toml
└── src/
    └── moravasploit/
        ├── __init__.py
        ├── __main__.py
        ├── cli.py
        ├── console.py
        ├── core/
        │   ├── __init__.py
        │   ├── module.py
        │   ├── loader.py
        │   ├── menu.py
        │   ├── scope.py
        │   ├── session.py
        │   └── logger.py
        ├── targets/
        │   ├── linux/
        │   │   ├── recon/
        │   │   ├── exploits/
        │   │   ├── post/
        │   │   └── payloads/
        │   ├── macos/
        │   │   ├── recon/
        │   │   ├── exploits/
        │   │   ├── post/
        │   │   └── payloads/
        │   ├── windows/
        │   │   ├── recon/
        │   │   ├── exploits/
        │   │   ├── post/
        │   │   └── payloads/
        │   ├── android/
        │   │   ├── recon/
        │   │   ├── exploits/
        │   │   ├── post/
        │   │   └── payloads/
        │   └── ios/
        │       ├── recon/
        │       ├── exploits/
        │       ├── post/
        │       └── payloads/
        ├── native/
        ├── utils/
        └── data/

tests/
docs/
labs/


## Contributing

Contributions are welcome. Before submitting changes, please verify that the change follows the principles described in this document, follows the existing code style, includes tests for new functionality, and clearly states in the change description what was changed and why.

Suggestions for new modules should include a clear description of purpose, target system, category, and the conditions under which the module is used.

## Security

If you find a vulnerability in the tool itself, please report it responsibly, without public disclosure before the issue is resolved. Do not open a public issue for security problems. Contact the author directly using the email address provided below.

## License

MoravaSploit is released under the PolyForm Noncommercial License 1.0.0.

This means the tool is free for noncommercial use, research, education, and personal projects. Commercial use requires a separate license from the author. The source code must remain available under the same license. The author provides no warranties and is not liable for damage caused by use of the tool.

The full license text is in the LICENSE file.

For commercial licensing or other questions regarding use, contact the author.

## Author

Boban

- GitHub: https://github.com/Boban-EthicalHacker
- Email: boban.webdevelopment92@gmail.com

## Note

MoravaSploit is a project under development. Features and structure may change without prior notice. Follow the changes before using it in any environment.