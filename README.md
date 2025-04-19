# file-integrity-checker
Monitor specific files and directories for unauthorized changes using hashing.

1. Add the paths for files and directories that you want to monitor into `monitor.txt`.

2. Use `--init` or `-i` option to generate the baseline hashes for the files/directories specified in `monitor.txt`. Hashes calculated is written to `hashes.txt` file.

3. Then use `--check` or `-c` option to check for file integrity.

Logs are automatically generated for debugging.

---
Compilation on Linux (Debian-based distros):

    # install openssl
    $ sudo apt install libssl-dev
    $ gcc -o checker checker.c -lssl -lcrypto

Run it with the command:

    $ ./checker <option>

Options:
- `-h`, `--help`    Prints help information.
- `-i`, `--init`    Establish bashline hashes from files specified in `monitor.txt`.
- `-c`, `--check`   Check bashline hashes against current hashes.

---
### Reflections
