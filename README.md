# file-integrity-checker
Monitor specific files and directories for unauthorized changes using hashing. Checks the integrity of files by comparing baseline hashes with current hashes.

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
I chose to do this topic after my simple-file-scanner project because I wanted to learn and touch more on the blue-side of cybersecurity. I want to have more hands-on experience with hashing as I have never really used it before even though I did learned about it in University. So, this topic seems to be quite interesting to me. It is also quite doable with my current state of experience in C, not too easy that I don't learn anything, but also not too difficult that I would find it too overwhelming to handle.
In this project, I managed to practice what I learned in my previous project such as file I/O and memory management as well as learned new things like how to generate hash using the OpenSSL library, secure programming practices, and working with binary data and converting it into readable formats.