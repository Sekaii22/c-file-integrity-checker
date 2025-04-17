# c-file-integrity-checker

    sudo apt install libssl-dev
    gcc -fsanitize=address -o checker checker.c -lssl -lcrypto
