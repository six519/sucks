# Sucks

A minimal SOCKS5 proxy over SSH, written in C. Yes, `ssh -D <PORT>` does exist, but I want to create one anyway!

## Dependencies

- libconfig
- libssh

## How to build

```bash
mkdir build
cd build
cmake ..
make
```

## Note

- Don't forget to edit the `config.cfg` file, and ensure it is in the same directory as the executable file. 
- Password authentication is not supported.