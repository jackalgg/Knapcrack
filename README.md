# Knapcrack

Knapcrack is a parallel hash-cracking tool designed for high-performance brute-force password cracking. It leverages OpenMP and MPI for optimized performance and is intended for educational and ethical use only. Users must respect legal and ethical guidelines when utilizing this tool.

## Repository Structure

```plaintext
Knapcrack/
├── LICENSE                     # Apache 2.0 License
├── KnapCrack presentation.pptx           # PowerPoint presentation
├── Research report.pdf         # Official research report
├── README.md                   # Project README file
├── Knapcrack(Solution)/        # Contains the primary Knapcrack program
│   └── knapcrack.c
├── Testing Programs/           # Contains testing and minimal optimization programs
│   ├── crack.c                 # Serial version
│   └── knapcrack0.c            # Minimal optimization version
```

## Prerequisites

1. Download the `rockyou.txt` password list from [Kaggle](https://www.kaggle.com/datasets/wjburns/common-password-list-rockyoutxt).
2. Create a `hashes.txt` file in the root directory of the repository.
   - Populate `hashes.txt` with MD5 hashes of the passwords you wish to test against.
   - Example MD5 hash generation:
     ```bash
     echo -n "password" | md5sum
     ```

## Compilation Instructions

Ensure you have the necessary compilers and libraries installed, including `mpicc` and `libcrypto`. Use the following commands to compile the programs:

### Knapcrack Compilation
```bash
mpicc -fopenmp -o knapcrack knapcrack.c -lcrypto
```

### Knapcrack0 Compilation (Minimal Optimization Version)
```bash
mpicc -o knapcrack0 knapcrack0.c -lcrypto
```

### Crack.c Compilation (Serial Version)
```bash
gcc -o crack crack.c -lcrypto
```

## Usage Instructions

1. Ensure `rockyou.txt` and `hashes.txt` are in the same directory as the program binaries.
2. Execute the desired program with appropriate input files.

### Example
```bash
mpirun -np 4 ./knapcrack
```

Replace `-np 4` with the desired number of processes for Knapcrack.

## Ethical Usage

This tool is intended solely for educational purposes and ethical security testing in environments where you have explicit permission. Misuse of this tool may violate laws and ethical standards.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](./LICENSE) file for details.

## Contributing

We welcome contributions to improve Knapcrack! Please submit pull requests or issues for review.

## Disclaimer

The developers of Knapcrack are not responsible for any misuse of this tool. Always obtain proper authorization before conducting security tests.
