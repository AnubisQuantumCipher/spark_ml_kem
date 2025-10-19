# Spark_ML_KEM

Pure SPARK Ada implementation of ML-KEM-1024 (FIPS 203, Kyber) post-quantum key encapsulation

## Overview

Formally-verifiable implementation of ML-KEM-1024 post-quantum key encapsulation mechanism using module-lattice cryptography, providing IND-CCA2 security against quantum adversaries.

### Standards Compliance

- FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
- NIST PQC Round 3: Kyber

### Key Features

- ML-KEM-1024 parameter set (Category 5 security)
- Post-quantum IND-CCA2 security
- Deterministic encapsulation
- NTT-based polynomial arithmetic
- SHAKE256 XOF for sampling
- Formally verifiable SPARK contracts

## Building

### Prerequisites

- GNAT FSF 13.1+ or GNAT Pro 24.0+
- GPRbuild
- Alire (recommended)
- GNATprove (optional, for formal verification)

### Build with Alire

```bash
alr build
```

### Build with GPRbuild

```bash
gprbuild -P spark_ml_kem.gpr
```

### Formal Verification

```bash
gnatprove -P spark_ml_kem.gpr --level=2 --timeout=60
```

## Testing

```bash
cd tests
gprbuild -P test_spark_ml_kem.gpr
./obj/test_spark_ml_kem
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): Module structure and implementation details
- [SECURITY.md](SECURITY.md): Threat model, security properties, vulnerability reporting
- [API Reference](docs/API.md): Detailed API documentation

## Security

For security vulnerabilities, see [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Authors

AnubisQuantumCipher <sic.tau@pm.me>

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## References

See [docs/REFERENCES.md](docs/REFERENCES.md) for academic papers, RFCs, and technical standards.
