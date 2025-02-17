# Atomic-Disk-Drive

## Overview

Atomic Disk Drive is a distributed block storage system that implements an atomic register interface. It provides fault-tolerance through distribution across multiple processes, which can run on separate machines, while presenting a consistent interface to clients.

## Architecture

The system consists of two main components:
1. A Linux block device driver (provided)
2. A user-space distributed register implementation (to be implemented)

The user-space component is a distributed system where multiple processes communicate over TCP to maintain consistent sector data. The system can tolerate failures of individual processes as long as a majority of the processes remain operational.

## Key Features

- **Atomic Consistency**: Ensures that reads return the most recently written value
- **Fault Tolerance**: Continues operation despite individual process crashes
- **Concurrent Operations**: Supports parallel operations on different sectors
- **Persistence**: Stores data reliably across process restarts
- **Security**: Uses HMAC for authentication of messages

## Implementation Details

The implementation is based on the (N,N)-AtomicRegister algorithm, which:
- Ensures linearizability of operations
- Allows any process to initiate read/write operations
- Provides progress as long as a majority of processes are operational
- Handles process crashes and recovery

### Main Components to Implement:

1. **AtomicRegister**: Core logic implementing the register algorithm
2. **SectorsManager**: Manages persistent sector storage
3. **RegisterClient**: Handles TCP communication between processes
4. **Serialization/Deserialization**: Processes the TCP message formats

## Building and Testing

The project is implemented as a Rust library crate. The main entry point is `run_register_process()`, which starts a new process of the distributed register.

## Performance Requirements

- A minimum of 50 sectors processed per second when running with 4 system processes and 3 threads per process
- Efficient use of storage (maximum 10% overhead)
- Efficient memory usage (proportional to actively used sectors)

## Technical Constraints

- Maximum number of open file descriptors: 1024
- Sector size: 4096 bytes
- Limited to specific dependencies in Cargo.toml
- Asynchronous architecture using Tokio

## Usage

The distributed register processes communicate with clients (like the Linux block device driver) via TCP, supporting READ and WRITE operations on sectors. Internally, the processes use a TCP-based protocol to execute the atomic register algorithm.
