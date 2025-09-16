# Project Overview

This project is a TEE (Trusted Execution Environment) application developed under the secGear framework. It serves as a demonstration of the "switchless" technology, which is designed to optimize the performance of interactions between a Rich Execution Environment (REE) and a TEE. It works by reducing the number of context switches and data copies between the REE and TEE through the use of shared memory.

The project is written in C and uses CMake for building. It supports both Intel SGX and ARM TrustZone as TEE platforms.

The application consists of two main parts:
- A **host** application that runs in the REE.
- An **enclave** that runs in the TEE.

The host application creates an enclave, allocates a shared memory buffer, and then calls a function within the enclave using both a traditional ECALL and a switchless call. The enclave function simply copies a string into the provided buffer. This demonstrates the performance benefits of the switchless approach.

# Building and Running

To build the project, you will need to have the appropriate SDK for your target TEE platform (Intel SGX or ARM TrustZone) installed. The build process is managed by CMake.

**Build Steps:**

1.  Create a build directory:
    ```bash
    mkdir build
    cd build
    ```

2.  Run CMake to configure the project. You will need to specify the TEE platform you are targeting.

    For Intel SGX:
    ```bash
    cmake .. -DENCLAVE=SGX
    ```

    For ARM TrustZone:
    ```bash
    cmake .. -DENCLAVE=GP
    ```

3.  Build the project:
    ```bash
    make
    ```

**Running the Application:**

After a successful build, the executable will be located in the `build/bin` directory. To run the application, simply execute the `smx_test` binary:

```bash
./bin/smx_test
```

# Development Conventions

- The project follows the C99 standard.
- The interface between the host and the enclave is defined in the `switchless.edl` file.
- The host application code is located in the `host` directory.
- The enclave code is located in the `enclave` directory.
- The `CMakeLists.txt` files in each directory manage the build process for that component.
- The `codegen` tool is used to generate the necessary interface code from the EDL file.
- For switchless calls, the `transition_using_threads` keyword must be used in the EDL file.
- Shared memory is allocated on the host side using `cc_malloc_shared_memory` and freed using `cc_free_shared_memory`.
