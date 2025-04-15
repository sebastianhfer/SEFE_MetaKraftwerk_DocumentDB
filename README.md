# MetaKraftwerkMongoDB

MetaKraftwerkMongoDB is a Java-based utility designed for secure interaction with MongoDB databases. It incorporates TLS/SSL configuration for secure connections and employs AES encryption with PBKDF2 key derivation to enhance data security.

## Table of Contents

1. [Overview](#overview)
2. [Requirements](#requirements)
3. [What It Does](#what-it-does)
4. [Installation](#installation)
5. [Troubleshooting](#troubleshooting)
6. [References](#references)

## Overview

MetaKraftwerkMongoDB facilitates secure connectivity and data operations with MongoDB instances. The application:

- Establishes secure, TLS-enabled connections to MongoDB, optionally leveraging a PEM-based CA certificate.
- Executes queries against specified collections, retrieves results, and formats them for console output.
- Provides integrated methods for encrypting and decrypting data using advanced cryptographic algorithms.

This design is particularly well-suited for scenarios where data security and encrypted communications are vital.

## Requirements

- **Java Development Kit (JDK) / Java Runtime Environment (JRE)**: Version 8 or later.
- **MongoDB Server**: A running MongoDB instance accessible over the network.
- **TLS/SSL CA Certificate**: A PEM file (e.g., `global-bundle.pem`) is required for establishing a secure TLS connection.
- **External Libraries**:
  - **MongoDB Java Driver**: For database connectivity.
  - **Apache Log4j**: For logging application events and errors.
  - **Java Cryptography Extensions (JCE)**: Used for AES encryption/decryption and key derivation.

## Functionality

1. **Secure Database Connection**
   - Configures a secure (TLS/SSL) connection to a MongoDB instance.
   - Optionally utilizes a PEM file to create an SSL context for enhanced security.

2. **Query Execution and Result Handling**
   - Processes custom queries on MongoDB collections.
   - Retrieves and formats query results for console display.
   - Provides a default query execution using a table definition provided at instantiation.

3. **Data Encryption and Decryption**
   - Implements AES encryption with PBKDF2-derived keys.
   - Offers static methods to encrypt and decrypt strings to safeguard sensitive data.

4. **Logging and Diagnostic Output**
   - Uses Apache Log4j to log detailed events, errors, and diagnostic information.
   - Facilitates the debugging process through verbose logging options.

## Installation

1. **Clone the Repository**
   ```bash
   git clone [repository-url]
   cd [repository-directory]
   ```

2. **Resolve Dependencies**  
   Ensure that the following libraries are available in your project's classpath:
   - MongoDB Java Driver
   - Apache Log4j
   - Java Cryptography Extensions (if not already included in your JDK)

   *Note: This project can be integrated with build tools such as Maven or Gradle for dependency management.*

3. **Compile the Code**  
   - **Using Maven**:
     ```bash
     mvn compile
     ```
   - **Manual Compilation**:
     ```bash
     javac -cp "path/to/dependencies/*" de/metakraftwerk/MetaKraftwerkMongoDB.java
     ```

4. **Run the Application**  
   ```bash
   java -cp "path/to/dependencies:." de.metakraftwerk.MetaKraftwerkMongoDB
   ```
   
5. **Certificate Configuration**  
   - Place the `global-bundle.pem` file in the current working directory, or modify the file path in the code as required.

## Troubleshooting

- **Connection Issues**:
  - Verify that the MongoDB server is running and accessible.
  - Check that the network configuration and firewall settings allow traffic on the specified port.
  - Ensure the hostname, port, username, and password are correctly specified.
  - Confirm that the TLS/SSL CA certificate file (`global-bundle.pem`) is present and correctly referenced.

- **Encryption/Decryption Errors**:
  - Ensure that input strings for encryption/decryption are non-null and properly formatted.
  - Consult the Log4j output for detailed error messages and stack traces.

- **Logging and Debugging**:
  - Adjust the Log4j configuration to increase verbosity if additional diagnostic information is required.
  - Review the application logs to pinpoint issues during connection setup, query execution, or cryptographic operations.

## References

- **MongoDB Java Driver Documentation**: [MongoDB Driver](https://mongodb.github.io/mongo-java-driver/)
- **Java Cryptography Architecture (JCA)**: [Java Cryptography](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)
- **Apache Log4j**: [Log4j](https://logging.apache.org/log4j/1.2/)