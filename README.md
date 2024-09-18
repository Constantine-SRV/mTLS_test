
# Project Overview: mTLS Authentication Demonstration

This project demonstrates the capabilities of **mTLS (mutual TLS) authentication**.  
It implements two-way certificate validation (both client and server), providing a high level of security and data protection.

## Main Features:
- Detailed logging of all steps in the certificate verification process (both client and server) helps to easily identify errors and analyze the authentication process.
- **mTLS** eliminates the need for traditional username and password authentication, which is especially useful for devices and users not part of a domain.
- This project supports hosting resources with built-in authentication on non-domain servers, whether Windows or Linux, enhancing infrastructure flexibility and scalability.
- **Client certificate validation through a configurable Custom Trust Store** allows for precise security policy management by restricting access to only trusted certificates.

## Key Benefits of mTLS:
- Increased security through mandatory certificate validation on both sides (client and server).
- No need for passwords, reducing risks associated with credential compromise.
- The ability to deploy on servers without domain membership, making it ideal for flexible deployment in cloud and hybrid infrastructures.
