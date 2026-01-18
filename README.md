![Facet-RS](/assets/facet-rs.logo.svg)

**Facet-RS** is a Rust library that provides feature building blocks for use with
the [Eclipse Rust Data Plane SDK](https://github.com/eclipse-dataplane-core/dataplane-sdk-rust).

## Overview

Facet-RS includes the following components:

### Distributed Locking

Coordinate exclusive access to shared resources across multiple services or instances using a pluggable lock manager.
Features include:

- Reentrant locking
- Automatic expiration of stale locks to prevent deadlocks
- Multiple implementations (in-memory for testing, PostgreSQL for production)

### Token Management

Manage OAuth/JWT token lifecycles with automatic refresh and concurrency control:

- Automatic refresh of expiring tokens
- Distributed coordination to prevent concurrent refresh attempts
- Pluggable token storage and client implementations
- Built-in support for in-memory and persistent storage backends

### S3 Proxy

A proxy for accessing S3-compatible object storage services that supports token-based authentication and access control
with refresh capabilities. Features include:

- Transparent handling of S3 API requests
- Support for multiple S3-compatible storage providers
- Pluggable token verification and access control

## Build Requirements

Note `cmake` is required to build the S3 proxy.