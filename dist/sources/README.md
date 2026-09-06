# Corresponding MariaDB source

`mariadb-connector-j-3.0.9.tar.gz` is the unmodified upstream source archive:

- Origin: [MariaDB Connector/J 3.0.9](https://github.com/mariadb-corporation/mariadb-connector-j/tree/3.0.9).
- Download: `https://codeload.github.com/mariadb-corporation/mariadb-connector-j/tar.gz/refs/tags/3.0.9`.
- SHA-256: `9e47961e1879570f4fc134d0cea7957ac3e83cb2174c68349ee2032068ec1399`.
- License: LGPL-2.1-or-later; original license, copyright notices and build files remain in the archive.

FE notice assembly copies this archive into the installation's `legal/sources/`
and verifies it against `dist/product-provenance.json`. This default input is
intentionally versioned for offline builds. `MASSDB_MARIADB_SOURCE_ARCHIVE` may
point to another local copy with the same hash. Assembly never downloads it.

When upgrading the runtime JAR, obtain and review the matching source, preserve
the upstream license and build materials, update both hashes and the POM version,
and verify FE driver replacement. Do not change only the filename or version.
The archive covers MariaDB; it does not supply BE relinking materials.
