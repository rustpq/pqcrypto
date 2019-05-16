# frodo

This crate contains bindings to the C implementations of the following schemes, from [PQClean][pqc].

 * ``frodokem640shake`` - ``clean``
 * ``frodokem640aes`` - ``clean``
 * ``frodokem976aes`` - ``clean``
 * ``frodokem976shake`` - ``clean``
 * ``frodokem1344aes`` - ``clean``
 * ``frodokem1344shake`` - ``clean``

# Notes
Frodo needs a lot of stack space, specify env variable `RUST_MIN_STACK` to make sure it has
enough stack space in threads.


[pqc]: https://github.com/PQClean/PQClean/