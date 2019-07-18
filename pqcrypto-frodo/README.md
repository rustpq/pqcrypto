# frodo

This crate contains bindings to the C implementations of the following schemes, from [PQClean][pqc].

 * ``frodokem640shake`` - ``opt``
 * ``frodokem640aes`` - ``opt``
 * ``frodokem976aes`` - ``opt``
 * ``frodokem976shake`` - ``opt``
 * ``frodokem1344aes`` - ``opt``
 * ``frodokem1344shake`` - ``opt``

# Notes
If you use it via the FFI interface: The clean implementation of Frodo
needs a lot of stack space, specify env variable `RUST_MIN_STACK` to make
sure it has enough stack space in threads.

This is not relevant for the 'normal' api methods.


[pqc]: https://github.com/PQClean/PQClean/