urhash - fast hash of okayish quality
=====================================

The urhash function is implemented with following goals in mind:
- be one of the fastest hashes for small machines running OpenWRT
- pass [SMHasher](https://github.com/rurban/smhasher) test suite
- "security" is not a goal, collisions on untrusted inputs are okay
- being platform-dependent and having alignment requirements is okay, assembly is not
- focused on DNS-like strings being the inputs: less than 256 bytes, no streaming support

### Build modifiers

The following macros can be set at compilation time to modify `urhash.h`'s behavior.
All of them are disabled by default.

- `URHASH_H_AS_HDR`: implementation is not directly included by `urhash.h`
  and is built as a separate object file. That basically disables marking the
  function as a `static inline` and hides the implementation.
- `URHASH_H_AS_OBJ`: provides the implementation for `URHASH_H_AS_HDR` mode.
- `URHASH_NO_TRICKERY`: disables the trickery that overrides C compiler
  settings in favor of performance.

### License

The library file `urhash.h` is MIT licensed.
