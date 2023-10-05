# sorbet
Simple One-Trick-Pony Encryption Tool

**SOTPET - Simple One-Trick Pony Encryption Tool**

My wishlist for the tool was:
* multithreading,
* piping through,
* being fast, and
* error-tolerant.

For a simple operation like
> tar -cf - / |lbzip2 |sorbet -e passwordfile >/dev/tape

