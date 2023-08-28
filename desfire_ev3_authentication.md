# Authentication methods available with his library

The DesfireEv3.java class library is supporting two authentication methods:

The first method is named "**authenticateLegacy**" that is available on DESFire EV1 and onwards tags. This version is using
AES-based keys and it's only purpose is to release a read or write access on files with communication mode Plain.

For files with communication modes MACed or Full enciphered the modern **authenticateEv2First** method is in use, available
on DESFire EV2 and onwards tags. This authentication releases the read and write operations for "MACed" files and releases and encrypt
the data on read and write operations. As some commands use an encrypted data transfer this method is used.

The library chooses the authentication method automatically depending on the communication mode of the file to operate on.

## Does the  library support "Leakage Resilient Primitive" (LRP) authentication ?

I'm sorry but the  answer is NO - **the library is not supporting "Leakage Resilient Primitive" (LRP) authentication**.

[back to the main manual](manual_talk_to_your_desfire_ev3_card.md)
