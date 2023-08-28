# DESFire EV file operations

On a Mifare DESFire EV3 tags six file types are available, each with a specific characteristic. Im describing all 
of them in a short overview to understand what file is usage for which task:

**Standard file**: The most easy file type to work with. It has a fixed file size and can be written or read in a 
simple manner. It should be primarily used for static data that is written once and on later life cycle only read 
(the reason for this described later at point „data security“). Regarding deletion: see my note on deletion.

**Backup file**: this file type works as similar to Standard files and writing of data is accepted immediately, but 
valid only after a following „commit command“ (see my note on commit). You should use a Backup file for all data 
that is read and written on life cycle. Regarding deletion: see my note on deletion

**Value file**: A file type where you cannot write data but only change of values. Think of a prepaid canteen application: 
you buy this card with a predefined value, that can get debited on usage (buy a lemonade). When the credit is 0 
(the card is „empty“) you credit the card by paying some money at the cashier and the card is „reloaded“. Use this file 
type for use cases where you need to debit or credit values. A „commit command“ is necessary to finalize the change.

**Linear Record file**: This file type is like an array of Backup files. At creation you define how many records are accepted 
in this file and you can write new records up to that limit. When the Linear Record file is „full“ (meaning is has as many 
records as the maximum number) no more records can be written to the file. You can use this file type if you know in advance 
how many records should be written to the card (think of a „Bonus card“ - with each level you just want to store the date or 
timestamp when this level was reached, and when you have 5 level you need a maximum of 5 records). Regarding deletion: see my 
note on deletion.

**Cyclic Record file**: they are very similar to Linear Record files but are used in a cycling manner. You are defining a 
maximum number of records as well (e.g. 5 records) and when you store the records 1, 2, 3 and 4 it works analogue to the Linear 
Record file. But when writing the 5th record the first written record („nr 1“) will get deleted, the record number 2 is now 
record 1 and so on. The last written record is now on position 4. So in the end the storage capacity needs to be („maximum 
number of readable records“ + 1). The reason for this behavior is simple - the file needs some spare bytes to cache the fifth 
record until the deletion of the first took place. Regarding deletion: see my note on deletion.

A note on „**data security**“: Contactless cards as the DESFire are powered by the electric field that is emitted by the card reader. 
As the user can move the card out of distance at any time it could happen that on writing a huge amount of data to the Standard 
file to the card the connection is disturbed. The consequence can be dramatic - some data are written and some not. This will 
end in a corrupted data file but this is visible earliest on next (read) usage.

A better way to deal with this scenario is to work with file types that support a subsequent „commit command“. When the writing 
process to a Backup file is interrupted and nothing happens to data written so far, they get thrown away. If the write process 
is complete the data is stored in some spare/virtual storage and the „commit command“ is just shifting these data to the real 
storage - this is done in an atomic period of time and cannot get interrupted.

A second note regarding **deletion of data**: You can delete Standard, Backup and Value files and clear Linear and Cyclic Record 
files (meaning the deletion of all records), but the the storage space does not get released. If having a Standard file of 500 
bytes size the remaining space on an 2048er 2K card is about 1500 bytes. If you „delete“ the file the content is no longer available 
for reading, but when you recreate the file the remaining storage will be 1000 bytes. The only way to release the storage space is 
to format the card, but that will delete all data on the card. 

There is one additional file type available and that is a **Transaction MAC file**. This file type has a special purpose and is not 
intended to store user data in it. The file is optional on a DESFire EV3 tag and can be create one time in each application. It stores 
the last MAC's that where used when a transaction is committed (see above notes for Backup, Value and Record files) and is readable 
only. With the data in this file a backend service can verify the last successful transaction.

See the desfire_ev3_transaction_mac_file_operations for more information.

## Which file related commands are available with the library ?

The following commands are available with this library:

- select a file
- create a Standard, Backup, Value, Linear Record and Cyclic Record file with communication modes Plain, MACed and Full enciphered 
- create a Transaction MAC file (communication modes Plain only)
- write to and read from a Standard, Backup, Linear Record and Cyclic Record file
- read from and credit or debit a Value file
- delete a file
- get the file settings

## What are the typical workflows for different file types ?

All workflows start after tapping a tag to the NFC reader and "selecting app" for "A1A2A3" (you should have run the "Setup test environment 
before).

### Standard file

- select file (red button)
- choose file number 0 (Plain), 1 (MACed) or 2 (Full enciphered)
- authenticate with key 1 "App R & W" default (* 1) (green button)
- press "write" (orange button)
- press "read" (orange button)
- an example operation output can be: 
```plaintext
read from a data file fileNumber: 2 data length: 256 data: 323032332e30382e32372031303a33323a3533000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebec
read from a data file fileNumber: 2 data: 2023.08.27 10:32:53??!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~�������������������������������������������������������������������������������������������������������������
```

### Backup file











