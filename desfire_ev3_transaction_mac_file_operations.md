# DESFire EV3 Transaction MAC file operations

This file type has a special purpose and is not intended to store user data in it. The file is 
optional on a DESFire EV3 tag and can be create one time in each application. It stores
the last MAC's that where used when a transaction is committed (see above notes for Backup, Value 
and Record files) and is readable only. With the data in this file a backend service can verify the 
last successful transaction.

This app can enable the Transaction MAC feature using the two "create" buttons and you you should 
know what the consequences are when using this file. In general - the file is readable like a 
Standard file with a file size of 12 bytes. The data is:

Transaction counter (4 bytes, LSB encoding) || Transaction MAC value (8 bytes)

The Transaction counter stores the counter of the last successful committing to a file on the tag. 
The Transaction MAC value is calculated over all transactions done and where committed and encrypted   
with the **Transaction MAC key** (a 16 bytes long AES-128 key).

## Create a Transaction MAC file without Commit Reader Id

Committing a transaction does not require a Reader ID - this Reader Id is an individual value for 
a NFC reader and used to identify the place of transaction.

## Create a Transaction MAC file with Commit Reader Id

Committing a transaction does require a Reader ID - this Reader Id is an individual value for 
a NFC reader and used to identify the place of transaction.

When the "Commit Read Id" is enabled some file operations will no longer work; this is due to the fact 
that the Reader Id should be provided in a secure way:

- write to a Backup file in Communication.Mode Plain
- crediting or debiting a Value file in Communication.Mode Plain
- write a record to a Linear Record file in Communication.Mode Plain
- write a record to a Cyclic Record file in Communication.Mode Plain

