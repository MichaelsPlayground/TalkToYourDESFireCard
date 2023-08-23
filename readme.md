# Talk to your Mifare DESFire EV1/EV2/EV3 card

This is a sample app to demonstrate how to work with a Mifare DESFire EV1/EV2/EV3 card. 

For simplicity this app uses a DESFire tag with **factory settings** means:

- it uses **Plain communication** only (no MACed or Enciphered Communication)
- it shows how to work with **Standard Files** only (no Backup, Value, Linear Record, Cyclic Record or TransactionMAC Files)
- there are 2 **Access modes** hardcoded: **Free Access** (use without any key) and **Key Secured Access** with 5 predefined keys
  (0 = Application Master Key, 1 = Read & Write access key, 2 = Change Access Rights key, 3 = Read access key and 4 = Write access key)
- it works with a predefined **Application Identifier** (AID) of "D1D2D3"
- the  Standard files have a hardcoded size of 32 bytes
- the app is working with **DES keys** only and the **Master Application KEY** and it's **Key Settings** remain unchanged to prevent from any damage to the card

As the **Authentication** with a key is essentially for a successful transaction there is a huge amount of code lines taken from another 
project. I copied all necessary code from the **NFCJLIB project** available here: https://github.com/andrade/nfcjlib which is provided 
by **Daniel Andrade**, thanks a lot for his contribution. Please obey the LICENCE here: https://github.com/andrade/nfcjlib/blob/master/LICENSE.

The only 'official' information's on DESFire EVx cards can be found here (yes, you understand it right - 'official' and useful 
documentation is available only on another card type, the DESFire Light tag): 

Data sheet – MIFARE DESFire Light: https://www.nxp.com/docs/en/data-sheet/MF2DL_H_x0.pdf

Application note – AN12343 MIFARE DESFire Light Features and Hints: https://www.nxp.com/docs/en/application-note/AN12343.pdf

Leakage Resilient Primitive (LRP) Specification: https://www.nxp.com/docs/en/application-note/AN12304.pdf (test vectors)

Symmetric key diversification's: https://www.nxp.com/docs/en/application-note/AN10922.pdf

System level security measures for MIFARE installations: https://www.nxp.com/docs/en/application-note/AN10969.pdf

For differences between Mifare DESFire EVx versions see: MIFARE DESFire EV3 contactless multi-application IC MF3DHx3_SDS.pdf (page 5)

DESFire protocol (overview about DESFire EV1 commands): https://github.com/revk/DESFireAES/blob/master/DESFire.pdf

NTAG 424 DNA NT4H2421Gx.pdf: https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf

NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf: https://www.nxp.com/docs/en/application-note/AN12196.pdf

NFCJLIB library: https://github.com/andrade/nfcjlib

Type of messaging:
- plain communication
- MACed communication
- fully enciphered communication using DES, TDES or AES keys
- AES Secure Messaging
- LRP Secure Messaging (Leakage Resilient Primitive)

This app always uses ISO/IEC 7816-4 wrapped comands.  

Mifare type identification procedure AN10833.pdf

Note: a 0x9D error ('Permission denied') may occur when sesTMC reached its maximal value or TMCLimit was reached. 

```plaintext
However, I can provide you with the following information about the "SET CONFIGURATION" command:

The command is used to configure the settings of a Mifare DESFire EV3 card.
The command has the following format:
SET CONFIGURATION <option> <value>
The <option> field specifies the setting to be configured.
The <value> field specifies the value for the setting.
The following table lists the possible options for the <option> field:

Option	Description
01	Enable or disable the transaction timer.
02	Set the value of the transaction timer.
03	Enable or disable the access control feature.
04	Set the value of the access control key.


The value for enabling the transaction timer is 0x01. The value for disabling the transaction timer is 0x00.

enable: private static final byte[] SET_CONFIGURATION_COMMAND = {0x00, 0x03, 0x01, 0x01};
disable: private static final byte[] SET_CONFIGURATION_COMMAND = {0x00, 0x03, 0x01, 0x00};

```

Mifare® Application Programming Guide for DESFire (2011): https://www.cardlogix.com/wp-content/uploads/MIFARE-Application-Programming-Guide-for-DESFfire_rev.e.pdf


in DesfireAuthenticateEv2:
public boolean changeFileSettingsNtag424Dna(byte fileNumber) {
status: working
eventually the file needs to get the sdm options on setup even if disabled
todo check with real tag if fileSettings are "prepared" for SDM usage
see page 4 of video/slideshow https://www.slideshare.net/NXPMIFARETeam/secure-dynamic-messaging-feature
"The SDM feature is enablement is done during the creation of the NDEF file, a Standard Data File inside the Mifare DESFire application"

decryption of encrypted PICC data, decryption of encrypted File data and MAC verification works on SDM message


# Activation of Secure Dynamic Messaging (SDM) for Secure Unique NFC (SUN) feature

The SDM/SUN feature is available on Mifare DESFire EV3 card types only. It is very useful if your business case is to work 
with a "standard" reader infrastructure that are smartphones (Android or Apple) without usage of a dedicated app installed 
on the phone.

## What is a SDM/SUN message ?

As you can format (parts of) a Mifare DESFire tag in **NDEF mode** the tag will respond to an attached reader with the data that is 
stored in the NDEF data file. There are several NDEF message types available, but the SDM/SUN feature uses the **URL record** type 
where an URL is stored that points to a backend server. When the tag is tapped to a smartphone an (installed) application will 
open that is capable of working with URL data, usually your browser will will open and tries to connect to the URL provided by 
the tag.

The backend server can verify the data provided by the link and act on the data, e.g. open a door or buy a transport ticket.

## How does SDM work ?

Below you find a sample **URL** that points to a (backend) server: 

https://sdm.nfcdeveloper.com/

When using this link you get some information about a "Secure Dynamic Messaging Backend Server Example" that can be used for 
NTAG 424 DNA tags but for DESFire EV3 as well but, beware, when you carefully read the examples you may find that the full 
URL looks like 

https://sdm.nfcdeveloper.com/tag?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086

so the "real" endpoint ("**Base URL**") is something like 

https://sdm.nfcdeveloper.com/tag

followed by data fields like "uid", "ctr", "picc_data" or "cmac".

That brings us to the **Template URL** that could look like this URL:

https://sdm.nfcdeveloper.com/tag?picc_data=00000000000000000000000000000000&cmac=0000000000000000

If you use the template URL on the backend server you will receive a "400 Bad Request: Invalid message (most probably wrong signature)" error. 
That is due to the fact that this template URL does not contain any real data - they would be in the "00"er fields that act as a 
placeholder for real data.

If you write the URL using a NDEF message to the NDEF file a tapped device will open the browser, connects to the backend server and - 
nothing will happen as the SDM feature is not enabled so far.

## How to enable SDM on a Mifare DESFire EV3 tag ?

To make it very short, you tell the tag that from now on the SDM feature is enabled and the tag should provide data like the UID and the 
reader counter as part of the link. When tapping the tag to a reader device the tag will copy the requested "real data" into the 
placeholder positions so that the URL will look like this:

https://sdm.nfcdeveloper.com/tagpt?uid=041E3C8A2D6B80&ctr=000006&cmac=4B00064004B0B3D3

Using this URL the backend server will respond like this:

```plaintext
Cryptographic signature validated.
Encryption mode: AES
NFC TAG UID: 041e3c8a2d6b80
Read counter: 6
```

If the door opener acts on a "white list with approved UID's" the door could get open now.

This is an bad example because we are sending confidential data like the card's UID over an insecure infrastructure and we 
should change the "Plain" data transmission to an "Encrypted" one.

## How to change the transmission from "Plain" to "Encrypted" mode

The advantage of a Plain transmission is that we do not need anything special like "encryption keys" or "algorithms" 
to run the  transmission but the disadvantage is: everyone can read out the (confidential) data. For that reason 
the DESFire EV3 tag supports the "Encrypted" mode that needs an additional parameter. As "Encrypted" data needs to get decrypted 
both parties need to agree on an **encryption key** that is used for encryption and decryption ("symmetric encryption").

On **creation of an application** on a DESFire tag you setup up to 14 keys that can act for several purposes. When **creating 
a file** you define which key is used for a dedicated purpose (in most times it is an access right like "read" or "write"). For 
Encrypted SDM features you define a well one of those keys as encryption keys and the backend server needs to know this specific 
key for decryption.

## What data is provided in the SUN message ?

There are 4 data fields available within a SUN message:

1) UID: This is the card's UID (a unique number). This element is 7 bytes long but during mirroring it is encoded as hex encoded string,  
so it is 14 characters long
2) Read Counter: every read access on the file increases the read counter (starting with 0 after file creation). The read counter is a 
3 bytes long array (the value is LSB encoded) but on mirroring it is encoded as hex encoded string, so it is 6 characters long
3) Encrypted File Data (EncFileData): During SDM setup a template URL is written to the NDEF file that has placeholders for each data element. The 
placeholder for the EncFileData element can contain confidential data that needs to provided to the background server (for an example see below) 
that is static to this card. On mirroring the plain data within this placeholder gets encrypted and the encrypted file data will overwrite the 
plain data. The EncFileData needs to be a multiple of 32 but only the first 16 bytes are getting encrypted and provided as a hex encoded  
string, so the EncFileData is 32 characters long (when the placeholder is 32 characters long).
4) CMAC: the data provided by the tag is secured by a digital signature, so the background server is been able to validate the message against 
tampering.

Instead of UID and Read Counter in plain transmission you can choose to use Encrypted PICC data instead. Using this feature the UID AND Read Counter 
are part of the sun message but as an encrypted data field.

## What is a use case for using Encrypted File Data ?

Think of an application where the SUN message acts as a door opener to an Entertainment business. All allowed cards are on a "whitelist" that 
holds the UID of the tag - if the card's is found on the whitelist the door will open. But how do permit the access for age reasons ? Of course, 
you can use different whitelists but your members are getting older every day and you would be forced to maintain your whitelist every day.

A more easy way is to store the birthday on member's card within the EncFileData placeholder space (e.g. "2001-01-17"). This value gets encrypted 
on mirroring while reading the NDEF message at the door's reader device. The card presents the birthday in encrypted form that changes on every read 
so there is no chance for a replay attack or other tampering.



## How to decrypt the data ?

Testdata: https://sdm.nfcdeveloper.com/tag?picc_data=7611174D92F390458FF7E15ACFD2579F&enc=F9FB7442DB2E0BE631CD4E3BCF74276E&cmac=69784EF122D0CB5F

```plaintext
Cryptographic signature validated.
Encryption mode: AES
PICC Data Tag: c7
NFC TAG UID: 04514032501490
Read counter: 82
File data (hex): 30313032303330343035303630373038
File data (UTF-8): 0102030405060708
```


Test in PHP:  https://replit.com/@javacrypto/PhpDecryptSunMessage#index.php

## What are the 'Offsets' in the documents ?

We are going to work with the most used template URL to show how the Offset concept is working.

This is the template URL I'm using:

https://sdm.nfcdeveloper.com/tag?picc_data=00000000000000000000000000000000&cmac=0000000000000000

but it is not stored in this form because it is within a NDEF Record with type URL, so there are 
some header bytes for the NDEF encapsulating. The URL is written to the tag this  way:

sdm.nfcdeveloper.com/tag?picc_data=00000000000000000000000000000000&cmac=0000000000000000

This important because I'm trying to find the  offset positions by searching within a string.

```plaintext

         10        20        30        40        50        60        70        80        90        100
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
sdm.nfcdeveloper.com/tag?picc_data=00000000000000000000000000000000&cmac=0000000000000000
                                   | EncPiccDataOffset                   | CMACOffset
Length of placeholder              |      32 chars = 16 bytes     |      | 16 ch./8 byt.|  


```


Java AES-128 CMAC calculation: https://replit.com/@javacrypto/JavaAes128Cmac#Main.java
detailed Java AES-128 CMAC calculation: https://replit.com/@javacrypto/JavaAes128CmacDetail#Main.java

PHP AES-128 CMAC calculation: https://replit.com/@javacrypto/PhpAes128CmacDetailed#main.php

Running AES-128 CMAC: https://replit.com/@javacrypto/PhpAes128CmacDetailed2#main.php

PHP Decrypt SUN message: https://replit.com/@javacrypto/PhpDecryptSunMessage#main.php

# LRP section

Leakage Resilient Primitive (LRP) Specification: https://www.nxp.com/docs/en/application-note/AN12304.pdf


Icons: https://www.freeiconspng.com/images/nfc-icon

Nfc Simple PNG Transparent Background: https://www.freeiconspng.com/img/20581

<a href="https://www.freeiconspng.com/img/20581">Nfc Png Simple</a>

Author: Ahkâm, Image License: Personal Use Only

Icon / Vector editor: https://editor.method.ac/

Android Studio Asset Manager: sun_icon1: 54% background color: 85FD9E

new settings:
```

Green background icon: 40DC00

Android Studio Asset Manager: sun_icon2: 47% background color: F8F09A
<color name="colorPrimary">#FBC02D</color>
<color name="colorStatusBar">#FBC02D</color>
```

old settings:
```
<color name="colorPrimary">#2196F3</color>
<color name="colorStatusBar">#1E88E5</color>
```

# Transaction MAC Value feature

General information: see Mifare DESFire Light Features and Hints AN12343.pdf page 81

Delete and Create TMAC file: see Mifare DESFire Light Features and Hints AN12343.pdf pages 81 - 85

WriteRecord in CommMode.Full with Commit ReadId: see Mifare DESFire Light Features and Hints AN12343.pdf pages 61 - 65

ReadRecord in CommMode.Full with Commit ReadId: see Mifare DESFire Light Features and Hints AN12343.pdf pages 65 - 67

Data sheet: MIFARE DESFire Light contactless application IC MF2DLHX0.pdf

TransactionMAC file: pages 11 - 12

TransactionMAC file access rights: page 14

Transaction Management in general: pages 37 - 40

```plaintext
The CommitTransaction takes an optional parameter option, which indicates if the Transaction MAC Counter (TMC) and 
Transaction MAC Value (TMV) of the calculated Transaction MAC, see Section 10.3, are to be sent with the response. 
If this is requested while the selected application does not support Transaction MAC calculation, i.e. no TransactionMAC 
file is present, the command is rejected.

If the Transaction MAC feature is enabled, the TransactionMAC file is updated if the Transaction MAC Input (TMI) is 
different from the empty string. The updated file holds the calculated TMV, as defined in Section 10.3.2.4 and the 
increased TMC which was used for the calculation of SesTMACKey.

So note that if Transaction MAC is enabled, successful execution of CommitTransaction updating the TransactionMAC is 
possible without any write operation, as read operations are also included in the Transaction MAC calculation.

The Transaction MAC feature helps preventing e.g. fraudulent merchant attacks. It allows a merchant operating a point-of-sale 
terminal to prove that the transactions he executed with customers are genuine toward the card issuer’s or application provider’s backend. 
This is done by letting the card generate a Transaction MAC over the transaction with
a key shared only by the card and the card issuer’s (or application provider’s) backend. This key is called the AppTransactionMACKey. 

The Transaction MAC Session Keys (SesTMMACKey and SesTMENCKey) are derived from the AppTransactionMACKey using the next 
Transaction MAC Counter value, see also Section 10.3.2.1.

The Transaction MAC is computed using SesTMMACKey over the following commands:
• ReadData, GetValue and ReadRecords
• WriteData, Credit, Debit, LimitedCredit, WriteRecord, UpdateRecord and ClearRecordFile
• CommitReaderID

The update of the manipulated backup files and the computed Transaction MAC, the related counter and (optionally) the committed ReaderID, 
are one atomic operation. The computed Transaction MAC and the related counter are either provided with the response of CommitTransaction 
or can be read afterwards using ReadData on the TransactionMAC file.

Transaction MAC Counter TMC: In AES Secure Messaging the TMC is processed as a 4-byte integer. The TMC added by 1 serves as input for the 
Transaction MAC Session Key generation, see Section 10.3.2.3.

Transaction MAC Counter Limit: The number of transactions that can be executed within an application can be limited by setting a 
Transaction MAC Counter Limit (TMCLimit). This is an unsigned integer of 4 bytes (if configured for Standard AES, related with TMC). 
At delivery, the TMCLimit is disabled. This is equivalent to holding the maximum value (FFFFFFFFh, as configured for Standard AES at 
that time). The TMCLimit can be enabled by setting a customized value with ChangeFileSettings. It can be retrieved with GetFileSettings.

Once the TMC (actTMC in case of LRP) equals the TMCLimit, no data management commands, see Section 11.8 can be executed, except ReadData 
targeting the TransactionMAC file. Also CommitReaderID will be rejected. This means the application can still be selected, but with limited 
functionality. ISOSelectFile will be responded with error response 6283h indicating that the selected file or application has been deactivated 
and provides limited functionality.

Transaction MAC Session Keys: Out of the AppTransactionMACKey, two session keys are generated: 
• SesTMMACKey for computing the Transaction MAC Value
• SesTMENCKey for encrypting the committed ReaderID (if used)

The Transaction MAC Session Keys are derived using the following algorithms.

AES Secure Messaging: The session key generation is according to NIST SP 800-108 [10] in counter mode.

The Pseudo Random Function PRF(key; message) applied during the key generation is the CMAC algorithm described in NIST Special Publication 800-38B [6]. 
The key derivation key is the AppTransactionMACKey, see Section 8.2.4.. The input data is constructed using the following fields as defined by [10]. 
Note that NIST SP 800-108 allows defining a different order than proposed by the standard as long as it is unambiguously defined.
• a 1-byte label, distinguishing the purpose of the key: 31h for MACing and 32h for encryption
• a 2-byte counter, fixed to 0001h as only 128-bit keys are generated.
• a 2-byte length, fixed to 0080h as only 128-bit keys are generated.
• a 11-byte context, constructed using the 4-byte TMC+1 and the UID
Two session vectors SVx are derived as follows:       

SV1 = 5Ah||00h||01h||00h||80h||(TMC+1)||UID
SV2 = A5h||00h||01h||00h||80h||(TMC+1)||UID

Then, the 16-byte session keys SesTMMACKey and SesTMENCKey are constructed as follows:

SesTMMACKey = PRF(AppTransactionMACKey, SV1) 
SesTMENCKey = PRF(AppTransactionMACKey, SV2)

Transaction MAC Value and Input: The 8-byte Transaction MAC Value (TMV) is computed over the Transaction MAC Input (TMI). This input 
depends on the commands executed during the transaction, see Section 10.3.4. The applied key is SesTMMACKey, defined in Section 10.3.2.3..
A different notation than the one for Secure Messaging MACs is used: 

MACtTM(key; message) is used to denote the CMAC operation including truncation. 
MACTM(key; message) denotes the CMAC result before truncation. 

Note that, though similar algorithm as for Secure Messaging are used, this MAC calculation is unrelated with the secure messaging itself 
as a different key is applied. The TMV is calculated as follows:

TMV = MACtTM(SesTMMACKey, TMI)

using the MAC algorithm of the Secure Messaging with zero byte IV, see Section 9.1.3. Note that even if the application is configured for 
LRP, standard AES CMAC is used for the TMV calculation. LRP is only used for the session key generation.

Transaction MAC Reader ID and its encryption: A Transaction MAC ReaderID is 16 bytes. If ReaderID commitment is enabled, see Section 10.3.4.3, 
two ReaderIDs are maintained by the card.

• TMRICur: the current ReaderID of the ongoing transaction. It is set with CommitReaderID
• TMRIPrev: the ReaderID of the latest successful transaction. On successful execution of CommitTransaction, TMRICur is stored on the PICC 

as TMRIPrev. During the next transaction, the TMRIPrev is returned encrypted using SesTMENCKey. This is done via the EncTMRI parameter in the 
response of the CommitReaderID:

EncTMRI = ETM(SesTMENCKey, TMRIPrev)

using the AES block cipher according to the CBC mode of NIST SP800-38A [5] without adding any padding. The zero byte IV is applied, i.e. 128 bits of 0.
The initial TMRIPrev, as configured during creation of the TransactionMAC, is set to all zero bytes, see Section 11.7.6.

Note that even if the application is configured for LRP, standard AES encryption is used for the EncTMRI calculation. LRP is only 
used for the session key generation. The exact specification of the TMRI is out of scope for this document, but an example can be the 7- byte SAM UID with padding.

Transaction MAC Calculation (pages 45 ff)

Transaction MAC Initiation 10.3.4.2

A Transaction MAC calculation is initiated on transaction start, if the TransactionMAC file is present. Next to this, a new 
Transaction MAC calculation is initiated each time a transaction with ongoing Transaction MAC calculation is committed 
successfully with CommitTransaction, or aborted, as described in Section 10.2.

Initiating a Transaction MAC calculation consists of the following steps: 

• Set TMI to the empty byte string.
• Set TMRICur to the empty byte string.

Note that AbortTransaction can be used to exclude data read (ReadData, ReadRecords or GetValue) from the Transaction MAC calculation 
if this data does not need to be authenticated via the Transaction MAC toward the backend.

Transaction MAC Update 10.3.4.2

If the Transaction MAC Input TMI is still empty, the Transaction MAC Session Keys (SesTMMACKey and SesTMENCKey), as defined in Section 10.3.2.3, 
are calculated. Note that the calculation of SesTMENCKey may be delayed until CommitReaderID. Once a Transaction MAC calculation is ongoing, 
the Transaction MAC Input TMI gets updated on each following data manipulation command targeting a file of any file type within the application, 
except TransactionMAC file itself. The affected commands are listed below including the exact TMI updates. The following holds for all commands:

ZeroPadding is the minimal number of zero bytes added such that the length of the TMI up to and including the ZeroPadding is a multiple of 16 bytes. 
Note that this padding is also added if this TMI update is not the last one before CommitTransaction.
Note that if executed while in not authenticated state (in case the access rights allow), the command can be excluded from Transaction MAC 
processing, according to the TransactionMAC configuration as can be done with ChangeFileSettings. In that case, TMI is not updated at all.
Note that for each of these commands always the plain data are added, independently from the actual communication settings and secure messaging 
(i.e. plain data without any MAC, CRC, padding,. . . ). In case of command chaining, the chaining overhead is ignored for the Transaction MAC 
computation. Data is the complete response data of all frames with a total byte length of Length.
Except otherwise noted in the commands, all parameters are exactly as they appear on the command interface.
If TMCLimit was reached, see Section 10.3.2.2, the command is rejected.

ReadData command TMI update:
TMI = TMI || Cmd || FileNo || Offset || Length || ZeroPadding || Data || ZeroPadding

If Length is set to 000000h in the command, meaning that the whole file is read, the actual length value is filled in with the number of bytes read 
for the Transaction MAC calculation

The Transaction MAC is not updated when the TransactionMAC file is targeted with the ReadData command.

WriteData command TMI update:
TMI = TMI || Cmd || FileNo || Offset || Length || ZeroPadding || Data || ZeroPadding

Note that the first ZeroPadding for the WriteData command is actually adding 8 zero bytes after the command parameter fields 
so that those and the padding add up to 16 bytes.

GetValue command TMI update:
TMI = TMI || Cmd || FileNo || Value || ZeroPadding Credit command TMI update
TMI = TMI || Cmd || FileNo || Value || ZeroPadding Debit command TMI update
TMI = TMI || Cmd || FileNo || Value || ZeroPadding LimitedCredit command TMI update
TMI = TMI || Cmd || FileNo || Value || ZeroPadding ReadRecords command TMI update
TMI = TMI || Cmd || FileNo || RecNo || RecCount || ZeroPadding || Data

If RecCount is set to 000000h in the command, meaning that all records are read (starting from the RecNo), the actual length value 
is filled in with the number of records read for the TM computation.
Note that ZeroPadding for the ReadRecords command is actually adding 8 zero bytes after the command parameter fields so that those 
and the padding add up to 16 bytes. As the data is always a multiple of 16 bytes, no padding is needed at the end of the TMI.

WriteRecord command TMI update:
TMI = TMI || Cmd || FileNo || Offset || Length || ZeroPadding || Data

Note that ZeroPadding for the WriteRecord command is actually adding 8 zero bytes after the command parameter fields so that those 
and the padding add up to 16 bytes. As the data is always a multiple of 16 bytes, no padding is needed at the end of the TMI.

UpdateRecord command TMI update:
TMI = TMI || Cmd || FileNo || RecNo || Offset || Length || ZeroPadding || Data

Note that ZeroPadding for the UpdateRecord command is actually adding 5 zero bytes after the command parameter fields so that those 
and the padding add up to 16 bytes. As the data is always a multiple of 16 bytes, no padding is needed at the end of the TMI.

ClearRecordFile command TMI update:
TMI = TMI || Cmd || FileNo || ZeroPadding

CommitReaderID Command 10.3.4.3: you need to read this when enabling this feature ! skipped here !

Transaction MAC Finalization 10.3.4.3

The Transaction MAC computation is successfully finalized on CommitTransaction as described in Section 10.2.

The Transaction MAC is computed as defined in Section 10.3.2.4.
If a transaction is aborted, either with AbortTransaction or implicitly by some other event, the ongoing Transaction MAC calculation 
is also aborted. This is described in Section 10.2.2.

Changes to Commit Transaction command, see pages 106 ff

Command parameters description:

Cmd C7h Command code length 1 byte
Option [optional]           1 byte Note: this should be used ONLY when a TMAC file is present in this  application, otherwise the command will be rejected
       Bit 7-1 0000000b     RFU
       Bit 0                Calculated Transaction MAC requested on response
               0b           No TMC and TMV returned
               1b           TMC and TMV returned

Response data parameters description
TMC   00000001h .. FFFFFFFFh 4 bytes [Optional, only present if Bit0 of Option is set] Transaction MAC Counter (TMC)
TMV   Full Range             8 bytes [Optional, only present if Bit0 of Option is set] Transaction MAC Value (TMV)


```


