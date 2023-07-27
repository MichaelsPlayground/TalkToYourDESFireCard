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
public boolean changeFileSettingsSdmEv2(byte fileNumber) {
NOT working although test is success
eventually the file needs to get the sdm options on setup even if disabled
todo check with real tag if fileSettings are "prepared" for SDM usage
see page 4 of video/slideshow https://www.slideshare.net/NXPMIFARETeam/secure-dynamic-messaging-feature
"The SDM feature is enablement is done during the creation of the NDEF file, a Standard Data File inside the Mifare DESFire application"


