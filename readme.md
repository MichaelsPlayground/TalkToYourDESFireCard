# Talk to your Mifare DESFire EV1/EV2/EV3 card

This is a sample app to demonstrate how to work with a Mifare DESFire EV1/EV2/EV3 card. 

For simplicity this app uses a DESFire tag with factory settings means:

- it works with a predefined **Application Identifier** (AID) of "D1D2D3"
- it uses **Plain communication** only (no MACed or Enciphered Communication)
- it shows how to work with **Standard Files** only (no Backup, Value, Linear Record, Cyclic Record or TransactionMAC Files)
- there are 2 **Access modes** hardcoded: **Free Access** (use without any key) or **Key Secured Access** with 5 predefined keys
  (0 = Application Master Key, 1 = Read & Write access key, 2 = Change Access Rights key, 3 = Read access key and 4 = Write access key)
- the  Standard files have a hardcoded size of 32 bytes

As the **Authentication** with a key is essentially for a successful transaction there is a huge amount of code lines taken from another 
project. I copied all necessary code from the NFCJLIB project available here: https://github.com/andrade/nfcjlib which is provided 
by **Daniel Andrade**, thanks a lot for his contribition. Please obey the LICENCE here: https://github.com/andrade/nfcjlib/blob/master/LICENSE.





