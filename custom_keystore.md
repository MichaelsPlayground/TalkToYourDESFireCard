# Custom keystore for Mifare DESFire DES and AES key storage

When working with confidential key material like application keys for DESFire tags you need to store the 
keys in a secret way.

The best place for saving such data is Android's keystore but there is a hick up: a key that once was stored 
in the keystore will never leave this keystore later. There are encryption and decryption methods defined using 
these keys but you cannot get them to run an authentication on a DESFire tag.

The second best option is to use an app's own keystore on base of Bouncy Castle Keystore ("BKS") because that is available 
on all modern Android versions.

The CustomKeystore class is a class that encapsulates all code for a secure key storage.

## What is the general workflow for key storage ?

1) instantiate the class
2) initialize the class (an one time procedure)
3) store a key in the app's keystore
4) read a key from the app's keystore

## step 1 instantiate the class

To get access to the class the class is instantiated by providing a context, e.g.:

```CustomKeystore customKeystore = new CustomKeystore(view.getContext());```

## step 2 initialize the class (an one time procedure)

This step needs to be done only for the first usage, a so called "one time procedure". For this 
we provide a passphrase to the class, e.g. 
```plaintext
if (!isInitialized) {
   customKeystore.initialize("123456".toCharArray()); 
}
```

**Check that the customKeystore was NOT initialized before, otherwise you will loose all stored data.**

## step 3 store a key in the app's keystore

Storing or overwriting a key in the keystore is as simple as it is a "one-liner", e.g. 

``` plaintext
byte[] keyToStore = '12345678901234567890123456789012';
boolean writeSuccess = customKeystore.storeKey((byte) 0x02, keyToStore);
if (!writeSuccess) {
   Log.d(TAG, "Error during storing a key in the CustomKeystore with this key number");
   return;
}
```

## step 4 read a key from the app's keystore

Reading a key from the keystore is an "one-liner" as well, e.g.

``` plaintext
byte[] key = customKeystore.readKey((byte) 0x02));
if (key == null) {
   Log.d(TAG, "There is no key stored in the CustomKeystore with this key number");
   return;
}
```

## step 5 get all stored key aliases from the keystore

If you want to know which keys are stored in the keystore you call e.g.

```List<String> keyAliasesList = customKeystore.getKeystoreAliases();```



[back to the main manual](manual_talk_to_your_desfire_ev3_card.md)
