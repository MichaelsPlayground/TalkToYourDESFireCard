package de.androidcrypto.talktoyourdesfirecard;

import java.util.Arrays;

/**
 * This class takes the output of the getKeySettings command and analyzes the data for an easy access.
 * Before using the data check 'isKeySettingsValid()' - only on 'true' use the data
 * The first data of the constructor (applicationIdentifier) is used to determine if some data are analyzed
 * or not, so please fill it with the application identifier of the actual application (use '0x000000' in case
 * the MAIN APPLICATION IDENTIFIER is the source of data.
 * For convenient printouts use 'dump()'
 */

public class ApplicationKeySettings {

    private byte[] applicationIdentifier;
    private byte[] keySettings;
    private byte keySettingsByte; // beware - this is just a named byte
    private byte numberOfKeysByte; // beware - this is just a named byte
    private int keyType; // 00 = DES, 40 = TDES, 80 = AES keys
    private String keyTypeName; // DES / TDES / AES
    private boolean isKeyTypeDes = false;
    private boolean isKeyTypeTDes = false;
    private boolean isKeyTypeAes = false;
    private boolean isKeyTypeUnknown = false;
    private int numberOfKeys;
    // key settings
    private int carKeyNumber;
    private boolean isMasterKeyAuthenticationNecessaryToChangeAnyKey; // '0' true = default
    private boolean isApplicationKeyAuthenticationNecessaryToChangeAnyKey; // '1..D' false = default
    private boolean isKeyAuthenticationNecessaryToChangeThisKey; // 'E' false = default
    private boolean isApplicationKeysChangeFrozen; // 'F' false = default
    private boolean isMasterKeyChangeable = false; // true = frozen
    private boolean isMasterKeyAuthenticationNeededForFileDirectoryAccess = false;
    private boolean isMasterKeyAuthenticationNeededForCreateDeleteFile = false;
    private boolean isChangeOfMasterKeySettingsAllowed = false; // true = frozen
    private boolean isMasterApplicationSettings;
    private final byte[] MasterApplicationIdentifier = Utils.hexStringToByteArray("000000");
    private boolean isKeySettingsValid = false;

    public ApplicationKeySettings(byte[] applicationIdentifier, byte[] keySettings) {
        if ((applicationIdentifier == null) || (applicationIdentifier.length != 3)) {
            return;
        }
        if ((keySettings == null) || (keySettings.length != 2)) {
            return;
        }
        this.applicationIdentifier = applicationIdentifier;
        this.keySettings = keySettings;
        this.keySettingsByte = keySettings[0];
        this.numberOfKeysByte = keySettings[1];
        analyze();
    }

    private void analyze() {
        // kind of settings, depending on PICC or Application level
        if (Arrays.equals(applicationIdentifier, MasterApplicationIdentifier)) {
            isMasterApplicationSettings = true;
        } else {
            isMasterApplicationSettings = false;
        }

        // analyze byte 1
        numberOfKeys = Utils.byteToLowerNibbleInt(numberOfKeysByte);
        keyType = Utils.byteToUpperNibbleInt(numberOfKeysByte);
        if (keyType == 0) {
            keyTypeName = "DES";
            isKeyTypeDes = true;
        } else if (keyType == 4) {
            keyTypeName = "TDES";
            isKeyTypeTDes = true;
        } else if (keyType == 8) {
            keyTypeName = "AES";
            isKeyTypeAes = true;
        } else {
            keyTypeName = "unknown";
            isKeyTypeUnknown = true;
        }

        // analyze byte 0
        // on picc level only bits 0..3 are in use, bits 4..7 are RFU
        // the application settings are bitwise combined with carKeyByte
        /*
			bit 0 is most right bit (counted from right to left)
			bit 0 = application master key is changeable (1) or frozen (0)
			bit 1 = application master key authentication is needed for file directory access (1)
			bit 2 = application master key authentication is needed before CreateFile / DeleteFile (1)
			bit 3 = change of the application master key settings is allowed (1)
			bit 4-7 = hold the Access Rights for changing application keys (ChangeKey command)
			• 0x0: Application master key authentication is necessary to change any key (default).
			• 0x1 .. 0xD: Authentication with the specified key is necessary to change any key.
			• 0xE: Authentication with the key to be changed (same KeyNo) is necessary to change a key.
			• 0xF: All Keys (except application master key, see Bit0) within this application are frozen.
		 */
        if (isMasterApplicationSettings) {
            // PICC level
            getConfiguration();
        } else {
            // Application level
            carKeyNumber = Utils.byteToUpperNibbleInt(keySettingsByte);
            getCarAccessRights();
            getConfiguration();
        }
        isKeySettingsValid = true;
    }

    private void getConfiguration() {
        isMasterKeyChangeable = Utils.testBit(keySettingsByte, 0);
        isMasterKeyAuthenticationNeededForFileDirectoryAccess = !Utils.testBit(keySettingsByte, 1); // !
        isMasterKeyAuthenticationNeededForCreateDeleteFile = !Utils.testBit(keySettingsByte, 2); // !
        isChangeOfMasterKeySettingsAllowed = Utils.testBit(keySettingsByte, 3);
    }

    private void getCarAccessRights() {
        if (carKeyNumber == 0) {
            // 00
            isMasterKeyAuthenticationNecessaryToChangeAnyKey = true;
            isApplicationKeyAuthenticationNecessaryToChangeAnyKey = false;
            isKeyAuthenticationNecessaryToChangeThisKey = false;
            isApplicationKeysChangeFrozen = false;
        }
        if ((carKeyNumber > 0) && (carKeyNumber < 14)) {
            // 01..13
            isMasterKeyAuthenticationNecessaryToChangeAnyKey = false;
            isApplicationKeyAuthenticationNecessaryToChangeAnyKey = true;
            isKeyAuthenticationNecessaryToChangeThisKey = false;
            isApplicationKeysChangeFrozen = false;
        }
        if (carKeyNumber == 14) {
            isMasterKeyAuthenticationNecessaryToChangeAnyKey = false;
            isApplicationKeyAuthenticationNecessaryToChangeAnyKey = false;
            isKeyAuthenticationNecessaryToChangeThisKey = true;
            isApplicationKeysChangeFrozen = false;
        }
        if (carKeyNumber == 15) {
            isMasterKeyAuthenticationNecessaryToChangeAnyKey = false;
            isApplicationKeyAuthenticationNecessaryToChangeAnyKey = false;
            isKeyAuthenticationNecessaryToChangeThisKey = false;
            isApplicationKeysChangeFrozen = true;
        }
    }

    public String dump() {
        StringBuilder sb = new StringBuilder();
        sb.append(Utils.printData("applicationId", applicationIdentifier)).append("\n");
        sb.append(Utils.printData("keySettings", keySettings)).append("\n");
        sb.append("number of keys: ").append(numberOfKeys).append("\n");
        sb.append("keyType: ").append(keyTypeName).append("\n");
        sb.append("isMasterKeyChangeable: ").append(isMasterKeyChangeable).append("\n");
        sb.append("isMasterKeyAuthenticationNeededForFileDirectoryAccess: ").append(isMasterKeyAuthenticationNeededForFileDirectoryAccess).append("\n");
        sb.append("isMasterKeyAuthenticationNeededForCreateDeleteFile: ").append(isMasterKeyAuthenticationNeededForCreateDeleteFile).append("\n");
        sb.append("isChangeOfMasterKeySettingsAllowed: ").append(isChangeOfMasterKeySettingsAllowed).append("\n");
        if (!isChangeOfMasterKeySettingsAllowed) {
            sb.append("*** WARNING: this tag is frozen ***").append("\n");
        }
        if (isMasterApplicationSettings) {
            sb.append("This are the settings for the Master Application").append("\n");
        } else {
            sb.append("This are the settings for an Application").append("\n");
            sb.append("keyNumber for changing keys: ").append(carKeyNumber).append("\n");
            sb.append("isMasterKeyAuthenticationNecessaryToChangeAnyKey: ").append(isMasterKeyAuthenticationNecessaryToChangeAnyKey).append("\n");
            sb.append("isApplicationKeyAuthenticationNecessaryToChangeAnyKey: ").append(isApplicationKeyAuthenticationNecessaryToChangeAnyKey).append("\n");
            sb.append("isKeyAuthenticationNecessaryToChangeThisKey: ").append(isKeyAuthenticationNecessaryToChangeThisKey).append("\n");
            sb.append("isApplicationKeysChangeFrozen: ").append(isApplicationKeysChangeFrozen).append("\n");
        }
        if (!isKeySettingsValid) {
            sb.append("*** WARNING: this key settings are INVALID ***").append("\n");
        } else {
            sb.append("-----------------").append("\n");
        }
        return sb.toString();
    }

    /**
     * section for getter
     */

    public int getKeyType() {
        return keyType;
    }

    public String getKeyTypeName() {
        return keyTypeName;
    }

    public boolean isKeyTypeDes() {
        return isKeyTypeDes;
    }

    public boolean isKeyTypeTDes() {
        return isKeyTypeTDes;
    }

    public boolean isKeyTypeAes() {
        return isKeyTypeAes;
    }

    public boolean isKeyTypeUnknown() {
        return isKeyTypeUnknown;
    }

    public int getNumberOfKeys() {
        return numberOfKeys;
    }

    public int getCarKeyNumber() {
        return carKeyNumber;
    }

    public boolean isMasterKeyAuthenticationNecessaryToChangeAnyKey() {
        return isMasterKeyAuthenticationNecessaryToChangeAnyKey;
    }

    public boolean isApplicationKeyAuthenticationNecessaryToChangeAnyKey() {
        return isApplicationKeyAuthenticationNecessaryToChangeAnyKey;
    }

    public boolean isKeyAuthenticationNecessaryToChangeThisKey() {
        return isKeyAuthenticationNecessaryToChangeThisKey;
    }

    public boolean isApplicationKeysChangeFrozen() {
        return isApplicationKeysChangeFrozen;
    }

    public boolean isMasterKeyChangeable() {
        return isMasterKeyChangeable;
    }

    public boolean isMasterKeyAuthenticationNeededForFileDirectoryAccess() {
        return isMasterKeyAuthenticationNeededForFileDirectoryAccess;
    }

    public boolean isMasterKeyAuthenticationNeededForCreateDeleteFile() {
        return isMasterKeyAuthenticationNeededForCreateDeleteFile;
    }

    public boolean isChangeOfMasterKeySettingsAllowed() {
        return isChangeOfMasterKeySettingsAllowed;
    }

    public boolean isMasterApplicationSettings() {
        return isMasterApplicationSettings;
    }

    public byte[] getMasterApplicationIdentifier() {
        return MasterApplicationIdentifier;
    }

    public boolean isKeySettingsValid() {
        return isKeySettingsValid;
    }
}
