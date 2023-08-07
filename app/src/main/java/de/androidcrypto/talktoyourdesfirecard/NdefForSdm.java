package de.androidcrypto.talktoyourdesfirecard;


import android.text.TextUtils;
import android.util.Log;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;

/**
 * This class will prepare a NDEF message to work with the SUN feature (Secure Unique NFC) by
 * enabling the Secure Dynamic Messaging (SDM) feature that includes mirroring of PICC data
 *
 * Note: this class is working on NTAG 424 DNA only (tested) and does not support all available
 * mirroring options:
 * The only available option is the usage of 'Encrypted PICC data' and SDMMAC meaning the NDEF will contain
 * two dynamic parts:
 * 1) Encrypted PICC data that is a 32 characters long (hex encoded) string that contains these encrypted 4 elements:
 *    - PICC data tag (1 byte) - contains coded length of UID, bits for enabled UID mirroring and ReadCounter mirroring
 *    - PICC UID (7 bytes)
 *    - ReadCounter (3 bytes)
 *    - RandomData (5 bytes, if UID and ReadCounter mirroring are enabled)
 * 2) SDMMAC mirror - the cryptographic checksum over encrypted data
 *    - is a 16 characters long (hex encoded) string that contains the 8 bytes long CMAC
 *
 * If you use the following SampleBaseUrl you can verify the SUN message online (https://sdm.nfcdeveloper.com/):
 * https://sdm.nfcdeveloper.com/tag?picc_data=00000000000000000000000000000000&cmac=0000000000000000
 *
 * NTAG 424 DNA: Encrypted PICC Data mirroring with SDMMAC (CMAC) - Example:
 * https://sdm.nfcdeveloper.com/tag?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086
 */
public class NdefForSdm {
    private static final String TAG = NdefForSdm.class.getName();

    public static final String SAMPLE_BASE_URL = "https://sdm.nfcdeveloper.com/tag?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086";
    public static final String FULL_SAMPLE_BASE_UR1 = "https://sdm.nfcdeveloper.com/tag?picc_data=00000000000000000000000000000000&cmac=0000000000000000";
    public static final String SAMPLE_BASE_UR1 = "https://sdm.nfcdeveloper.com/tag";

    private String urlBase = "";
    private String urlParameterHeader = "?"; // this is the beginning of parameter within an URL
    private String urlParameterFooter = "="; // character between parameterName and data
    private String urlParameterNext = "&"; // character between parameterName and data
    private String urlEncryptedPiccName = "picc_data";
    private String urlEncryptedPiccPlaceholder = "00000000000000000000000000000000";
    private final int encryptedPiccLength = 32;
    private String urlPlainUidName = "uid";
    private String urlPlainUidPlaceholder = "00000000000000";
    private final int plainUidLength = 14;
    private String urlPlainSDMReadCtrName = "ctr";
    private String urlPlainSDMReadCtrPlaceholder = "000000";
    private final int plainSDMReadCtrLength = 6;
    private String urlEncryptedDataName = "sdmenc";
    private String urlEncryptedDataPlaceholder = "00000000000000000000000000000000";
    private final int encryptedDataLength = 32; // note: only the first 16 bytes are encrypted, the next 16 bytes are not used and delivering
    private String urlCmacName = "cmac";
    private String urlCmacPlaceholder = "0000000000000000";
    private final int cmacLength = 16;
    private String urlTemplate = "";

    // parameter for complex url builder
    private byte fileOption;
    private byte[] accessRights;
    private byte sdmOptions;
    private byte[] sdmAccessRights;
    private byte[] uidOffset;
    private byte[] sdmReadCounterOffset;
    private byte[] piccDataOffset;
    private byte[] sdmMacInputOffset;
    private byte[] sdmEncOffset;
    private byte[] sdmEncLength;
    private byte[] sdmMacOffset;
    private byte[] sdmReadCounterLimit;




    private String errorCodeReason = "";

    public enum CommunicationSettings {
        Plain, MACed, Full
    }

    /**
     * this will setup the class with default parameter for usage with https://sdm.nfcdeveloper.com/tag
     * @param urlBase
     */
    public NdefForSdm(String urlBase) {
        if (isValidUrl(urlBase)) {
            Log.e(TAG, "The url is valid: " + urlBase);
            this.urlBase = removeTrailingSlashs(urlBase);
        } else {
            Log.e(TAG, "The url is not valid, aborted");
            return;
        }
    }

    public NdefForSdm(String urlBase, String urlParameterHeader, String urlParameterFooter, String urlEncryptedPiccName, String urlEncryptedPiccPlaceholder, String urlCmacName, String urlCmacPlaceholder) {
        this.urlBase = urlBase;
        this.urlParameterHeader = urlParameterHeader;
        this.urlParameterFooter = urlParameterFooter;
        this.urlEncryptedPiccName = urlEncryptedPiccName;
        this.urlEncryptedPiccPlaceholder = urlEncryptedPiccPlaceholder;
        this.urlCmacName = urlCmacName;
        this.urlCmacPlaceholder = urlCmacPlaceholder;
    }

    public String urlBuilder() {
        StringBuilder sb = new StringBuilder();
        sb.append(urlBase);
        sb.append(urlParameterHeader).append(urlEncryptedPiccName).append(urlParameterFooter);
        sb.append(urlEncryptedPiccPlaceholder);
        sb.append(urlParameterNext).append(urlCmacName).append(urlParameterFooter);
        sb.append(urlCmacPlaceholder);
        urlTemplate = sb.toString();
        return urlTemplate;
    }

    public int getOffsetEncryptedPiccData() {
        if (TextUtils.isEmpty(urlTemplate)) {
            Log.e(TAG, "use the URL builder first to generate a urlTemplate, aborted");
            return -1;
        }
        // build the complete parameter string
        StringBuilder sb = new StringBuilder();
        sb.append(urlParameterHeader).append(urlEncryptedPiccName).append(urlParameterFooter);
        String parameterString = sb.toString();
        // find the position in the urlTemplate
        int pos = urlTemplate.indexOf(parameterString);
        if (!(pos > 0)) {
            Log.e(TAG, "could not find the position of the data, aborted");
            return -1;
        }
        final int positionCorrection = 1;
        return (pos + parameterString.length() - positionCorrection);
    }

    public int getOffsetSDMMACData() {
        if (TextUtils.isEmpty(urlTemplate)) {
            Log.e(TAG, "use the URL builder first to generate a urlTemplate, aborted");
            return -1;
        }
        // build the complete parameter string
        StringBuilder sb = new StringBuilder();
        sb.append(urlParameterNext).append(urlCmacName).append(urlParameterFooter);
        String parameterString = sb.toString();
        // find the position in the urlTemplate
        int pos = urlTemplate.indexOf(parameterString);
        if (!(pos > 0)) {
            Log.e(TAG, "could not find the position of the data, aborted");
            return -1;
        }
        final int positionCorrection = 1;
        return (pos + parameterString.length() - positionCorrection);
    }



    private boolean isValidUrl(String url) {
        if (url.length() == 0) return false;
        try {
            // it will check only for scheme and not null input
            new URL(url).toURI();
            return true;
        } catch (MalformedURLException | URISyntaxException e) {
            return false;
        }
    }

    private String removeTrailingSlashs(String s) {
        return s.replaceAll("/+$", "");
    }

    /**
     * section for complex url builder
     */

    /**
     * This complex builder tries to build the template url, the fileOption byte, the sdmOptions byte
     * and various placeholder, depending on given parameter.
     * It uses the pre-defined parameter names for string concatenation.
     * As there are "no go" combinations it is strong recommended to check the errorCodeReason why a
     * specific combination was not successful.
     * Use the getters named in errorCodeReason to retrieve the fileOption byte, the sdmOptions byte
     * and offset byte arrays.
     * Note: I did not test if the SDM enablement is allowed only for file number 2 as with NTAG 424 DNA tags
     *
     * For detailed information on 'ChangeFileSettings' command see
     * NTAG 424 DNA NT4H2421Gx.pdf pages 65 - 69
     */

    public String complexUrlBuilder(int fileNumber, CommunicationSettings communicationSetting, int keyRW, int keyCar, int keyR, int keyW,
                                    boolean enableSdm, boolean enableUid, boolean enableSdmReadCounter, boolean enableSdmReadCounterLimit,
                                    boolean enableSdmEncFileData, int sdmEncFileDataLength, boolean enableAsciiData, int keySdmCtrRet, int keySdmMetaRead,
                                    int keySdmFileRead) {
        boolean success = validateComplexParameter(fileNumber, keyRW, keyCar, keyR,  keyW, keySdmCtrRet, keySdmMetaRead, keySdmFileRead, sdmEncFileDataLength);
        if (!success) return null; // the errorCodeReason has the  failure reason

        // fileOptions
        fileOption = (byte) 0x00;
        if (communicationSetting == CommunicationSettings.Plain) fileOption = (byte) 0x00;
        if (communicationSetting == CommunicationSettings.MACed) fileOption = (byte) 0x01;
        if (communicationSetting == CommunicationSettings.Full) fileOption = (byte) 0x03;
        if (enableSdm) {
            fileOption = Utils.setBitInByte(fileOption, 6);
        }

        // access rights
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F)) ;// Read Access & Write Access
        accessRights[0] = accessRightsRwCar;
        accessRights[1] = accessRightsRW;

        // sdm options
        // [Optional, present if FileOption[Bit 6] set]
        if (enableSdm) {
            sdmOptions = (byte) 0x00;
            if (enableUid) {
                sdmOptions = Utils.setBitInByte(sdmOptions, 7);
            }
            if (enableSdmReadCounter) {
                sdmOptions = Utils.setBitInByte(sdmOptions, 6);
            }
            if (enableSdmReadCounterLimit) {
                sdmOptions = Utils.setBitInByte(sdmOptions, 5);
            }
            if (enableSdmEncFileData) {
                sdmOptions = Utils.setBitInByte(sdmOptions, 4);
            }
            if (enableAsciiData) {
                sdmOptions = Utils.setBitInByte(sdmOptions, 0);
            }
        }

        // sdm access rights
        // [Optional, present if FileOption[Bit 6] set]
        if (enableSdm) {
            int keyRfu = 15;
            byte accessRightsRfuCtrRet = (byte) ((keyRfu << 4) | (keySdmCtrRet & 0x0F)); // RFU & SDM Counter Retrieve
            byte accessRightsMetaReadFileRead = (byte) ((keyR << 4) | (keyW & 0x0F));// Meta Data Read & File Read
            accessRights[0] = accessRightsRfuCtrRet;
            accessRights[1] = accessRightsMetaReadFileRead;
        }

        // uid offset
        // [Optional, present if ((SDMOptions[Bit 7] = 1b) AND (SDMMetaRead access right = Eh)]
        // 0h .. (FileSize - UIDLength)


        // SDMReadCtrOffset
        // [Optional, present if ((SDMOptions[Bit 6] = 1b) AND (SDMMetaRead access right = Eh)]
        // 0h .. (FileSize - SDMReadCtrLength) Offset within the file
        // FFFFFFh No SDMReadCtr mirroring


        // PICCDataOffset
        // [Optional, present if SDMMetaRead access right =0h..4h]
        // 0h .. (FileSize - PICCDataLength)



        // SDMMACInputOffset
        // [Optional, present if SDMFileRead access right != Fh]
        // 0h .. (SDMMACOffset)



        // SDMENCOffset
        // [Optional, present if ((SDMFileRead access right != Fh) AND (SDMOptions[Bit 4] = 1b))]
        // SDMMACInputOffset .. (SDMMACOffset - 32)


        // SDMENCLength
        // [Optional, present if ((SDMFileRead access right != Fh) AND (SDMOptions[Bit 4] = 1b))]
        // 32 .. (SDMMACOffset - SDMENCOffset), Offset within the file, must be multiple of 32

        //  [if (SDMFileRead access right != Fh) AND (SDMOptions[Bit 4] = 1b)] Offset within the file



        // SDMMACOffset
        // [Optional, present if SDMFileRead access right != Fh]
        // SDMMACInputOffset .. (FileSize - 16) : [if (SDMFileRead access right != Fh) AND (SDMOptions[Bit 4] = 0b)] Offset within the file
        // (SDMENCOffset + SDMENCLength) .. (FileSize- 16) : [if (SDMFileRead access right != Fh) AND (SDMOptions[Bit 4] = 1b)] Offset within the file


        // SDMReadCtrLimit
        // [Optional, present if SDMOptions[Bit 5] = 1b]
        // Full range


        StringBuilder sbError = new StringBuilder();
        if (enableSdm) {
            sbError.append("SDM enabled, get fileOption").append(",");
        } else {
            sbError.append("SDM not enabled").append(",");
        }


        StringBuilder sb = new StringBuilder();
        sb.append(urlBase);



        errorCodeReason = sbError.toString();
        urlTemplate = sb.toString();
        return urlTemplate;
    }

    /**
     * This is NOT a LOGICAL validation but a PHYSICAL validation, means it only does validate the ranges in theory.
     * E.g. when an application has a maximum number of 5 keys then a key number of 10 will fail on the PICC but this
     * validation will success as 10 is in the range of maximum allowed keys per application (15).
     * @param fileNumber
     * @param keyRW
     * @param keyCar
     * @param keyR
     * @param keyW
     * @param keySdmCtrRet
     * @param keySdmMetaRead
     * @param keySdmFileRead
     * @param sdmEncFileDataLength : should be a multiple of 16, this validation checks for values 16/32/48 only
     * @return
     */

    private boolean validateComplexParameter(int fileNumber, int keyRW, int keyCar, int keyR, int keyW,
                                             int keySdmCtrRet, int keySdmMetaRead, int keySdmFileRead, int sdmEncFileDataLength) {
        if ((fileNumber < 0) || (fileNumber > 31)) {
            errorCodeReason = "fileNumber is not in range 00..31, aborted";
            return false;
        }
        if ((keyRW < 0) || (keyRW > 15)) {
            errorCodeReason = "keyRW is not in range 00..15, aborted";
            return false;
        }
        if ((keyCar < 0) || (keyCar > 15)) {
            errorCodeReason = "keyCar is not in range 00..15, aborted";
            return false;
        }
        if ((keyR < 0) || (keyR > 15)) {
            errorCodeReason = "keyR is not in range 00..15, aborted";
            return false;
        }
        if ((keyW < 0) || (keyW > 15)) {
            errorCodeReason = "keyW is not in range 00..15, aborted";
            return false;
        }
        if ((keySdmCtrRet < 0) || (keySdmCtrRet > 15)) {
            errorCodeReason = "keySdmCtrRet is not in range 00..15, aborted";
            return false;
        }
        if ((keySdmMetaRead < 0) || (keySdmMetaRead > 15)) {
            errorCodeReason = "keySdmMetaRead is not in range 00..15, aborted";
            return false;
        }
        if ((keySdmFileRead < 0) || (keySdmFileRead > 15)) {
            errorCodeReason = "keySdmFileRead is not in range 00..15, aborted";
            return false;
        }
        if ((sdmEncFileDataLength != 16) && (sdmEncFileDataLength != 32) && (sdmEncFileDataLength != 48)) {
            errorCodeReason = "sdmEncFileDataLength is not 16 / 32 / 48, aborted";
            return false;
        }
        return true;
    }

    /**
     * section for getter
     */

    public String getUrlTemplate() {
        return urlTemplate;
    }

    public String getUrlBase() {
        return urlBase;
    }

    public byte getFileOption() {
        return fileOption;
    }

    public String getErrorCodeReason() {
        return errorCodeReason;
    }
}
