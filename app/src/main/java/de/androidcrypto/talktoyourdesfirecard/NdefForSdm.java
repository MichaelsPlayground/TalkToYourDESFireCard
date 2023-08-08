package de.androidcrypto.talktoyourdesfirecard;


import android.text.TextUtils;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;

/**
 * This class will prepare a NDEF message to work with the SUN feature (Secure Unique NFC) by
 * enabling the Secure Dynamic Messaging (SDM) feature that includes mirroring of PICC data
 * <p>
 * Note: this class is working on NTAG 424 DNA only (tested) and does not support all available
 * mirroring options:
 * The only available option is the usage of 'Encrypted PICC data' and SDMMAC meaning the NDEF will contain
 * two dynamic parts:
 * 1) Encrypted PICC data that is a 32 characters long (hex encoded) string that contains these encrypted 4 elements:
 * - PICC data tag (1 byte) - contains coded length of UID, bits for enabled UID mirroring and ReadCounter mirroring
 * - PICC UID (7 bytes)
 * - ReadCounter (3 bytes)
 * - RandomData (5 bytes, if UID and ReadCounter mirroring are enabled)
 * 2) SDMMAC mirror - the cryptographic checksum over encrypted data
 * - is a 16 characters long (hex encoded) string that contains the 8 bytes long CMAC
 * <p>
 * If you use the following SampleBaseUrl you can verify the SUN message online (https://sdm.nfcdeveloper.com/):
 * https://sdm.nfcdeveloper.com/tag?picc_data=00000000000000000000000000000000&cmac=0000000000000000
 * <p>
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
    private String urlEncryptedDataName = "enc";
    private String urlEncryptedDataPlaceholder = "0102030405060708A1A2A3A4A5A6A7A8";
    private final int encryptedDataLength = 32; // note: only the first 16 bytes are encrypted, the next 16 bytes are not used on delivering but for hex encoding
    private String urlCmacName = "cmac";
    private String urlCmacPlaceholder = "0000000000000000";
    private final int cmacLength = 16;
    private String urlTemplate = "";

    // parameter for complex url builder
    private byte fileOption;
    private byte[] accessRights;
    private byte sdmOptions;
    private byte[] sdmAccessRights;
    private byte[] sdmUidOffset;
    private byte[] sdmReadCounterOffset;
    private byte[] sdmEncPiccDataOffset;
    private byte[] sdmMacInputOffset;
    private byte[] sdmEncOffset;
    private byte[] sdmEncLength;
    private byte[] sdmMacOffset;
    private byte[] sdmReadCounterLimit;
    public static int SDM_READ_COUNTER_LIMIT_MAXIMUM = 16777214;
    private byte[] commandData;


    private String errorCodeReason = "";

    public enum CommunicationSettings {
        Plain, MACed, Full
    }

    /**
     * this will setup the class with default parameter for usage with https://sdm.nfcdeveloper.com/tag
     *
     * @param urlBase
     */
    public NdefForSdm(String urlBase) {
        if (isValidUrl(urlBase)) {
            Log.e(TAG, "The url is valid: " + urlBase);
            this.urlBase = removeTrailingSlashes(urlBase);
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

    public int getOffsetUidData() {
        if (TextUtils.isEmpty(urlTemplate)) {
            Log.e(TAG, "use the URL builder first to generate an urlTemplate, aborted");
            return -1;
        }
        // build the complete parameter string
        StringBuilder sb = new StringBuilder();
        //sb.append(urlParameterHeader).append(urlPlainUidName).append(urlParameterFooter);
        sb.append(urlPlainUidName).append(urlParameterFooter);
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

    public int getOffsetReadCtrData() {
        if (TextUtils.isEmpty(urlTemplate)) {
            Log.e(TAG, "use the URL builder first to generate an urlTemplate, aborted");
            return -1;
        }
        // build the complete parameter string
        StringBuilder sb = new StringBuilder();
        //sb.append(urlParameterHeader).append(urlPlainUidName).append(urlParameterFooter);
        sb.append(urlPlainSDMReadCtrName).append(urlParameterFooter);
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

    public int getOffsetEncryptedPiccData() {
        if (TextUtils.isEmpty(urlTemplate)) {
            Log.e(TAG, "use the URL builder first to generate an urlTemplate, aborted");
            return -1;
        }
        // build the complete parameter string
        StringBuilder sb = new StringBuilder();
        //sb.append(urlParameterHeader).append(urlEncryptedPiccName).append(urlParameterFooter);
        sb.append(urlEncryptedPiccName).append(urlParameterFooter);
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

    public int getOffsetEncryptedFileData() {
        if (TextUtils.isEmpty(urlTemplate)) {
            Log.e(TAG, "use the URL builder first to generate an urlTemplate, aborted");
            return -1;
        }
        // build the complete parameter string
        StringBuilder sb = new StringBuilder();
        //sb.append(urlParameterHeader).append(urlEncryptedPiccName).append(urlParameterFooter);
        sb.append(urlEncryptedDataName).append(urlParameterFooter);
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
            Log.e(TAG, "use the URL builder first to generate an urlTemplate, aborted");
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

    private String removeTrailingSlashes(String s) {
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
     * It building was successful you can get the complete command array for the changeFileSettings command.
     *
     * Presets:
     * The 'sdmEncFileDataLength' is fixed to 32 meaning the first 16 bytes are encrypted
     * The 'enableAsciiData' is fixed to true as NTAG 424 DNA tags only support this value (DESFire EV3 as well ?)
     * The 'readCounterLimit' needs to be in range 0 .. 16777214 ('0xEFFFFF')
     *
     * Note: I did not test if the SDM enablement is allowed only for file number 2 as with NTAG 424 DNA tags
     * <p>
     * For detailed information on 'ChangeFileSettings' command see
     * NTAG 424 DNA NT4H2421Gx.pdf pages 65 - 69
     */

    public String complexUrlBuilder(int fileNumber, CommunicationSettings communicationSetting, int keyRW, int keyCar, int keyR, int keyW,
                                    boolean enableSdm, boolean enableUid, boolean enableSdmReadCounter, boolean enableSdmReadCounterLimit,
                                    int readCounterLimit, boolean enableSdmEncFileData, int sdmEncFileDataLength, boolean enableAsciiData,
                                    int keySdmCtrRet, int keySdmMetaRead, int keySdmFileRead) {
        errorCodeReason = "";
        boolean success = validateComplexParameter(fileNumber, keyRW, keyCar, keyR, keyW, readCounterLimit,
                keySdmCtrRet, keySdmMetaRead, keySdmFileRead, sdmEncFileDataLength);
        if (!success) return null; // the errorCodeReason has the failure reason
        // this is the only allowed status for NTAG 424 DNA, don't know if this is valid for DESFire EV3 as well
        if (!enableAsciiData) {
            errorCodeReason = "You need to enable ASCII data, aborted";
            return null;
        }

        // sbError is used to provide the generated data fields
        StringBuilder sbError = new StringBuilder();
        sbError.append("** start the complex building **");
        if (enableSdm) {
            sbError.append("SDM enabled, get fileOption").append(", ");
        } else {
            sbError.append("SDM not enabled").append(", ");
        }

        // sb contains the template generated depending on input parameters
        StringBuilder sb = new StringBuilder();
        sb.append(urlBase);

        // baos contains the command generated depending on input parameters
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // baos.write(fileNumber); // the fileNumber is not part of the commandParameter

        // fileOptions
        fileOption = (byte) 0x00;
        if (communicationSetting == CommunicationSettings.Plain) fileOption = (byte) 0x00;
        if (communicationSetting == CommunicationSettings.MACed) fileOption = (byte) 0x01;
        if (communicationSetting == CommunicationSettings.Full) fileOption = (byte) 0x03;
        if (enableSdm) {
            fileOption = Utils.setBitInByte(fileOption, 6);
        }
        baos.write(fileOption);

        // access rights
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F));// Read Access & Write Access
        accessRights = new byte[2];
        accessRights[0] = accessRightsRwCar;
        accessRights[1] = accessRightsRW;
        baos.write(accessRightsRwCar);
        baos.write(accessRightsRW);

        // sdm options
        // [Optional, present if FileOption[Bit 6] set]
        if (enableSdm) {
            sdmOptions = (byte) 0x00;
            if (enableUid) {
                sdmOptions = Utils.setBitInByte(sdmOptions, 7);
                sbError.append("SDM UID enabled").append(", ");
            } else {
                sbError.append("SDM UID disabled").append(", ");
            }
            if (enableSdmReadCounter) {
                sdmOptions = Utils.setBitInByte(sdmOptions, 6);
                sbError.append("SDM ReadCounter enabled").append(", ");
            } else {
                sbError.append("SDM ReadCounter disabled").append(", ");
            }
            if (enableSdmReadCounterLimit) {
                sdmOptions = Utils.setBitInByte(sdmOptions, 5);
                sbError.append("SDM ReadCounterLimit enabled").append(", ");
            } else {
                sbError.append("SDM ReadCounterLimit disabled").append(", ");
            }
            if (enableSdmEncFileData) {
                sdmOptions = Utils.setBitInByte(sdmOptions, 4);
                sbError.append("SDM EncFileData enabled").append(", ");
            } else {
                sbError.append("SDM EncFileData disabled").append(", ");
            }
            if (enableAsciiData) {
                sdmOptions = Utils.setBitInByte(sdmOptions, 0);
                sbError.append("SDM AsciiData enabled").append(", ");
            } else {
                sbError.append("SDM AsciiData disabled").append(", ");
            }
            baos.write(sdmOptions);
        }

        // sdm access rights
        // [Optional, present if FileOption[Bit 6] set]
        sdmAccessRights = new byte[2];
        if (enableSdm) {
            int keyRfu = 15;
            byte accessRightsRfuCtrRet = (byte) ((keyRfu << 4) | (keySdmCtrRet & 0x0F)); // RFU & SDM Counter Retrieve
            byte accessRightsMetaReadFileRead = (byte) ((keySdmMetaRead << 4) | (keySdmFileRead & 0x0F));// Meta Data Read & File Read
            sdmAccessRights[0] = accessRightsRfuCtrRet;
            sdmAccessRights[1] = accessRightsMetaReadFileRead;
            baos.write(accessRightsRfuCtrRet);
            baos.write(accessRightsMetaReadFileRead);
        }

        // at this point we are only collecting which fields are present within the template and command

        // uid offset
        // [Optional, present if ((SDMOptions[Bit 7] = 1b) AND (SDMMetaRead access right = Eh)]
        // 0h .. (FileSize - UIDLength)
        boolean isPresentUidOffset = false;
        if (enableSdm) {
            if (enableUid) {
                if (keySdmMetaRead == 14) {
                    sbError.append("UID mirror in Plain enabled - GET this Offset").append(", ");
                    isPresentUidOffset = true;
                } else {
                    sbError.append("UID mirror in EncryptedPICC enabled - GET this Offset").append(", ");
                }
            }
        }

        // SDMReadCtrOffset
        // [Optional, present if ((SDMOptions[Bit 6] = 1b) AND (SDMMetaRead access right = Eh)]
        // 0h .. (FileSize - SDMReadCtrLength) Offset within the file
        // FFFFFFh No SDMReadCtr mirroring
        boolean isPresentReadCtrOffset = false;
        if (enableSdm) {
            if (enableSdmReadCounter) {
                if (keySdmMetaRead == 14) {
                    sbError.append("ReadCounter mirror in Plain enabled - GET this Offset").append(", ");
                    isPresentReadCtrOffset = true;
                } else {
                    sbError.append("ReadCounter mirror in EncryptedPICC enabled - GET this Offset").append(", ");
                }
            }
        }

        // PICCDataOffset
        // [Optional, present if SDMMetaRead access right =0h..4h]
        // 0h .. (FileSize - PICCDataLength)
        boolean isPresentEncPICCDataOffset = false;
        if (enableSdm) {
            if ((keySdmMetaRead >= 0) && (keySdmMetaRead <= 4)) {
                sbError.append("EncPICCData enabled - GET this Offset").append(", ");
                isPresentEncPICCDataOffset = true;
            }
        }

        // SDMMACInputOffset
        // [Optional, present if SDMFileRead access right != Fh]
        // 0h .. (SDMMACOffset)
        boolean isPresentSDMMACInputOffset = false;
        if (enableSdm) {
            if (keySdmFileRead != 15) {
                sbError.append("SDMMACInput active, GET this Offset").append(", ");
                isPresentSDMMACInputOffset = true;
            }
        }

        // SDMENCOffset
        // [Optional, present if ((SDMFileRead access right != Fh) AND (SDMOptions[Bit 4] = 1b))]
        // SDMMACInputOffset .. (SDMMACOffset - 32)

        // SDMENCLength
        // [Optional, present if ((SDMFileRead access right != Fh) AND (SDMOptions[Bit 4] = 1b))]
        // 32 .. (SDMMACOffset - SDMENCOffset), Offset within the file, must be multiple of 32
        boolean isPresentSDMENCOffset = false;
        boolean isPresentSDMENCLength = false;
        if (enableSdm) {
            if (enableSdmEncFileData) {
                if (keySdmFileRead != 15) {
                    sbError.append("SDM EncryptedFileData enabled - GET this Offset").append(", ");
                    isPresentSDMENCOffset = true;
                    sbError.append("SDM EncryptedFileDataLength active").append(", ");
                    isPresentSDMENCLength = true;
                } else {
                    sbError.append("SDM EncryptedFileData was enabled but keySdmFileRead is 15, no data is present").append(", ");
                    isPresentSDMENCOffset = false;
                    isPresentSDMENCLength = false;
                }
            }
        }

        // SDMMACOffset
        // [Optional, present if SDMFileRead access right != Fh]
        // SDMMACInputOffset .. (FileSize - 16) : [if (SDMFileRead access right != Fh) AND (SDMOptions[Bit 4] = 0b)] Offset within the file
        // (SDMENCOffset + SDMENCLength) .. (FileSize- 16) : [if (SDMFileRead access right != Fh) AND (SDMOptions[Bit 4] = 1b)] Offset within the file
        boolean isPresentSDMMACOffset = false;
        if (enableSdm) {
            if (keySdmFileRead != 15) {
                sbError.append("SDMMAC active - GET this Offset").append(", ");
                isPresentSDMMACOffset = true;
            }
        }

        // SDMReadCtrLimit
        // [Optional, present if SDMOptions[Bit 5] = 1b]
        // Full range
        boolean isPresentReadCtrLimitOffset = false;
        if (enableSdm) {
            if (enableSdmReadCounterLimit) {
                    sbError.append("ReadCounterLimit activated").append(", ");
                    isPresentReadCtrLimitOffset = true;
            }
        }

        // building the template url based on enabled options
        // see NTAG 424 DNA NT4H2421Gx.pdf page 43 for visual data
        if (enableSdm) sb.append(urlParameterHeader);
        if (isPresentUidOffset) {
            sb.append(urlPlainUidName).append(urlParameterFooter).append(urlPlainUidPlaceholder);
        }

        if (isPresentReadCtrOffset) {
            if (isPresentUidOffset) sb.append(urlParameterNext); // the '&' character
            sb.append(urlPlainSDMReadCtrName).append(urlParameterFooter).append(urlPlainSDMReadCtrPlaceholder);
        }
        // if uid and/or read counter are present there is no encrypted PICC data and vice versa
        // so encrypted PICC data start as first element if enabled
        if (isPresentEncPICCDataOffset) {
            sb.append(urlEncryptedPiccName).append(urlParameterFooter).append(urlEncryptedPiccPlaceholder);
        }

        // encrypted file data
        if (isPresentSDMENCOffset) {
            sb.append(urlParameterNext); // the '&' character
            sb.append(urlEncryptedDataName).append(urlParameterFooter).append(urlEncryptedDataPlaceholder);
            // note: as I hardcoded the 'EncryptedFileDataLength' to 32 there is no need to append more
            // placeholders here
        }

        if (isPresentSDMMACOffset) {
            sb.append(urlParameterNext); // the '&' character
            sb.append(urlCmacName).append(urlParameterFooter).append(urlCmacPlaceholder);
        }

        urlTemplate = sb.toString();

        // the template is ready, now find the positions of the placeholders in the template
        int posUidOffset = 0;
        int posReadCtrOffset = 0;
        int posEncPiccOffset = 0;
        int posEncFileDataOffset = 0;
        int posMacOffset = 0;
        int posMacInputOffset = 0;

        posUidOffset = getOffsetUidData();
        posReadCtrOffset = getOffsetReadCtrData();
        posEncPiccOffset = getOffsetEncryptedPiccData();
        posEncFileDataOffset = getOffsetEncryptedFileData();
        posMacOffset = getOffsetSDMMACData();
        posMacInputOffset = posMacOffset; // if no EncFileData is present/enabled
        if (isPresentSDMENCOffset) { // calculate the MAC over FileData as well
            posMacInputOffset = posEncFileDataOffset;
        }
        Log.d(TAG, "posUidOffset:     " + posUidOffset);
        Log.d(TAG, "posReadCtrOffset: " + posReadCtrOffset);
        Log.d(TAG, "posEncPiccOffset: " + posEncPiccOffset);
        Log.d(TAG, "posEncDataOffset: " + posEncFileDataOffset);
        Log.d(TAG, "posMacOffset:     " + posMacOffset);
        Log.d(TAG, "posMacInpOffset:  " + posMacInputOffset);

        // get the needed offsets and build the command string
        if (isPresentUidOffset) {
            if (posUidOffset < 1) {
                sbError.append("\n").append("ERROR: posUID not valid, aborted");
                sbError.append("\n").append("returning a template but no offset data or command");
                errorCodeReason = sbError.toString();
                return urlTemplate;
            }
            sdmUidOffset = Utils.intTo3ByteArrayInversed(posUidOffset);
            baos.write(sdmUidOffset, 0, sdmUidOffset.length);
        }

        if (isPresentReadCtrOffset) {
            if (posReadCtrOffset < 1) {
                sbError.append("\n").append("ERROR: posReadCounter not valid, aborted");
                sbError.append("\n").append("returning a template but no offset data or command");
                errorCodeReason = sbError.toString();
                return urlTemplate;
            }
            sdmReadCounterOffset = Utils.intTo3ByteArrayInversed(posReadCtrOffset);
            baos.write(sdmReadCounterOffset, 0, sdmReadCounterOffset.length);
        }

        if (isPresentEncPICCDataOffset) {
            if (posEncPiccOffset < 1) {
                sbError.append("\n").append("ERROR: posEncPICCData not valid, aborted");
                sbError.append("\n").append("returning a template but no offset data or command");
                errorCodeReason = sbError.toString();
                return urlTemplate;
            }
            sdmEncPiccDataOffset = Utils.intTo3ByteArrayInversed(posEncPiccOffset);
            baos.write(sdmEncPiccDataOffset, 0, sdmEncPiccDataOffset.length);
        }

        if (isPresentSDMMACInputOffset) {
            if (posMacInputOffset < 1) {
                sbError.append("\n").append("ERROR: posMacInput not valid, aborted");
                sbError.append("\n").append("returning a template but no offset data or command");
                errorCodeReason = sbError.toString();
                return urlTemplate;
            }
            sdmMacInputOffset = Utils.intTo3ByteArrayInversed(posMacInputOffset);
            baos.write(sdmMacInputOffset, 0, sdmMacInputOffset.length);
        }

        if (isPresentSDMENCOffset) {
            if (posEncFileDataOffset < 1) {
                sbError.append("\n").append("ERROR: posEncFileData not valid, aborted");
                sbError.append("\n").append("returning a template but no offset data or command");
                errorCodeReason = sbError.toString();
                return urlTemplate;
            }
            sdmEncOffset = Utils.intTo3ByteArrayInversed(posEncFileDataOffset);
            baos.write(sdmEncOffset, 0, sdmEncOffset.length);
        }

        if (isPresentSDMENCLength) {
            sdmEncLength = Utils.intTo3ByteArrayInversed(sdmEncFileDataLength);
            baos.write(sdmEncLength, 0, sdmEncLength.length);
        }

        if (isPresentSDMMACOffset) {
            if (posMacOffset < 1) {
                sbError.append("\n").append("ERROR: posMAC not valid, aborted");
                sbError.append("\n").append("returning a template but no offset data or command");
                errorCodeReason = sbError.toString();
                return urlTemplate;
            }
            sdmMacOffset = Utils.intTo3ByteArrayInversed(posMacOffset);
            baos.write(sdmMacOffset, 0, sdmMacOffset.length);
        }

        if (isPresentReadCtrLimitOffset) {
            sdmReadCounterLimit = Utils.intTo3ByteArrayInversed(readCounterLimit);
            baos.write(sdmReadCounterLimit, 0, sdmReadCounterLimit.length);
        }

        errorCodeReason = sbError.toString();

        commandData = baos.toByteArray();
        Log.d(TAG, "errorCodeReason: " + errorCodeReason);
        Log.d(TAG, "urlTemplate: " + urlTemplate);
        Log.d(TAG, Utils.printData("commandData", commandData));
        return urlTemplate;
    }

    /**
     * This is NOT a LOGICAL validation but a PHYSICAL validation, means it only does validate the ranges in theory.
     * E.g. when an application has a maximum number of 5 keys then a key number of 10 will fail on the PICC but this
     * validation will success as 10 is in the range of maximum allowed keys per application (15).
     *
     * @param fileNumber
     * @param keyRW
     * @param keyCar
     * @param keyR
     * @param keyW
     * @param readCounterLimit, minimum is 0, maximum is 16777214 (SDM_READ_COUNTER_LIMIT_MAXIMUM)
     * @param keySdmCtrRet
     * @param keySdmMetaRead
     * @param keySdmFileRead
     * @param sdmEncFileDataLength : should be a multiple of 16, this validation checks for values 16/32/48 only
     * @return
     */

    private boolean validateComplexParameter(int fileNumber, int keyRW, int keyCar, int keyR, int keyW, int readCounterLimit,
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
        // note: the value 16777215 = '0xFFFFFF' would mean that the counter limit is
        // active but the readCounter is not mirrored
        // As the limit is 1 below you can't run this option
        if ((readCounterLimit < 0) || readCounterLimit > SDM_READ_COUNTER_LIMIT_MAXIMUM) {
            errorCodeReason = "readCounterLimit is not in range 0..16777214, aborted";
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
        // this is a hard coded limitation
        if (sdmEncFileDataLength != 32) {
            errorCodeReason = "sdmEncFileDataLength is not 32, aborted";
            return false;
        }
        /*
        if ((sdmEncFileDataLength != 16) && (sdmEncFileDataLength != 32) && (sdmEncFileDataLength != 48)) {
            errorCodeReason = "sdmEncFileDataLength is not 16 / 32 / 48, aborted";
            return false;
        }
         */
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
