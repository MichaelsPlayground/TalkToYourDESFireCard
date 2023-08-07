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
    private String urlCmacName = "cmac";
    private String urlCmacPlaceholder = "0000000000000000";
    private String urlTemplate = "";

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

    public String getUrlTemplate() {
        return urlTemplate;
    }

    public String getUrlBase() {
        return urlBase;
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
}
