package de.androidcrypto.talktoyourdesfirecard;

/***************************************************************************
 *
 * This file is part of the 'External NFC API' project at
 * https://github.com/skjolber/external-nfc-api
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ****************************************************************************/


import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;


public class VersionInfo {

    private int hardwareVendorId;
    private int hardwareType;
    private int hardwareSubtype;
    private int hardwareVersionMajor;
    private int hardwareVersionMinor;
    private int hardwareStorageSize;
    private int hardwareProtocol;

    private int softwareVendorId;
    private int softwareType;
    private int softwareSubtype;
    private int softwareVersionMajor;
    private int softwareVersionMinor;
    private int softwareStorageSize;
    private int softwareProtocol;

    byte[] uid = new byte[7]; // [7];
    byte[] batchNumber = new byte[5]; //[5];
    private int productionWeek;
    private int productionYear;
    private byte productionWeekByte;
    private byte productionYearByte;

    // Source: https://github.com/skjolber/external-nfc-api/blob/d1cf337dbfca6d34b6a71fd951e60fb467ea2f01/core/src/main/java/com/github/skjolber/nfc/service/desfire/VersionInfo.java

    /**
     * A short identification overview:
     * HardwareType of (lower nibble):
     * 0xX1 = MIFARE DESFire
     * 0xX2 = MIFARE Plus
     * 0xX3 = MIFARE Ultralight
     * 0x04 = NTAG 4xx
     * 0xX5 = RFU
     * 0xX6 = RFU
     * 0xX7 = NTAG I2C
     * 0x08 = MIFARE DESFire Light
     *
     * HardwareType of (upper nibble):
     * 0x0X = MIFARE native IC
     * 0x8X = Implementation
     * 0x9X = Applet on a Java  card
     * 0xAX = MIFARE 2GO
     */

    public VersionInfo(byte[] bytes) throws IOException {
        if(bytes.length < 7 + 7 + uid.length + batchNumber.length + 2) {
            throw new IllegalArgumentException();
        }

        DataInputStream din = new DataInputStream(new ByteArrayInputStream(bytes));

        hardwareVendorId = din.read();
        hardwareType = din.read();
        hardwareSubtype = din.read();
        hardwareVersionMajor = din.read();
        hardwareVersionMinor = din.read();
        hardwareStorageSize = din.read();
        hardwareProtocol = din.read();

        softwareVendorId = din.read();
        softwareType = din.read();
        softwareSubtype = din.read();
        softwareVersionMajor = din.read();
        softwareVersionMinor = din.read();
        softwareStorageSize = din.read();
        softwareProtocol = din.read();

        din.readFully(uid);
        din.readFully(batchNumber);

        productionWeek = din.read();
        productionYear = din.read();
        productionWeekByte = (byte) (productionWeek & 0xff);
        productionYearByte = (byte) (productionYear & 0xff);
    }

    public String getHardwareVersion() {
        return hardwareVersionMajor + "." + hardwareVersionMinor;
    }

    public String getSoftwareVersion() {
        return softwareVersionMajor + "." + softwareVersionMinor;
    }

    public int getHardwareVendorId() {
        return hardwareVendorId;
    }

    public void setHardwareVendorId(int hardwareVendorId) {
        this.hardwareVendorId = hardwareVendorId;
    }

    public int getHardwareType() {
        return hardwareType;
    }

    public void setHardwareType(int hardwareType) {
        this.hardwareType = hardwareType;
    }

    public int getHardwareSubtype() {
        return hardwareSubtype;
    }

    public void setHardwareSubtype(int hardwareSubtype) {
        this.hardwareSubtype = hardwareSubtype;
    }

    public int getHardwareVersionMajor() {
        return hardwareVersionMajor;
    }

    public void setHardwareVersionMajor(int hardwareVersionMajor) {
        this.hardwareVersionMajor = hardwareVersionMajor;
    }

    public int getHardwareVersionMinor() {
        return hardwareVersionMinor;
    }

    public void setHardwareVersionMinor(int hardwareVersionMinor) {
        this.hardwareVersionMinor = hardwareVersionMinor;
    }

    public int getHardwareStorageSize() {
        if((hardwareStorageSize & 1) > 0) {
            // >
        } else {
            // =
        }

        return (int)Math.pow (2, hardwareStorageSize >> 1);

        //return String.format("%s%d", ((hardwareStorageSize & 1) > 0 ? ">" : "="), (int)pow (2, hardwareStorageSize >> 1));
    }

    public void setHardwareStorageSize(int hardwareStorageSize) {
        this.hardwareStorageSize = hardwareStorageSize;
    }

    public int getHardwareProtocol() {
        return hardwareProtocol;
    }

    public void setHardwareProtocol(int hardwareProtocol) {
        this.hardwareProtocol = hardwareProtocol;
    }

    public int getSoftwareVendorId() {
        return softwareVendorId;
    }

    public void setSoftwareVendorId(int softwareVendorId) {
        this.softwareVendorId = softwareVendorId;
    }

    public int getSoftwareType() {
        return softwareType;
    }

    public void setSoftwareType(int softwareType) {
        this.softwareType = softwareType;
    }

    public int getSoftwareSubtype() {
        return softwareSubtype;
    }

    public void setSoftwareSubtype(int softwareSubtype) {
        this.softwareSubtype = softwareSubtype;
    }

    public int getSoftwareVersionMajor() {
        return softwareVersionMajor;
    }

    public void setSoftwareVersionMajor(int softwareVersionMajor) {
        this.softwareVersionMajor = softwareVersionMajor;
    }

    public int getSoftwareVersionMinor() {
        return softwareVersionMinor;
    }

    public void setSoftwareVersionMinor(int softwareVersionMinor) {
        this.softwareVersionMinor = softwareVersionMinor;
    }

    public int getSoftwareStorageSize() {
        return (int)Math.pow (2, softwareStorageSize >> 1);
    }

    public void setSoftwareStorageSize(int softwareStorageSize) {
        this.softwareStorageSize = softwareStorageSize;
    }

    public int getSoftwareProtocol() {
        return softwareProtocol;
    }

    public void setSoftwareProtocol(int softwareProtocol) {
        this.softwareProtocol = softwareProtocol;
    }

    public byte[] getUid() {
        return uid;
    }

    public void setUid(byte[] uid) {
        this.uid = uid;
    }

    public byte[] getBatchNumber() {
        return batchNumber;
    }

    public void setBatchNumber(byte[] batchNumber) {
        this.batchNumber = batchNumber;
    }

    public int getProductionWeek() {
        return productionWeek;
    }

    public void setProductionWeek(int productionWeek) {
        this.productionWeek = productionWeek;
    }

    public int getProductionYear() {
        return productionYear;
    }

    public void setProductionYear(int productionYear) {
        this.productionYear = productionYear;
    }

    public byte getProductionWeekByte() {
        return productionWeekByte;
    }

    public void setProductionWeekByte(byte productionWeekByte) {
        this.productionWeekByte = productionWeekByte;
    }

    public byte getProductionYearByte() {
        return productionYearByte;
    }

    public void setProductionYearByte(byte productionYearByte) {
        this.productionYearByte = productionYearByte;
    }

    public String dump() {
        StringBuilder sb = new StringBuilder();
        sb.append("hardwareVendorId: ").append(hardwareVendorId).append("\n");
        sb.append("hardwareType: ").append(hardwareType).append("\n");
        sb.append("hardwareSubtype: ").append(hardwareSubtype).append("\n");
        sb.append("hardwareVersionMajor: ").append(hardwareVersionMajor).append("\n");
        sb.append("hardwareVersionMinor: ").append(hardwareVersionMinor).append("\n");
        sb.append("hardwareStorageSize: ").append(hardwareStorageSize).append("\n");

        sb.append("hardwareProtocol: ").append(hardwareProtocol).append("\n");
        sb.append("softwareVendorId: ").append(softwareVendorId).append("\n");
        sb.append("softwareType: ").append(softwareType).append("\n");
        sb.append("softwareSubtype: ").append(softwareSubtype).append("\n");

        sb.append("softwareType: ").append(softwareType).append("\n");
        sb.append("softwareVersionMajor: ").append(softwareVersionMajor).append("\n");
        sb.append("softwareVersionMinor: ").append(softwareVersionMinor).append("\n");
        sb.append("softwareStorageSize: ").append(softwareStorageSize).append("\n");

        sb.append("softwareProtocol: ").append(softwareProtocol).append("\n");
        sb.append("softwareStorageSize: ").append(softwareStorageSize).append("\n");
        sb.append("Uid: ").append(Utils.bytesToHex(uid)).append("\n");
        sb.append("batchNumber: ").append(Utils.bytesToHex(batchNumber)).append("\n");
        sb.append("productionWeek: ").append(Utils.byteToHex(productionWeekByte)).append("\n");
        sb.append("productionYear: ").append(Utils.byteToHex(productionYearByte)).append("\n");
        sb.append("*** dump ended ***").append("\n");
        return sb.toString();
    }

}