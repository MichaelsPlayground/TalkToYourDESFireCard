package de.androidcrypto.talktoyourdesfirecard.isodep_adapter;

import java.io.IOException;

public interface IsoDepWrapper {

	byte[] transceive(byte[] data) throws IOException;
	
	
}
