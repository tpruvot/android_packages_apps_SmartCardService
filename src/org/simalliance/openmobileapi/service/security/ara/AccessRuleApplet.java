/*
 * Copyright 2010 Giesecke & Devrient GmbH.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package org.simalliance.openmobileapi.service.security.ara;


import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AccessControlException;

import org.simalliance.openmobileapi.service.CardException;
import org.simalliance.openmobileapi.service.IChannel;
import org.simalliance.openmobileapi.service.Util;
import org.simalliance.openmobileapi.service.security.CommandApdu;
import org.simalliance.openmobileapi.service.security.ResponseApdu;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.BerTlv;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.ParserException;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.Response_DO_Factory;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.Response_RefreshTag_DO;

public class AccessRuleApplet {
    
    final private static String ACCESS_RULE_APPLET_TAG = "AccessRuleApplet";  

    final private static CommandApdu mGetSpecific = new CommandApdu(0x80, 0xCA, 0xFF, 0x50, 0x00);

    final private static CommandApdu mGetNext = new CommandApdu(0x80, 0xCA, 0xFF, 0x60, 0x00);

    final private static CommandApdu mGetRefreshTag = new CommandApdu(0x80, 0xCA, 0xDF, 0x20, 0x00 );

    private IChannel mChannel = null;

    public AccessRuleApplet(IChannel channel) {
        mChannel = channel;
    }

    public byte[] readSpecificAccessRule( byte[] aid_ref_do ) throws AccessControlException, CardException {

    	if( aid_ref_do == null ){
			throw new AccessControlException("GET DATA (specific): Reference data object must not be null.");
    	}
    	
    	ByteArrayOutputStream stream = new ByteArrayOutputStream();
    	int arLen = 0;
    	
    	// send GET DATA (specific)
    	CommandApdu apdu = (CommandApdu) mGetSpecific.clone();
        apdu.setData(aid_ref_do);
        ResponseApdu response = send(apdu);
        
        // OK
        if( response.isStatus( 0x9000 ) ){
        	
        	// check if more data has to be fetched
        	BerTlv tempTlv = null;
        	try {
				tempTlv = BerTlv.decode(response.getData(), 0);
			} catch (ParserException e) {
				throw new AccessControlException("GET DATA (specific) not successfull. Tlv encoding wrong.");
			}
			
			// the first data block contain the length of the full TLV.
			arLen = tempTlv.getValueLength();
			
			try {
				stream.write(response.getData());
			} catch (IOException e) {
				throw new AccessControlException("GET DATA (specific) IO problem. " + e.getMessage() );
			}

			int le;
			// send subsequent GET DATA (next) commands
			while( stream.size() < arLen ){
				le = arLen - stream.size();
				if( le > 0xFF ){
					le = 0xFF;
				}
		    	// send GET DATA (next)
		    	apdu = (CommandApdu) mGetNext.clone();
		        apdu.setLe(le);
		        response = send(apdu);
				
		        // OK
		        if( response.isStatus( 0x9000 ) ){
					try {
						stream.write(response.getData());
					} catch (IOException e) {
						throw new AccessControlException("GET DATA (next) IO problem. " + e.getMessage() );
					}
		        } else {
		        	throw new AccessControlException( "GET DATA (next) not successfull, . SW1SW2=" + response.getSW1SW2()); 
		        }
			}
        	return stream.toByteArray();
        	// referenced data not found
        } else if( response.isStatus( 0x6A88 )){
        	return null;
        } else {
        	throw new AccessControlException("GET DATA (specific) not successfull. SW1SW2=" + response.getSW1SW2());
        }
    }

    public long readRefreshTag() throws AccessControlException, CardException {

    	// send GET DATA (specific)
    	CommandApdu apdu = (CommandApdu) mGetRefreshTag.clone();
        ResponseApdu response = send(apdu);
        
        // OK
        if( response.isStatus( 0x9000 ) ){
        	
        	// check if more data has to be fetched
        	BerTlv tempTlv = null;
        	Response_RefreshTag_DO refreshDo;
        	try {
				tempTlv = Response_DO_Factory.createDO(response.getData());
				
				if( tempTlv instanceof Response_RefreshTag_DO ){
					refreshDo = (Response_RefreshTag_DO)tempTlv;
					return refreshDo.getRefreshTag();
				} else {
					throw new AccessControlException("GET REFRESH TAG returned invalid Tlv.");
				}
			} catch (ParserException e) {
				throw new AccessControlException("GET REFRESH TAG not successfull. Tlv encoding wrong.");
			}
        } 
        
        throw new AccessControlException("GET REFRESH TAG not successfull.");			
        
    }

    /*    
    public boolean readAPLCertificate(ByteArrayOutputStream bytes, int offset, int length)
            throws AccessControlException, org.simalliance.openmobileapi.service.CardException {
        CommandApdu apdu = mReadAPLCertificate.clone();
        apdu.setP1(offset >> 8 & 0xFF);
        apdu.setP2(offset & 0xFF);
        apdu.setLe(length & 0xFF);
        ResponseApdu response = send(apdu);
        byte[] data = response.getData();
        bytes.reset();
        try {
			bytes.write(data);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        //bytes.clear();
        //bytes.append(data, 0, data.length);
        if (response.getSW1SW2() == 0x6A86) {
            return true;
        }
        response.checkStatus(new int[] {
                0x9000, 0x6A82
        }, "READ AP CERTIFICATE");
        return false;
    }

    public byte[] readAPKACRecord(byte[] hashApkCert) throws AccessControlException, org.simalliance.openmobileapi.service.CardException {
        CommandApdu apdu = mReadACLRecord.clone();
        apdu.setData(hashApkCert);
        ResponseApdu response = send(apdu);
        if (response.getSW1SW2() == 0x6984) {
            throw new AccessControlException("referenced ACL contains invalid data");
        }
        response.checkStatus(new int[] {
                0x9000, 0x6A83
        }, "READ APK AC RECORD");
        return response.getData();
    }
    
    public boolean readACLRecordNFC(byte[] hashApkCert) throws org.simalliance.openmobileapi.service.CardException {
        CommandApdu apdu = mReadACLRecord.clone();
        apdu.setP2(0x01);
        apdu.setData(hashApkCert);
        ResponseApdu response = send(apdu);
        if(response.getSW1SW2() == 0x9000)  
            return true;
        else
            return false;
    }
*/
    private ResponseApdu send(CommandApdu cmdApdu) throws org.simalliance.openmobileapi.service.CardException {
        
        byte[] response = mChannel.transmit(cmdApdu.toBytes());
        
        ResponseApdu resApdu = new ResponseApdu(response);
        return resApdu;
    }

}
