/*
 * Copyright 2012 Giesecke & Devrient GmbH.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.simalliance.openmobileapi.service.security.ara;

import android.util.Log;

import java.security.AccessControlException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.NoSuchElementException;
import java.util.MissingResourceException;

import org.simalliance.openmobileapi.service.CardException;
import org.simalliance.openmobileapi.service.IChannel;
import org.simalliance.openmobileapi.service.ISmartcardServiceCallback;
import org.simalliance.openmobileapi.service.ITerminal;
import org.simalliance.openmobileapi.service.security.AccessController;
import org.simalliance.openmobileapi.service.security.ChannelAccess;

public class AraController {

    protected AraControlDB mAccessControlDB = null;

    protected AccessController mMaster = null;
    
    protected boolean[] mNfcEventFlags = null;
    
    protected boolean mNoSuchElement = false;

    protected String ACCESS_CONTROLLER_TAG = "ARA AccessController";

    public static final byte[] ARA_M_AID = new byte[] {
            (byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x51, (byte)0x41, (byte)0x43, (byte)0x4C,
            (byte)0x00
    };

    public AraController(AccessController master) {
    	mMaster = master;
    }

    public boolean isNoSuchElement(){
    	return mNoSuchElement;
    }
    
    public static byte[] getAraMAid() {
        return ARA_M_AID;
    }
    
    public boolean[] isNFCEventAllowed(ITerminal terminal, byte[] aid,
            String[] packageNames, ISmartcardServiceCallback callback) throws CardException
    {
    	// the NFC Event Flags boolean array is created and filled in internal_enableAccessConditions.
    	mNfcEventFlags = null;
        enableAccessConditions(terminal, aid, packageNames, callback, true);
        return mNfcEventFlags;
    }
    
    public ChannelAccess enableAccessConditions(ITerminal terminal, byte[] aid,
            String[] packageNames, ISmartcardServiceCallback callback) {
        
        return enableAccessConditions(terminal, aid, packageNames, callback, false);
    }

    protected ChannelAccess enableAccessConditions(ITerminal terminal, byte[] aid,
            String[] packageNames, ISmartcardServiceCallback callback, boolean checkForNfcAccess) {
        
        ChannelAccess channelAccess = new ChannelAccess();
        IChannel channel = null;
    	String reason = "";
    	
        try {
            channel = openChannel(terminal, getAraMAid(), callback);
        } catch (Exception e) {
            String msg = e.toString();
            msg = " ARA-M couldn't be selected: " + msg;

            if (e instanceof NoSuchElementException) { 
            	mNoSuchElement = true;
                // SELECT failed
                // Access Rule Applet is not available => deny any access
            	reason = " No Access because ARA-M is not available";

                throw new AccessControlException(reason);
                
            } else if( e instanceof MissingResourceException ){ 
            	// re-throw exception
            	// fixes issue 23
            	// this indicates that no channel is left for accessing the SE element
            	throw (MissingResourceException)e;
        	}else { 
                // MANAGE CHANNEL failed or other error
                // no free channel available or another error => No access => Deny Any Access
            	reason = msg;

                throw new AccessControlException(reason);
            }
        }   // End of Exception handling

        try {
            // Read content from ARA 

            channelAccess = internalEnableAccessConditions(channel, aid, packageNames, checkForNfcAccess);

        } catch (Exception e) {
            String msg = e.toString();
            reason = "ARA error: " + msg;

            closeChannel(channel);
            throw new AccessControlException(msg); // Throw Exception
        }
        closeChannel(channel);
        return channelAccess;
    }
    
    protected IChannel openChannel(ITerminal terminal, byte[] aid, ISmartcardServiceCallback callback) throws Exception
    {


        long hChannel = terminal.openLogicalChannel(aid, callback);

        IChannel channel = terminal.getChannel(hChannel);
        // set access conditions to access ARA-M.
        ChannelAccess araChannelAccess = new ChannelAccess();
        araChannelAccess.setNoAccess(false, "");
        araChannelAccess.setApduAccess(true);
        channel.setChannelAccess(araChannelAccess);
        return channel;
}

    protected void closeChannel(IChannel channel) {
        try {
            if (channel != null && channel.getChannelNumber() != 0) {

                channel.close();

            }
        } catch (org.simalliance.openmobileapi.service.CardException e) {
        }
    }

    protected ChannelAccess internalEnableAccessConditions(IChannel channel, byte[] aid,
            String[] packageNames, boolean checkForNfcAccess) throws NoSuchAlgorithmException, AccessControlException,
            CardException, CertificateException {

        ChannelAccess channelAccess = new ChannelAccess();
        if (channel == null) {
            throw new AccessControlException("channel must be specified");
        }
        if (packageNames == null || packageNames.length == 0) {
            throw new AccessControlException("package names must be specified");
        }
        if (aid == null || aid.length == 0) {
            throw new AccessControlException("AID must be specified");
        }
        if (aid.length < 5 || aid.length > 16) {
            throw new AccessControlException("AID has an invalid length");
        }
        
        // create ara controller db if not available 
        // otherwise re-use access controller DB for caching
        if( mAccessControlDB == null ) { 
        	mAccessControlDB = new AraControlDB();
        } 
        // set new applet handler since a new channel is used.
    	mAccessControlDB.setApplet(new AccessRuleApplet(channel));
        
        if(checkForNfcAccess) // NFC Access Control
        {
           mNfcEventFlags = new boolean[packageNames.length];
           int i=0;
           for( String packageName : packageNames ) {
               // estimate the device application's certificates.
               Certificate[] appCerts = mMaster.getAPPCerts(packageName);
               // APP certificates must be available => otherwise Exception
               if (appCerts == null || appCerts.length == 0) {
                   throw new AccessControlException("Application Certificates are invalid or do not exist.");
               }
        	   

                channelAccess = mAccessControlDB.getAccessRule(aid, appCerts);
                mNfcEventFlags[i] = channelAccess.isNFCEventAllowed();

                i++;
           }
           // return null since the intresting data is in the boolean array mNfcEventFlags
           return null;
        }
        else // SE Access Control
        {
            if(packageNames.length > 1)
                throw new AccessControlException(" Only one package name is allowed");
            
            // estimate device application's certificates.
            Certificate[] appCerts = mMaster.getAPPCerts(packageNames[0]);
            
            // APP certificates must be available => otherwise Exception
            if (appCerts == null || appCerts.length == 0) {
                throw new AccessControlException("Application certificates are invalid or do not exist.");
            }

            try {

                channelAccess = mAccessControlDB.getAccessRule(aid, appCerts);

            } catch (Throwable exp) {


                throw new AccessControlException(exp.getMessage());
            }
            return channelAccess;
        }
    }
    
    protected byte[] getEmptyHash() {
        return new byte[] {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
    }
    
    
    protected boolean checkAPPCert(Certificate aplCert, Certificate appCert) {

        if (appCert.equals(aplCert)) {
            return true;
        }

        try {
            PublicKey apPublicKey = aplCert.getPublicKey();
            appCert.verify(apPublicKey);
            return true;
        } catch (Exception e) {
            // APKP Certificate couldn't be verified
        }

        return false;
    }
}
