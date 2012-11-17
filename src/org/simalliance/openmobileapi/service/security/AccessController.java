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

package org.simalliance.openmobileapi.service.security;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.security.AccessControlException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.MissingResourceException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.simalliance.openmobileapi.service.CardException;
import org.simalliance.openmobileapi.service.IChannel;
import org.simalliance.openmobileapi.service.ISmartcardServiceCallback;
import org.simalliance.openmobileapi.service.ITerminal;
import org.simalliance.openmobileapi.service.Util;
import org.simalliance.openmobileapi.service.security.ara.AraController;
 

public class AccessController {

    protected PackageManager mPackageManager = null;
    
    protected AraController mAraController = null;
    
    protected final String ACCESS_CONTROLLER_TAG = "AccessController";

    protected final String ARA_ENFORCER = "Access Rule Enforcer: ";

    public AccessController(PackageManager packageManager) {
        mPackageManager = packageManager;
        // by default Access Rule Applet is preferred.
        mAraController = new AraController( this );
    }
    
    public static byte[] getDefaultAccessControlAid(){
    	return AraController.getAraMAid();
    }

    public static Certificate decodeCertificate(byte[] certData) throws CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory
                .generateCertificate(new ByteArrayInputStream(certData));
       
        return cert;
    }
    
    public void checkCommand(IChannel channel, byte[] command) {

        ChannelAccess ca = channel.getChannelAccess();
        String reason = ca.getReason();
        if (reason.length() == 0) {
            reason = "Command not allowed!";
        }
        if (ca == null) {

            throw new AccessControlException(ARA_ENFORCER + "Channel access not set");
        }
        if (ca.isNoAccess()) {

            throw new AccessControlException(ARA_ENFORCER + reason);
        }
        if (ca.isUseApduFilter()) {
            ApduFilter[] accessConditions = ca.getApduFilter();
            if (accessConditions == null || accessConditions.length == 0) {

                throw new AccessControlException(ARA_ENFORCER + "Access Rule not available: " + reason);
            }
            for (ApduFilter ac : accessConditions) {
                if (CommandApdu.compareHeaders(command, ac.getMask(), ac.getApdu())) {

                    return;
                }
            }

            throw new AccessControlException(ARA_ENFORCER + "Access Rule does not match: " + reason);
        }
        if (ca.isApduAccess()) {

            return;
        } else {

            throw new AccessControlException(ARA_ENFORCER + "APDU access NOT allowed" );
        }
    }
    
    
    public boolean[] isNFCEventAllowed(ITerminal terminal, byte[] aid,
            String[] packageNames, ISmartcardServiceCallback callback) throws CardException
    {
    	if( mAraController != null ){
    		return mAraController.isNFCEventAllowed(terminal, aid, packageNames, callback);
    	}
    	


    	return null;
    		
    		
        //ChannelAccess ac = enableAccessConditions(terminal, aid, packageNames, callback, error, true);
        //return ac.isNFCEventAllowedFlags();
    }
    
    public ChannelAccess enableAccessConditions(ITerminal terminal, byte[] aid,
            String[] packageNames, ISmartcardServiceCallback callback) {
        
    	ChannelAccess channelAccess = null;
    	
    	// this is the new GP Access Control Enforcer implementation
    	if( mAraController != null ){
    		try {

    			channelAccess = mAraController.enableAccessConditions(terminal, aid, packageNames, callback);
    		} catch( Exception e ) {
    			if( e instanceof MissingResourceException ) {
    				throw new MissingResourceException( ARA_ENFORCER + e.getMessage(), "", "");
    			}

    			else {
    				throw new AccessControlException( ARA_ENFORCER + "access denied: " + e.getMessage() );
    			}
    		}
    	}


    	if( channelAccess == null || // precautionary check
			(channelAccess.isApduAccess() == false &&
			 channelAccess.isUseApduFilter() == false)) {
    		throw new AccessControlException( ARA_ENFORCER + "no APDU access allowed!" );
    	}
    	

    	
        return channelAccess;
    }
    
    /**
     * Returns Certificate chain for one package.
     * 
     * @param packageName
     * @return
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws AccessControlException
     * @throws CardException
     */
    public Certificate[] getAPPCerts(String packageName)
            throws CertificateException, NoSuchAlgorithmException, AccessControlException,
            CardException {

        List<PackageInfo> pkgInfoList = mPackageManager
                .getInstalledPackages(PackageManager.GET_PERMISSIONS | PackageManager.GET_GIDS
                        | PackageManager.GET_SIGNATURES);
        
        if(packageName == null || packageName.length() == 0)
            throw new AccessControlException("Package Name not defined");

        ArrayList<Certificate> appCerts = new ArrayList<Certificate>();
//        for(String packageName : packageNames)
        {
            PackageInfo foundPkgInfo = null;
            for (PackageInfo pkgInfo : pkgInfoList) {
                if (packageName.equals(pkgInfo.packageName)) {
                    foundPkgInfo = pkgInfo;
                    break;
                }
            }
            if (foundPkgInfo == null) {
                throw new AccessControlException("Package does not exist");
            }
    
            // this is the certificate chain...
            for (Signature signature : foundPkgInfo.signatures) {
                appCerts.add(decodeCertificate(signature.toByteArray()));
                continue;
            }
        }
        return appCerts.toArray(new Certificate[appCerts.size()]);
    }
    
    public static byte[] getAppCertHash(Certificate appCert) throws CertificateEncodingException
    {
        /**
         * Note: This loop is needed as workaround for a bug in Android 2.3.
         * After a failed certificate verification in a previous step the
         * MessageDigest.getInstance("SHA") call will fail with the
         * AlgorithmNotSupported exception. But a second try will normally
         * succeed.
         */
        MessageDigest md = null;
        for (int i = 0; i < 10; i++) {
            try {
                md = MessageDigest.getInstance("SHA");
                break;
            } catch (Exception e) {
            }
        }
        if (md == null) {
            throw new AccessControlException("Hash can not be computed");
        }
        return md.digest(appCert.getEncoded());
    }
}
