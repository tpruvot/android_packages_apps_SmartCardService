/*
 * Copyright 2012 Giesecke & Devrient GmbH.
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

import java.io.ByteArrayOutputStream;
import java.security.AccessControlException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import org.simalliance.openmobileapi.service.CardException;
import org.simalliance.openmobileapi.service.IChannel;
import org.simalliance.openmobileapi.service.security.ApduFilter;
import org.simalliance.openmobileapi.service.security.AccessController;
import org.simalliance.openmobileapi.service.security.ChannelAccess;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.AID_REF_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.AR_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.BerTlv;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.DO_Exception;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.Hash_REF_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.ParserException;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.REF_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.Response_AR_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.Response_DO_Factory;


import java.util.*;



public class AraControlDB {

    private AccessRuleApplet mApplet;
    
    public AccessRuleApplet getApplet() {
		return mApplet;
	}

	public void setApplet(AccessRuleApplet mApplet) {
		this.mApplet = mApplet;
	}

	private long mRefreshTag = 0L;
    
    private Map<REF_DO, ChannelAccess> mRuleCache = new HashMap<REF_DO, ChannelAccess>();

    AraControlDB() throws AccessControlException, CardException {
    }
    
    public ChannelAccess getAccessRule( byte[] aid, Certificate[] appCerts ) throws AccessControlException, CardException, CertificateEncodingException {

    	ChannelAccess channelAccess = null;
    	long tag = mApplet.readRefreshTag();
    	// generate hash value of end entity certificate...
    	byte[] appCertHash = AccessController.getAppCertHash(appCerts[0]);
    	
    	// check if ARA data has been changed
    	// if yes then reload the channel access rule from ARA.
    	// otherwise it is save to use the cached rule.
    	if( mRefreshTag == tag ) {
        	channelAccess = findAccessRuleInCache( aid, appCertHash );
        	if( channelAccess != null ){
        		return channelAccess;
        	}
    	} else {
    		// if refresh tag differs -> invalidate the whole cache.
    		mRuleCache.clear();
    		mRefreshTag = tag;    		
    	}
    	
    	channelAccess = readAccessRule( aid, appCerts );
    		
    	// if no rule was found return an empty access rule
    	// with all access denied.
    	if( channelAccess == null ){
    		channelAccess = new ChannelAccess();
            channelAccess.setNoAccess(true, "no access rule found!" );
            channelAccess.setApduAccess(false);
    		channelAccess.setNFCEventAllowed(false);
    	} 

    	// save access rule in cache.
    	this.putAccessRuleInCache(aid, appCertHash, channelAccess);
    	
    	return channelAccess;
    }
    
    
    private ChannelAccess readAccessRule( byte[] aid, Certificate[] appCerts) throws AccessControlException, CardException {
    	
    	// TODO: check difference between DeviceCertHash and Certificate Chain (EndEntityCertHash, IntermediateCertHash (1..n), RootCertHash)
    	// The DeviceCertificate is equal to the EndEntityCertificate.
    	// The android systems seems always to deliver only the EndEntityCertificate, but this seems not to be sure.
    	// thats why we implement the whole chain.
    	
    	AID_REF_DO aid_ref_do = null;
    	Hash_REF_DO hash_ref_do = null;
    	AR_DO ar_do = null;
        REF_DO ref_do = null;

        // build-up hash map key as specific as possible.
        REF_DO ref_do_key = null;
		try {
	        ref_do_key = this.buildHashMapKey(aid, AccessController.getAppCertHash(appCerts[0]));
		} catch (CertificateEncodingException e1) {
			throw new AccessControlException("Problem with App Certificate.");
		}
        
    	// Search Rule A ( Certificate(s); AID )
    	// walk through certificate chain.
    	for( Certificate appCert : appCerts ){
    	
	        aid_ref_do = getAidRefDo(aid);    	        
			try {
				hash_ref_do = new Hash_REF_DO(AccessController.getAppCertHash(appCert));
		        ref_do = new REF_DO(aid_ref_do, hash_ref_do);
		        ar_do = readSpecificAccessRule( ref_do );
		        
		        if( ar_do != null ){
		        	return mapArDo2ChannelAccess( ref_do_key, ar_do );
		        }
			} catch (CertificateEncodingException e) {
				throw new AccessControlException("Problem with App Certificate.");
			}
    	}
	    	

    	// SearchRule B ( <AllDeviceApplications>; AID)
    	aid_ref_do =  getAidRefDo(aid);    	        
    	hash_ref_do = new Hash_REF_DO(); // empty hash ref
        ref_do = new REF_DO(aid_ref_do, hash_ref_do);
        ar_do = readSpecificAccessRule( ref_do );
        
        if( ar_do != null ){
        	return mapArDo2ChannelAccess( ref_do_key, ar_do );
        }
    	
    	
    	// Search Rule C ( Certificate(s); <AllSEApplications> )
    	for( Certificate appCert : appCerts ){
        	aid_ref_do = new AID_REF_DO(AID_REF_DO._TAG);        	
	        try {
				hash_ref_do = new Hash_REF_DO(AccessController.getAppCertHash(appCert));
		        ref_do = new REF_DO(aid_ref_do, hash_ref_do);
		        ar_do = readSpecificAccessRule( ref_do );
		        
		        if( ar_do != null ){
		        	return mapArDo2ChannelAccess( ref_do_key, ar_do );
		        }
			} catch (CertificateEncodingException e) {
				throw new AccessControlException("Problem with App Certificate.");
			}
    	}
	    	
    	// SearchRule D ( <AllDeviceApplications>; <AllSEApplications>)
    	aid_ref_do =  new AID_REF_DO(AID_REF_DO._TAG); 
    	hash_ref_do = new Hash_REF_DO();
        ref_do = new REF_DO(aid_ref_do, hash_ref_do);
        ar_do = readSpecificAccessRule( ref_do );
        
        if( ar_do != null ){
        	return mapArDo2ChannelAccess( ref_do_key, ar_do );
        }
        
        return null;
    }
    
    private AR_DO readSpecificAccessRule( REF_DO ref_do  ) throws AccessControlException, CardException {

    	ByteArrayOutputStream out = new ByteArrayOutputStream(); 
        try {
			ref_do.build(out);
			
			byte[] data = mApplet.readSpecificAccessRule(out.toByteArray());
			// no data returned, but no exception
			// -> no rule.
			if( data == null ) {
				return null;
			}
			
			BerTlv tlv = Response_DO_Factory.createDO( data );
			if( tlv == null ) {
				return null; // no rule
			} if( tlv instanceof Response_AR_DO ){
				return ((Response_AR_DO)tlv).getArDo(); 
			} else {
				throw new AccessControlException( "Applet returned invalid or wrong data object!");
			}
			
		} catch (DO_Exception e) {
			throw new AccessControlException("Data Object Exception: " + e.getMessage());
		} catch (ParserException e) {
			throw new AccessControlException("Parsing Data Object Exception: " + e.getMessage());
		}
    }
    
    private ChannelAccess mapArDo2ChannelAccess(REF_DO ref_do, AR_DO ar_do ){
    	ChannelAccess channelAccess = new ChannelAccess();
    	
    	// check apdu access allowance
    	if( ar_do.getApduArDo() != null ){
        	// first if there is a rule for access, reset the general deny flag.
    		channelAccess.setNoAccess(false, "");
			channelAccess.setUseApduFilter(false);
	    	
	    	if( ar_do.getApduArDo().isApduAllowed() ){
	    		// check the apdu filter
	    		ArrayList<byte[]> apduHeaders = ar_do.getApduArDo().getApduHeaderList();
	    		ArrayList<byte[]> filterMasks = ar_do.getApduArDo().getFilterMaskList();
	    		if( apduHeaders != null &&
	    			filterMasks != null && 
	    			apduHeaders.size() > 0 &&
	    			apduHeaders.size() == filterMasks.size()  ){
	    			
	    			ApduFilter[] accessConditions = new ApduFilter[apduHeaders.size()];
	    			for( int i = 0; i < apduHeaders.size(); i++){
	    				accessConditions[i] = new ApduFilter( apduHeaders.get(i), filterMasks.get(i));
	    			}
	    			channelAccess.setUseApduFilter(true);
	    			channelAccess.setApduFilter(accessConditions);
	    		} else {
	    			// general APDU access
	    			channelAccess.setApduAccess(true);
	    		}
	    	} else {
	    		// apdu access is not allowed at all.
	    		channelAccess.setApduAccess(false);
	    	}
    	} else {
    		channelAccess.setNoAccess(true, "No APDU access rule available.!");
    	}
    	
    	// check for NFC Event allowance
    	if( ar_do.getNfcArDo() != null ){
    		channelAccess.setNFCEventAllowed(ar_do.getNfcArDo().isNfcAllowed());
    	} else {
    		channelAccess.setNFCEventAllowed(false);
    	}

    	mRuleCache.put(ref_do, channelAccess);
    	return channelAccess;
    }
    
    private void putAccessRuleInCache( byte[] aid, byte[] appCertHash, ChannelAccess channelAccess ) {
    	REF_DO ref_do = this.buildHashMapKey(aid, appCertHash);
	    mRuleCache.put(ref_do, channelAccess);
    }

    private ChannelAccess findAccessRuleInCache( byte[] aid, byte[] appCertHash ) {
    	REF_DO ref_do = this.buildHashMapKey(aid, appCertHash);
	    return mRuleCache.get(ref_do);
    }

    private REF_DO buildHashMapKey( byte[] aid, byte[] appCertHash ){
		// Build key
	    Hash_REF_DO hash_ref_do = new Hash_REF_DO(appCertHash) ;
	    REF_DO ref_do = new REF_DO(getAidRefDo(aid), hash_ref_do);
	    
	    return ref_do;
    }
    
    private AID_REF_DO getAidRefDo( byte[] aid ){
	    AID_REF_DO aid_ref_do = null;
	    byte[] defaultAid = new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00 }; // this is the placeholder for the default aid.
	    
	    if( aid == null || Arrays.equals( aid, defaultAid )){
	    	aid_ref_do = new AID_REF_DO(AID_REF_DO._TAG_DEFAULT_APPLICATION);        	
	    } else {
	    	aid_ref_do = new AID_REF_DO(AID_REF_DO._TAG, aid);        	
	    }
	    
	    return aid_ref_do;
    }
}
