/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import net.minidev.json.JSONObject;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceDataHolder;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.ZonedDateTime;
import java.util.UUID;


/**
 * This class create random codes for various purposes.
 */

public class AuthReqIDManager {
    private static final Log log = LogFactory.getLog(AuthReqIDManager.class);

RealmService realmService;

    private AuthReqIDManager() {

    }

    private static AuthReqIDManager codeGeneratorInstance = new AuthReqIDManager();

    public static AuthReqIDManager getInstance() {
        if (codeGeneratorInstance == null) {

            synchronized (AuthReqIDManager.class) {

                if (codeGeneratorInstance == null) {

                    /* instance will be created at request time */
                    codeGeneratorInstance = new AuthReqIDManager();
                }
            }
        }
        return codeGeneratorInstance;


    }

    /**
     * This method create and returns CIBA auth_req_id
     * @param cibaAuthRequestDTO which contains the validated parameters from the cibA authentication request
     * @return JWT
     * @throws IdentityOAuth2Exception,ParseException
     */
    public JWT getCibaAuthCode(CibaAuthRequestDTO cibaAuthRequestDTO) throws ParseException,
            IdentityOAuth2Exception, InvalidOAuthClientException, JOSEException, NoSuchAlgorithmException {


        JWTClaimsSet requestClaims = this.buildJWT(cibaAuthRequestDTO);


        String clientApp = cibaAuthRequestDTO.getAudience();

        OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientApp);
        String clientSecret = appDO.getOauthConsumerSecret();
        String tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(clientApp);

        JWT JWTStringAsAuthReqID = OAuth2Util.signJWT(requestClaims, JWSAlgorithm.RS256, tenantDomain);
        //using recommended algorithm by FAPI [PS256,ES256 also  can be used]

        return JWTStringAsAuthReqID;
    }


    /**
     * This method create and returns CIBA auth_req_id claims
     * @param cibaAuthRequestDTO which contains the validated parameters from the cibA authentication request
     * @return JWTClaimsSet
     * @throws IdentityOAuth2Exception,ParseException
     */
    private  JWTClaimsSet buildJWT(CibaAuthRequestDTO cibaAuthRequestDTO) throws ParseException {
        //jwt as a responseDTO

        String issuingServer = cibaAuthRequestDTO.getIssuer();
        String clientApp = cibaAuthRequestDTO.getAudience();
        String jwtIdentifier = AuthReqIDManager.getInstance().getRandomID();
        String scope = cibaAuthRequestDTO.getScope();
        String acr = cibaAuthRequestDTO.getAcrValues();
        String userCode = cibaAuthRequestDTO.getUserCode(); // can be a null string
        String bindingMessage = cibaAuthRequestDTO.getBindingMessage();// can be a null string
        String transactionContext = cibaAuthRequestDTO.getTransactionContext();// can be a null string
        String userHint = cibaAuthRequestDTO.getUserHint();
        long issuedTime = ZonedDateTime.now().toInstant().toEpochMilli();
      //  cibaAuthRequestDTO.setIssuedTime(issuedTime); //add missing values
        long durability = this.getExpiresIn(cibaAuthRequestDTO)*1000;
        long expiryTime = issuedTime+durability;
       // cibaAuthRequestDTO.setExpiredTime(expiryTime);
        long notBeforeUsable = issuedTime+ CibaParams.interval*1000;
       // cibaAuthRequestDTO.setNotBeforeTime(notBeforeUsable);

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .claim("iss", issuingServer)
                    .claim("aud", clientApp)
                    .claim("jti", jwtIdentifier)
                    .claim("exp", expiryTime)
                    .claim("iat", issuedTime)
                    .claim("nbf", notBeforeUsable)
                    .claim("scope", scope)
                    .claim("acr", acr)
                    .claim("user_code", userCode)
                    .claim("binding_message", bindingMessage)
                    .claim("transaction_context", transactionContext)
                    .claim("user_hint", userHint)
                    .build();
            return claims;


    }


    /**
     * This method create and returns CIBA auth_req_id claims
     * @return random uudi  string
     */
    public String getRandomID() {
        UUID ID = UUID.randomUUID();
        return ID.toString();

    }


    /**
     * This method create hash of the provided auth_req_id
     * @param JWTStringAsAuthReqID is a auth_req_id
     * @return String - hashed auth_req_id
     */
    public String createHash(String JWTStringAsAuthReqID) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        // getInstance() method is called with algorithm SHA-512

        // digest() method is called
        // to calculate message digest of the input string
        // returned as array of byte
        byte[] messageDigest = md.digest(JWTStringAsAuthReqID.getBytes());

        // Convert byte array into signum representation
        BigInteger no = new BigInteger(1, messageDigest);

        // Convert message digest into hex value
        String hashtext = no.toString(16);

        // Add preceding 0s to make it 32 bit
        while (hashtext.length() < 32) {
            hashtext = "0" + hashtext;
        }

        // return the HashText
        return hashtext;
    }

    /**
     * This method process and return the expiresin for auth_req_id
     * @param cibaAuthRequestDTO is a auth_req_id
     * @return long - expiry time of the auth-req_id
     */
    public long getExpiresIn(CibaAuthRequestDTO cibaAuthRequestDTO) {

        if (cibaAuthRequestDTO.getRequestedExpiry() == 0) {
           return CibaParams.expiresIn;
        } else  {
            return cibaAuthRequestDTO.getRequestedExpiry();
        }
    }


    /**
     * This method check whether user exists in store
     * @param tenantID tenantID of the clientAPP
     * @param user_id_hint that identifies a user
     * @return boolean
     */
    public  boolean isUserExists(int tenantID,String user_id_hint) throws UserStoreException {
        return CibaServiceDataHolder.getRealmService().
                getTenantUserRealm(tenantID).getUserStoreManager().
                isExistingUser(user_id_hint);

    }

}

