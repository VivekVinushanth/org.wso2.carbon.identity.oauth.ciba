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
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

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
     * Generate a random string.
     */
    public JWT getCibaAuthCode(CibaAuthRequestDTO cibaAuthRequestDTO) throws ParseException, IdentityOAuth2Exception, InvalidOAuthClientException, JOSEException, NoSuchAlgorithmException {


        JWTClaimsSet requestClaims = this.buildJWT(cibaAuthRequestDTO);


        String clientApp = cibaAuthRequestDTO.getAudience();

        OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientApp);
        String clientSecret = appDO.getOauthConsumerSecret();
        String tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(clientApp);

        JWT JWTStringAsAuthReqID = OAuth2Util.signJWT(requestClaims, JWSAlgorithm.RS256, tenantDomain);
        //using recommended algorithm by FAPI [PS256,ES256 also  can be used]



        return JWTStringAsAuthReqID;
    }

    private  JWTClaimsSet buildJWT(CibaAuthRequestDTO cibaAuthRequestDTO) throws ParseException {


        String issuingServer = cibaAuthRequestDTO.getIssuer();
        String clientApp = cibaAuthRequestDTO.getAudience();
        String jwtIdentifier = AuthReqIDManager.getInstance().getRandomID();
        String scope = cibaAuthRequestDTO.getScope();
        String acr = cibaAuthRequestDTO.getAcrValues();
        String userCode = cibaAuthRequestDTO.getUserCode(); // can be a null string
        String bindingMessage = cibaAuthRequestDTO.getBindingMessage();
        String userHint = cibaAuthRequestDTO.getUserHint();
        long issuedTime = ZonedDateTime.now().toInstant().toEpochMilli();
        log.info("");
        long durability = this.getExpiresIn(cibaAuthRequestDTO)*1000;
        long expiryTime = issuedTime+durability;
        long notBeforeUsable = issuedTime+ CibaParams.interval*1000;

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
                    .claim("user_hint", userHint)
                    .build();
            return claims;


    }


    public String getRandomID() {
        UUID ID = UUID.randomUUID();
        return ID.toString();

    }

    public String getUserid() {
        UUID userId = UUID.randomUUID();
        return userId.toString();
    }

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
        log.info("Creating cibaAuthrequestCode Hash" +hashtext);
        return hashtext;
    }


    public long getExpiresIn(CibaAuthRequestDTO cibaAuthRequestDTO) {

        if (cibaAuthRequestDTO.getRequestedExpiry() == 0) {
           return CibaParams.expiresIn;
        } else  {
            return cibaAuthRequestDTO.getRequestedExpiry();
        }
    }

}

