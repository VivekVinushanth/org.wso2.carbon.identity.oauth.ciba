package org.wso2.carbon.identity.oauth.ciba.util;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import net.minidev.json.JSONObject;
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

    static long requestedExpiry;

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
    public JWT getCibaAuthCode(String authRequest) throws ParseException, IdentityOAuth2Exception, InvalidOAuthClientException, JOSEException, NoSuchAlgorithmException {
        SignedJWT signedJWT = SignedJWT.parse(authRequest);
        // Payload payload = signedJWT.getPayload();
        JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();

        JWTClaimsSet requestClaims = this.buildJWT(authRequest);
        //JWTClaimsSet requestClaims = signedJWT.getJWTClaimsSet();

        String clientApp = String.valueOf(jo.get("iss"));

        OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientApp);
        String clientSecret = appDO.getOauthConsumerSecret();
        String tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(clientApp);

        JWT JWTStringAsAuthReqID = OAuth2Util.signJWT(requestClaims, JWSAlgorithm.RS256, tenantDomain);  //using recommended algorithm by FAPI [PS256,ES256 also  can be used]

        System.out.println(JWTStringAsAuthReqID);


        return JWTStringAsAuthReqID;
    }

    private static JWTClaimsSet buildJWT(String authRequest) throws ParseException {
        SignedJWT signedJWT = SignedJWT.parse(authRequest);
        JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();

       /* String issuingServer = String.valueOf(jo.get("aud"));*/
        String issuingServer = "wso2.is.ciba";
        String clientApp = String.valueOf(jo.get("iss"));
        String jwtIdentifier = String.valueOf(jo.get("jti"));

      // TODO: 10/4/19 these things have to be verified...change accrodingly

        String scope = String.valueOf(jo.get("scope"));

        // TODO: 10/2/19 consider the following optional paramters and consider what we need to add back 
        String acr = String.valueOf(jo.get("acr"));
        String userCode = String.valueOf(jo.get("user_code")); // can be a null string
        String bindingMessage = String.valueOf(jo.get("binding_message"));


        if (jo.get("requested_expiry") == null) {
            //do nothing
        } else {

            String requestedExpiryasString = String.valueOf(jo.get("requested_expiry"));
            requestedExpiry= Long.parseLong(requestedExpiryasString);

        }

        long issuedTime = ZonedDateTime.now().toInstant().toEpochMilli();
        long durability = CibaConstants.expiresIn * 1000;
        long expiryTime = issuedTime + durability;
        long notBeforeUsable = issuedTime+CibaConstants.interval*1000;


        if ((String.valueOf(jo.get("login_hint_token")) == "null" || String.valueOf(jo.get("login_hint_token")).equals("null"))
                && (String.valueOf(jo.get("login_hint")) != "null"||! String.valueOf(jo.get("login_hint")).equals("null"))
                && (String.valueOf(jo.get("id_token_hint")) == "null" || String.valueOf(jo.get("id_token_hint")).equals("null"))) {

            String login_hint = String.valueOf(jo.get("login_hint"));

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
                    .claim("requested_expiry", requestedExpiry)
                    .claim("user_hint", login_hint)
                    .build();
            return claims;

        } else {
            String id_token_hint = String.valueOf(jo.get("id_token_hint"));

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .claim("iss",issuingServer)
                    .claim("aud", clientApp)
                    .claim("jti", jwtIdentifier)
                    .claim("exp", expiryTime)
                    .claim("iat", issuedTime)
                    .claim("nbf", notBeforeUsable)
                    .claim("scope", scope)
                    .claim("acr", acr)
                    .claim("user_code", userCode)
                    .claim("binding_message", bindingMessage)
                    .claim("requested_expiry", requestedExpiry)
                    .claim("user_hint", id_token_hint)
                    .build();
            return claims;
        }
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

}

