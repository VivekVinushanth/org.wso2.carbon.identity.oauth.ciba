
package org.wso2.carbon.identity.oauth.ciba.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceDataHolder;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

import javax.servlet.http.HttpServletResponse;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.util.UUID;

/**
 * This class create random codes for various purposes.
 */

public class AuthReqManager {

    private static final Log log = LogFactory.getLog(AuthReqManager.class);

    RealmService realmService;

    private AuthReqManager() {

    }

    private static AuthReqManager authReqManagerInstance = new AuthReqManager();

    public static AuthReqManager getInstance() {

        if (authReqManagerInstance == null) {

            synchronized (AuthReqManager.class) {

                if (authReqManagerInstance == null) {

                    /* instance will be created at request time */
                    authReqManagerInstance = new AuthReqManager();
                }
            }
        }
        return authReqManagerInstance;

    }

    /**
     * This method create and returns CIBA auth_req_id
     *
     * @param cibaAuthResponseDTO which contains the validated parameters from the cibA authentication request
     * @return JWT
     * @throws CibaCoreException
     */
    public JWT getCibaAuthCode(CibaAuthResponseDTO cibaAuthResponseDTO) throws CibaCoreException {

        try {
            JWTClaimsSet requestClaims = this.buildJWT(cibaAuthResponseDTO);

            String clientApp = cibaAuthResponseDTO.getAudience();

            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientApp);

            String clientSecret = appDO.getOauthConsumerSecret();
            String tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(clientApp);

            JWT JWTStringAsAuthReqID = OAuth2Util.signJWT(requestClaims, JWSAlgorithm.RS256, tenantDomain);
            //using recommended algorithm by FAPI [PS256,ES256 also  can be used]
            return JWTStringAsAuthReqID;

        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }

    //private CibaAuthResponseDTO buildAuthResponseD

    /**
     * This method create and returns CIBA auth_req_id claims
     *
     * @param cibaAuthResponseDTO which contains the validated parameters from the ciba authentication request
     * @return JWTClaimsSet
     */
    private JWTClaimsSet buildJWT(CibaAuthResponseDTO cibaAuthResponseDTO) {

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience(cibaAuthResponseDTO.getAudience())
                .issuer(cibaAuthResponseDTO.getIssuer())
                .jwtID(cibaAuthResponseDTO.getJWTID())
                .claim(CibaParams.USER_HINT, cibaAuthResponseDTO.getUserHint())
                .claim("exp", cibaAuthResponseDTO.getExpiredTime())
                .claim("iat", cibaAuthResponseDTO.getIssuedTime())
                .claim("nbf", cibaAuthResponseDTO.getNotBeforeTime())
                .claim(CibaParams.SCOPE, cibaAuthResponseDTO.getScope())
                .claim("acr", cibaAuthResponseDTO.getAcrValues())
                .claim(CibaParams.USER_CODE, cibaAuthResponseDTO.getUserCode())
                .claim(CibaParams.BINDING_MESSAGE, cibaAuthResponseDTO.getBindingMessage())
                .claim(CibaParams.TRANSACTION_CONTEXT, cibaAuthResponseDTO.getTransactionContext())
                .build();
        return claims;

    }

    public CibaAuthResponseDTO buildCibaAuthResponseDTO(CibaAuthRequestDTO cibaAuthRequestDTO) {

        CibaAuthResponseDTO cibaAuthResponseDTO = new CibaAuthResponseDTO();

        long issuedTime = ZonedDateTime.now().toInstant().toEpochMilli();
        //  cibaAuthRequestDTO.setIssuedTime(issuedTime); //add missing values
        long durability = this.getExpiresIn(cibaAuthRequestDTO) * 1000;
        long expiryTime = issuedTime + durability;
        // cibaAuthRequestDTO.setExpiredTime(expiryTime);
        long notBeforeUsable = issuedTime + CibaParams.interval * 1000;
        // cibaAuthRequestDTO.setNotBeforeTime(notBeforeUsable);

        cibaAuthResponseDTO.setIssuer(cibaAuthRequestDTO.getAudience());
        cibaAuthResponseDTO.setAudience(cibaAuthRequestDTO.getIssuer());
        cibaAuthResponseDTO.setJWTID(this.getRandomID());
        cibaAuthResponseDTO.setUserHint(cibaAuthRequestDTO.getUserHint());
        cibaAuthResponseDTO.setExpiredTime(expiryTime);
        cibaAuthResponseDTO.setIssuedTime(issuedTime);
        cibaAuthResponseDTO.setNotBeforeTime(notBeforeUsable);
        cibaAuthResponseDTO.setScope(cibaAuthRequestDTO.getScope());
        cibaAuthResponseDTO.setAcrValues(cibaAuthRequestDTO.getAcrValues());
        cibaAuthResponseDTO.setUserCode(cibaAuthRequestDTO.getUserCode());
        cibaAuthResponseDTO.setBindingMessage(cibaAuthRequestDTO.getBindingMessage());
        cibaAuthResponseDTO.setTransactionContext(cibaAuthRequestDTO.getTransactionContext());

        return cibaAuthResponseDTO;
    }

    /**
     * This method create and returns CIBA auth_req_id claims
     *
     * @return random uudi  string
     */
    public String getRandomID() {

        UUID ID = UUID.randomUUID();
        return ID.toString();

    }

    /**
     * This method create hash of the provided auth_req_id
     *
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
     *
     * @param cibaAuthRequestDTO is a auth_req_id
     * @return long - expiry time of the auth-req_id
     */
    public long getExpiresIn(CibaAuthRequestDTO cibaAuthRequestDTO) {

        if (cibaAuthRequestDTO.getRequestedExpiry() == 0) {
            return CibaParams.expiresIn;
        } else {
            return cibaAuthRequestDTO.getRequestedExpiry();
        }
    }

    public long getExpiresInForResponse(CibaAuthResponseDTO cibaAuthResponseDTO) {

        if (cibaAuthResponseDTO.getRequestedExpiry() == 0) {
            return CibaParams.expiresIn;
        } else {
            return cibaAuthResponseDTO.getRequestedExpiry();
        }
    }

    /**
     * This method check whether user exists in store
     *
     * @param tenantID     tenantID of the clientAPP
     * @param user_id_hint that identifies a user
     * @return boolean object
     */
    public boolean isUserExists(int tenantID, String user_id_hint) throws CibaCoreException {

        try {
            return CibaServiceDataHolder.getRealmService().
                    getTenantUserRealm(tenantID).getUserStoreManager().
                    isExistingUser(user_id_hint);

        } catch (UserStoreException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ErrorCodes.INTERNAL_SERVER_ERROR,
                    e.getMessage());
        }

    }

}

