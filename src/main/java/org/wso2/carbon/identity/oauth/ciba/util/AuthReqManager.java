
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

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.util.UUID;
import javax.servlet.http.HttpServletResponse;

/**
 * This class create authcode and authResponse DTO.
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
     * This method create and returns ciba AuthCodeDO.
     *
     * @param cibaAuthResponseDTO which is infiltarted with validated paramters from authRequestDTO.
     * @return JWT CibaAuthCode which will have necessary claims for auth_req_id.
     * @throws CibaCoreException Exception thrown at CibaCoreComponent.
     */
    public JWT getCibaAuthCode(CibaAuthResponseDTO cibaAuthResponseDTO) throws CibaCoreException {

        String clientId = cibaAuthResponseDTO.getAudience();
        try {
            JWTClaimsSet requestClaims = this.buildJWT(cibaAuthResponseDTO);

            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientId);

            String clientSecret = appDO.getOauthConsumerSecret();
            String tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(clientId);

            JWT JWTStringAsAuthReqID = OAuth2Util.signJWT(requestClaims, JWSAlgorithm.RS256, tenantDomain);
            // Using recommended algorithm by FAPI [PS256,ES256 also  can be used]

            if (log.isDebugEnabled()) {
                log.debug("Returning CibaAuthCode for the request made by client : " + clientId);
            }
            return JWTStringAsAuthReqID;

        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error in building and returning CibaAuthCode for the request made by client : " + clientId);
            }
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }

    /**
     * This method create and returns CIBA auth_req_id claims.
     *
     * @param cibaAuthResponseDTO Contains the validated parameters from the ciba authentication request.
     * @return JWTClaimsSet Returns JWT.
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

        if (log.isDebugEnabled()) {
            log.debug("Successfully created JWT from CibaAuthResponseDTO and returning in regard to the   " +
                    "the request made by client " + cibaAuthResponseDTO.getAudience());
        }

        return claims;

    }

    /**
     * This method transfers validated values of AuthenticationRequestDTO to AuthenticationResponseDTO.
     *
     * @param cibaAuthRequestDTO Ciba Authentication Request DTO.
     * @return CibaAuthResponseDTO Returns JWT.
     */
    public CibaAuthResponseDTO buildCibaAuthResponseDTO(CibaAuthRequestDTO cibaAuthRequestDTO) {

        CibaAuthResponseDTO cibaAuthResponseDTO = new CibaAuthResponseDTO();

        long issuedTime = ZonedDateTime.now().toInstant().toEpochMilli();
        long durability = this.getExpiresIn(cibaAuthRequestDTO) * 1000;
        long expiryTime = issuedTime + durability;
        long notBeforeUsable = issuedTime + CibaParams.interval * 1000;

        cibaAuthResponseDTO.setIssuer(cibaAuthRequestDTO.getAudience());
        cibaAuthResponseDTO.setAudience(cibaAuthRequestDTO.getIssuer());
        cibaAuthResponseDTO.setJWTID(this.getUniqueAuthCodeDOKey());
        cibaAuthResponseDTO.setUserHint(cibaAuthRequestDTO.getUserHint());
        cibaAuthResponseDTO.setExpiredTime(expiryTime);
        cibaAuthResponseDTO.setIssuedTime(issuedTime);
        cibaAuthResponseDTO.setNotBeforeTime(notBeforeUsable);
        cibaAuthResponseDTO.setScope(cibaAuthRequestDTO.getScope());
        cibaAuthResponseDTO.setAcrValues(cibaAuthRequestDTO.getAcrValues());
        cibaAuthResponseDTO.setUserCode(cibaAuthRequestDTO.getUserCode());
        cibaAuthResponseDTO.setBindingMessage(cibaAuthRequestDTO.getBindingMessage());
        cibaAuthResponseDTO.setTransactionContext(cibaAuthRequestDTO.getTransactionContext());

        if (log.isDebugEnabled()) {
            log.debug("Successfully transferred validated values from CIbaAuthRequestDTO to CibaAuthResponseDTO and " +
                    "for the  request made by client : " + cibaAuthResponseDTO.getAudience());
        }

        return cibaAuthResponseDTO;
    }

    /**
     * This method returns a unique AuthCodeDOKey.
     *
     * @return String Returns random uuid.
     */
    public String getUniqueAuthCodeDOKey() {

        UUID id = UUID.randomUUID();
        return id.toString();

    }

    /**
     * This method returns a random id.
     *
     * @return String Returns random uuid.
     */
    public String getUniqueID() {

        UUID uuid = UUID.randomUUID();
        return uuid.toString();

    }

    /**
     * This method create hash of the provided auth_req_id.
     *
     * @param JWTStringAsAuthReqID auth_req_id.
     * @return String Hashed auth_req_id.
     */
    public String createHash(String JWTStringAsAuthReqID) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        // getInstance() method is called with algorithm SHA-512

        // digest() method is called.
        // To calculate message digest of the input string.
        // Returned as array of byte.
        byte[] messageDigest = md.digest(JWTStringAsAuthReqID.getBytes());

        // Convert byte array into signum representation.
        BigInteger no = new BigInteger(1, messageDigest);

        // Convert message digest into hex value.
        String hashtext = no.toString(16);

        // Add preceding 0s to make it 32 bit.
        while (hashtext.length() < 32) {
            hashtext = "0" + hashtext;
        }

        // Return the HashText.
        return hashtext;
    }

    /**
     * This method process and return the expires_in for auth_req_id.
     *
     * @param cibaAuthRequestDTO DTO accumulating validated parameters from CibaAuthenticationRequest.
     * @return long Returns expiry_time of the auth-req_id.
     */
    public long getExpiresIn(CibaAuthRequestDTO cibaAuthRequestDTO) {

        if (cibaAuthRequestDTO.getRequestedExpiry() == 0) {
            return CibaParams.expiresIn;
        } else {
            return cibaAuthRequestDTO.getRequestedExpiry();
        }
    }

    /**
     * This method process and return the expires_in for auth_req_id.
     *
     * @param cibaAuthResponseDTO DTO accumulating response parameters.
     * @return long Returns expiry_time of the auth-req_id.
     */
    public long getExpiresInForResponse(CibaAuthResponseDTO cibaAuthResponseDTO) {

        if (cibaAuthResponseDTO.getRequestedExpiry() == 0) {
            return CibaParams.expiresIn;
        } else {
            return cibaAuthResponseDTO.getRequestedExpiry();
        }
    }

    /**
     * This method check whether user exists in store.
     *
     * @param tenantID     tenantID of the clientAPP
     * @param userIdHint that identifies a user
     * @return boolean Returns whether user exists in store.
     */
    public boolean isUserExists(int tenantID, String userIdHint) throws CibaCoreException {

        try {
            return CibaServiceDataHolder.getRealmService().
                    getTenantUserRealm(tenantID).getUserStoreManager().
                    isExistingUser(userIdHint);

        } catch (UserStoreException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ErrorCodes.INTERNAL_SERVER_ERROR,
                    e.getMessage());
        }

    }

}

