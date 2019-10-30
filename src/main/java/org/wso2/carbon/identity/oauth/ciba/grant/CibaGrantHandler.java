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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.grant;

import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.oauth.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaAuthCodeMgtDAO;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaAuthMgtDAO;
import net.minidev.json.JSONObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth.ciba.util.AuthReqManager;

import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.ZonedDateTime;
import javax.servlet.http.HttpServletResponse;

/**
 * Grant Handler for Ciba.
 */

public class CibaGrantHandler extends AbstractAuthorizationGrantHandler {

    // This is used to keep the pre processed authorization code in the OAuthTokenReqMessageContext.
    public static final String AUTH_REQ_ID = "auth_req_id";
    private static final String INVALID_GRANT = "invalid_grant";
    private static final String MISSING_AUTH_REQ_ID = "auth_req_id_missing";
    private static Log log = LogFactory.getLog(CibaGrantHandler.class);

    /**
     * @param tokReqMsgCtx Token message request context.
     * @return Boolean Returns true if valid grant or else otherwise.
     * @throws IdentityOAuth2Exception OAuth2Exception
     */
    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        super.validateGrant(tokReqMsgCtx);
        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        String auth_req_id = null; //initiating auth_req_id

        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();

        // Obtaining auth_req_id from request
        for (RequestParameter parameter : parameters) {
            if (AUTH_REQ_ID.equals(parameter.getKey())) {
                if (parameter.getValue() != null && parameter.getValue().length > 0) {
                    auth_req_id = parameter.getValue()[0];
                }
            }
        }

        if (auth_req_id == null) {
            if(log.isDebugEnabled()){

            }
            throw new IdentityOAuth2Exception(MISSING_AUTH_REQ_ID);
        }

        if (!tokenReq.getGrantType().equals(CibaParams.OAUTH_CIBA_GRANT_TYPE)) {
            throw new IdentityOAuth2Exception(INVALID_GRANT);
        }

        try {
            SignedJWT signedJWT = SignedJWT.parse(auth_req_id);

            JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();
            CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();


            // Validate polling for tokenRequest.
            validatePolling(jo, auth_req_id, cibaAuthCodeDO);

            this.setPropertiesForTokenGeneration(tokReqMsgCtx, tokenReq, auth_req_id, cibaAuthCodeDO);
            return true;

        } catch (ParseException | CibaCoreException e) {
            throw new IdentityOAuth2Exception("invalid_request_parameters");

        }

    }

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenRespDTO tokenRespDTO = super.issue(tokReqMsgCtx);

        return tokenRespDTO;
    }

    public void validatePolling(JSONObject auth_req_id, String authReqID, CibaAuthCodeDO cibaAuthCodeDO)
            throws IdentityOAuth2Exception, CibaCoreException {

        try {
            String authReqIdKey = this.getCodeIDfromAuthReqCodeHash(authReqID);
            CibaAuthCodeMgtDAO.getInstance().getCibaAuthCodeDO(authReqIdKey,cibaAuthCodeDO);

            validateAuthReqID(authReqID);

            validateIssuer(auth_req_id);

            validateAudience(auth_req_id);

            validatePollingAllowed(cibaAuthCodeDO);

            activeAuthreqID(cibaAuthCodeDO);

            validatePollingFrequency(cibaAuthCodeDO);

            if (IsConsentGiven(cibaAuthCodeDO).equals(false)) {
                throw new IdentityOAuth2Exception("consent_denied");

            }

            if (IsUserAuthenticated(cibaAuthCodeDO).equals(false)) {
                //authentication status has to be obtained from db
                throw new IdentityOAuth2Exception("authorization_pending");

            }


        } catch (CibaCoreException ex) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ErrorCodes.INTERNAL_SERVER_ERROR
                    , ex.getErrorDescritption());
        }
    }

    public Boolean IsConsentGiven(CibaAuthCodeDO cibaAuthCodeDO) {

        return !cibaAuthCodeDO.getAuthenticationStatus().equals(AuthenticationStatus.DENIED.toString());
    }

    public String getCodeIDfromAuthReqCodeHash(String authReqID)
            throws CibaCoreException {

        try {
            String hashedCibaAuthReqCode = AuthReqManager.getInstance().createHash(authReqID);
            log.info("hashed at grant : " + hashedCibaAuthReqCode);

            if (CibaAuthMgtDAO.getInstance().isHashedAuthReqIDExists(hashedCibaAuthReqCode)) {
                return CibaAuthMgtDAO.getInstance().getCibaAuthCodeDOKey(hashedCibaAuthReqCode);
            } else {
                return null;
            }
        } catch (NoSuchAlgorithmException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ErrorCodes.INTERNAL_SERVER_ERROR
                    , e.getMessage());
        }

    }

    public void validateAuthReqID(String authReqID)
            throws CibaCoreException, IdentityOAuth2Exception {
        // Validate whether auth_req_id issued or not.
        try {

            String hashedAuthReqID = AuthReqManager.getInstance().createHash(authReqID);

            //check whether the incoming auth_req_id exists/ valid.
            if (!CibaAuthMgtDAO.getInstance().isHashedAuthReqIDExists(hashedAuthReqID)) {
                throw new IdentityOAuth2Exception("invalid auth_req_id");

            }
        } catch (NoSuchAlgorithmException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ErrorCodes.INTERNAL_SERVER_ERROR,
                    e.getMessage());
        }

    }

    public void validateIssuer(JSONObject auth_req_id) throws IdentityOAuth2Exception {

        String issuer = String.valueOf(auth_req_id.get("iss"));
        if (issuer == null || StringUtils.isBlank(issuer)) {
            throw new IdentityOAuth2Exception("invalid auth_req_id");
        }

        if (!issuer.equals(CibaParams.CIBA_AS_AUDIENCE)) {
            throw new IdentityOAuth2Exception("invalid auth_req_id");
        }

    }

    public void validateAudience(JSONObject auth_req_id) throws IdentityOAuth2Exception {

        try {
            String audience = String.valueOf(auth_req_id.get("aud"));

            if (audience == null || StringUtils.isBlank(audience)) {
                throw new IdentityOAuth2Exception("invalid auth_req_id");
            }

            OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(audience);

        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("invalid auth_req_id");
        }

    }

    public void activeAuthreqID(CibaAuthCodeDO cibaAuthCodeDO) throws IdentityOAuth2Exception {
        //to check whether auth_req_id has expired or not
        /*        String expiryTimeasString = String.valueOf(auth_req_id.get("exp"));*/
        long expiryTime = cibaAuthCodeDO.getExpiryTime();

        long currentTime = ZonedDateTime.now().toInstant().toEpochMilli();
        if (currentTime > expiryTime) {
            if (log.isDebugEnabled()) {
                log.debug("CIBA AuthReqID is in expired state.Token Request Denied.");
            }
            throw new IdentityOAuth2Exception("expired_token");

        }
    }

    public void validatePollingAllowed(CibaAuthCodeDO cibaAuthCodeDO) {

        return;  //incase if implementing 'ping mode' in future.
    }

    public void validatePollingFrequency(CibaAuthCodeDO cibaAuthCodeDO)
            throws IdentityOAuth2Exception, CibaCoreException {
        //Check the frequency of polling and do the needfull

            long currentTime = ZonedDateTime.now().toInstant().toEpochMilli();

            long lastpolltime = cibaAuthCodeDO.getLastPolledTime();
            long interval = cibaAuthCodeDO.getInterval();
            String cibaAuthCodeID = cibaAuthCodeDO.getCibaAuthCodeDOKey();

            if (!(currentTime - lastpolltime > interval * 1000)) {

                long newInterval = interval + CibaParams.INTERVAL_INCREMENT;
                if (log.isDebugEnabled()) {
                    log.debug("Incorrect Polling frequency.Updated the Polling frequency on the table.");
                }

                CibaAuthMgtDAO.getInstance().updatePollingInterval(cibaAuthCodeID, newInterval);
                throw new IdentityOAuth2Exception("slow_down");
            }

            // Update last pollingTime.
            CibaAuthMgtDAO.getInstance().updateLastPollingTime(cibaAuthCodeID, currentTime);
    }

    public Boolean IsUserAuthenticated(CibaAuthCodeDO cibaAuthCodeDO)
            throws CibaCoreException {

        //String cibaAuthCodeID = this.getCodeIDfromAuthReqCodeHash(authReqID);

        // String authenticationStatus = CibaAuthMgtDAO.getInstance().getAuthenticationStatus(cibaAuthCodeID);

        String authenticationStatus = cibaAuthCodeDO.getAuthenticationStatus();
        String cibaAuthCodeID = cibaAuthCodeDO.getCibaAuthCodeDOKey();
        if (authenticationStatus.equals(AuthenticationStatus.AUTHENTICATED.toString())) {
            //if authenticated update the status as token delivered.
            CibaAuthMgtDAO.getInstance().persistStatus(cibaAuthCodeID, AuthenticationStatus.
                    TOKEN_DELIVERED.toString());
            log.info("User Authenticated.");
            return true;
        } else if (authenticationStatus.equals(AuthenticationStatus.TOKEN_DELIVERED.toString())) {
            log.info("Token Already delievered.");
            return true;

        } else {
            if (log.isDebugEnabled()) {
                log.info("User still not authenticated.Client can keep polling till authReqID expired.");
            }

            return false;
        }
    }

    public void setPropertiesForTokenGeneration(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                OAuth2AccessTokenReqDTO tokenReq, String auth_req_id,
                                                CibaAuthCodeDO cibaAuthCodeDO)
            throws ParseException {

        SignedJWT signedJWT = SignedJWT.parse(auth_req_id);

        //String payload = signedJWT.getPayload().toString();
        //System.out.println("Payload" + payload);

        JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();
        String[] scope = OAuth2Util.buildScopeArray(String.valueOf(jo.get("scope")));

        String authenticatedUserName = cibaAuthCodeDO.getAuthenticatedUser();

        tokReqMsgCtx.setAuthorizedUser(OAuth2Util.getUserFromUserName(authenticatedUserName));
        tokReqMsgCtx.setScope(scope);


    }

}