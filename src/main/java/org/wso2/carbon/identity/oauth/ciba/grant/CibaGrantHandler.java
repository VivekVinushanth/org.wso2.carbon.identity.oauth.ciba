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
import org.wso2.carbon.identity.oauth.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaAuthResponseMgtDAO;
import net.minidev.json.JSONObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth.ciba.util.AuthReqIDManager;

import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.text.ParseException;
import java.time.ZonedDateTime;

public class CibaGrantHandler  extends AbstractAuthorizationGrantHandler {

    // This is used to keep the pre processed authorization code in the OAuthTokenReqMessageContext.
    public static final String AUTH_REQ_ID = "auth_req_id";
    private static Log log = LogFactory.getLog(CibaGrantHandler.class);

    /**
     * @param tokReqMsgCtx Token message request context
     * @return true if validation is successful, false otherwise
     * @throws IdentityOAuth2Exception
     */
    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        super.validateGrant(tokReqMsgCtx);
        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        String auth_req_id= null; //initiating auth_req_id
        boolean isValid=false;

        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();

        // Obtaining auth_req_id from request
        for(RequestParameter parameter : parameters){
            if(AUTH_REQ_ID.equals(parameter.getKey())){
                if(parameter.getValue() != null && parameter.getValue().length > 0){
                    auth_req_id = parameter.getValue()[0];
                }
            }
        }

        if(auth_req_id != null) {
            if (!tokenReq.getGrantType().equals(CibaParams.OAUTH_CIBA_GRANT_TYPE)) {

                throw new IdentityOAuth2Exception("Invalid GrantType.");


            } else {

                SignedJWT signedJWT = null;
                try {
                    signedJWT = SignedJWT.parse(auth_req_id);

                    //String payload = signedJWT.getPayload().toString();
                    //System.out.println("Payload" + payload);

                    JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();
                    CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
                    if(handlePolling(jo,auth_req_id,cibaAuthCodeDO)) {
                        isValid = true;
                        this.setPropertiesForTokenGeneration(tokReqMsgCtx, tokenReq, auth_req_id,cibaAuthCodeDO);
                    }
                } catch (ParseException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (SQLException e) {
                    e.printStackTrace();
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }


            }
        } else {

            throw new IdentityOAuth2Exception("Invalid request.");

        }

        return isValid;

    }

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenRespDTO tokenRespDTO = super.issue(tokReqMsgCtx);

        return tokenRespDTO;
    }

    private boolean handlePolling(JSONObject auth_req_id,String authReqID,CibaAuthCodeDO cibaAuthCodeDO)
            throws NoSuchAlgorithmException, SQLException, ClassNotFoundException, IdentityOAuth2Exception {

        if (IsAuthReqIDValid(auth_req_id,authReqID).equals(false)) {
            throw new IdentityOAuth2Exception("Invalid auth_req_id.");

        } else {
            String authCodeID = this.getCodeIDfromAuthReqCodeHash(authReqID);
            log.info("found code"+authCodeID);
            CibaAuthResponseMgtDAO.getInstance().getAuthCodeDO(authCodeID,cibaAuthCodeDO);
            log.info("found this" + cibaAuthCodeDO.getCibaAuthCodeID());
            if (IsPollingAllowed(cibaAuthCodeDO).equals(false)) {
                throw new IdentityOAuth2Exception("Polling is not allowed.");

            } else if (IsAuthReqIDActive(cibaAuthCodeDO).equals(false)) {
                //can be done with both.Done with cibaAuthCodeObject
                throw new IdentityOAuth2Exception("expired_token");

            } else if (IsCorrectPollingFrequency(cibaAuthCodeDO).equals(false)) {
                //need db anyhow
                throw new IdentityOAuth2Exception("Slow Down.");

            } else if (IsUserAuthenticated(cibaAuthCodeDO).equals(false)){
                //authentication status has to be obtained from db

                throw new IdentityOAuth2Exception("Authorization Pending.");

            } else {

                return true;
            }
        }

    }



    private String getCodeIDfromAuthReqCodeHash(String authReqID)
            throws NoSuchAlgorithmException, SQLException, ClassNotFoundException {
        /*  String authReqID = auth_req_id.toString();*/
        String hashedCibaAuthReqCode = AuthReqIDManager.getInstance().createHash(authReqID);


        if (CibaAuthResponseMgtDAO.getInstance().isHashedAuthIDExists(hashedCibaAuthReqCode)) {
            return CibaAuthResponseMgtDAO.getInstance().getCibaAuthReqCodeID(hashedCibaAuthReqCode);
        }else {
            return null;
        }

    }

    private Boolean IsAuthReqIDValid(JSONObject auth_req_id,String authReqID) throws NoSuchAlgorithmException, SQLException, ClassNotFoundException {
        //to check whether auth_req_id issued or not
        boolean isValid;
        /*String authReqID = authReqID;*/
        String hashedAuthReqID = AuthReqIDManager.getInstance().createHash(authReqID);


        //check whether the incoming auth_req_id exists/ valid.
        if(CibaAuthResponseMgtDAO.getInstance().isHashedAuthIDExists(hashedAuthReqID)){
            isValid = this.isValidAudience(auth_req_id);
            //check whether the audience is valid [audiene has to be clienID]


            isValid = this.isValidIssuer(auth_req_id);
            //check whether the issuer of authReqID is WSO2-IS-CIBA

            return isValid;
        }else{
            isValid=false;
            return  isValid;
        }


    }


    private boolean isValidIssuer(JSONObject auth_req_id) {
      /*  String issuer = String.valueOf(auth_req_id.get("aud"));
        if(issuer == null) {
            return false;
        } else {
            if(issuer!="wso2.is.ciba"){
                log.error("Invalid Issuer.");
                return false;
            } else {
                return true;
            }
        }*/
        return true;
    }

    private boolean isValidAudience (JSONObject auth_req_id) {
      /*  String audience = String.valueOf(auth_req_id.get("aud"));
        if(audience == null) {
            return false;
        } else {
            return true;
        }*/
        return true;
    }

    private Boolean IsAuthReqIDActive(CibaAuthCodeDO cibaAuthCodeDO){
        //to check whether auth_req_id has expired or not
/*        String expiryTimeasString = String.valueOf(auth_req_id.get("exp"));*/
        long expiryTime = cibaAuthCodeDO.getExpiryTime();

        long currentTime = ZonedDateTime.now().toInstant().toEpochMilli();
        if (currentTime >  expiryTime) {
            log.info("CIBA AuthReqID is in expired state.Token Request Denied.");
            return false;

        } else {
            log.info("CIBA AuthReqID is in active state.Token request accepted.");
            return true;
        }
    }

    private Boolean IsPollingAllowed(CibaAuthCodeDO cibaAuthCodeDO) {
        return  true;  //incase if implementing 'ping mode' in future.
    }


    private Boolean IsCorrectPollingFrequency(CibaAuthCodeDO cibaAuthCodeDO)
            throws NoSuchAlgorithmException, SQLException, ClassNotFoundException {
        //Check the frequency of polling and do the needfull
        //String cibaAuthCodeID = this.getCodeIDfromAuthReqCodeHash(auth_req_id);
        long currentTime = ZonedDateTime.now().toInstant().toEpochMilli();

        long lastpolltime = cibaAuthCodeDO.getLastPolledTime();
        long interval = cibaAuthCodeDO.getInterval();
        String cibaAuthCodeID = cibaAuthCodeDO.getCibaAuthCodeID();

        log.info(currentTime+" cuurent");
        log.info(interval*1000+" interval");
        log.info(lastpolltime+" lastpolled");
        if(currentTime - lastpolltime > interval*1000){

            CibaAuthResponseMgtDAO.getInstance().updateLastPollingTime(cibaAuthCodeID,currentTime);
            log.info("Polling frequency verified.");
            log.info("Last poll was made at "+currentTime+"." );
            return true;
        }else {
            long newInterval = interval+CibaParams.INTERVAL_INCREMENT;
            log.info("Incorrect Polling frequency.Updated the Polling frequency on the table.");
            CibaAuthResponseMgtDAO.getInstance().updatePollingInterval(cibaAuthCodeID,newInterval);
            return false;
        }
    }

    private Boolean IsUserAuthenticated(CibaAuthCodeDO cibaAuthCodeDO)
            throws NoSuchAlgorithmException, SQLException, ClassNotFoundException {

        //String cibaAuthCodeID = this.getCodeIDfromAuthReqCodeHash(authReqID);

       // String authenticationStatus = CibaAuthResponseMgtDAO.getInstance().getAuthenticationStatus(cibaAuthCodeID);

        String authenticationStatus = cibaAuthCodeDO.getAuthenticationStatus();
        String cibaAuthCodeID = cibaAuthCodeDO.getCibaAuthCodeID();
        if(authenticationStatus.equals(AuthenticationStatus.AUTHENTICATED.toString())){
            //if authenticated update the status as token delivered.
            CibaAuthResponseMgtDAO.getInstance().persistStatus(cibaAuthCodeID,AuthenticationStatus.
                    TOKEN_DELIEVERED.toString());
            log.info("User Authenticated.");
            return  true;
        } else if (authenticationStatus.equals(AuthenticationStatus.TOKEN_DELIEVERED.toString())){
            log.info("Token Already delievered.");
            return  true;
        } else {
            log.info("User still not authenticated.Client can keep polling till authReqID expired.");
            return false;
        }
    }



    private void setPropertiesForTokenGeneration(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                 OAuth2AccessTokenReqDTO tokenReq, String auth_req_id,CibaAuthCodeDO cibaAuthCodeDO)
            throws NoSuchAlgorithmException, SQLException, ClassNotFoundException, ParseException {

        SignedJWT signedJWT = SignedJWT.parse(auth_req_id);

        //String payload = signedJWT.getPayload().toString();
        //System.out.println("Payload" + payload);

        JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();
        String cibaAuthCodeID = this.getCodeIDfromAuthReqCodeHash(auth_req_id);
        String [] scope = OAuth2Util.buildScopeArray(String.valueOf(jo.get("scope")));
       // String authenticatedUserName = CibaAuthResponseMgtDAO.getInstance().getAuthenticatedUser(cibaAuthCodeID);
        String authenticatedUserName = cibaAuthCodeDO.getAuthenticatedUser();
        log.info("Authenticated user obtained from persistant store is '"+authenticatedUserName+"'");
        tokReqMsgCtx.setAuthorizedUser(OAuth2Util.getUserFromUserName(authenticatedUserName));
        tokReqMsgCtx.setScope(scope);
        // keep the pre processed authz code as a OAuthTokenReqMessageContext property to avoid
        // calculating it again when issuing the access token.

    }



}