package org.wso2.carbon.identity.oauth.ciba.grant;

import com.nimbusds.jwt.SignedJWT;
import org.wso2.carbon.identity.oauth.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaAuthResponseMgtDAO;
import net.minidev.json.JSONObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
        String auth_req_id= tokReqMsgCtx.getProperty("auth_req_id").toString(); //initiating auth_req_id


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
            if (!tokenReq.getGrantType().equals(CibaConstants.OAUTH_CIBA_GRANT_TYPE)) {

                throw new IdentityOAuth2Exception("Invalid GrantType.");


            } else {

                SignedJWT signedJWT = null;
                try {
                    signedJWT = SignedJWT.parse(auth_req_id);

                    //String payload = signedJWT.getPayload().toString();
                    //System.out.println("Payload" + payload);

                    JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();
                    if(handlePolling(jo)){
                        return true;
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
        try {
            setPropertiesForTokenGeneration(tokReqMsgCtx, tokenReq,auth_req_id);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return true;

    }




    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenRespDTO tokenRespDTO = super.issue(tokReqMsgCtx);

        return tokenRespDTO;
    }

    private boolean handlePolling(JSONObject auth_req_id) throws NoSuchAlgorithmException, SQLException, ClassNotFoundException, IdentityOAuth2Exception {
        if (IsAuthReqIDValid(auth_req_id).equals(false)) {
            throw new IdentityOAuth2Exception("Invalid auth_req_id.");

        } else if (IsPollingAllowed(auth_req_id).equals(false)) {
            throw new IdentityOAuth2Exception("Polling is not allowed.");

        } else if (IsAuthReqIDActive(auth_req_id).equals(false)) {
            throw new IdentityOAuth2Exception("expired_token");

        } else if (IsCorrectPollingFrequency(auth_req_id).equals(false)) {

            throw new IdentityOAuth2Exception("Slow Down.");

        } else if (IsAuthorizationPending(auth_req_id).equals(true)){

            throw new IdentityOAuth2Exception("Authorization Pending.");

        } else {

            return true;
        }

    }



    private String getCodeIDfromAuthReqCodeHash(JSONObject auth_req_id) throws NoSuchAlgorithmException, SQLException, ClassNotFoundException {
        String authReqID = auth_req_id.toString();
        String hashedCibaAuthReqCode = AuthReqIDManager.getInstance().createHash(authReqID);

        if (CibaAuthResponseMgtDAO.getInstance().isHashedAuthIDExists(hashedCibaAuthReqCode)) {
            return CibaAuthResponseMgtDAO.getInstance().getCibaAuthReqCodeID(hashedCibaAuthReqCode);
        }else {
            return null;
        }

    }

    private Boolean IsAuthReqIDValid(JSONObject auth_req_id) throws NoSuchAlgorithmException, SQLException, ClassNotFoundException {
        //to check whether auth_req_id issued or not
        boolean isValid;
        String authReqID = auth_req_id.toString();
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
        String issuer = String.valueOf(auth_req_id.get("aud"));
        if(issuer == null) {
            return false;

        } else {
            if(issuer!="wso2.is.ciba"){
                return false;
            } else {
                return true;
            }
        }
    }

    private boolean isValidAudience (JSONObject auth_req_id) {
        String audience = String.valueOf(auth_req_id.get("aud"));
        if(audience == null) {
            return false;

        } else {

            return true;

        }
    }

    private Boolean IsAuthReqIDActive(JSONObject auth_req_id){
        //to check whether auth_req_id has expired or not
        String expiryTimeasString = String.valueOf(auth_req_id.get("exp"));
        long expiryTime = Long.parseLong(expiryTimeasString);

        long currentTime = ZonedDateTime.now().toInstant().toEpochMilli();
        if (currentTime >  expiryTime) {
            return false;
        } else {
            return true;
        }
    }

    private Boolean IsPollingAllowed(JSONObject auth_req_id) {
        return  true;  //incase if implementing 'ping mode' in future.
    }


    private Boolean IsCorrectPollingFrequency(JSONObject auth_req_id) throws NoSuchAlgorithmException, SQLException, ClassNotFoundException {
        //Check the frequency of polling and do the needfull

        String cibaAuthReqCodeID = this.getCodeIDfromAuthReqCodeHash(auth_req_id);
        long currentTime = ZonedDateTime.now().toInstant().toEpochMilli();
        long lastpolltime = CibaAuthResponseMgtDAO.getInstance().getCibaLastPolledTime(cibaAuthReqCodeID);
        long interval = CibaAuthResponseMgtDAO.getInstance().getCibaPollingInterval(cibaAuthReqCodeID);

        if(currentTime - lastpolltime < interval*1000){

            CibaAuthResponseMgtDAO.getInstance().updateLastPollingTime(cibaAuthReqCodeID,currentTime);
            return true;
        }else {
            long newInterval = interval+3;
            CibaAuthResponseMgtDAO.getInstance().updatePollingInterval(cibaAuthReqCodeID,newInterval);
            return false;
        }
    }

    private Boolean IsAuthorizationPending(JSONObject auth_req_id) throws NoSuchAlgorithmException, SQLException, ClassNotFoundException {

        String cibaAuthReqCodeID = this.getCodeIDfromAuthReqCodeHash(auth_req_id);

        String authenticationStatus = CibaAuthResponseMgtDAO.getInstance().getAuthenticationStatus(cibaAuthReqCodeID);

        if(authenticationStatus.equals(AuthenticationStatus.AUTHENTICATED.toString())){
             //if authenticated update the status as token delivered.
            CibaAuthResponseMgtDAO.getInstance().persistStatus(cibaAuthReqCodeID,AuthenticationStatus.TOKEN_DELIEVERED.toString());
            return  true;
        } else{
            return false;
        }
    }



    private void setPropertiesForTokenGeneration(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                 OAuth2AccessTokenReqDTO tokenReq, String auth_req_id) throws NoSuchAlgorithmException, SQLException, ClassNotFoundException, ParseException {

        SignedJWT signedJWT = SignedJWT.parse(auth_req_id);

        //String payload = signedJWT.getPayload().toString();
        //System.out.println("Payload" + payload);

        JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();
        String cibaAuthReqCodeID = this.getCodeIDfromAuthReqCodeHash(jo);
       // String [] scope = auth_req_id.get("scope");
        String authenticatedUserName = CibaAuthResponseMgtDAO.getInstance().getAuthenticatedUser(cibaAuthReqCodeID);
        tokReqMsgCtx.setAuthorizedUser(OAuth2Util.getUserFromUserName(authenticatedUserName));
        //tokReqMsgCtx.setScope(scope);
        // keep the pre processed authz code as a OAuthTokenReqMessageContext property to avoid
        // calculating it again when issuing the access token.

    }



}
