package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.wso2.carbon.identity.oauth.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaAuthResponseMgtDAO;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.authz.handlers.AbstractResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;

import java.sql.SQLException;

/**
 * This class is responsible for handling the authorize requests with ciba as response type.
 * */
public class CibaResponseTypeHandler extends AbstractResponseTypeHandler {

    private static Log log = LogFactory.getLog(CibaResponseTypeHandler.class);

    public CibaResponseTypeHandler() {
    }



    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws IdentityOAuth2Exception {
        OAuth2AuthorizeRespDTO respDTO = new OAuth2AuthorizeRespDTO();
        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();

       String cibaAuthCodeID = authorizationReqDTO.getNonce();
        // TODO: 10/9/19 sent as nonce [but need to modify]
       String cibaAuthenticatedUser = authorizationReqDTO.getUser().getUserName();
       String authenticationStatus = AuthenticationStatus.AUTHENTICATED.toString();

     log.info("sttar can be obtained hererer " +oauthAuthzMsgCtx.getProperty("state"));

        try {
            CibaAuthResponseMgtDAO.getInstance().persistStatus(cibaAuthCodeID, authenticationStatus);
            CibaAuthResponseMgtDAO.getInstance().persistUser(cibaAuthCodeID, cibaAuthenticatedUser);
        } catch (SQLException e) {
           if (log.isDebugEnabled()) {
              log.error("Exception caught in accessing the database." + e);
           }

        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

        //respDTO.setCallbackURI("https://localhost:9443/authenticationendpoint/authenticated.jsp");
        respDTO.setCallbackURI(authorizationReqDTO.getCallbackUrl());
        return respDTO;
    }


}