package org.wso2.carbon.identity.oauth.ciba.grant;

import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.validators.AbstractValidator;

import javax.servlet.http.HttpServletRequest;

/**
 * Grant validator for CIBA Token Request
 * For CIBA Grant to be valid the required parameters are
 * grant_type and expires_in
 */
public class CibaGrantValidator extends AbstractValidator<HttpServletRequest> {

    public CibaGrantValidator() {
        requiredParams.add(OAuth.OAUTH_GRANT_TYPE);
        requiredParams.add(CibaGrantHandler.AUTH_REQ_ID);
    }
}
