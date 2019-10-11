package org.wso2.carbon.identity.oauth.ciba.handlers;


import org.apache.oltu.oauth2.as.validator.TokenValidator;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import javax.servlet.http.HttpServletRequest;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.CLIENT_ID;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.SCOPE;

/**
 * This class is responsible for validating the authorize responses with ciba as response type.
 * */
public class CibaResponseTypeValidator extends TokenValidator {
    public CibaResponseTypeValidator() {
    }

    @Override
    public void validateRequiredParameters(HttpServletRequest request) throws OAuthProblemException {

        super.validateRequiredParameters(request);

        String clientID = request.getParameter(CLIENT_ID);

        // For code token response type, the scope parameter should contain 'openid' as one of the scopes.
        String openIdScope = request.getParameter(SCOPE);
      /*  if (StringUtils.isBlank(openIdScope) || !isContainOIDCScope(openIdScope)) {
            throw OAuthProblemException.error(OAuthError.TokenResponse.INVALID_REQUEST)
                    .description("Request with \'client_id\' = \'" + clientID + "\' has " +
                            "\'response_type\' for \'ciba flow\'; but \'openid\' scope not found.");
        }*/
    }

    @Override
    public void validateMethod(HttpServletRequest request) throws OAuthProblemException {

        String method = request.getMethod();
        if (!OAuth.HttpMethod.GET.equals(method) && !OAuth.HttpMethod.POST.equals(method)) {
            throw OAuthProblemException.error(OAuthError.CodeResponse.INVALID_REQUEST)
                    .description("Method not correct.");
        }
    }

    @Override
    public void validateContentType(HttpServletRequest request) throws OAuthProblemException {
    }

    /**
     * Method to check whether the scope parameter string contains 'openid' as a scope.
     *
     * @param scope
     * @return
     */
    /*private static boolean isContainOIDCScope(String scope) {

        String[] scopeArray = scope.split("\\s+");
        for (String anyScope : scopeArray) {
            if (anyScope.equals(OAuthConstants.Scope.OPENID)) {
                return true;
            }
        }
        return false;
    }*/
}
