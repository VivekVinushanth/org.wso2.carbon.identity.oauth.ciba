package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

/**
 * This class handle mechanism of making authorize request to the authorize request.
 * */
public class CibaAuthorizationHandler {


    private static final Log log = LogFactory.getLog(CibaAuthorizationHandler.class);

    private CibaAuthorizationHandler() {

    }

    private static CibaAuthorizationHandler cibaAuthorizationHandlerInstance = new CibaAuthorizationHandler();

    public static CibaAuthorizationHandler getInstance() {
        if (cibaAuthorizationHandlerInstance == null) {

            synchronized (CibaAuthorizationHandler.class) {

                if (cibaAuthorizationHandlerInstance == null) {

                    /* instance will be created at request time */
                    cibaAuthorizationHandlerInstance = new CibaAuthorizationHandler();
                }
            }
        }
        return cibaAuthorizationHandlerInstance;
    }

    /**
     * @param authzRequestDto AuthorizeRequest Data Transfer Object
     * @return void. Trigger authorize request after building the url
     * @throws ExecutionException,IOException
     */
    public void initiateAuthzRequest(AuthzRequestDTO authzRequestDto) throws InterruptedException,
            ExecutionException, IOException {

     /*  RestTemplate restTemplate = new RestTemplate();

        String result = restTemplate.getForObject(CibaParams.AUTHORIZE_ENDPOINT+"?scope=openid&" +
                "response_type=ciba&nonce="+authzRequestDto.getAuthReqIDasState() +"&redirect_uri=" +
                authzRequestDto.getCallBackUrl() + "&client_id=" + authzRequestDto.getClient_id() + "&user=" +
                authzRequestDto.getUser(), String.class);*/

        this.fireAndForget(CibaParams.AUTHORIZE_ENDPOINT + "?scope=openid&" +
                CibaParams.RESPONSE_TYPE + "=" + CibaParams.RESPONSE_TYPE_VALUE + "&" + CibaParams.NONCE + "=" +
                authzRequestDto.getAuthReqIDasState() + "&" + CibaParams.REDIRECT_URI +
                "=" + authzRequestDto.getCallBackUrl() + "&" + CibaParams.CLIENT_ID + "=" +
                authzRequestDto.getClient_id() + "&user=" + authzRequestDto.getUser());
    }


    /**
     * @param url URL for authorize request.
     * @return void. Initiate the async authorize request
     * @throws IdentityOAuth2Exception
     */
    public void fireAndForget(String url) throws ExecutionException, InterruptedException, IOException {

        CloseableHttpAsyncClient client = HttpAsyncClients.createDefault();
        client.start();
        HttpGet request = new HttpGet(url);

        Future<HttpResponse> future = client.execute(request, null);
        HttpResponse response = future.get();
        int statuscode =  response.getStatusLine().getStatusCode();
        if (statuscode == 200) {
            client.close();
        } else if (statuscode == 404) {
            if (log.isDebugEnabled()) {
                log.warn("Error in authorize request. Authorize Endpoint throws a bad request.");
            }
            client.close();
        } else {
            if (log.isDebugEnabled()) {
                log.warn("Closing the authorize request.");
            }
            client.close();
        }

    }

}
