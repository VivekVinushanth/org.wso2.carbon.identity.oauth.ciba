package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;


public class CibaAuthorizationHandler implements Handler {

    private static final String CLIENT_ID = "client_id";
    private static final String STATE_PARAMATER = "state";
    private static final String USER_IDENTITY = "user";

    private static final Log log = LogFactory.getLog(CibaAuthorizationHandler.class);

    private CibaAuthorizationHandler() {

    }

    private static CibaAuthorizationHandler CibaAuthorizationHandlerInstance = new CibaAuthorizationHandler();

    public static CibaAuthorizationHandler getInstance() {
        if (CibaAuthorizationHandlerInstance == null) {

            synchronized (CibaAuthorizationHandler.class) {

                if (CibaAuthorizationHandlerInstance == null) {

                    /* instance will be created at request time */
                    CibaAuthorizationHandlerInstance = new CibaAuthorizationHandler();
                }
            }
        }
        return CibaAuthorizationHandlerInstance;


    }


    public void initiateAuthzRequest(AuthzRequestDTO authzRequestDto) throws InterruptedException, ExecutionException, IOException {

     /*  RestTemplate restTemplate = new RestTemplate();

        String result = restTemplate.getForObject(CibaConstants.AUTHORIZE_ENDPOINT+"?scope=openid&" +
                "response_type=ciba&nonce="+authzRequestDto.getAuthReqIDasState() +"&redirect_uri=" +
                authzRequestDto.getCallBackUrl() + "&client_id=" + authzRequestDto.getClient_id() + "&user=" +
                authzRequestDto.getUser(), String.class);*/

        this.fireAndForget(CibaConstants.AUTHORIZE_ENDPOINT + "?scope=openid&" +
                "response_type=ciba&nonce=" + authzRequestDto.getAuthReqIDasState() + "&redirect_uri=" +
                authzRequestDto.getCallBackUrl() + "&client_id=" + authzRequestDto.getClient_id() + "&user=" +
                authzRequestDto.getUser());


    }

    public void fireAndForget(String URL) throws ExecutionException, InterruptedException, IOException {

        CloseableHttpAsyncClient client = HttpAsyncClients.createDefault();
        client.start();
        HttpGet request = new HttpGet(URL);

        Future<HttpResponse> future = client.execute(request, null);
        HttpResponse response = future.get();
        int statuscode =  response.getStatusLine().getStatusCode();
        if (statuscode==200) {
            client.close();
        } else {
            log.warn("Error in authorize request");
        }

    }

}
