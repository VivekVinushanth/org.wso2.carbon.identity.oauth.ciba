package org.wso2.carbon.identity.oauth.ciba.util;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.wso2.carbon.identity.oauth.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;


public class CibaAuthCodeDOBuilder {


    private static final Log log = LogFactory.getLog(CibaAuthCodeDOBuilder.class);
    private CibaAuthCodeDOBuilder() {

    }

    private static CibaAuthCodeDOBuilder CibaAuthCodeDOBuilderInstance = new CibaAuthCodeDOBuilder();

    public static CibaAuthCodeDOBuilder getInstance() {
        if (CibaAuthCodeDOBuilderInstance == null) {

            synchronized (CibaAuthCodeDOBuilder.class) {

                if (CibaAuthCodeDOBuilderInstance == null) {

                    /* instance will be created at request time */
                    CibaAuthCodeDOBuilderInstance = new CibaAuthCodeDOBuilder();
                }
            }
        }
        return CibaAuthCodeDOBuilderInstance;


    }

    public CibaAuthCodeDO buildCibaAuthCodeDO(String cibaAuthCode) throws NoSuchAlgorithmException, ParseException {
        SignedJWT signedJWT = SignedJWT.parse(cibaAuthCode);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();

        String  lastpolledTimeasString = jo.get("iat").toString();
        long lastPolledTime = Long.parseLong(lastpolledTimeasString);
        log.info("last polled here"+lastPolledTime);
        String  expiryTimeasString = jo.get("exp").toString();
        long expiryTime = Long.parseLong(expiryTimeasString);
        log.info("expiry herre"+ expiryTime);

        String bindingMessage;
        String transactionContext;
        String scope;


        if (jo.get("binding_message") == null ||
                String.valueOf(jo.get("binding_message")).isEmpty()){
            bindingMessage= "null";

        } else{
            bindingMessage = String.valueOf(jo.get("binding_message")) ;
            log.info("binding herre" + bindingMessage);
        }



        if (jo.get("transaction_context")== null  ||
                String.valueOf(jo.get("transaction_context")).isEmpty()){
            transactionContext= "null";

        } else{
            transactionContext  = jo.get("transaction_context").toString();
            log.info("transaction value herre" + transactionContext);
        }


        if (jo.get("scope") == null  ||
                String.valueOf(jo.get("scope")).isEmpty()){
            scope= "null";

        } else{
            scope  = jo.get("scope").toString();
            log.info("scope" + scope);
        }



        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        cibaAuthCodeDO.setCibaAuthCodeID(AuthReqIDManager.getInstance().getRandomID());
        cibaAuthCodeDO.setCibaAuthCode(cibaAuthCode);
        cibaAuthCodeDO.setHashedCibaAuthCode(AuthReqIDManager.getInstance().createHash(cibaAuthCode));
        cibaAuthCodeDO.setAuthenticationStatus(AuthenticationStatus.REQUESTED.toString());
        cibaAuthCodeDO.setLastPolledTime(lastPolledTime);
        cibaAuthCodeDO.setInterval(CibaParams.interval);
        cibaAuthCodeDO.setExpiryTime(expiryTime);
        cibaAuthCodeDO.setBindingMessage(bindingMessage);
        cibaAuthCodeDO.setTransactionContext(transactionContext);
        cibaAuthCodeDO.setScope(scope);


            return cibaAuthCodeDO;
    }


}
