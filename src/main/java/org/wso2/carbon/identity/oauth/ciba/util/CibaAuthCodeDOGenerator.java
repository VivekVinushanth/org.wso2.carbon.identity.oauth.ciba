package org.wso2.carbon.identity.oauth.ciba.util;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.wso2.carbon.identity.oauth.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import javax.servlet.http.HttpServletResponse;

public class CibaAuthCodeDOGenerator {

    private static final Log log = LogFactory.getLog(CibaAuthCodeDOGenerator.class);

    private CibaAuthCodeDOGenerator() {

    }

    private static CibaAuthCodeDOGenerator cibaAuthCodeDOGeneratorInstance = new CibaAuthCodeDOGenerator();

    public static CibaAuthCodeDOGenerator getInstance() {

        if (cibaAuthCodeDOGeneratorInstance == null) {

            synchronized (CibaAuthCodeDOGenerator.class) {

                if (cibaAuthCodeDOGeneratorInstance == null) {

                    /* instance will be created at request time */
                    cibaAuthCodeDOGeneratorInstance = new CibaAuthCodeDOGenerator();
                }
            }
        }
        return cibaAuthCodeDOGeneratorInstance;

    }

    public CibaAuthCodeDO generateCibaAuthCodeDO(String cibaAuthCode) throws CibaCoreException {

        try {
            SignedJWT signedJWT = signedJWT = SignedJWT.parse(cibaAuthCode);

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();

            String lastpolledTimeasString = jo.get("iat").toString();
            long lastPolledTime = Long.parseLong(lastpolledTimeasString);
            String expiryTimeasString = jo.get("exp").toString();
            long expiryTime = Long.parseLong(expiryTimeasString);

            String hashValueOfCibaAuthReqId = AuthReqManager.getInstance().createHash(cibaAuthCode);
            log.info("hashed value : " + hashValueOfCibaAuthReqId);

            String bindingMessage;
            String transactionContext;
            String scope;

            if (jo.get("binding_message") == null ||
                    String.valueOf(jo.get("binding_message")).isEmpty()) {
                bindingMessage = "null";

            } else {
                bindingMessage = String.valueOf(jo.get("binding_message"));
            }

            if (jo.get("transaction_context") == null ||
                    String.valueOf(jo.get("transaction_context")).isEmpty()) {
                transactionContext = "null";

            } else {
                transactionContext = jo.get("transaction_context").toString();
            }

            if (jo.get("scope") == null ||
                    String.valueOf(jo.get("scope")).isEmpty()) {
                scope = "null";

            } else {
                scope = jo.get("scope").toString();
            }

            CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
            cibaAuthCodeDO.setCibaAuthCodeDOKey(AuthReqManager.getInstance().getUniqueAuthCodeDOKey());
            cibaAuthCodeDO.setHashedCibaAuthReqId(hashValueOfCibaAuthReqId);
            cibaAuthCodeDO.setAuthenticationStatus(AuthenticationStatus.REQUESTED.toString());
            cibaAuthCodeDO.setLastPolledTime(lastPolledTime);
            cibaAuthCodeDO.setInterval(CibaParams.interval);
            cibaAuthCodeDO.setExpiryTime(expiryTime);
            cibaAuthCodeDO.setBindingMessage(bindingMessage);
            cibaAuthCodeDO.setTransactionContext(transactionContext);
            cibaAuthCodeDO.setScope(scope);

            return cibaAuthCodeDO;
        } catch (ParseException | NoSuchAlgorithmException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }
}
