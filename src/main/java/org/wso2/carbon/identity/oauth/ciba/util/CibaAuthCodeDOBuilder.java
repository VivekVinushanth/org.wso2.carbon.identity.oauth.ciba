package org.wso2.carbon.identity.oauth.ciba.util;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.wso2.carbon.identity.oauth.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.ZonedDateTime;

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

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        cibaAuthCodeDO.setCibaAuthCodeID(AuthReqIDManager.getInstance().getRandomID());
        cibaAuthCodeDO.setCibaAuthCode(cibaAuthCode);
        cibaAuthCodeDO.setHashedCibaAuthCode(AuthReqIDManager.getInstance().createHash(cibaAuthCode));
        cibaAuthCodeDO.setAuthenticationStatus(AuthenticationStatus.REQUESTED.toString());
        cibaAuthCodeDO.setLastPolledTime(lastPolledTime);
        cibaAuthCodeDO.setInterval(CibaParams.interval);
        cibaAuthCodeDO.setExpiryTime(expiryTime);

            return cibaAuthCodeDO;
    }


}
