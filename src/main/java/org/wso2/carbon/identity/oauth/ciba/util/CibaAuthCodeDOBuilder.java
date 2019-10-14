package org.wso2.carbon.identity.oauth.ciba.util;

import org.wso2.carbon.identity.oauth.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.NoSuchAlgorithmException;
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

    public CibaAuthCodeDO buildCibaAuthCodeDO(String cibaAuthCode) throws NoSuchAlgorithmException {
        long lastPolledTime = ZonedDateTime.now().toInstant().toEpochMilli();

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        cibaAuthCodeDO.setCibaAuthCodeID(AuthReqIDManager.getInstance().getRandomID());
        cibaAuthCodeDO.setCibaAuthCode(cibaAuthCode);
        cibaAuthCodeDO.setHashedCibaAuthCode(AuthReqIDManager.getInstance().createHash(cibaAuthCode));
        log.info("Generated hash for the authCode is" + AuthReqIDManager.getInstance().createHash(cibaAuthCode));
        cibaAuthCodeDO.setAuthenticationStatus(AuthenticationStatus.REQUESTED.toString());
        cibaAuthCodeDO.setLastPolledTime(lastPolledTime);
        cibaAuthCodeDO.setInterval(CibaParams.interval);

            return cibaAuthCodeDO;
    }


}
