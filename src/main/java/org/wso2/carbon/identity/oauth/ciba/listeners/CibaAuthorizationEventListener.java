package org.wso2.carbon.identity.oauth.ciba.listeners;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaResponseTypeHandlerHandler;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceDataHolder;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;

public class CibaAuthorizationEventListener  {

    private static final Log log = LogFactory.getLog(CibaAuthorizationEventListener.class);


    private CibaAuthorizationEventListener() {

    }

    private static CibaAuthorizationEventListener cibaAuthorizationEventListenerInstance = new CibaAuthorizationEventListener();

    public static CibaAuthorizationEventListener getInstance() {

        if (cibaAuthorizationEventListenerInstance == null) {

            synchronized (CibaAuthorizationEventListener.class) {

                if (cibaAuthorizationEventListenerInstance == null) {

                    /* instance will be created at request time */
                    cibaAuthorizationEventListenerInstance = new CibaAuthorizationEventListener();
                }
            }
        }
        return cibaAuthorizationEventListenerInstance;
    }




}
