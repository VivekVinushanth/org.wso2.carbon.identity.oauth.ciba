package org.wso2.carbon.identity.oauth.ciba.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import java.sql.Connection;


public class PersistantManager {
    private static final Log log = LogFactory.getLog(PersistantManager.class);


    private PersistantManager() {

    }

    private static PersistantManager PersistantManagerInstance = new PersistantManager();

    public static PersistantManager getInstance() {
        if (PersistantManagerInstance == null) {

            synchronized (PersistantManager.class) {

                if (PersistantManagerInstance == null) {

                    /* instance will be created at request time */
                    PersistantManagerInstance = new PersistantManager();
                }
            }
        }
        return PersistantManagerInstance;


    }

    public Connection getDbConnection() {

       return IdentityDatabaseUtil.getDBConnection();
    }

}
