package org.wso2.carbon.identity.oauth.ciba.dao;

import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CibAuthCodeMgtDAO {


    private static final Log log = LogFactory.getLog(CibAuthCodeMgtDAO.class);
    private CibAuthCodeMgtDAO() {

    }

    private static CibAuthCodeMgtDAO cibAuthCodeMgtDAOInstance = new CibAuthCodeMgtDAO();

    public static CibAuthCodeMgtDAO getInstance() {
        if (cibAuthCodeMgtDAOInstance == null) {

            synchronized (CibAuthCodeMgtDAO.class) {

                if (cibAuthCodeMgtDAOInstance == null) {

                    /* instance will be created at request time */
                    cibAuthCodeMgtDAOInstance = new CibAuthCodeMgtDAO();
                }
            }
        }
        return cibAuthCodeMgtDAOInstance;


    }

    public void persistCibaAuthReqCode (CibaAuthCodeDO cibaAuthCodeDO) throws SQLException, ClassNotFoundException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.STORE_CIBA_AUTH_REQ_CODE);
            prepStmt.setString(1, cibaAuthCodeDO.getCibaAuthCodeID());
            prepStmt.setString(2, cibaAuthCodeDO.getCibaAuthCode());
            prepStmt.setString(3, cibaAuthCodeDO.getHashedCibaAuthCode());
            prepStmt.setString(4, cibaAuthCodeDO.getAuthenticationStatus());
            prepStmt.setLong(5, cibaAuthCodeDO.getLastPolledTime());
            prepStmt.setLong(6, cibaAuthCodeDO.getInterval());
            prepStmt.execute();
            connection.commit();
        }
    }

}
