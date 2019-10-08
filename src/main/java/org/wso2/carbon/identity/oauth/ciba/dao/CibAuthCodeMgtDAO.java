package org.wso2.carbon.identity.oauth.ciba.dao;

import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.util.PersistantManager;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CibAuthCodeMgtDAO {


    private static final Log log = LogFactory.getLog(CibAuthCodeMgtDAO.class);
    private CibAuthCodeMgtDAO() {

    }

    private static CibAuthCodeMgtDAO CibAuthCodeMgtDAOInstance = new CibAuthCodeMgtDAO();

    public static CibAuthCodeMgtDAO getInstance() {
        if (CibAuthCodeMgtDAOInstance == null) {

            synchronized (CibAuthCodeMgtDAO.class) {

                if (CibAuthCodeMgtDAOInstance == null) {

                    /* instance will be created at request time */
                    CibAuthCodeMgtDAOInstance = new CibAuthCodeMgtDAO();
                }
            }
        }
        return CibAuthCodeMgtDAOInstance;


    }

    public void persistCibaAuthReqCode (CibaAuthCodeDO cibaAuthCodeDO) throws SQLException, ClassNotFoundException {
        Connection connection = PersistantManager.getInstance().getDbConnection();
        PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.STORE_CIBA_AUTH_REQ_CODE);
        prepStmt.setString(1, cibaAuthCodeDO.getCibaAuthCodeID());
        prepStmt.setString(2, cibaAuthCodeDO.getCibaAuthCode());
        prepStmt.setString(3, cibaAuthCodeDO.getHashedCibaAuthCode());
        prepStmt.setString(4, cibaAuthCodeDO.getAuthenticationStatus().toString());
        prepStmt.setLong(5,cibaAuthCodeDO.getLastPolledTime());
        prepStmt.setLong(6,cibaAuthCodeDO.getInterval());
        prepStmt.execute();
        connection.commit();
    }


}
