package org.wso2.carbon.identity.oauth.ciba.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.util.PersistantManager;

import java.sql.*;

public class CibaAuthResponseMgtDAO {
    private static final Log log = LogFactory.getLog(CibaAuthResponseMgtDAO.class);

    protected final static String DB_PATH= "~/test";
    protected final static String CONNECTION_STRING = "jdbc:h2:" + DB_PATH ;
    private CibaAuthResponseMgtDAO() {

    }

    private static CibaAuthResponseMgtDAO CibaAuthResponseMgtDAOInstance = new CibaAuthResponseMgtDAO();

    public static CibaAuthResponseMgtDAO getInstance() {
        if (CibaAuthResponseMgtDAOInstance == null) {

            synchronized (CibaAuthResponseMgtDAO.class) {

                if (CibaAuthResponseMgtDAOInstance == null) {

                    /* instance will be created at request time */
                    CibaAuthResponseMgtDAOInstance = new CibaAuthResponseMgtDAO();
                }
            }
        }
        return CibaAuthResponseMgtDAOInstance;


    }

    public void persistStatus(String cibaAuthCodeID, String cibaAuthentcationStatus) throws SQLException, ClassNotFoundException {
       
       Connection connection = PersistantManager.getInstance().getDbConnection();
        PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_AUTHENTICATION_STATUS);
        prepStmt.setString(1,cibaAuthCodeID);
        prepStmt.setString(2,cibaAuthentcationStatus );

        prepStmt.execute();
        connection.commit();
    }


    public void persistUser(String cibaAuthCodeID, String cibaAuthenticatedUser) throws SQLException, ClassNotFoundException {
     
       Connection connection = PersistantManager.getInstance().getDbConnection();
        PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_CIBA_AUTHENTICATED_USER);
        prepStmt.setString(1,cibaAuthCodeID);
        prepStmt.setString(2,cibaAuthenticatedUser );

        prepStmt.execute();
        connection.commit();
    }


    public boolean isHashedAuthIDExists(String hashedCibaAuthReqCode) {
        try {
         
           Connection connection = PersistantManager.getInstance().getDbConnection();
            PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.CHECK_IF_AUTH_REQ_CODE_HASHED_EXISTS);
            prepStmt.setString(1, hashedCibaAuthReqCode);

            ResultSet resultSet = null;

            resultSet = prepStmt.executeQuery();

            //System.out.println("result set "+resultSet);
            int count;
            while (resultSet.next()) {
                count = (resultSet.getInt(1));

                if (count >= 1) {
                    //do nothing

                    prepStmt.close();
                    return true;
                } else {
                    //connection.close();
                    prepStmt.close();

                    return false;
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }


    public String getCibaAuthReqCodeID(String hashedCibaAuthReqCode) throws ClassNotFoundException, SQLException {
     
       Connection connection = PersistantManager.getInstance().getDbConnection();
        PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.RETRIEVE_AUTH_REQ_CODE_ID_BY_CIBA_AUTH_REQ_CODE_HASH);
        prepStmt.setString(1, hashedCibaAuthReqCode);

        ResultSet resultSet = null;

        resultSet = prepStmt.executeQuery();
        return resultSet.getString(1);
    }


    public long getCibaLastPolledTime (String cibaAuthReqCodeID) throws ClassNotFoundException, SQLException {
     
       Connection connection = PersistantManager.getInstance().getDbConnection();
        PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.RETRIEVE_LAST_POLLED_TIME);
        prepStmt.setString(1, cibaAuthReqCodeID);

        ResultSet resultSet = null;

        resultSet = prepStmt.executeQuery();
        return resultSet.getLong(1);

    }


    public long getCibaPollingInterval (String cibaAuthReqCodeID) throws SQLException, ClassNotFoundException {
     
       Connection connection = PersistantManager.getInstance().getDbConnection();
        PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.RETRIEVE_POLLING_INTERVAL);
        prepStmt.setString(1, cibaAuthReqCodeID);

        ResultSet resultSet = null;

        resultSet = prepStmt.executeQuery();
        return resultSet.getLong(1);

    }

    public void updateLastPollingTime(String cibaAuthReqCodeID, long currentTime ) throws ClassNotFoundException, SQLException {
     
       Connection connection = PersistantManager.getInstance().getDbConnection();
        PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_LAST_POLLED_TIME);
        prepStmt.setString(1,cibaAuthReqCodeID);
        prepStmt.setLong(2,currentTime );

        prepStmt.execute();
        connection.commit();
    }

    public void updatePollingInterval(String cibaAuthReqCodeID , long newInterval) throws SQLException, ClassNotFoundException {
     
       Connection connection = PersistantManager.getInstance().getDbConnection();
        PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_POLLING_INTERVAL);
        prepStmt.setString(1,cibaAuthReqCodeID);
        prepStmt.setLong(2,newInterval );

        prepStmt.execute();
        connection.commit();
    }

    public String getAuthenticationStatus(String cibaAuthReqCodeID) throws ClassNotFoundException, SQLException {
     
       Connection connection = PersistantManager.getInstance().getDbConnection();
        PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.RETRIEVE_AUTHENTICATION_STATUS);
        prepStmt.setString(1, cibaAuthReqCodeID);

        ResultSet resultSet = null;

        resultSet = prepStmt.executeQuery();
        return resultSet.getString(1);
    }

    public String  getAuthenticatedUser(String cibaAuthReqCodeID) throws SQLException, ClassNotFoundException {
     
       Connection connection = PersistantManager.getInstance().getDbConnection();
        PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.RETRIEVE_AUTHENTICATED_USER);
        prepStmt.setString(1, cibaAuthReqCodeID);

        ResultSet resultSet = null;

        resultSet = prepStmt.executeQuery();
        return resultSet.getString(1);
    }
}
