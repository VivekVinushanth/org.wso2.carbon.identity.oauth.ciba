package org.wso2.carbon.identity.oauth.ciba.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.*;

public class CibaAuthResponseMgtDAO {
    private static final Log log = LogFactory.getLog(CibaAuthResponseMgtDAO.class);

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

       try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
           PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_AUTHENTICATION_STATUS);
           prepStmt.setString(1, cibaAuthentcationStatus);
           prepStmt.setString(2, cibaAuthCodeID);

           prepStmt.execute();
           connection.commit();
       }
    }


    public void persistUser(String cibaAuthCodeID, String cibaAuthenticatedUser) throws SQLException, ClassNotFoundException {

       try  (Connection connection = IdentityDatabaseUtil.getDBConnection()){
           PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_CIBA_AUTHENTICATED_USER);
           prepStmt.setString(1, cibaAuthenticatedUser);
           prepStmt.setString(2, cibaAuthCodeID);

           prepStmt.execute();
           connection.commit();
       }
    }


    public boolean isHashedAuthIDExists(String hashedCibaAuthReqCode) throws SQLException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {

            PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.CHECK_IF_AUTH_REQ_CODE_HASHED_EXISTS);
            prepStmt.setString(1, hashedCibaAuthReqCode);

            ResultSet resultSet = null;

            resultSet = prepStmt.executeQuery();

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

        return false;
         }
    }




    public String getCibaAuthReqCodeID(String hashedCibaAuthReqCode) throws ClassNotFoundException, SQLException {

       try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
           PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.RETRIEVE_AUTH_REQ_CODE_ID_BY_CIBA_AUTH_REQ_CODE_HASH);
           prepStmt.setString(1, hashedCibaAuthReqCode);

           ResultSet resultSet = null;

           resultSet = prepStmt.executeQuery();

           if (resultSet.next()) {
               return resultSet.getString(1);
           } else {
               return null;
           }
       }

    }


    public long getCibaLastPolledTime (String cibaAuthReqCodeID) throws ClassNotFoundException, SQLException {

       try  (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
           PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.RETRIEVE_LAST_POLLED_TIME);
           prepStmt.setString(1, cibaAuthReqCodeID);

           ResultSet resultSet = null;

           resultSet = prepStmt.executeQuery();
           if (resultSet.next()) {
               return resultSet.getLong(1);
           } else {
               return 0;
           }
       }
    }





    public long getCibaPollingInterval (String cibaAuthReqCodeID) throws SQLException, ClassNotFoundException {

       try  (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
           PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.RETRIEVE_POLLING_INTERVAL);
           prepStmt.setString(1, cibaAuthReqCodeID);

           ResultSet rs = null;
           rs = prepStmt.executeQuery();
           if (rs.next()) {
               return rs.getLong(1);
           } else {
               return 0;
           }

       }

    }

    public void updateLastPollingTime(String cibaAuthReqCodeID, long currentTime ) throws ClassNotFoundException, SQLException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_LAST_POLLED_TIME);
            prepStmt.setLong(1, currentTime);
            prepStmt.setString(2, cibaAuthReqCodeID);

            prepStmt.execute();
            connection.commit();
        }
    }

    public void updatePollingInterval(String cibaAuthReqCodeID , long newInterval) throws SQLException, ClassNotFoundException {

       try  (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
           PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_POLLING_INTERVAL);
           prepStmt.setLong(1, newInterval);
           prepStmt.setString(2, cibaAuthReqCodeID);

           prepStmt.execute();
           connection.commit();
       }
    }

    public String getAuthenticationStatus(String cibaAuthReqCodeID) throws ClassNotFoundException, SQLException {

       try  (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
           PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.RETRIEVE_AUTHENTICATION_STATUS);
           prepStmt.setString(1, cibaAuthReqCodeID);

           ResultSet resultSet = null;

           resultSet = prepStmt.executeQuery();
           if (resultSet.next()) {
               return resultSet.getString(1);

           } else {
               return null;
           }
       }
    }


    public String  getAuthenticatedUser(String cibaAuthReqCodeID) throws SQLException, ClassNotFoundException {
try  (Connection connection = IdentityDatabaseUtil.getDBConnection()) {

    PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.RETRIEVE_AUTHENTICATED_USER);
    prepStmt.setString(1, cibaAuthReqCodeID);

    ResultSet resultSet = null;

    resultSet = prepStmt.executeQuery();
    if (resultSet.next()) {
        return resultSet.getString(1);
    } else {
        return null;
    }
}
    }


    /*public CibaAuthCodeDO getAuthCodeDO (String authReqCode){
        PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.RETRIEVE_AUTH_CODE_DO);
        prepStmt.setString(1, cibaAuthReqCodeID);

        ResultSet resultSet = null;

        resultSet = prepStmt.executeQuery();
        if(resultSet.next()) {
            return resultSet.getString(1);
        }
        else {
            return null;
        }
    }*/

}