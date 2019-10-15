/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * This class is responsible for Ciba Authentication response and persist CibaAuthCode.
 */
public class CibaAuthResponseMgtDAO {
    private static final Log log = LogFactory.getLog(CibaAuthResponseMgtDAO.class);

    private CibaAuthResponseMgtDAO() {
    }

    private static CibaAuthResponseMgtDAO cibaAuthResponseMgtDAOInstance = new CibaAuthResponseMgtDAO();

    public static CibaAuthResponseMgtDAO getInstance() {
        if (cibaAuthResponseMgtDAOInstance == null) {

            synchronized (CibaAuthResponseMgtDAO.class) {

                if (cibaAuthResponseMgtDAOInstance == null) {

                    /* instance will be created at request time */
                    cibaAuthResponseMgtDAOInstance = new CibaAuthResponseMgtDAO();
                }
            }
        }
        return cibaAuthResponseMgtDAOInstance;


    }

    /**
     * This method store the status of the releavant CibAuthCode identified by the CibaAuthcodeID.
     * @param cibaAuthCodeID Identifier for CibaAuthCode
     * @param cibaAuthentcationStatus Status of the relevant CibaAuthCode
     * @throws SQLException
     */
    public void persistStatus(String cibaAuthCodeID, String cibaAuthentcationStatus) throws
            SQLException, ClassNotFoundException {

       try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
           PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                   CibaSQLQueries.UPDATE_AUTHENTICATION_STATUS);
           prepStmt.setString(1, cibaAuthentcationStatus);
           prepStmt.setString(2, cibaAuthCodeID);

           prepStmt.execute();
           connection.commit();
       }
    }


    /**
     * This method store the authenticated user of the releavant CibAuthCode identified by the CibaAuthcodeID.
     * @param cibaAuthCodeID Identifier for CibaAuthCode
     * @param cibaAuthenticatedUser authenticated user for the relevant CibaAuthCode
     * @throws SQLException
     */
    public void persistUser(String cibaAuthCodeID, String cibaAuthenticatedUser)
            throws SQLException, ClassNotFoundException {

       try  (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
           PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                   UPDATE_CIBA_AUTHENTICATED_USER);
           prepStmt.setString(1, cibaAuthenticatedUser);
           prepStmt.setString(2, cibaAuthCodeID);

           prepStmt.execute();
           connection.commit();
       }
    }


    /**
     * This method check whether hash of CibaAuthCode exists.
     * @param hashedCibaAuthReqCode hash of CibaAuthCode
     * @return boolean
     * @throws SQLException
     */
    public boolean isHashedAuthIDExists(String hashedCibaAuthReqCode) throws SQLException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {

            PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    CHECK_IF_AUTH_REQ_CODE_HASHED_EXISTS);
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



    /**
     * This method returns CibaAuthCodeID for the hash of CibaAuthcode.
     * @param hashedCibaAuthReqCode hash of CibaAuthCode
     * @return String
     * @throws SQLException
     */
    public String getCibaAuthReqCodeID(String hashedCibaAuthReqCode) throws ClassNotFoundException, SQLException {

       try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
           PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                   RETRIEVE_AUTH_REQ_CODE_ID_BY_CIBA_AUTH_REQ_CODE_HASH);
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

    /**
     * This method returns the lastpolledtime of cibaAuthCode with relevant ID.
     * @param cibaAuthReqCodeID identifier of CibaAuthCode
     * @return long
     * @throws SQLException
     */
    public long getCibaLastPolledTime (String cibaAuthReqCodeID) throws ClassNotFoundException, SQLException {

       try  (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
           PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                   CibaSQLQueries.RETRIEVE_LAST_POLLED_TIME);
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




    /**
     * This method returns the polling Interval of cibaAuthCode with relevant ID.
     * @param cibaAuthReqCodeID identifier of CibaAuthCode
     * @return long
     * @throws SQLException
     */
    public long getCibaPollingInterval (String cibaAuthReqCodeID) throws SQLException, ClassNotFoundException {

       try  (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
           PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                   CibaSQLQueries.RETRIEVE_POLLING_INTERVAL);
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

    /**
     * This method updates the last polled time of cibaAuthCode with relevant ID.
     * @param cibaAuthReqCodeID identifier of CibaAuthCode
     * @throws SQLException
     */
    public void updateLastPollingTime (String cibaAuthReqCodeID, long currentTime)
            throws ClassNotFoundException, SQLException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_LAST_POLLED_TIME);
            prepStmt.setLong(1, currentTime);
            prepStmt.setString(2, cibaAuthReqCodeID);

            prepStmt.execute();
            connection.commit();
        }
    }


    /**
     * This method updates the polling Interval of cibaAuthCode with relevant ID.
     * @param cibaAuthReqCodeID identifier of CibaAuthCode
     * @return long
     * @throws SQLException
     */
    public void updatePollingInterval(String cibaAuthReqCodeID , long newInterval)
            throws SQLException, ClassNotFoundException {

       try  (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
           PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_POLLING_INTERVAL);
           prepStmt.setLong(1, newInterval);
           prepStmt.setString(2, cibaAuthReqCodeID);

           prepStmt.execute();
           connection.commit();
       }
    }

    /**
     * This method updates the polling Interval of cibaAuthCode with relevant ID.
     * @param cibaAuthReqCodeID identifier of CibaAuthCode
     * @return long
     * @throws SQLException
     */
    public String getAuthenticationStatus(String cibaAuthReqCodeID) throws ClassNotFoundException, SQLException {

       try  (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
           PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                   RETRIEVE_AUTHENTICATION_STATUS);
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


    /**
     * This method returns the authenticated user of cibaAuthCode with relevant ID.
     * @param cibaAuthReqCodeID identifier of CibaAuthCode
     * @return long
     * @throws SQLException
     */
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

    /**
     * This method updates the polling Interval of cibaAuthCode with relevant ID.
     * @param cibaAuthReqCodeID identifier of CibaAuthCode
     * @return long
     * @throws SQLException
     */
    public void getAuthCodeDO (String cibaAuthReqCodeID,CibaAuthCodeDO cibaAuthCodeDO) throws SQLException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.RETRIEVE_AUTH_CODE_DO_FROM_CIBA_AUTH_REQ_CODE_ID);

            prepStmt.setString(1, cibaAuthReqCodeID);

            ResultSet resultSet = null;

            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
               cibaAuthCodeDO.setCibaAuthCodeID(resultSet.getString(1));
               cibaAuthCodeDO.setCibaAuthCode(resultSet.getString(2));
               cibaAuthCodeDO.setHashedCibaAuthCode(resultSet.getString(3));
               cibaAuthCodeDO.setAuthenticationStatus(resultSet.getString(4));
               cibaAuthCodeDO.setLastPolledTime(resultSet.getLong(5));
               cibaAuthCodeDO.setInterval(resultSet.getLong(6));
               cibaAuthCodeDO.setAuthenticatedUser(resultSet.getString(7));
               cibaAuthCodeDO.setExpiryTime(resultSet.getLong(8));

            } else {
                throw new SQLException();
            }
        }
    }

}