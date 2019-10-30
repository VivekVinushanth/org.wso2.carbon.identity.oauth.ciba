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
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.servlet.http.HttpServletResponse;

/**
 * This class is responsible for Ciba Authentication response and persisting CibaAuthCode.
 */
public class CibaAuthMgtDAO {

    private static final Log log = LogFactory.getLog(CibaAuthMgtDAO.class);

    private CibaAuthMgtDAO() {

    }

    private static CibaAuthMgtDAO cibaAuthMgtDAOInstance = new CibaAuthMgtDAO();

    public static CibaAuthMgtDAO getInstance() {

        if (cibaAuthMgtDAOInstance == null) {

            synchronized (CibaAuthMgtDAO.class) {

                if (cibaAuthMgtDAOInstance == null) {

                    /* instance will be created at request time */
                    cibaAuthMgtDAOInstance = new CibaAuthMgtDAO();
                }
            }
        }
        return cibaAuthMgtDAOInstance;

    }

    /**
     * This method persists the status of the relevant CibAuthCode identified by the CibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey       Identifier for CibaAuthCodeDOKey.
     * @param cibaAuthentcationStatus Status of the relevant Ciba Authentication.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void persistStatus(String cibaAuthCodeDOKey, String cibaAuthentcationStatus) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.UPDATE_AUTHENTICATION_STATUS)) {

                prepStmt.setString(1, cibaAuthentcationStatus);
                prepStmt.setString(2, cibaAuthCodeDOKey);

                prepStmt.execute();
                connection.commit();

                if (log.isDebugEnabled()) {
                    log.debug("Successfully persisted the authentication_status identified by AuthCodeDOKey : " +
                            cibaAuthCodeDOKey);
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in persisting the authentication_status identified by AuthCodeDOKey : " +
                        cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR,
                    "SQL exception in persisting authenticated_status. " + e.getMessage());
        }
    }

    /**
     * This method persists the authenticated_user of the relevant CibAuthCode identified by the CibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey     Identifier for CibaAuthCode.
     * @param cibaAuthenticatedUser Authenticated_user of the relevant CibaAuthCode.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void persistUser(String cibaAuthCodeDOKey, String cibaAuthenticatedUser) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    UPDATE_CIBA_AUTHENTICATED_USER)) {
                prepStmt.setString(1, cibaAuthenticatedUser);
                prepStmt.setString(2, cibaAuthCodeDOKey);

                prepStmt.execute();
                connection.commit();

                if (log.isDebugEnabled()) {
                    log.debug("Successfully persisted the authenticated_user identified by AuthCodeDOKey : " +
                            cibaAuthCodeDOKey);
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in persisting the authenticated_user identified by AuthCodeDOKey : " +
                        cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR,
                    "SQL exception in persisting authenticated_user." + e.getMessage());
        }
    }

    /**
     * This method check whether hash of CibaAuthCode exists.
     *
     * @param hashedCibaAuthReqId hash of CibaAuthReqID.
     * @return boolean Returns whether given HashedAuthReqId present or not.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public boolean isHashedAuthReqIDExists(String hashedCibaAuthReqId) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {

            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    CHECK_IF_AUTH_REQ_ID_HASH_EXISTS)) {
                prepStmt.setString(1, hashedCibaAuthReqId);

                ResultSet resultSet = prepStmt.executeQuery();

                int count;

                while (resultSet.next()) {
                    count = (resultSet.getInt(1));

                    if (count >= 1) {
                        //do nothing
                        prepStmt.close();

                        if (log.isDebugEnabled()) {
                            log.debug("Successfully checked whether provided hashedAuthReqId : " + hashedCibaAuthReqId +
                                    "exists.");
                            log.debug("Provided hashedAuthReqId exists.It is from a valid auth_req_id.");
                        }
                        return true;

                    } else {
                        //connection.close();
                        prepStmt.close();
                        if (log.isDebugEnabled()) {
                            log.debug("Successfully checked whether provided hashedAuthReqId : " + hashedCibaAuthReqId +
                                    "exists.");
                            log.debug("Provided hashedAuthReqId does not exist. hashedAuthReqId is not from valid " +
                                    "auth_req_id.");
                        }
                        return false;
                    }
                }

                return false;
            }
        } catch (SQLException e) {

            if (log.isDebugEnabled()) {
                log.debug("Unsuccessful in checking whether provided hashedAuthReqId : " + hashedCibaAuthReqId +
                        "exists.");
            }
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * This method returns CibaAuthCodeDOkey for the hash of CibaAuthReqId.
     *
     * @param hashedCibaAuthReqId hash of CibaAuthReqId.
     * @return String Returns CibaAuthCodeDOKey.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public String getCibaAuthCodeDOKey(String hashedCibaAuthReqId) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    RETRIEVE_CIBA_AUTH_CODE_DO_KEY_BY_CIBA_AUTH_REQ_ID_HASH)) {
                prepStmt.setString(1, hashedCibaAuthReqId);

                ResultSet resultSet = prepStmt.executeQuery();

                if (resultSet.next()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully returning CibaAuthCodeDOKey : " + resultSet.getString(1) + "for the " +
                                "hashedCibaAuthReqId : " + hashedCibaAuthReqId);
                    }
                    return resultSet.getString(1);
                } else {

                    if (log.isDebugEnabled()) {
                        log.debug("Could not find CibaAuthCodeDOKey for the hashedCibaAuthReqId : " +
                                hashedCibaAuthReqId);
                    }
                    return null;
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occured when finding CibaAuthCodeDOKey for the hashedCibaAuthReqId : " +
                        hashedCibaAuthReqId);
            }
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }

    /**
     * This method returns the lastPolledTime of tokenRequest with CibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey Identifier of CibaAuthCodeDO.
     * @return long Returns lastPolledTime.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public long getCibaLastPolledTime(String cibaAuthCodeDOKey) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.RETRIEVE_LAST_POLLED_TIME)) {
                prepStmt.setString(1, cibaAuthCodeDOKey);

                ResultSet resultSet = prepStmt.executeQuery();
                if (resultSet.next()) {

                    if (log.isDebugEnabled()) {
                        log.debug("Successfully returning lastPolledTime of TokenRequest : " + resultSet.getLong(1) +
                                "for the " + "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
                    }
                    return resultSet.getLong(1);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No field found for lastPolledTime of TokenRequest : " + resultSet.getLong(1) +
                                "for the " + "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
                    }
                    return 0;
                }
            }

        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in retrieving lastPolledTime of TokenRequest for  the " +
                        "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * This method returns the pollingInterval of tokenRequest with CibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey identifier of CibaAuthReqId.
     * @return long Returns pollingInterval of tokenRequest.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public long getCibaPollingInterval(String cibaAuthCodeDOKey) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.RETRIEVE_POLLING_INTERVAL)) {
                prepStmt.setString(1, cibaAuthCodeDOKey);

                ResultSet rs = prepStmt.executeQuery();
                if (rs.next()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully returning pollingInterval of TokenRequest : " + rs.getLong(1) +
                                "for the " + "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
                    }
                    return rs.getLong(1);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No field found for pollingInterval of TokenRequest with cibaAuthCodeDOKey : " +
                                cibaAuthCodeDOKey);
                    }
                    return 0;
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in retrieving pollingInterval of TokenRequest for the " +
                        "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }

    /**
     * This method updates the last polled time of tokenRequest with CibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey Identifier of CibaAuthCodeDO.
     * @param currentTime       CurrentTime in milliseconds.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void updateLastPollingTime(String cibaAuthCodeDOKey, long currentTime)
            throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_LAST_POLLED_TIME)) {
                prepStmt.setLong(1, currentTime);
                prepStmt.setString(2, cibaAuthCodeDOKey);

                prepStmt.execute();
                connection.commit();
                if (log.isDebugEnabled()) {
                    log.debug("Successfully updated lastPollingTime of TokenRequest  with cibaAuthCodeDOKey : " +
                            cibaAuthCodeDOKey);
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in updating lastPollingTime of TokenRequest  with cibaAuthCodeDOKey : " +
                        cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * This method updates the polling Interval of tokenRequest with cibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey identifier of CibaAuthCode.
     * @param newInterval       Updated polling frequency.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void updatePollingInterval(String cibaAuthCodeDOKey, long newInterval)
            throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_POLLING_INTERVAL)) {
                prepStmt.setLong(1, newInterval);
                prepStmt.setString(2, cibaAuthCodeDOKey);

                prepStmt.execute();
                connection.commit();
                if (log.isDebugEnabled()) {
                    log.debug("Successfully updated pollingInterval of TokenRequest  with cibaAuthCodeDOKey : " +
                            cibaAuthCodeDOKey);
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in updating pollingInterval of TokenRequest  with cibaAuthCodeDOKey : " +
                        cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * This method returns authenticationStatus of authenticationRequest with specific cibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey identifier of CibaAuthCodeDO.
     * @return String Returns AuthenticationStatus.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public String getAuthenticationStatus(String cibaAuthCodeDOKey) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    RETRIEVE_AUTHENTICATION_STATUS)) {
                prepStmt.setString(1, cibaAuthCodeDOKey);

                ResultSet resultSet = prepStmt.executeQuery();
                if (resultSet.next()) {

                    if (log.isDebugEnabled()) {
                        log.debug("Successfully obtained authenticationStatus of TokenRequest  with " +
                                "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
                    }
                    return resultSet.getString(1);

                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No field found for authenticationStatus of TokenRequest  with " +
                                "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
                    }
                    return null;
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in obtaining authenticationStatus of TokenRequest  with " +
                        "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * This method returns the authenticated user of authenticationRequest for cibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey identifier of CibaAuthCode
     * @return Returns AuthenticatedUser.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public String getAuthenticatedUser(String cibaAuthCodeDOKey) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {

            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.CibaSQLQueries.RETRIEVE_AUTHENTICATED_USER)) {
                prepStmt.setString(1, cibaAuthCodeDOKey);

                ResultSet resultSet = prepStmt.executeQuery();
                if (resultSet.next()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully obtained authenticatedUser of TokenRequest  with " +
                                "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
                    }
                    return resultSet.getString(1);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No field found for authenticatedUser of TokenRequest  with " +
                                "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
                    }
                    return null;
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in obtaining authenticatedUser of TokenRequest  with " +
                        "cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

}
