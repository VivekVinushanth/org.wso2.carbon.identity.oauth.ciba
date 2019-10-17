package org.wso2.carbon.identity.oauth.ciba.internal;

import org.wso2.carbon.user.core.service.RealmService;


/**
 * SCIM service holder class.
 *
 */
public class CibaServiceDataHolder {

        private static RealmService realmService;

        /**
         * Get realm service.
         *
         * @return
         */
        public static RealmService getRealmService() {

            return CibaServiceDataHolder.realmService;
        }

        /**
         * Set realm service.
         *
         * @param realmService
         */
        public static void setRealmService(RealmService realmService) {

            CibaServiceDataHolder.realmService = realmService;
        }
}
