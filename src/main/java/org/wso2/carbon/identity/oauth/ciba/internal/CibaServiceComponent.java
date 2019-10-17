package org.wso2.carbon.identity.oauth.ciba.internal;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;

@Component(
        name = "identity.ciba.service",
        immediate = true
)
public class CibaServiceComponent {


    private static final Log log = LogFactory.getLog(CibaServiceComponent.class);


    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            CibaServiceComponent cibaServiceComponent = new CibaServiceComponent();
            ctxt.getBundleContext().registerService(CibaServiceComponent.class, cibaServiceComponent, null);
            if (log.isDebugEnabled()) {
                log.info("CibaHandler bundle is activated");
            }
        } catch (Throwable e) {
            log.error("CibaHandler Authenticator bundle activation Failed", e);
        }

    }

    /**
     * Set realm service implementation
     *
     * @param realmService RealmService
     */
    @Reference(
            name = "realm.service",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("realmService set in CibaComponent bundle");
        }
        CibaServiceDataHolder.setRealmService(realmService);
    }

    /**
     * Unset realm service implementation
     */
    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("realmService unset in CibaComponent bundle");
        }
        CibaServiceDataHolder.setRealmService(null);
    }
}
