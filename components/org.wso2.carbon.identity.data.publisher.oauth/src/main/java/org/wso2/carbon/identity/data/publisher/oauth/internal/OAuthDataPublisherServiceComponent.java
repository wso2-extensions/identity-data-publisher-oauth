/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.data.publisher.oauth.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.core.handler.HandlerComparator;
import org.wso2.carbon.identity.data.publisher.oauth.OAuthInterceptorHandlerProxy;
import org.wso2.carbon.identity.data.publisher.oauth.listener.OAuthTokenIssuanceDASDataPublisher;
import org.wso2.carbon.identity.data.publisher.oauth.listener.OAuthTokenIssuanceLogPublisher;
import org.wso2.carbon.identity.data.publisher.oauth.listener.OAuthTokenRevocationDASPublisher;
import org.wso2.carbon.identity.data.publisher.oauth.listener.OAuthTokenValidationDASDataPublisher;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;

import java.util.Collections;

/**
 * @scr.component name="org.wso2.carbon.identity.data.publisher.oauth" immediate="true"
 * @scr.reference name="org.wso2.carbon.event.stream.core"
 * interface="org.wso2.carbon.event.stream.core.EventStreamService"
 * cardinality="1..1" policy="dynamic"  bind="setEventStreamService"
 * unbind="unsetEventStreamService"
 * @scr.reference name="org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor"
 * interface="org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor"
 * cardinality="0..n" policy="dynamic"
 * bind="setAuthEventInterceptor"
 * unbind="unsetOauthEventInterceptor"
 */
public class OAuthDataPublisherServiceComponent {

    private static Log log = LogFactory.getLog(OAuthDataPublisherServiceComponent.class);

    protected void activate(ComponentContext context) {

        BundleContext bundleContext = context.getBundleContext();

        try {
            bundleContext.registerService(OAuthEventInterceptor.class, new OAuthTokenIssuanceDASDataPublisher(), null);
            bundleContext.registerService(OAuthEventInterceptor.class, new OAuthTokenIssuanceLogPublisher(), null);
            bundleContext.registerService(OAuthEventInterceptor.class, new OAuthTokenValidationDASDataPublisher(), null);
            bundleContext.registerService(OAuthEventInterceptor.class, new OAuthTokenRevocationDASPublisher(), null);
            bundleContext.registerService(OAuthEventInterceptor.class, new OAuthInterceptorHandlerProxy(), null);
        } catch (Throwable e) {
            log.error("Error occurred while activating Oauth data publisher bundle, ", e);
        }
    }

    protected void setEventStreamService(EventStreamService publisherService) {
        if(log.isDebugEnabled()) {
            log.debug("Registering EventStreamService");
        }
        OAuthDataPublisherServiceHolder.getInstance().setPublisherService(publisherService);
    }

    protected void unsetEventStreamService(EventStreamService publisherService) {
        if(log.isDebugEnabled()) {
            log.debug("Un-registering EventStreamService");
        }
        OAuthDataPublisherServiceHolder.getInstance().setPublisherService(null);
    }

    protected void setAuthEventInterceptor(OAuthEventInterceptor oAuthEventInterceptor) {

        if (oAuthEventInterceptor == null) {
            log.warn("Null OAuthEventListener received, hence not registering");
            return;
        }

        if (OAuthConstants.OAUTH_INTERCEPTOR_PROXY.equalsIgnoreCase(oAuthEventInterceptor.getName())) {
            log.debug("Oauth intercepter Proxy is getting registered, Hence skipping");
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Setting OAuthEventListener :" + oAuthEventInterceptor.getClass().getName());
        }
        OAuthDataPublisherServiceHolder.getInstance().addOauthEventListener(oAuthEventInterceptor);
        Collections.sort(OAuthDataPublisherServiceHolder.getInstance().getOAuthEventInterceptors(),
                new HandlerComparator());
        Collections.reverse(OAuthDataPublisherServiceHolder.getInstance().getOAuthEventInterceptors());
    }

    protected void unsetOauthEventInterceptor(OAuthEventInterceptor oAuthEventInterceptor) {

        if (oAuthEventInterceptor == null) {
            log.warn("Null Oauth event interceptor received, hence not un-registering");
            return;
        }

        if (OAuthConstants.OAUTH_INTERCEPTOR_PROXY.equalsIgnoreCase(oAuthEventInterceptor.getName())) {
            log.debug("Proxy is un-registering, Hence skipping");
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Un-setting oAuthEventInterceptor:" + oAuthEventInterceptor.getClass().getName());
        }
        OAuthDataPublisherServiceHolder.getInstance().removeOauthEventListener(oAuthEventInterceptor);
    }

}
