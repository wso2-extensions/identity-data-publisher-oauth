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
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.core.handler.HandlerComparator;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.data.publisher.oauth.OAuthInterceptorHandlerProxy;
import org.wso2.carbon.identity.data.publisher.oauth.listener.OAuthTokenIssuanceDASDataPublisher;
import org.wso2.carbon.identity.data.publisher.oauth.listener.OAuthTokenIssuanceLogPublisher;
import org.wso2.carbon.identity.data.publisher.oauth.listener.OAuthTokenRevocationDASPublisher;
import org.wso2.carbon.identity.data.publisher.oauth.listener.OAuthTokenValidationDASDataPublisher;
import org.wso2.carbon.identity.data.publisher.oauth.listener.PasswordGrantAuditLogger;
import org.wso2.carbon.identity.data.publisher.oauth.listener.RefreshTokenGrantAuditLogger;
import org.wso2.carbon.identity.data.publisher.oauth.listener.TokenRevocationAuditLogger;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;

import java.util.Collections;

@Component(
        name = "org.wso2.carbon.identity.data.publisher.oauth",
        immediate = true)
public class OAuthDataPublisherServiceComponent {

    private static final Log log = LogFactory.getLog(OAuthDataPublisherServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        BundleContext bundleContext = context.getBundleContext();
        try {
            bundleContext.registerService(OAuthEventInterceptor.class, new OAuthTokenIssuanceDASDataPublisher(), null);
            bundleContext.registerService(OAuthEventInterceptor.class, new OAuthTokenIssuanceLogPublisher(), null);
            bundleContext.registerService(OAuthEventInterceptor.class, new OAuthTokenValidationDASDataPublisher(),
                    null);
            bundleContext.registerService(OAuthEventInterceptor.class, new OAuthTokenRevocationDASPublisher(), null);
            bundleContext.registerService(OAuthEventInterceptor.class, new OAuthInterceptorHandlerProxy(), null);
            bundleContext.registerService(OAuthEventInterceptor.class, new PasswordGrantAuditLogger(), null);
            bundleContext.registerService(OAuthEventInterceptor.class, new TokenRevocationAuditLogger(), null);
            bundleContext.registerService(OAuthEventInterceptor.class, new RefreshTokenGrantAuditLogger(), null);
        } catch (Throwable e) {
            log.error("Error occurred while activating Oauth data publisher bundle, ", e);
        }
    }

    @Reference(
            name = "org.wso2.carbon.event.stream.core",
            service = org.wso2.carbon.event.stream.core.EventStreamService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetEventStreamService")
    protected void setEventStreamService(EventStreamService publisherService) {

        if (log.isDebugEnabled()) {
            log.debug("Registering EventStreamService");
        }
        OAuthDataPublisherServiceHolder.getInstance().setPublisherService(publisherService);
    }

    protected void unsetEventStreamService(EventStreamService publisherService) {

        if (log.isDebugEnabled()) {
            log.debug("Un-registering EventStreamService");
        }
        OAuthDataPublisherServiceHolder.getInstance().setPublisherService(null);
    }

    @Reference(
            name = "org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor",
            service = org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOauthEventInterceptor")
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
        Collections.sort(OAuthDataPublisherServiceHolder.getInstance().getOAuthEventInterceptors(), new
                HandlerComparator());
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

    @Reference(
            name = "org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent",
            service = org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEvent")
    protected void setIdentityCoreInitializedEvent(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        // Nothing to implement
    }

    protected void unsetIdentityCoreInitializedEvent(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        // Nothing to implement
    }
}

