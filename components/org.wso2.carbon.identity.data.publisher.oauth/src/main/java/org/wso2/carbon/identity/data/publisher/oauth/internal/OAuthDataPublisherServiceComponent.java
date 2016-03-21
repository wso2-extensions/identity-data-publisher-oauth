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
import org.wso2.carbon.identity.data.publisher.oauth.listener.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.event.OAuthEventListener;

/**
 * @scr.component name="org.wso2.carbon.identity.data.publisher.oauth" immediate="true"
 * @scr.reference name="org.wso2.carbon.event.stream.core"
 * interface="org.wso2.carbon.event.stream.core.EventStreamService"
 * cardinality="1..1" policy="dynamic"  bind="setEventStreamService"
 * unbind="unsetEventStreamService"
 */
public class OAuthDataPublisherServiceComponent {

    private static Log log = LogFactory.getLog(OAuthDataPublisherServiceComponent.class);

    protected void activate(ComponentContext context) {

        BundleContext bundleContext = context.getBundleContext();

        try {
            bundleContext.registerService(OAuthEventListener.class, new OAuthEventInterceptor(), null);
        } catch (Throwable e) {
            log.error("Error occurred while activating WorkflowImplServiceComponent bundle, ", e);
        }

    }

    protected void setEventStreamService(EventStreamService publisherService) {

        OAuthDataPublisherServiceHolder.getInstance().setPublisherService(publisherService);
    }

    protected void unsetEventStreamService(EventStreamService publisherService) {

        OAuthDataPublisherServiceHolder.getInstance().setPublisherService(null);
    }

}
