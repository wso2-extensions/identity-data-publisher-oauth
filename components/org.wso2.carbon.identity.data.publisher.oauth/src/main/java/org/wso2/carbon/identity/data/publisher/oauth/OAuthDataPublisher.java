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

package org.wso2.carbon.identity.data.publisher.oauth;

import org.wso2.carbon.databridge.commons.Event;
import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.data.publisher.oauth.internal.OAuthDataPublisherServiceHolder;

public class OAuthDataPublisher {

    public static final String TOKEN_ISSUE_EVENT_STREAM_NAME = "org.wso2.carbon.identity.oauth.token.issuance:1.0.0";
    public static final String TOKEN_REVOKE_EVENT_STREAM_NAME = "org.wso2.carbon.identity.oauth.token.revocation:1.0.0";

    private EventStreamService publisher;

    public OAuthDataPublisher() {

        publisher = OAuthDataPublisherServiceHolder.getInstance().getPublisherService();
    }

    public void publishTokenIssueEvent(String user, String tenantDomain, String userstoreDomain, String clientId,
                                       String grantType, String tokenId, String authzScopes, String unAuthzScopes,
                                       boolean isSuccess, String errorCode, String errorMsg,
                                       long accessTokenValidityMillis, long refreshTokenValidityMillis,
                                       long issuedTime) {

        Object[] payloadData = new Object[14];
        payloadData[0] = user;
        payloadData[1] = tenantDomain;
        payloadData[2] = userstoreDomain;
        payloadData[3] = clientId;
        payloadData[4] = grantType;
        payloadData[5] = tokenId;
        payloadData[6] = authzScopes;
        payloadData[7] = unAuthzScopes;
        payloadData[8] = isSuccess;
        payloadData[9] = errorCode;
        payloadData[10] = errorMsg;
        payloadData[11] = accessTokenValidityMillis;
        payloadData[12] = refreshTokenValidityMillis;
        payloadData[13] = issuedTime;
        Event event = new Event(TOKEN_ISSUE_EVENT_STREAM_NAME, System.currentTimeMillis(), null, null, payloadData);
        publisher.publish(event);
    }


    public void publishTokenRevocationEvent(String clientId, boolean isSuccess,
                                            String errorMsg, String errorCode, String tokenId, String revokedBy) {

        Object[] payloadData = new Object[6];
        payloadData[0] = clientId;
        payloadData[1] = isSuccess;
        payloadData[2] = errorMsg;
        payloadData[3] = errorCode;
        payloadData[4] = tokenId;
        payloadData[5] = revokedBy;
        Event event = new Event(TOKEN_REVOKE_EVENT_STREAM_NAME, System.currentTimeMillis(), null, null, payloadData);
        publisher.publish(event);
    }

}
