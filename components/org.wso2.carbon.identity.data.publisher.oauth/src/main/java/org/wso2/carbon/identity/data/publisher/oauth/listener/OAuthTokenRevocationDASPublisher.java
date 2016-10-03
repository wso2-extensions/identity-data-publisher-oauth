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

package org.wso2.carbon.identity.data.publisher.oauth.listener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.databridge.commons.Event;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.data.publisher.oauth.OAuthDataPublisherConstants;
import org.wso2.carbon.identity.data.publisher.oauth.OAuthDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.oauth.internal.OAuthDataPublisherServiceHolder;
import org.wso2.carbon.identity.data.publisher.oauth.model.TokenData;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Map;

public class OAuthTokenRevocationDASPublisher extends AbstractOAuthEventInterceptor {

    public static final Log LOG = LogFactory.getLog(OAuthTokenRevocationDASPublisher.class);

    @Override
    public void onPreTokenRevocationByClient(OAuthRevocationRequestDTO oAuthRevocationRequestDTO, Map<String, Object>
            params) throws IdentityOAuth2Exception {
        // To be implemented
    }

    @Override
    public void onPostTokenRevocationByClient(OAuthRevocationRequestDTO oAuthRevocationRequestDTO,
                                              OAuthRevocationResponseDTO oAuthRevocationResponseDTO, AccessTokenDO
                                                      accessTokenDO, RefreshTokenValidationDataDO
                                                      refreshTokenValidationDataDO, Map<String, Object> params)
            throws IdentityOAuth2Exception {

        System.out.println("============= token revocation by client");
    }

    @Override
    public void onPostTokenRevocationByResourceOwner(org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO
                                                             oAuthRevocationRequestDTO, org.wso2.carbon.identity
                                                             .oauth.dto.OAuthRevocationResponseDTO
                                                             oAuthRevocationResponseDTO, AccessTokenDO accessTokenDO,
                                                     Map<String, Object> params) throws IdentityOAuth2Exception {
        System.out.println("Token revocation by resource owner");
    }


    public void doPublishOauthTokenRevocation(TokenData tokenData) {

        Object[] payloadData = new Object[11];

        payloadData[0] = tokenData.getTokenId();
        payloadData[1] = tokenData.getClientId();
        payloadData[2] = tokenData.getUser();
        payloadData[3] = tokenData.getTenantDomain();
        payloadData[4] = tokenData.getUserStoreDomain();
        payloadData[5] = tokenData.getGrantType();
        payloadData[7] = tokenData.getAuthzScopes();
        payloadData[8] = tokenData.getRevokedTime();
        payloadData[8] = tokenData.isActive();
        payloadData[9] = tokenData.getAccessTokenValidityMillis();
        payloadData[10] = tokenData.getIssuedTime();

        String[] publishingDomains = (String[]) tokenData.getParameter(OAuthDataPublisherConstants.TENANT_ID);
        if (publishingDomains != null && publishingDomains.length > 0) {
            try {
                FrameworkUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                for (String publishingDomain : publishingDomains) {
                    Object[] metadataArray = OAuthDataPublisherUtils.getMetaDataArray(publishingDomain);
                    Event event = new Event(OAuthDataPublisherConstants.TOKEN_VALIDATION_EVENT_STREAM_NAME, System
                            .currentTimeMillis(), metadataArray, null, payloadData);
                    OAuthDataPublisherServiceHolder.getInstance().getPublisherService().publish(event);
                    if (LOG.isDebugEnabled() && event != null) {
                        LOG.debug("Sending out event : " + event.toString());
                    }
                }
            } finally {
                FrameworkUtils.endTenantFlow();
            }
        }
    }


    @Override
    public String getName() {
        return OAuthDataPublisherConstants.OAUTH_TOKEN_REVOCATION_DAS_DATA_PUBLISHER;
    }

}
