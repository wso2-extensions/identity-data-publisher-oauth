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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.databridge.commons.Event;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.data.publisher.oauth.OAuthDataPublisherConstants;
import org.wso2.carbon.identity.data.publisher.oauth.OAuthDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.oauth.internal.OAuthDataPublisherServiceHolder;
import org.wso2.carbon.identity.data.publisher.oauth.model.TokenData;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class OAuthTokenValidationDASDataPublisher extends AbstractOAuthEventInterceptor {

    public static final Log LOG = LogFactory.getLog(OAuthTokenValidationDASDataPublisher.class);

    @Override
    public void onPostTokenValidation(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO,
                                      OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO, Map<String,
            Object> params) throws IdentityOAuth2Exception {

        AccessTokenDO accessTokenDO;
        try {
            accessTokenDO = OAuth2Util.getAccessTokenDOfromTokenIdentifier(oAuth2TokenValidationRequestDTO
                    .getAccessToken().getIdentifier());
        } catch (IllegalArgumentException e) {
            // TODO such erroneous cases should be published through another publisher.
            // Intentionally catch this RuntimeException to break the flow when the access token is invalid.
            // There can be a different publisher which can publish that data in that erroneous flow.
            LOG.error("The access token is invalid. Hence failed to publish data through "
                    + OAuthDataPublisherConstants.OAUTH_TOKEN_VALIDATION_DAS_DATA_PUBLISHER);
            return;
        }

        StringBuilder authzScopes = new StringBuilder();
        List<String> grantedScopes = Arrays.asList(oAuth2TokenValidationResponseDTO.getScope());
        TokenData tokenData = new TokenData();
        if (accessTokenDO != null) {
            tokenData.setClientId(accessTokenDO.getConsumerKey());
            tokenData.setIssuedTime(accessTokenDO.getIssuedTime().getTime());
            tokenData.setAccessTokenValidityMillis(accessTokenDO.getValidityPeriodInMillis());
            tokenData.setIssuedTime(accessTokenDO.getIssuedTime().getTime());
        }
        tokenData.setTokenId(oAuth2TokenValidationRequestDTO.getAccessToken().getIdentifier());
        tokenData.setUser(oAuth2TokenValidationResponseDTO.getAuthorizedUser());
        tokenData.setGrantType(oAuth2TokenValidationRequestDTO.getAccessToken().getTokenType());
        for (String scope : grantedScopes) {
            authzScopes.append(scope).append(" ");
        }
        if (IdentityUtil.isNotBlank(authzScopes.toString())) {
            tokenData.setAuthzScopes(authzScopes.toString());
        }
        if (StringUtils.isNotBlank(tokenData.getUser())) {
            tokenData.setTenantDomain(MultitenantUtils.getTenantDomain(tokenData.getUser()));
            tokenData.setUserStoreDomain(IdentityUtil.extractDomainFromName(tokenData.getUser()));
        }
        tokenData.setIsActive(oAuth2TokenValidationResponseDTO.isValid());
        doPublishOauthTokenValidation(tokenData);
    }

    @Override
    public void onPostTokenValidation(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO,
                                      OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO, Map<String,
            Object> params) throws IdentityOAuth2Exception {

        StringBuilder authzScopes = new StringBuilder();
        String[] publishingTenantDomains = null;
        List<String> grantedScopes = Arrays.asList(oAuth2IntrospectionResponseDTO.getScope());
        TokenData tokenData = new TokenData();
        tokenData.setTokenId(oAuth2TokenValidationRequestDTO.getAccessToken().getIdentifier());
        tokenData.setUser(oAuth2IntrospectionResponseDTO.getUsername());
        if (tokenData.getUser() != null) {
            tokenData.setTenantDomain(MultitenantUtils.getTenantDomain(tokenData.getUser()));
            tokenData.setUserStoreDomain(IdentityUtil.extractDomainFromName(tokenData.getUser()));
        }
        tokenData.setGrantType(oAuth2TokenValidationRequestDTO.getAccessToken().getTokenType());
        for (String scope : grantedScopes) {
            authzScopes.append(scope).append(" ");
        }
        if (params != null && params.get(OAuth2Util.OAUTH2_VALIDATION_MESSAGE_CONTEXT) != null) {
            OAuth2TokenValidationMessageContext tokenValidationMessageContext = (OAuth2TokenValidationMessageContext)
                    params.get(OAuth2Util.OAUTH2_VALIDATION_MESSAGE_CONTEXT);
            if (tokenValidationMessageContext.getProperty("AccessTokenDO") != null) {
                AccessTokenDO accessTokenDO = (AccessTokenDO) tokenValidationMessageContext.getProperty("AccessTokenDO");
                if (accessTokenDO != null) {
                    tokenData.setClientId(accessTokenDO.getConsumerKey());
                    try {
                        OAuthAppDO oAuthAppDO = OAuthDataPublisherUtils.getApplication(accessTokenDO.getConsumerKey());
                        if (oAuthAppDO != null && oAuthAppDO.getUser() != null) {
                            publishingTenantDomains = OAuthDataPublisherUtils.getTenantDomains(oAuthAppDO.getUser()
                                    .getTenantDomain(), tokenData.getTenantDomain());
                        }

                    } catch (InvalidOAuthClientException e) {
                        LOG.debug("Could not retrieve oauth application information, Hence not publishing application" +
                                " data");
                    }
                }
            }
        }
        if (publishingTenantDomains == null) {
            publishingTenantDomains = OAuthDataPublisherUtils.getTenantDomains(null, tokenData.getTenantDomain());
        }
        tokenData.addParameter(OAuthDataPublisherConstants.TENANT_ID, publishingTenantDomains);
        if (IdentityUtil.isNotBlank(authzScopes.toString())) {
            tokenData.setAuthzScopes(authzScopes.toString());
        }
        tokenData.setIssuedTime(oAuth2IntrospectionResponseDTO.getIat());
        if (tokenData.isActive() && tokenData.getClientId() != null && oAuth2IntrospectionResponseDTO.getExp() >= 0) {
            tokenData.setAccessTokenValidityMillis(System.currentTimeMillis() - oAuth2IntrospectionResponseDTO.getExp
                    ());
        }

        tokenData.setIsActive(oAuth2IntrospectionResponseDTO.isActive());
        doPublishOauthTokenValidation(tokenData);
    }

    public void doPublishOauthTokenValidation(TokenData tokenData) {

        Object[] payloadData = new Object[10];

        payloadData[0] = tokenData.getTokenId();
        payloadData[1] = tokenData.getClientId();
        payloadData[2] = tokenData.getUser();
        payloadData[3] = tokenData.getTenantDomain();
        payloadData[4] = tokenData.getUserStoreDomain();
        payloadData[5] = tokenData.getGrantType();
        payloadData[6] = tokenData.getAuthzScopes();
        payloadData[7] = tokenData.isActive();
        payloadData[8] = tokenData.getAccessTokenValidityMillis();
        payloadData[9] = tokenData.getIssuedTime();

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
        return OAuthDataPublisherConstants.OAUTH_TOKEN_VALIDATION_DAS_DATA_PUBLISHER;
    }

}
