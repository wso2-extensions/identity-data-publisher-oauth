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

import org.wso2.carbon.databridge.commons.Event;
import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.data.publisher.oauth.OAuthDataPublisherConstants;
import org.wso2.carbon.identity.data.publisher.oauth.internal.OAuthDataPublisherServiceHolder;
import org.wso2.carbon.identity.data.publisher.oauth.model.TokenData;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;

import java.util.Arrays;
import java.util.List;

public class OAuthTokenValidationDASDataPublisher extends AbstractOAuthEventInterceptor {

    private EventStreamService publisher;

    public OAuthTokenValidationDASDataPublisher() {
        publisher = OAuthDataPublisherServiceHolder.getInstance().getPublisherService();
    }

    @Override
    public void onPostTokenValidation(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO,
                                      OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO)
            throws IdentityOAuth2Exception {

        StringBuilder authzScopes = new StringBuilder();
        List<String> grantedScopes = Arrays.asList(oAuth2TokenValidationResponseDTO.getScope());
        TokenData tokenData = new TokenData();
        tokenData.setTokenId(oAuth2TokenValidationRequestDTO.getAccessToken().getTokenType());
        tokenData.setUser(oAuth2TokenValidationResponseDTO.getAuthorizedUser());
        tokenData.setGrantType(oAuth2TokenValidationRequestDTO.getAccessToken().getTokenType());
        for (String scope : grantedScopes) {
            authzScopes.append(scope).append(" ");
        }
        tokenData.setAuthzScopes(authzScopes.toString());
        tokenData.setIsActive(oAuth2TokenValidationResponseDTO.isValid());
        doPublishOauthTokenValidation(tokenData);
    }

    @Override
    public void onPostTokenValidation(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO,
                                      OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO)
            throws IdentityOAuth2Exception {

        StringBuilder authzScopes = new StringBuilder();
        List<String> grantedScopes = Arrays.asList(oAuth2IntrospectionResponseDTO.getScope());
        TokenData tokenData = new TokenData();
        tokenData.setTokenId(oAuth2TokenValidationRequestDTO.getAccessToken().getTokenType());
        tokenData.setUser(oAuth2IntrospectionResponseDTO.getUsername());
        tokenData.setGrantType(oAuth2TokenValidationRequestDTO.getAccessToken().getTokenType());
        for (String scope : grantedScopes) {
            authzScopes.append(scope).append(" ");
        }
        tokenData.setAuthzScopes(authzScopes.toString());
        tokenData.setIsActive(oAuth2IntrospectionResponseDTO.isActive());


    }

    public void doPublishOauthTokenValidation(TokenData tokenData) {
        Object[] payloadData = new Object[7];
        payloadData[0] = tokenData.getUser();
        payloadData[1] = tokenData.getTenantDomain();
        payloadData[2] = tokenData.getUserStoreDomain();
        payloadData[3] = tokenData.getClientId();
        payloadData[4] = tokenData.getGrantType();
        payloadData[5] = tokenData.getTokenId();
        payloadData[6] = tokenData.getAuthzScopes();
        Event event = new Event(OAuthDataPublisherConstants.TOKEN_VALIDATION_EVENT_STREAM_NAME, System
                .currentTimeMillis(), null, null, payloadData);
        publisher.publish(event);

    }

    @Override
    public String getName() {
        return OAuthDataPublisherConstants.OAUTH_TOKEN_VALIDATION_DAS_DATA_PUBLISHER;
    }

}
