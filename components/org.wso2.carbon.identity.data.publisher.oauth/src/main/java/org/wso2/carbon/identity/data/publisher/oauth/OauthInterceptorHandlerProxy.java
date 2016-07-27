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

import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.data.publisher.oauth.internal.OAuthDataPublisherServiceHolder;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.List;

public class OauthInterceptorHandlerProxy extends AbstractIdentityHandler implements OAuthEventInterceptor {

    private List<OAuthEventInterceptor> oAuthEventInterceptors = OAuthDataPublisherServiceHolder.getInstance()
            .getOAuthEventInterceptors();

    @Override
    public void onPreTokenIssue(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, OAuthTokenReqMessageContext
            oAuthTokenReqMessageContext) throws IdentityOAuth2Exception {
        for (OAuthEventInterceptor interceptor : oAuthEventInterceptors) {
            if (interceptor.isEnabled()) {
                interceptor.onPreTokenIssue(oAuth2AccessTokenReqDTO, oAuthTokenReqMessageContext);
            }
        }

    }

    @Override
    public void onPostTokenIssue(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, OAuth2AccessTokenRespDTO
            oAuth2AccessTokenRespDTO, OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws
            IdentityOAuth2Exception {
        for (OAuthEventInterceptor interceptor : oAuthEventInterceptors) {
            if (interceptor.isEnabled()) {
                interceptor.onPostTokenIssue(oAuth2AccessTokenReqDTO, oAuth2AccessTokenRespDTO,
                        oAuthTokenReqMessageContext);
            }
        }

    }

    @Override
    public void onPreTokenIssue(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext) throws
            IdentityOAuth2Exception {
        for (OAuthEventInterceptor interceptor : oAuthEventInterceptors) {
            if (interceptor.isEnabled()) {
                interceptor.onPreTokenIssue(oAuthAuthzReqMessageContext);
            }
        }

    }

    @Override
    public void onPostTokenIssue(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext, AccessTokenDO
            accessTokenDO, OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO) throws IdentityOAuth2Exception {
        for (OAuthEventInterceptor interceptor : oAuthEventInterceptors) {
            if (interceptor.isEnabled()) {
                interceptor.onPostTokenIssue(oAuthAuthzReqMessageContext, accessTokenDO, oAuth2AuthorizeRespDTO);
            }
        }
    }

    @Override
    public void onPreTokenRenewal(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, OAuthTokenReqMessageContext
            oAuthTokenReqMessageContext) throws IdentityOAuth2Exception {
        for (OAuthEventInterceptor interceptor : oAuthEventInterceptors) {
            if (interceptor.isEnabled()) {
                interceptor.onPreTokenRenewal(oAuth2AccessTokenReqDTO, oAuthTokenReqMessageContext);
            }
        }

    }

    @Override
    public void onPostTokenRenewal(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, OAuth2AccessTokenRespDTO
            oAuth2AccessTokenRespDTO, OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws
            IdentityOAuth2Exception {
        for (OAuthEventInterceptor interceptor : oAuthEventInterceptors) {
            if (interceptor.isEnabled()) {
                interceptor.onPreTokenRenewal(oAuth2AccessTokenReqDTO, oAuthTokenReqMessageContext);
            }
        }

    }

    @Override
    public void onPreTokenRevocationByClient(org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO
                                                     oAuthRevocationRequestDTO) throws IdentityOAuth2Exception {
        for (OAuthEventInterceptor interceptor : oAuthEventInterceptors) {
            if (interceptor.isEnabled()) {
                interceptor.onPreTokenRevocationByClient(oAuthRevocationRequestDTO);
            }
        }

    }

    @Override
    public void onPostTokenRevocationByClient(org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO
                                                      oAuthRevocationRequestDTO,
                                              org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO oAuthRevocationResponseDTO,
                                              AccessTokenDO accessTokenDO, RefreshTokenValidationDataDO
                                                      refreshTokenValidationDataDO) throws IdentityOAuth2Exception {
        for (OAuthEventInterceptor interceptor : oAuthEventInterceptors) {
            if (interceptor.isEnabled()) {
                interceptor.onPostTokenRevocationByClient(oAuthRevocationRequestDTO, oAuthRevocationResponseDTO,
                        accessTokenDO, refreshTokenValidationDataDO);
            }
        }
    }

    @Override
    public void onPreTokenRevocationByResourceOwner(OAuthRevocationRequestDTO oAuthRevocationRequestDTO) throws
            IdentityOAuth2Exception {

        for (OAuthEventInterceptor interceptor : oAuthEventInterceptors) {
            if (interceptor.isEnabled()) {
                interceptor.onPreTokenRevocationByResourceOwner(oAuthRevocationRequestDTO);
            }
        }
    }

    @Override
    public void onPostTokenRevocationByResourceOwner(OAuthRevocationRequestDTO oAuthRevocationRequestDTO,
                                                     OAuthRevocationResponseDTO oAuthRevocationResponseDTO,
                                                     AccessTokenDO accessTokenDO) throws IdentityOAuth2Exception {
        for (OAuthEventInterceptor interceptor : oAuthEventInterceptors) {
            if (interceptor.isEnabled()) {
                interceptor.onPostTokenRevocationByResourceOwner(oAuthRevocationRequestDTO,
                        oAuthRevocationResponseDTO, accessTokenDO);
            }
        }
    }

    @Override
    public void onPreTokenValidation(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO) throws
            IdentityOAuth2Exception {
        for (OAuthEventInterceptor interceptor : oAuthEventInterceptors) {
            if (interceptor.isEnabled()) {
                interceptor.onPreTokenValidation(oAuth2TokenValidationRequestDTO);
            }
        }

    }

    @Override
    public void onPostTokenValidation(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO,
                                      OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO) throws
            IdentityOAuth2Exception {
        for (OAuthEventInterceptor interceptor : oAuthEventInterceptors) {
            if (interceptor.isEnabled()) {
                interceptor.onPostTokenValidation(oAuth2TokenValidationRequestDTO,
                        oAuth2TokenValidationResponseDTO);
            }
        }
    }

    @Override
    public String getName() {
        return OAuthConstants.OAUTH_INTERCEPTOR_PROXY;
    }
}
