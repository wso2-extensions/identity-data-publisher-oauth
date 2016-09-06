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

import org.wso2.carbon.identity.data.publisher.oauth.OAuthDataPublisherConstants;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;

public class OAuthTokenRevocationDASPublisher extends AbstractOAuthEventInterceptor {

    @Override
    public void onPreTokenRevocationByClient(OAuthRevocationRequestDTO oAuthRevocationRequestDTO) throws
            IdentityOAuth2Exception {
        // To be implemented
    }

    @Override
    public void onPostTokenRevocationByClient(OAuthRevocationRequestDTO oAuthRevocationRequestDTO,
                                              OAuthRevocationResponseDTO oAuthRevocationResponseDTO, AccessTokenDO
                                                      accessTokenDO, RefreshTokenValidationDataDO
                                                      refreshTokenValidationDataDO) throws IdentityOAuth2Exception {
        // To be implemented
    }

    @Override
    public void onPreTokenRevocationByResourceOwner(org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO
                                                            oAuthRevocationRequestDTO) throws
            IdentityOAuth2Exception {
        // To be implemented
    }

    @Override
    public void onPostTokenRevocationByResourceOwner(org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO
                                                             oAuthRevocationRequestDTO, org.wso2.carbon.identity
                                                             .oauth.dto.OAuthRevocationResponseDTO
                                                             oAuthRevocationResponseDTO, AccessTokenDO accessTokenDO)
            throws IdentityOAuth2Exception {
        // To be implemented
    }

    @Override
    public String getName() {
        return OAuthDataPublisherConstants.OAUTH_TOKEN_REVOCATION_DAS_DATA_PUBLISHER;
    }

}
