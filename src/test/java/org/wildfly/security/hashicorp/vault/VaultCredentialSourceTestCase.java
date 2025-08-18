/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import io.github.jopenlibs.vault.SslConfig;
import org.junit.Assert;
import org.junit.Test;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.interfaces.ClearPassword;

public class VaultCredentialSourceTestCase {

    @Test
    public void testGetSecretFromVaultService() throws Exception {
        // setup test container with vault
        SslConfig sslConfig = new SslConfig()
                .verify(false);
        VaultContainer<?> vaultContainer = new VaultContainer<>("hashicorp/vault:1.13")
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 top_secret=password123",
                        "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass"
                );
        vaultContainer.start();

        // Start Vault service
        VaultService vaultService = new VaultService(vaultContainer.getHttpHostAddress(), "myroot", "/v1/secret/data/testing2", sslConfig, false);
        vaultService.start();

        // Test credential source with vault service
        VaultCredentialSource credentialSource = new VaultCredentialSource(vaultService, "secret/testing1", "top_secret");
        PasswordCredential credential = credentialSource.getCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null);
        Assert.assertEquals("password123", String.valueOf(credential.getPassword(ClearPassword.class).getPassword()));
    }
}
