/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.junit.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.vault.VaultContainer;

import static org.junit.Assert.assertEquals;
import static org.wildfly.common.Assert.assertTrue;

public class ElytronVaultTestCase {

    @Test
    public void testVaultIsRunningAndConfigured() throws Exception {

        VaultContainer<?> vaultContainer = new VaultContainer<>("hashicorp/vault:1.13")
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 top_secret=password123",
                        "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass"
                );

        vaultContainer.start();

        GenericContainer.ExecResult result = vaultContainer.execInContainer(
                "vault",
                "kv",
                "get",
                "-format=json",
                "secret/testing1"
        );
        assertTrue(result.getStdout().contains("password123"));

        Response response = RestAssured
                .given()
                .header("X-Vault-Token", "myroot")
                .when()
                .get(vaultContainer.getHttpHostAddress() + "/v1/secret/data/testing1")
                .thenReturn();

        assertEquals("password123", response.getBody().jsonPath().getString("data.data.top_secret"));

        Response responseWithIncorrectToken = RestAssured
                .given()
                .header("X-Vault-Token", "incorrect")
                .when()
                .get(vaultContainer.getHttpHostAddress() + "/v1/secret/data/testing1")
                .thenReturn();
        assertEquals("[permission denied]", responseWithIncorrectToken.getBody().jsonPath().getString("errors"));

        Response responseTesting2 = RestAssured
                .given()
                .header("X-Vault-Token", "myroot")
                .when()
                .get(vaultContainer.getHttpHostAddress() + "/v1/secret/data/testing2")
                .thenReturn();

        assertEquals("secretpass", responseTesting2.getBody().jsonPath().getString("data.data.dbuser"));

        vaultContainer.stop();
    }

}
