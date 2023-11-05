package com.example.keycloaktest;

import jakarta.ws.rs.core.Response;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@RequiredArgsConstructor
@Slf4j
@Service
public class KeycloakUserService {

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;
    private final Keycloak keycloak;

    public ResponseEntity<?> createUser(String username, String password) {
        UserRepresentation user = new UserRepresentation();
        user.setEnabled(true);
        user.setUsername(username);
        user.setCredentials(Arrays.asList(createPasswordCredential(password)));

        RealmResource realmResource = keycloak.realm(realm);
        UsersResource usersResource = realmResource.users();

        // 사용자 생성
        Response response = usersResource.create(user);
        System.out.println(response.getStatus());
        if (response.getStatus() == 201) {
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.status(response.getStatus()).build();
        }
    }

    private CredentialRepresentation createPasswordCredential(String password) {
        CredentialRepresentation passwordCredential = new CredentialRepresentation();
        passwordCredential.setTemporary(false);
        passwordCredential.setType(CredentialRepresentation.PASSWORD);
        passwordCredential.setValue(password);
        return passwordCredential;
    }



    public boolean existsByUsername(String userName) {

        List<UserRepresentation> search = keycloak.realm(realm).users()
                .search(userName);
        if(search.size() > 0){
            log.debug("search : {}", search.get(0).getUsername());
            return true;
        }
        return false;
    }
}
