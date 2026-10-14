package com.astraval.iotrootbackend.modules.apikey;

import com.astraval.iotrootbackend.modules.apikey.dto.ApiKeyCreatedResponse;
import com.astraval.iotrootbackend.modules.user.User;
import com.astraval.iotrootbackend.modules.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ApiKeyServiceTest {

    private ApiKeyRepository repository;
    private UserRepository userRepository;
    private ApiKeyService service;
    private User user;

    @BeforeEach
    void setUp() {
        repository = mock(ApiKeyRepository.class);
        userRepository = mock(UserRepository.class);
        service = new ApiKeyService(repository, userRepository);

        user = new User();
        user.setUserId(4L);
        user.setVerified(true);
        user.setIsActive(true);
        when(userRepository.findByUserIdAndIsActiveTrue(4L)).thenReturn(Optional.of(user));
        when(repository.save(any(ApiKey.class))).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void createsAOneTimeSecretAndStoresOnlyItsHash() {
        ApiKeyCreatedResponse response = service.create(4L, "Dashboard export");

        assertTrue(response.getApiKey().startsWith("iotr_live_"));
        ArgumentCaptor<ApiKey> captor = ArgumentCaptor.forClass(ApiKey.class);
        verify(repository).save(captor.capture());
        ApiKey stored = captor.getValue();
        assertEquals(64, stored.getKeyHash().length());
        assertNotEquals(response.getApiKey(), stored.getKeyHash());
        assertTrue(response.getApiKey().startsWith(stored.getKeyPrefix()));
    }

    @Test
    void authenticatesAnActiveKeyAndRecordsLastUse() {
        ApiKeyCreatedResponse created = service.create(4L, "Reader");
        ApiKey key = new ApiKey();
        key.setUser(user);
        when(repository.findByKeyHashAndRevokedAtIsNull(anyString())).thenReturn(Optional.of(key));

        assertEquals(4L, service.authenticate(created.getApiKey()));
        assertNotNull(key.getLastUsedAt());
        verify(repository, times(2)).save(any(ApiKey.class));
    }
}
