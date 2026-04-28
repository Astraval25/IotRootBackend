package com.astraval.iotrootbackend.config;

import com.astraval.iotrootbackend.modules.device.DeviceStatusWebSocketHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    private final DeviceStatusWebSocketHandler deviceStatusWebSocketHandler;
    private final DeviceStatusWebSocketAuthInterceptor authInterceptor;

    public WebSocketConfig(DeviceStatusWebSocketHandler deviceStatusWebSocketHandler,
                           DeviceStatusWebSocketAuthInterceptor authInterceptor) {
        this.deviceStatusWebSocketHandler = deviceStatusWebSocketHandler;
        this.authInterceptor = authInterceptor;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(deviceStatusWebSocketHandler, "/ws/device-status")
                .addInterceptors(authInterceptor)
                .setAllowedOriginPatterns("*");
    }
}
