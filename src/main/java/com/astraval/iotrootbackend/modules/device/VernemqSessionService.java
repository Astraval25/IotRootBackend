package com.astraval.iotrootbackend.modules.device;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
public class VernemqSessionService {

    private final ObjectMapper objectMapper;
    private final String vmqAdminPath;
    private final String brokerHost;
    private final int brokerPort;
    private final Duration commandTimeout;

    public VernemqSessionService(
            ObjectMapper objectMapper,
            @Value("${vernemq.admin.path:/opt/vernemq/bin/vmq-admin}") String vmqAdminPath,
            @Value("${vernemq.broker.host:iotroot.astraval.com}") String brokerHost,
            @Value("${vernemq.broker.port:1883}") int brokerPort,
            @Value("${vernemq.admin.timeout-seconds:5}") long timeoutSeconds
    ) {
        this.objectMapper = objectMapper;
        this.vmqAdminPath = vmqAdminPath;
        this.brokerHost = brokerHost;
        this.brokerPort = brokerPort;
        this.commandTimeout = Duration.ofSeconds(timeoutSeconds);
    }

    public String getBrokerHost() {
        return brokerHost;
    }

    public int getBrokerPort() {
        return brokerPort;
    }

    public Map<String, Map<String, String>> getSessionDetailsByClientId() {
        List<String> command = new ArrayList<>();
        command.add(vmqAdminPath);
        command.add("session");
        command.add("show");
        command.add("--format=json");

        CommandResult result = runCommand(command);
        if (!result.success) {
            return Map.of();
        }

        try {
            JsonNode root = objectMapper.readTree(result.stdout);
            JsonNode table = root.path("table");
            if (!table.isArray()) {
                return Map.of();
            }

            Map<String, Map<String, String>> byClientId = new HashMap<>();
            for (JsonNode row : table) {
                String clientId = readText(row, "client_id");
                if (clientId == null || clientId.isBlank()) {
                    continue;
                }

                Map<String, String> details = new HashMap<>();
                row.fields().forEachRemaining(entry -> {
                    JsonNode value = entry.getValue();
                    details.put(entry.getKey(), value.isNull() ? "" : value.asText(""));
                });
                byClientId.put(clientId, details);
            }
            return byClientId;
        } catch (IOException exception) {
            return Map.of();
        }
    }

    private CommandResult runCommand(List<String> command) {
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);

        try {
            Process process = processBuilder.start();
            boolean finished = process.waitFor(commandTimeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                return new CommandResult(false, "", "Timed out");
            }

            String stdout = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            boolean success = process.exitValue() == 0;
            return new CommandResult(success, stdout, success ? "" : stdout);
        } catch (IOException | InterruptedException exception) {
            if (exception instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return new CommandResult(false, "", exception.getMessage());
        }
    }

    private String readText(JsonNode node, String key) {
        JsonNode value = node.path(key);
        if (value.isMissingNode() || value.isNull()) {
            return null;
        }
        String text = value.asText("");
        return text.isBlank() ? null : text;
    }

    private record CommandResult(boolean success, String stdout, String error) {
    }
}
