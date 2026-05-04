package com.devpath.api.notification.service;

import com.devpath.api.notification.dto.NotificationResponse;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@Service
public class NotificationSseService {

    private static final long SSE_TIMEOUT_MILLIS = 60L * 60L * 1000L;

    // 사용자별 SSE 연결을 메모리에 보관한다.
    private final Map<Long, SseEmitter> emitters = new ConcurrentHashMap<>();

    public SseEmitter subscribe(Long learnerId) {
        SseEmitter emitter = new SseEmitter(SSE_TIMEOUT_MILLIS);

        // 같은 사용자가 재구독하면 최신 연결로 교체한다.
        emitters.put(learnerId, emitter);

        emitter.onCompletion(() -> emitters.remove(learnerId));
        emitter.onTimeout(() -> emitters.remove(learnerId));
        emitter.onError(error -> emitters.remove(learnerId));

        sendConnectEvent(learnerId, emitter);

        return emitter;
    }

    public void send(Long learnerId, NotificationResponse response) {
        SseEmitter emitter = emitters.get(learnerId);

        if (emitter == null) {
            return;
        }

        try {
            emitter.send(SseEmitter.event()
                    .name("notification")
                    .data(response));
        } catch (IOException exception) {
            emitters.remove(learnerId);
        }
    }

    private void sendConnectEvent(Long learnerId, SseEmitter emitter) {
        try {
            emitter.send(SseEmitter.event()
                    .name("connect")
                    .data("notification-sse-connected:" + learnerId));
        } catch (IOException exception) {
            emitters.remove(learnerId);
        }
    }
}
