package edu.spring.mall.websocket;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

@Configuration
@EnableWebSocket
public class WebsocketConfig implements WebSocketConfigurer{

	@Override
	public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(userQueryWebSocketHandler(), "/echo")
        .setAllowedOrigins("*")
        .addInterceptors(new SecurityHandshakeInterceptor());
	}

	@Bean
	public UserQueryWebsocketHandler userQueryWebSocketHandler() {
	      return new UserQueryWebsocketHandler();
	    }


}
