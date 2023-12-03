package edu.spring.mall.service;

import java.util.Collection;

import org.springframework.web.socket.WebSocketSession;

import edu.spring.mall.domain.ChatRoomVO;
import edu.spring.mall.websocket.ChatRoom;

public interface ChatRoomService {
	ChatRoom create(String roomId, WebSocketSession userSession);
	Collection<ChatRoomVO> getAllChatList();
	void joinRoom(String roomId, WebSocketSession adminSession);
	ChatRoom getChatRoom(String roomId);

	ChatRoom getChatRoom(WebSocketSession session);

	void  removeChatRoom(String roomId , WebSocketSession session);

}

