package edu.spring.mall.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.socket.WebSocketSession;

import edu.spring.mall.domain.ChatRoomVO;
import edu.spring.mall.websocket.ChatRoom;

@Service
public class ChatRoomServiceImple implements ChatRoomService {
	private Logger logger = LoggerFactory.getLogger(ChatRoomServiceImple.class);
	//이건 채팅방의 정보를 가지고 있는 객체 모음
    private Map<String, ChatRoom> chatList = new ConcurrentHashMap<>();
    //이건 매핑을 위한 자료 구조
    private Map<WebSocketSession, ChatRoom> chatMapping = new ConcurrentHashMap<>();



	@Override
	public ChatRoom create(String roomId, WebSocketSession userSession) {
		logger.info("채팅방 생성");
		ChatRoom room = new ChatRoom(roomId, userSession, null, new ArrayList<>(), new Date());
		chatList.put(roomId, room);
		chatMapping.put(userSession, room);
		return room;
	}
	
	@Override
	public Collection<ChatRoomVO> getAllChatList() {
		logger.info("memberId 호출");
	    Collection<ChatRoom> rooms = chatList.values();
	    List<ChatRoomVO> roomList = new ArrayList<>();
	    for (ChatRoom room : rooms) {
	    	String username = (String) room.getUserSession().getAttributes().get("username");
	        ChatRoomVO roomVo = new ChatRoomVO(room,username);
	        roomList.add(roomVo);
	    }

	    return roomList;
	}

	@Override
	public void joinRoom(String roomId, WebSocketSession adminSession) {
		logger.info("채팅방 입장: roomId=" + roomId);
	    ChatRoom room = chatList.get(roomId);
		if(room == null) {
			logger.info("채팅방이 없음");
			return;
		}
	    room.setAdminSession(adminSession);
	    chatMapping.put(adminSession, room);
	}

	@Override
	public ChatRoom getChatRoom(String roomId) {
		logger.info("getChatRoom 호출");
	    return chatList.get(roomId);
	}

	public ChatRoom getChatRoom(WebSocketSession session) {
		logger.info("getChatRoom 호출");
	    return chatMapping.get(session);
	}

	public void removeChatRoom(String roomId, WebSocketSession session) {
		logger.info("removeChatRoom 호출");
		chatList.remove(roomId);
		chatMapping.remove(session);
	}

}
