package edu.spring.mall.websocket;

import java.util.Date;
import java.util.List;

import org.springframework.messaging.Message;
import org.springframework.web.socket.WebSocketSession;

public class ChatRoom {
		private String roomId;
		private WebSocketSession userSession;
		private WebSocketSession adminSession;
		private List<Message> messages;
		private Date createdDate;
	public String getRoomId() {
		return roomId;
	}
	public void setRoomId(String roomId) {
		this.roomId = roomId;
	}
	public WebSocketSession getUserSession() {
		return userSession;
	}
	public void setUserSession(WebSocketSession userSession) {
		this.userSession = userSession;
	}
	public WebSocketSession getAdminSession() {
		return adminSession;
	}
	public void setAdminSession(WebSocketSession adminSession) {
		this.adminSession = adminSession;
	}
	public List<Message> getMessages() {
		return messages;
	}
	public void setMessages(List<Message> messages) {
		this.messages = messages;
	}
	public Date getCreatedDate() {
		return createdDate;
	}
	public void addMessage(Message message) {
		this.messages.add(message);
	}
	public void setCreatedDate(Date createdDate) {
		this.createdDate = createdDate;
	}
	public ChatRoom(String roomId, WebSocketSession userSession, WebSocketSession adminSession, List<Message> messages,
			Date createdDate) {
		super();
		this.roomId = roomId;
		this.userSession = userSession;
		this.adminSession = adminSession;
		this.messages = messages;
		this.createdDate = createdDate;
	}
	public ChatRoom() {
		super();
	}
	@Override
	public String toString() {
		return "ChatRoom [roomId=" + roomId + ", userSession=" + userSession + ", adminSession=" + adminSession
				+ ", messages=" + messages + ", createdDate=" + createdDate + "]";
	}
	
	 
	 
}
