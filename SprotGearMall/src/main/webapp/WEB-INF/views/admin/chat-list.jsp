<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ include file="/WEB-INF/views/includes/header.jsp" %>
    
<!DOCTYPE html>
<html>
<head>
    <title>관리자 채팅방 목록</title>
</head>
<body>
<div class="container-fluid">
  <div class="row">
    <!-- 왼쪽 메뉴 -->
    <div class="col-md-1 bg-light">
      <h4 class="bg-secondary">상품 관리</h4>
      <ul class="nav flex-column">

        <li class="nav-item">
          <a href="#" class="nav-link" onclick="loadContent('productList', 'contentDiv')">상품 목록</a>
        </li>
        <li class="nav-item">
          <a href="#" class="nav-link" onclick="loadContent('../product/register', 'contentDiv')">상품 등록</a>
        </li>
        
      </ul>
      <hr>
      <h4 class="bg-secondary">멤버 관리</h4>
      <ul class="nav flex-column">
        <li class="nav-item">
          <a href="#" class="nav-link" onclick="loadContent('memberList', 'contentDiv')">멤버 목록</a>
        </li>
        
        <li class="nav-item">
          <a href="#" class="nav-link" onclick="loadContent('orderManage', 'contentDiv')">주문 관리</a>
        </li>
        
        <li class="nav-item">
          <a href="/mall/admin/chat-list" class="nav-link">채팅 문의 확인</a>
        </li>
      </ul>
    </div>

    <!-- 오른쪽 컨텐츠 -->
    <div class="col-md-11">
         <div class="container mt-5">
    
        <h2>채팅방 목록</h2>
        <ul class="list-group">
            <!-- 채팅방 목록 출력되는곳 -->
            
        </ul>
    </div>
  </div>
</div>
</div>
    

    <script>
    $(document).ready(function() {
    	showChatRoom();
    });//end document.ready
    
    //server send event 로 구현해보기
    function showChatRoom(){
    	  $.ajax({
              url: "rooms", 
              method: "GET",
              success: function(rooms) {
            	  console.log(rooms)
                  displayChatRooms(rooms);
              }
          });
    }
    
    function displayChatRooms(rooms) {
        var roomsList = $('.list-group');
        roomsList.empty();

        rooms.forEach(function(room) {
            var roomDate = getRoomDateTime(room.roomId);
            var timeAgo = timeSince(roomDate);
            var chatRoomUrl = '/mall/qnaBoard/chat?roomId=' + encodeURIComponent(room.roomId);

            var roomElement = $('<a href="javascript:void(0)" class="list-group-item"></a>');
            roomElement.append('채팅방 번호 : ' + room.roomId + ' - ' + timeAgo + '<br>');
            roomElement.append('사용자 ID: ' + room.username);

            // 클릭 이벤트 리스너 추가
            roomElement.click(function(e) {
                e.preventDefault();
                console.log('url', chatRoomUrl);
                window.open(chatRoomUrl, '_blank', 'width=500,height=650'); 
            });

            roomsList.append(roomElement);
        });
    }
    
    
    function timeSince(date) {
        var seconds = Math.floor((new Date() - date) / 1000);
        interval = seconds / 86400;
        if (interval > 1) {
            return Math.floor(interval) + " 일 전";
        }
        interval = seconds / 3600;
        if (interval > 1) {
            return Math.floor(interval) + " 시간 전";
        }
        interval = seconds / 60;
        if (interval > 1) {
            return Math.floor(interval) + " 분 전";
        }
        return Math.floor(seconds) + " 초 전";
    }

    function getRoomDateTime(roomId) {
        var dateTimePart = roomId.split('-').slice(0, 6).join('-');
        var formattedDateTime = dateTimePart.replace(/(\d{4})-(\d{2})-(\d{2})-(\d{2})-(\d{2})-(\d{2})/, '$1-$2-$3T$4:$5:$6');
        return new Date(formattedDateTime);
    }

  

    </script>
</body>
</html>