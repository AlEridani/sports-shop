<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>

<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Insert title here</title>
</head>
<body>
	<h1>로그인 화면</h1>
	<form action="login" method="POST">
		<input type="text" name="memberId" required="required"placeholder="아이디"><br> 
		<input type="password"name="password" required="required" placeholder="비밀번호"><br> 
		<input type="submit" value="로그인">
	</form>
	<a href="register"><button>회원가입</button></a>
</body>
</html>