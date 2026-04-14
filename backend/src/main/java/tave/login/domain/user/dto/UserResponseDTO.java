package tave.login.domain.user.dto;
/*
record : 필드, 생성자(AllArgumentsConstructor), getter 자동생성(단, getter의 경우 메서드명이 필드이름과 같다)
웅덥객체에 주로 쓰인다
 */
public record UserResponseDTO(String username, Boolean social,  String nickname, String email) {

}
